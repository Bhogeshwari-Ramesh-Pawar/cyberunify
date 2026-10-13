"""CyberUnify: connect any SOC tool, see every log in one dashboard."""

from __future__ import annotations

import asyncio
import base64
import csv
import io
import json
import logging
import re
import secrets as pysecrets
import time
from collections import Counter
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from . import compliance, vendors
from .collectors import CollectorError, pull
from .config import Settings, get_settings
from .db import EVENT_STATUSES, Database
from .demo import DEMO_TOOLS, Simulator
from .ingest import pull_integration, rescore_window, run_cycle, store_records
from .integrations import build, new_webhook_token, seed_demo, to_public, token_hash
from .mapping import SEVERITY_SCALES, UNIFIED_FIELDS, map_record
from .models import CATEGORIES, RISK_LEVELS
from .parsers import parse_payload
from .presets import CONNECTION_TYPES, public_catalog, secret_keys
from .scoring import host_risk, score_one
from .search import Filters, facets, histogram, search
from .syslog import SyslogManager
from .vault import SecretBox

log = logging.getLogger("cyberunify")
HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=HERE / "templates")
RESOLVED = {"closed", "false_positive"}
MAX_WEBHOOK_BYTES = 5 * 1024 * 1024
RANGE_RE = re.compile(r"^(\d+)([mhd])$")
RANGE_Q = Query("24h", alias="range", description="15m, 1h, 24h, 7d or all")
SEARCH_Q = Query(None, max_length=500, description='Query, e.g. host:web-01 -success "brute force"')


# ---------- request bodies (module level so FastAPI can resolve them) ----------

class IntegrationIn(BaseModel):
    name: str = Field("", max_length=120)
    tool: str = "custom"
    type: str | None = None
    config: dict[str, Any] = Field(default_factory=dict)
    mapping: dict[str, str] = Field(default_factory=dict)
    severity_scale: str | None = None
    default_category: str | None = None
    enabled: bool = True


class TestIn(IntegrationIn):
    integration_id: int | None = None  # when editing: reuse stored secrets left blank in the form
    sample: str | None = Field(None, max_length=200_000)


class StatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "closed", "false_positive"]


class VendorIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    service: str = Field("", max_length=200)
    data_sensitivity: Literal["low", "medium", "high"]
    access_level: Literal["none", "limited", "privileged"]
    answers: dict[str, bool] = Field(default_factory=dict)


# ---------- app ----------

def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        db = Database(settings.db_path)
        box = SecretBox.from_env_or_file(settings.key_file)
        app.state.settings, app.state.db, app.state.box = settings, db, box
        app.state.simulator = Simulator() if settings.demo_mode else None
        app.state.dirty = False

        if settings.demo_mode:
            seed_demo(db, box, DEMO_TOOLS)
            if db.vendor_count() == 0:
                for name, service, sens, access, answers in vendors.DEMO_VENDORS:
                    db.add_vendor(vendors.assess_vendor(name, service, sens, access, answers))

        def deliver_syslog(integration_id: int, lines: list[str]) -> None:
            integ = db.get_integration(integration_id)
            if integ and integ["enabled"]:
                store_records(db, integ, parse_payload("\n".join(lines), "text"), settings)
                app.state.dirty = True

        app.state.syslog = SyslogManager(deliver_syslog, settings.syslog_host)
        app.state.syslog.start_flusher()
        await sync_syslog(app)
        await asyncio.to_thread(run_cycle, db, settings, box, app.state.simulator)

        tasks = [asyncio.create_task(_rescore_loop(app))]
        if settings.ingest_interval > 0:
            tasks.append(asyncio.create_task(_ingest_loop(app)))
        yield
        for t in tasks:
            t.cancel()
            with suppress(asyncio.CancelledError):
                await t
        await app.state.syslog.shutdown()
        db.close()

    app = FastAPI(title="CyberUnify", version="2.0.0", lifespan=lifespan,
                  description="Connect any SOC tool and see every log in one dashboard.")

    # Optional login: set CYBERUNIFY_ADMIN_PASSWORD to protect the dashboard and API.
    # Webhooks are exempt: they authenticate with their own secret token in the URL.
    @app.middleware("http")
    async def basic_auth(request: Request, call_next):
        password = settings.admin_password
        if password and not request.url.path.startswith("/api/ingest/"):
            header = request.headers.get("authorization", "")
            ok = False
            if header.lower().startswith("basic "):
                try:
                    _, _, given = base64.b64decode(header[6:]).decode().partition(":")
                    ok = pysecrets.compare_digest(given, password)
                except (ValueError, UnicodeDecodeError):
                    ok = False
            if not ok:
                return Response("Login required", 401, {"WWW-Authenticate": 'Basic realm="CyberUnify"'})
        return await call_next(request)

    # ---------- helpers ----------

    def db_(request: Request) -> Database:
        return request.app.state.db

    def window_start() -> int:
        return int((datetime.now(timezone.utc) - timedelta(hours=settings.window_hours)).timestamp())

    def parse_range(range_: str | None, since: int | None, until: int | None) -> tuple[int | None, int | None]:
        if since is not None or until is not None:
            return since, until
        if not range_ or range_ == "all":
            return window_start(), None
        m = RANGE_RE.match(range_)
        if not m:
            raise HTTPException(400, "range must look like 15m, 24h or 7d")
        seconds = int(m.group(1)) * {"m": 60, "h": 3600, "d": 86400}[m.group(2)]
        return max(window_start(), int(time.time()) - seconds), None

    def make_filters(range_, since, until, tool, level, host, category, status, integration_id, q) -> Filters:
        s, u = parse_range(range_, since, until)
        return Filters(since=s, until=u, tools=[t for t in (tool or "").split(",") if t],
                       levels=[lv for lv in (level or "").split(",") if lv in RISK_LEVELS],
                       host=host or None, category=category or None, status=status or None,
                       integration_id=integration_id, q=q or "")

    def window_events(request: Request):
        since = window_start()
        events = db_(request).events_since(since)
        return events, db_(request).statuses_since(since)

    def public_integrations(request: Request) -> list[dict[str, Any]]:
        counts = db_(request).event_counts_by_integration(window_start())
        mgr: SyslogManager = request.app.state.syslog
        return [to_public(i, request.app.state.box, settings.public_url, counts.get(i["id"], 0),
                          mgr.is_listening(i["id"]) if i["type"] == "syslog" else None)
                for i in db_(request).list_integrations()]

    def health(request: Request) -> list[dict[str, Any]]:
        out = []
        for i in public_integrations(request):
            if not i["enabled"]:
                continue
            ok = i["last_status"] == "ok" or (i["type"] == "syslog" and i.get("listening")) or \
                (i["type"] == "webhook" and i["last_status"] != "error")
            out.append({"source": i["name"], "status": "ok" if ok else "error"})
        return out

    # ---------- catalog ----------

    @app.get("/api/catalog")
    def catalog():
        return {**public_catalog(), "severity_scales": SEVERITY_SCALES, "categories": list(CATEGORIES),
                "unified_fields": list(UNIFIED_FIELDS), "levels": list(RISK_LEVELS),
                "statuses": list(EVENT_STATUSES), "public_url": settings.public_url}

    # ---------- integrations ----------

    @app.get("/api/integrations")
    def list_integrations(request: Request):
        return public_integrations(request)

    @app.post("/api/integrations", status_code=201)
    async def create_integration(body: IntegrationIn, request: Request):
        box = request.app.state.box
        try:
            row = build(body.model_dump(), box)
        except ValueError as err:
            raise HTTPException(400, str(err)) from err
        if row["type"] == "webhook":
            token, digest = new_webhook_token()
            row["webhook_token"], row["webhook_token_hash"] = box.encrypt(token), digest
        if row["type"] == "syslog" and _port_taken(request, row, None):
            raise HTTPException(400, f"Port {row['config']['port']}/{row['config'].get('protocol', 'udp')} is already used by another integration")
        new_id = db_(request).add_integration(row)
        await sync_syslog(request.app)
        integ = db_(request).get_integration(new_id)
        if CONNECTION_TYPES[integ["type"]]["mode"] == "pull" and integ["enabled"]:
            await asyncio.to_thread(pull_integration, db_(request), integ, settings, box)
            request.app.state.dirty = True
        return next(i for i in public_integrations(request) if i["id"] == new_id)

    def _port_taken(request: Request, row: dict[str, Any], own_id: int | None) -> bool:
        port, proto = row["config"].get("port"), row["config"].get("protocol", "udp")
        return any(i["type"] == "syslog" and i["id"] != own_id and not i["demo"] and i["config"].get("port") == port
                   and i["config"].get("protocol", "udp") == proto for i in db_(request).list_integrations())

    @app.put("/api/integrations/{integration_id}")
    async def update_integration(integration_id: int, body: IntegrationIn, request: Request):
        existing = db_(request).get_integration(integration_id)
        if not existing:
            raise HTTPException(404, "Integration not found")
        box = request.app.state.box
        try:
            row = build(body.model_dump(), box, existing)
        except ValueError as err:
            raise HTTPException(400, str(err)) from err
        if row["type"] == "webhook" and not existing.get("webhook_token"):
            token, digest = new_webhook_token()
            row["webhook_token"], row["webhook_token_hash"] = box.encrypt(token), digest
        if row["type"] == "syslog" and _port_taken(request, row, integration_id):
            raise HTTPException(400, f"Port {row['config']['port']} is already used by another integration")
        if row["type"] != existing["type"]:
            row["state"] = {}
        db_(request).update_integration(integration_id, row)
        await sync_syslog(request.app)
        return next(i for i in public_integrations(request) if i["id"] == integration_id)

    @app.post("/api/integrations/{integration_id}/enabled")
    async def toggle_integration(integration_id: int, request: Request, enabled: bool = True):
        if not db_(request).update_integration(integration_id, {"enabled": enabled}):
            raise HTTPException(404, "Integration not found")
        await sync_syslog(request.app)
        return {"ok": True, "enabled": enabled}

    @app.post("/api/integrations/{integration_id}/pull")
    async def pull_now(integration_id: int, request: Request):
        integ = db_(request).get_integration(integration_id)
        if not integ:
            raise HTTPException(404, "Integration not found")
        if integ["demo"]:
            sim = request.app.state.simulator or Simulator()
            result = await asyncio.to_thread(store_records, db_(request), integ, sim.records_for(integ["tool"]), settings)
        elif CONNECTION_TYPES[integ["type"]]["mode"] != "pull":
            raise HTTPException(400, "This integration receives data; there is nothing to pull.")
        else:
            result = await asyncio.to_thread(pull_integration, db_(request), integ, settings, request.app.state.box)
        await asyncio.to_thread(rescore_window, db_(request), settings)
        return result

    @app.post("/api/integrations/{integration_id}/rotate-token")
    def rotate_token(integration_id: int, request: Request):
        integ = db_(request).get_integration(integration_id)
        if not integ or integ["type"] != "webhook":
            raise HTTPException(404, "Webhook integration not found")
        token, digest = new_webhook_token()
        db_(request).update_integration(integration_id, {"webhook_token": request.app.state.box.encrypt(token),
                                                         "webhook_token_hash": digest})
        return next(i for i in public_integrations(request) if i["id"] == integration_id)

    @app.delete("/api/integrations/{integration_id}")
    async def delete_integration(integration_id: int, request: Request, purge: bool = False):
        if not db_(request).get_integration(integration_id):
            raise HTTPException(404, "Integration not found")
        removed = db_(request).delete_events_of(integration_id) if purge else 0
        db_(request).delete_integration(integration_id)
        await sync_syslog(request.app)
        return {"ok": True, "events_removed": removed}

    @app.post("/api/integrations/test")
    async def test_integration(body: TestIn, request: Request):
        """Try the connection (or a pasted sample) and show how records will be mapped. Nothing is stored."""
        box = request.app.state.box
        existing = db_(request).get_integration(body.integration_id) if body.integration_id else None
        try:
            row = build(body.model_dump(exclude={"integration_id", "sample"}), box, existing)
        except ValueError as err:
            return {"ok": False, "error": str(err)}
        conn_type = row["type"]
        if body.sample and body.sample.strip():
            fmt = row["config"].get("format", "auto")
            records = parse_payload(body.sample, "text" if conn_type == "syslog" else fmt, row["config"].get("records_path"))
            source = "sample"
        elif CONNECTION_TYPES[conn_type]["mode"] == "push":
            return {"ok": False, "error": "Paste a sample log from the tool to preview the mapping."}
        else:
            since = datetime.now(timezone.utc) - timedelta(hours=settings.window_hours)
            try:
                cfg = box.open(row["config"], secret_keys(conn_type))
                records, _ = await asyncio.to_thread(pull, conn_type, cfg, since, {}, 5)
            except (CollectorError, ValueError) as err:
                return {"ok": False, "error": str(err)}
            source = "live"
        if not records:
            return {"ok": True, "source": source, "records": [],
                    "message": "Connected, but no records were returned for the time window."}
        preview = []
        for rec in records[:5]:
            try:
                event, trace = map_record(rec, integration_id=0, tool=row["tool"], mapping=row["mapping"],
                                          severity_scale=row["severity_scale"], default_category=row["default_category"],
                                          inventory=settings.asset_inventory, fallback_host=row["name"])
                event.risk_score, event.risk_factors = score_one(
                    event.severity, event.mitre_tactic, settings.asset_criticality.get(event.host, 1.0), 0.0, 0.0)
                preview.append({"event": event.to_dict(), "trace": trace, "raw": rec})
            except ValueError as err:
                preview.append({"error": str(err), "raw": rec})
        return {"ok": True, "source": source, "records": preview}

    # ---------- webhook receiver ----------

    @app.post("/api/ingest/{token}")
    async def webhook(token: str, request: Request):
        integ = db_(request).integration_by_token_hash(token_hash(token))
        if not integ or integ["type"] != "webhook":
            raise HTTPException(404, "Unknown webhook")  # same answer for a wrong token: no oracle
        if not integ["enabled"]:
            raise HTTPException(409, "This integration is disabled")
        body = await request.body()
        if len(body) > MAX_WEBHOOK_BYTES:
            raise HTTPException(413, "Payload too large (max 5 MB)")
        try:
            records = parse_payload(body, integ["config"].get("format", "auto"), integ["config"].get("records_path"))
        except (ValueError, json.JSONDecodeError) as err:
            raise HTTPException(400, f"Could not parse payload: {err}") from err
        result = await asyncio.to_thread(store_records, db_(request), integ, records, settings)
        request.app.state.dirty = True
        return {"accepted": len(records), **result}

    # ---------- events (the unified log explorer) ----------

    @app.get("/api/events")
    def list_events(request: Request, range_: str = RANGE_Q, since: int | None = None,
                    until: int | None = None, tool: str | None = None, level: str | None = None,
                    host: str | None = None, category: str | None = None, status: str | None = None,
                    integration_id: int | None = None, q: str | None = SEARCH_Q,
                    sort: Literal["time", "risk"] = "time", limit: int = Query(100, ge=1, le=1000),
                    offset: int = Query(0, ge=0)):
        f = make_filters(range_, since, until, tool, level, host, category, status, integration_id, q)
        return search(db_(request), f, sort, limit, offset)

    @app.get("/api/events/stats")
    def event_stats(request: Request, range_: str = RANGE_Q, since: int | None = None,
                    until: int | None = None, tool: str | None = None, level: str | None = None,
                    host: str | None = None, category: str | None = None, status: str | None = None,
                    integration_id: int | None = None, q: str | None = SEARCH_Q,
                    buckets: int = Query(60, ge=10, le=200)):
        f = make_filters(range_, since, until, tool, level, host, category, status, integration_id, q)
        return {"histogram": histogram(db_(request), f, buckets), "facets": facets(db_(request), f)}

    @app.get("/api/events/export")
    def export_events(request: Request, range_: str = RANGE_Q, since: int | None = None,
                      until: int | None = None, tool: str | None = None, level: str | None = None,
                      host: str | None = None, category: str | None = None, status: str | None = None,
                      integration_id: int | None = None, q: str | None = SEARCH_Q,
                      format: Literal["csv", "ndjson"] = "csv"):
        f = make_filters(range_, since, until, tool, level, host, category, status, integration_id, q)
        rows = search(db_(request), f, "time", 50_000, 0)["items"]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
        if format == "ndjson":
            body = "".join(json.dumps(r, default=str) + "\n" for r in rows)
            media, ext = "application/x-ndjson", "ndjson"
        else:
            buf = io.StringIO()
            cols = ["timestamp", "tool", "host", "risk_level", "risk_score", "category", "message", "src_ip",
                    "dst_ip", "user", "rule", "action", "mitre_technique", "status", "id"]
            writer = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
            writer.writeheader()
            for r in rows:
                # Neutralise spreadsheet formulas in attacker-controlled fields (CSV injection).
                writer.writerow({k: ("'" + v if isinstance(v, str) and v[:1] in "=+-@\t\r" else v) for k, v in r.items()})
            body, media, ext = buf.getvalue(), "text/csv", "csv"
        return StreamingResponse(iter([body]), media_type=media,
                                 headers={"Content-Disposition": f'attachment; filename="cyberunify-events-{stamp}.{ext}"'})

    @app.get("/api/events/{event_id}")
    def get_event(event_id: str, request: Request):
        found = db_(request).get_event(event_id)
        if not found:
            raise HTTPException(404, "Event not found")
        event, status = found
        integ = db_(request).get_integration(event.integration_id)
        return event.to_dict(include_raw=True) | {"status": status, "integration": integ["name"] if integ else None}

    @app.patch("/api/events/{event_id}")
    def update_event(event_id: str, body: StatusUpdate, request: Request):
        if not db_(request).set_status(event_id, body.status):
            raise HTTPException(404, "Event not found")
        return {"ok": True, "status": body.status}

    # ---------- overview ----------

    @app.get("/api/summary")
    def summary(request: Request):
        db = db_(request)
        events, statuses = window_events(request)
        active = [e for e in events if statuses.get(e.id, "open") not in RESOLVED]
        levels = Counter(e.risk_level for e in active)
        day_ago = datetime.now(timezone.utc) - timedelta(hours=24)
        integs = public_integrations(request)
        hl = health(request)
        inventory_ips = set(settings.asset_inventory)
        external = Counter(e.src_ip for e in active if e.src_ip and e.src_ip not in inventory_ips and e.risk_score >= 35)
        f48 = Filters(since=int(time.time()) - 48 * 3600)
        return {
            "kpis": {
                "events": len(events),
                "events_24h": sum(1 for e in events if e.timestamp >= day_ago),
                "tools": len({i["tool"] for i in integs if i["enabled"]}),
                "integrations_ok": sum(1 for h in hl if h["status"] == "ok"),
                "integrations": len(hl),
                "critical": levels.get("critical", 0),
                "high": levels.get("high", 0),
                "hosts": len({e.host for e in events}),
            },
            "risk_levels": {lvl: levels.get(lvl, 0) for lvl in RISK_LEVELS},
            "timeline": histogram(db, f48, 48),
            "by_tool": Counter(e.tool for e in events).most_common(),
            "categories": Counter(e.category for e in active if e.risk_score >= 15).most_common(),
            "top_hosts": host_risk([e for e in active if e.risk_score >= 15])[:8],
            "top_sources": external.most_common(8),
            "top_events": [e.to_dict() | {"status": statuses.get(e.id, "open")}
                           for e in sorted(active, key=lambda e: e.risk_score, reverse=True)[:10]],
            "integrations": [{k: i.get(k) for k in ("id", "name", "tool", "type", "enabled", "demo", "last_status",
                                                     "last_error", "last_run_at", "events", "listening", "kind")}
                             for i in integs],
        }

    @app.get("/api/hosts")
    def hosts(request: Request):
        events, statuses = window_events(request)
        return host_risk([e for e in events if statuses.get(e.id, "open") not in RESOLVED and e.risk_score >= 15])

    @app.post("/api/refresh")
    async def refresh(request: Request):
        results = await asyncio.to_thread(run_cycle, db_(request), settings, request.app.state.box,
                                          request.app.state.simulator)
        return {"ok": True, "results": results}

    # ---------- compliance ----------

    @app.get("/api/compliance")
    def get_compliance(request: Request):
        events, statuses = window_events(request)
        return compliance.assess(events, statuses, health(request), db_(request).list_vendors())

    @app.get("/reports/iso27001", response_class=HTMLResponse)
    def iso_report(request: Request, download: bool = False):
        events, statuses = window_events(request)
        active = [e for e in events if statuses.get(e.id, "open") not in RESOLVED]
        s = summary(request)
        response = templates.TemplateResponse(request, "report.html", {
            "report": compliance.assess(events, statuses, health(request), db_(request).list_vendors()),
            "kpis": s["kpis"],
            "integrations": s["integrations"],
            "hosts": host_risk([e for e in active if e.risk_score >= 15])[:10],
            "top_events": sorted(active, key=lambda e: e.risk_score, reverse=True)[:10],
            "vendors": db_(request).list_vendors(),
            "window_hours": settings.window_hours,
            "generated": datetime.now(timezone.utc).strftime("%d %b %Y, %H:%M UTC"),
        })
        if download:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
            response.headers["Content-Disposition"] = f'attachment; filename="cyberunify-iso27001-{stamp}.html"'
        return response

    # ---------- third-party risk ----------

    @app.get("/api/vendors")
    def list_vendors(request: Request):
        return {"questions": [{"key": k, "text": t, "weight": w} for k, t, w in vendors.QUESTIONS],
                "items": db_(request).list_vendors()}

    @app.post("/api/vendors", status_code=201)
    def add_vendor(body: VendorIn, request: Request):
        try:
            result = vendors.assess_vendor(body.name, body.service, body.data_sensitivity, body.access_level, body.answers)
        except ValueError as err:
            raise HTTPException(400, str(err)) from err
        result["id"] = db_(request).add_vendor(result)
        return result

    @app.delete("/api/vendors/{vendor_id}")
    def delete_vendor(vendor_id: int, request: Request):
        if not db_(request).delete_vendor(vendor_id):
            raise HTTPException(404, "Vendor not found")
        return {"ok": True}

    # ---------- dashboard ----------

    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(HERE / "static" / "index.html", headers={"Cache-Control": "no-cache"})

    return app


async def sync_syslog(app: FastAPI) -> None:
    """Start/stop syslog listeners to match the integrations, recording bind errors on each one."""
    db: Database = app.state.db
    errors = await app.state.syslog.sync(db.list_integrations())
    for iid, error in errors.items():
        if error:
            db.update_integration(iid, {"last_status": "error", "last_error": error})
        else:
            integ = db.get_integration(iid)
            if integ and integ.get("last_status") == "error" and "listen" in (integ.get("last_error") or "").lower():
                db.update_integration(iid, {"last_status": None, "last_error": None})


async def _ingest_loop(app: FastAPI) -> None:
    while True:
        await asyncio.sleep(app.state.settings.ingest_interval)
        try:
            await asyncio.to_thread(run_cycle, app.state.db, app.state.settings, app.state.box, app.state.simulator)
            app.state.dirty = False
        except Exception:
            log.exception("scheduled ingest failed")


async def _rescore_loop(app: FastAPI) -> None:
    """Pushed data (webhooks, syslog) gets the full context-aware rescore within ~10 seconds."""
    while True:
        await asyncio.sleep(10)
        if app.state.dirty:
            app.state.dirty = False
            try:
                await asyncio.to_thread(rescore_window, app.state.db, app.state.settings)
            except Exception:
                log.exception("rescore failed")


app = create_app()
