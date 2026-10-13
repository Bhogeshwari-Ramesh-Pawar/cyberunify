"""CyberUnify API + dashboard."""

from __future__ import annotations

import asyncio
import logging
from collections import Counter
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from . import compliance, vendors
from .config import Settings, get_settings
from .db import ALERT_STATUSES, Database
from .ingest import run_ingest
from .models import RISK_LEVELS, Alert
from .scoring import host_risk

log = logging.getLogger("cyberunify")
HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=HERE / "templates")
RESOLVED = {"closed", "false_positive"}


# Request bodies live at module level: with postponed annotations FastAPI can only
# resolve models it can find in the module namespace, not ones local to create_app().
class StatusUpdate(BaseModel):
    status: Literal["open", "acknowledged", "closed", "false_positive"]


class VendorIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    service: str = Field("", max_length=200)
    data_sensitivity: Literal["low", "medium", "high"]
    access_level: Literal["none", "limited", "privileged"]
    answers: dict[str, bool] = Field(default_factory=dict)


async def _ingest_loop(app: FastAPI) -> None:
    while True:
        await asyncio.sleep(app.state.settings.ingest_interval)
        try:
            await asyncio.to_thread(run_ingest, app.state.db, app.state.settings)
        except Exception:  # keep the loop alive whatever a connector does
            log.exception("scheduled ingest failed")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.settings = settings
        app.state.db = Database(settings.db_path)
        if settings.demo_mode and app.state.db.vendor_count() == 0:
            for name, service, sens, access, answers in vendors.DEMO_VENDORS:
                app.state.db.add_vendor(vendors.assess_vendor(name, service, sens, access, answers))
        await asyncio.to_thread(run_ingest, app.state.db, settings)
        task = asyncio.create_task(_ingest_loop(app)) if settings.ingest_interval > 0 else None
        yield
        if task:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        app.state.db.close()

    app = FastAPI(title="CyberUnify", version="1.0.0", lifespan=lifespan,
                  description="Unified SOC dashboard with risk scoring and ISO 27001 reporting.")

    # ---------- helpers ----------

    def window(request: Request) -> tuple[list[Alert], dict[str, str]]:
        db: Database = request.app.state.db
        since = datetime.now(timezone.utc) - timedelta(hours=request.app.state.settings.window_hours)
        alerts = db.alerts_since(since)
        return alerts, db.alert_statuses(a.id for a in alerts)

    def sources(request: Request) -> list[dict]:
        return request.app.state.db.last_runs()

    # ---------- overview ----------

    @app.get("/api/summary")
    def summary(request: Request):
        alerts, statuses = window(request)
        active = [a for a in alerts if statuses.get(a.id, "open") not in RESOLVED]
        levels = Counter(a.risk_level for a in active)

        now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        hours = [now - timedelta(hours=h) for h in range(47, -1, -1)]
        timeline = {lvl: [0] * len(hours) for lvl in RISK_LEVELS}
        index = {h: i for i, h in enumerate(hours)}
        for a in alerts:
            i = index.get(a.timestamp.replace(minute=0, second=0, microsecond=0))
            if i is not None:
                timeline[a.risk_level][i] += 1

        return {
            "window_hours": request.app.state.settings.window_hours,
            "kpis": {
                "alerts": len(alerts),
                "open": sum(1 for a in alerts if statuses.get(a.id, "open") == "open"),
                "critical": levels.get("critical", 0),
                "high": levels.get("high", 0),
                "hosts": len({a.host for a in alerts}),
                "mean_risk": round(sum(a.risk_score for a in active) / len(active), 1) if active else 0,
            },
            "risk_levels": {lvl: levels.get(lvl, 0) for lvl in RISK_LEVELS},
            "timeline": {"hours": [h.isoformat() for h in hours], "series": timeline},
            "categories": Counter(a.category for a in active).most_common(),
            "tactics": Counter(a.mitre_tactic for a in active if a.mitre_tactic).most_common(),
            "by_source": Counter(a.source for a in alerts).most_common(),
            "top_hosts": host_risk(active)[:6],
            "top_alerts": [a.to_dict() | {"status": statuses.get(a.id, "open")}
                           for a in sorted(active, key=lambda a: a.risk_score, reverse=True)[:8]],
            "sources": sources(request),
        }

    # ---------- alerts ----------

    @app.get("/api/alerts")
    def list_alerts(
        request: Request,
        level: str | None = None,
        source: str | None = None,
        host: str | None = None,
        category: str | None = None,
        status: str | None = None,
        q: str | None = Query(None, max_length=100),
        sort: Literal["risk", "time"] = "risk",
        limit: int = Query(50, ge=1, le=500),
        offset: int = Query(0, ge=0),
    ):
        alerts, statuses = window(request)
        needle = (q or "").lower()

        def keep(a: Alert) -> bool:
            st = statuses.get(a.id, "open")
            return ((not level or a.risk_level == level) and (not source or a.source == source)
                    and (not host or a.host == host) and (not category or a.category == category)
                    and (not status or st == status)
                    and (not needle or needle in f"{a.title} {a.host} {a.src_ip} {a.user} {a.rule_id} {a.mitre_technique}".lower()))

        rows = [a for a in alerts if keep(a)]
        rows.sort(key=(lambda a: a.risk_score) if sort == "risk" else (lambda a: a.timestamp), reverse=True)
        return {
            "total": len(rows),
            "items": [a.to_dict() | {"status": statuses.get(a.id, "open")} for a in rows[offset:offset + limit]],
            "facets": {
                "sources": sorted({a.source for a in alerts}),
                "hosts": sorted({a.host for a in alerts}),
                "categories": sorted({a.category for a in alerts}),
                "statuses": list(ALERT_STATUSES),
                "levels": list(RISK_LEVELS),
            },
        }

    @app.get("/api/alerts/{alert_id}")
    def get_alert(alert_id: str, request: Request):
        found = request.app.state.db.get_alert(alert_id)
        if not found:
            raise HTTPException(404, "Alert not found")
        alert, status = found
        return alert.to_dict(include_raw=True) | {"status": status}

    @app.patch("/api/alerts/{alert_id}")
    def update_alert(alert_id: str, body: StatusUpdate, request: Request):
        if not request.app.state.db.set_alert_status(alert_id, body.status):
            raise HTTPException(404, "Alert not found")
        return {"ok": True, "status": body.status}

    @app.get("/api/hosts")
    def hosts(request: Request):
        alerts, statuses = window(request)
        return host_risk([a for a in alerts if statuses.get(a.id, "open") not in RESOLVED])

    # ---------- ingestion ----------

    @app.post("/api/ingest")
    async def ingest_now(request: Request):
        results = await asyncio.to_thread(run_ingest, request.app.state.db, request.app.state.settings)
        return {"ok": True, "results": results}

    @app.get("/api/sources")
    def list_sources(request: Request):
        return sources(request)

    # ---------- compliance ----------

    def compliance_report(request: Request) -> dict:
        alerts, statuses = window(request)
        return compliance.assess(alerts, statuses, sources(request), request.app.state.db.list_vendors())

    @app.get("/api/compliance")
    def get_compliance(request: Request):
        return compliance_report(request)

    @app.get("/reports/iso27001", response_class=HTMLResponse)
    def iso_report(request: Request, download: bool = False):
        alerts, statuses = window(request)
        active = [a for a in alerts if statuses.get(a.id, "open") not in RESOLVED]
        report = compliance.assess(alerts, statuses, sources(request), request.app.state.db.list_vendors())
        response = templates.TemplateResponse(request, "report.html", {
            "report": report,
            "kpis": summary(request)["kpis"],
            "hosts": host_risk(active)[:10],
            "top_alerts": sorted(active, key=lambda a: a.risk_score, reverse=True)[:10],
            "vendors": request.app.state.db.list_vendors(),
            "window_hours": request.app.state.settings.window_hours,
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
                "items": request.app.state.db.list_vendors()}

    @app.post("/api/vendors", status_code=201)
    def add_vendor(body: VendorIn, request: Request):
        try:
            result = vendors.assess_vendor(body.name, body.service, body.data_sensitivity, body.access_level, body.answers)
        except ValueError as err:
            raise HTTPException(400, str(err)) from err
        result["id"] = request.app.state.db.add_vendor(result)
        return result

    @app.delete("/api/vendors/{vendor_id}")
    def delete_vendor(vendor_id: int, request: Request):
        if not request.app.state.db.delete_vendor(vendor_id):
            raise HTTPException(404, "Vendor not found")
        return {"ok": True}

    # ---------- dashboard ----------

    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(HERE / "static" / "index.html")

    return app


app = create_app()
