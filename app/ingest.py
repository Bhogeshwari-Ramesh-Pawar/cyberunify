"""Pipeline: raw records → mapped events → stored → scored.

Push integrations (webhook, syslog) call `store_records` as data arrives; pull integrations
(Elasticsearch, Splunk, REST, file) are fetched by `pull_integration` on a schedule or on demand.
`rescore_window` recomputes risk for the whole window, because rarity and per-host
baselines depend on everything that has been seen.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from .collectors import CollectorError, pull
from .config import Settings
from .db import Database
from .mapping import map_record
from .models import Event
from .presets import CONNECTION_TYPES, secret_keys
from .scoring import score_alerts, score_one
from .vault import SecretBox

log = logging.getLogger("cyberunify.ingest")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def map_records(integration: dict[str, Any], records: list[dict[str, Any]], settings: Settings) -> tuple[list[Event], int]:
    """Map raw records with the integration's mapping. Returns (events, records skipped)."""
    events, skipped = [], 0
    for record in records:
        try:
            event, _ = map_record(
                record,
                integration_id=integration["id"],
                tool=integration["tool"],
                mapping=integration.get("mapping") or {},
                severity_scale=integration.get("severity_scale") or "auto",
                default_category=integration.get("default_category"),
                inventory=settings.asset_inventory,
                fallback_host=integration["name"],
            )
        except (ValueError, TypeError, KeyError) as err:
            skipped += 1
            log.debug("integration %s: skipped record: %s", integration["id"], err)
            continue
        # A first score straight away so new events show up ranked; the window rescore refines it.
        event.risk_score, event.risk_factors = score_one(
            event.severity, event.mitre_tactic, settings.asset_criticality.get(event.host, 1.0), 0.0, 0.0)
        events.append(event)
    return events, skipped


def store_records(db: Database, integration: dict[str, Any], records: list[dict[str, Any]], settings: Settings) -> dict[str, int]:
    events, skipped = map_records(integration, records, settings)
    cutoff = _now() - timedelta(hours=settings.window_hours)
    events = [e for e in events if e.timestamp >= cutoff]  # outside retention: don't store
    db.upsert_events(events)
    db.update_integration(integration["id"], {
        "last_status": "ok", "last_error": None, "last_run_at": _now().isoformat(), "last_count": len(events),
    })
    return {"stored": len(events), "skipped": skipped}


def pull_integration(db: Database, integration: dict[str, Any], settings: Settings, box: SecretBox,
                     transport=None) -> dict[str, Any]:
    conn_type = integration["type"]
    window_start = _now() - timedelta(hours=settings.window_hours)
    latest = db.latest_event_epoch(integration["id"])
    # Overlap by a minute so late-indexed events aren't missed; stable ids make repeats harmless.
    since = max(window_start, datetime.fromtimestamp(latest - 60, tz=timezone.utc)) if latest else window_start
    try:
        cfg = box.open(integration["config"], secret_keys(conn_type))
        records, state = pull(conn_type, cfg, since, integration.get("state") or {}, transport=transport)
    except (CollectorError, ValueError) as err:
        db.update_integration(integration["id"], {"last_status": "error", "last_error": str(err)[:500],
                                                  "last_run_at": _now().isoformat()})
        return {"integration": integration["name"], "status": "error", "error": str(err)}
    result = store_records(db, integration, records, settings)
    db.update_integration(integration["id"], {"state": state})
    return {"integration": integration["name"], "status": "ok", **result}


def rescore_window(db: Database, settings: Settings) -> int:
    since = int((_now() - timedelta(hours=settings.window_hours)).timestamp())
    events = db.events_since(since)
    score_alerts(events, settings.asset_criticality)
    db.update_scores(events)
    return len(events)


def run_cycle(db: Database, settings: Settings, box: SecretBox, simulator=None) -> list[dict[str, Any]]:
    """One scheduler tick: pull every enabled pull-integration, feed demo data, prune, rescore."""
    results = []
    for integ in db.list_integrations():
        if not integ["enabled"]:
            continue
        if integ["demo"]:
            if simulator is not None:
                records = simulator.records_for(integ["tool"])
                results.append({"integration": integ["name"], "status": "ok", "demo": True,
                                **store_records(db, integ, records, settings)})
            continue
        if CONNECTION_TYPES[integ["type"]]["mode"] == "pull":
            results.append(pull_integration(db, integ, settings, box))
    db.delete_events_before(int((_now() - timedelta(hours=settings.window_hours)).timestamp()))
    rescore_window(db, settings)
    return results
