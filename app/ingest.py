"""Ingestion pipeline: fetch → normalize → store → rescore the whole window."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import httpx

from .config import Settings
from .connectors.base import Connector
from .connectors.demo import DemoConnector
from .connectors.elastic import ElasticConnector
from .connectors.suricata import SuricataConnector
from .connectors.wazuh import WazuhConnector
from .db import Database
from .scoring import score_alerts

log = logging.getLogger("cyberunify.ingest")


def build_connectors(s: Settings) -> list[Connector]:
    connectors: list[Connector] = []
    if s.wazuh_url:
        connectors.append(WazuhConnector(s.wazuh_url, s.wazuh_user, s.wazuh_password, s.wazuh_index, s.wazuh_verify_tls))
    if s.elastic_url:
        connectors.append(ElasticConnector(s.elastic_url, s.elastic_api_key, s.elastic_index, s.elastic_verify_tls))
    if s.suricata_eve_path:
        connectors.append(SuricataConnector(s.suricata_eve_path, s.asset_inventory))
    if s.demo_mode:
        connectors.append(DemoConnector(s.asset_inventory))
    return connectors


def run_ingest(db: Database, settings: Settings, connectors: list[Connector] | None = None) -> list[dict]:
    """Pull from every connector, then rescore all alerts in the window.

    Rescoring the window (not just new alerts) matters: rarity and the per-host
    baseline depend on everything we've seen, so old scores shift as context grows.
    A failing connector is recorded and skipped; it never stops the others.
    """
    connectors = connectors if connectors is not None else build_connectors(settings)
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=settings.window_hours)
    results = []

    for conn in connectors:
        started = datetime.now(timezone.utc)
        since = max(db.latest_alert_time(conn.name) or window_start, window_start)
        try:
            alerts, skipped = conn.fetch(since)
            db.upsert_alerts(alerts)
            db.record_run(conn.name, started, "ok", len(alerts), skipped, None)
            results.append({"source": conn.name, "status": "ok", "fetched": len(alerts), "skipped": skipped})
        except (httpx.HTTPError, OSError, ValueError) as err:
            message = f"{type(err).__name__}: {err}"
            log.warning("connector %s failed: %s", conn.name, message)
            db.record_run(conn.name, started, "error", 0, 0, message[:500])
            results.append({"source": conn.name, "status": "error", "error": message})

    window = db.alerts_since(window_start)
    score_alerts(window, settings.asset_criticality)
    db.upsert_alerts(window)
    return results
