"""SQLite storage: unified events, integrations, ingest runs and vendor assessments."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Event

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id              TEXT PRIMARY KEY,
    integration_id  INTEGER NOT NULL,
    tool            TEXT NOT NULL,
    source_id       TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    ts_epoch        INTEGER NOT NULL,
    host            TEXT NOT NULL,
    message         TEXT NOT NULL,
    severity        INTEGER NOT NULL,
    category        TEXT NOT NULL,
    src_ip          TEXT,
    dst_ip          TEXT,
    user            TEXT,
    rule            TEXT,
    action          TEXT,
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    raw             TEXT NOT NULL,
    risk_score      REAL NOT NULL DEFAULT 0,
    risk_level      TEXT NOT NULL DEFAULT 'info',
    risk_factors    TEXT NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'open',
    ingested_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_ts    ON events(ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_tool  ON events(tool, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_host  ON events(host, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_level ON events(risk_level, ts_epoch);
CREATE INDEX IF NOT EXISTS idx_events_integ ON events(integration_id, ts_epoch);

CREATE TABLE IF NOT EXISTS integrations (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    name               TEXT NOT NULL,
    tool               TEXT NOT NULL,
    type               TEXT NOT NULL,
    config             TEXT NOT NULL,
    mapping            TEXT NOT NULL DEFAULT '{}',
    severity_scale     TEXT NOT NULL DEFAULT 'auto',
    default_category   TEXT,
    enabled            INTEGER NOT NULL DEFAULT 1,
    demo               INTEGER NOT NULL DEFAULT 0,
    webhook_token_hash TEXT UNIQUE,
    webhook_token      TEXT,
    state              TEXT NOT NULL DEFAULT '{}',
    last_status        TEXT,
    last_error         TEXT,
    last_run_at        TEXT,
    last_count         INTEGER NOT NULL DEFAULT 0,
    created_at         TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS vendors (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT NOT NULL,
    service          TEXT NOT NULL,
    data_sensitivity TEXT NOT NULL,
    access_level     TEXT NOT NULL,
    answers          TEXT NOT NULL,
    inherent_risk    REAL NOT NULL,
    control_score    REAL NOT NULL,
    residual_risk    REAL NOT NULL,
    tier             TEXT NOT NULL,
    gaps             TEXT NOT NULL,
    created_at       TEXT NOT NULL
);
"""

EVENT_STATUSES = ("open", "acknowledged", "closed", "false_positive")
INTEGRATION_COLUMNS = ("name", "tool", "type", "config", "mapping", "severity_scale", "default_category",
                       "enabled", "demo", "webhook_token_hash", "webhook_token", "state", "last_status",
                       "last_error", "last_run_at", "last_count")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # One shared connection guarded by a lock: syslog listeners, webhooks, the scheduler
        # and API requests all write through here.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL") if self.path != ":memory:" else None
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    def execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock, self._conn:
            return self._conn.execute(sql, tuple(params))

    # ---------- events ----------

    def upsert_events(self, events: Iterable[Event]) -> int:
        rows = [
            (e.id, e.integration_id, e.tool, e.source_id, e.timestamp.isoformat(), int(e.timestamp.timestamp()),
             e.host, e.message, e.severity, e.category, e.src_ip, e.dst_ip, e.user, e.rule, e.action,
             e.mitre_tactic, e.mitre_technique, json.dumps(e.raw, default=str), e.risk_score, e.risk_level,
             json.dumps(e.risk_factors), _now())
            for e in events
        ]
        if not rows:
            return 0
        # On conflict refresh everything except the analyst's triage status.
        sql = """
        INSERT INTO events (id, integration_id, tool, source_id, timestamp, ts_epoch, host, message, severity,
                            category, src_ip, dst_ip, user, rule, action, mitre_tactic, mitre_technique, raw,
                            risk_score, risk_level, risk_factors, ingested_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            timestamp=excluded.timestamp, ts_epoch=excluded.ts_epoch, host=excluded.host, message=excluded.message,
            severity=excluded.severity, category=excluded.category, src_ip=excluded.src_ip, dst_ip=excluded.dst_ip,
            user=excluded.user, rule=excluded.rule, action=excluded.action, mitre_tactic=excluded.mitre_tactic,
            mitre_technique=excluded.mitre_technique, raw=excluded.raw, risk_score=excluded.risk_score,
            risk_level=excluded.risk_level, risk_factors=excluded.risk_factors, ingested_at=excluded.ingested_at
        """
        with self._lock, self._conn:
            self._conn.executemany(sql, rows)
        return len(rows)

    def update_scores(self, events: Iterable[Event]) -> None:
        rows = [(e.risk_score, e.risk_level, json.dumps(e.risk_factors), e.id) for e in events]
        with self._lock, self._conn:
            self._conn.executemany("UPDATE events SET risk_score=?, risk_level=?, risk_factors=? WHERE id=?", rows)

    def events_since(self, since_epoch: int) -> list[Event]:
        rows = self.query("SELECT * FROM events WHERE ts_epoch >= ? ORDER BY ts_epoch", [since_epoch])
        return [row_to_event(r) for r in rows]

    def get_event(self, event_id: str) -> tuple[Event, str] | None:
        rows = self.query("SELECT * FROM events WHERE id = ?", [event_id])
        return (row_to_event(rows[0]), rows[0]["status"]) if rows else None

    def set_status(self, event_id: str, status: str) -> bool:
        if status not in EVENT_STATUSES:
            raise ValueError(f"status must be one of {EVENT_STATUSES}")
        return self.execute("UPDATE events SET status = ? WHERE id = ?", (status, event_id)).rowcount > 0

    def statuses_since(self, since_epoch: int) -> dict[str, str]:
        return {r["id"]: r["status"] for r in self.query("SELECT id, status FROM events WHERE ts_epoch >= ?", [since_epoch])}

    def latest_event_epoch(self, integration_id: int) -> int | None:
        row = self.query("SELECT MAX(ts_epoch) AS t FROM events WHERE integration_id = ?", [integration_id])[0]
        return row["t"]

    def delete_events_before(self, epoch: int) -> int:
        return self.execute("DELETE FROM events WHERE ts_epoch < ?", [epoch]).rowcount

    def delete_events_of(self, integration_id: int) -> int:
        return self.execute("DELETE FROM events WHERE integration_id = ?", [integration_id]).rowcount

    def event_counts_by_integration(self, since_epoch: int) -> dict[int, int]:
        rows = self.query("SELECT integration_id, COUNT(*) AS n FROM events WHERE ts_epoch >= ? GROUP BY integration_id",
                          [since_epoch])
        return {r["integration_id"]: r["n"] for r in rows}

    # ---------- integrations ----------

    def add_integration(self, data: dict[str, Any]) -> int:
        data = {k: data[k] for k in INTEGRATION_COLUMNS if k in data}
        data["created_at"] = _now()
        cols = ", ".join(data)
        marks = ", ".join("?" * len(data))
        return self.execute(f"INSERT INTO integrations ({cols}) VALUES ({marks})", _encode(data).values()).lastrowid

    def update_integration(self, integration_id: int, data: dict[str, Any]) -> bool:
        data = {k: data[k] for k in INTEGRATION_COLUMNS if k in data}
        if not data:
            return False
        sets = ", ".join(f"{k} = ?" for k in data)
        return self.execute(f"UPDATE integrations SET {sets} WHERE id = ?",
                            [*_encode(data).values(), integration_id]).rowcount > 0

    def delete_integration(self, integration_id: int) -> bool:
        return self.execute("DELETE FROM integrations WHERE id = ?", [integration_id]).rowcount > 0

    def get_integration(self, integration_id: int) -> dict[str, Any] | None:
        rows = self.query("SELECT * FROM integrations WHERE id = ?", [integration_id])
        return _decode(rows[0]) if rows else None

    def integration_by_token_hash(self, token_hash: str) -> dict[str, Any] | None:
        rows = self.query("SELECT * FROM integrations WHERE webhook_token_hash = ?", [token_hash])
        return _decode(rows[0]) if rows else None

    def list_integrations(self) -> list[dict[str, Any]]:
        return [_decode(r) for r in self.query("SELECT * FROM integrations ORDER BY id")]

    # ---------- vendors ----------

    def add_vendor(self, v: dict[str, Any]) -> int:
        return self.execute(
            """INSERT INTO vendors (name, service, data_sensitivity, access_level, answers, inherent_risk,
                                    control_score, residual_risk, tier, gaps, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            [v["name"], v["service"], v["data_sensitivity"], v["access_level"], json.dumps(v["answers"]),
             v["inherent_risk"], v["control_score"], v["residual_risk"], v["tier"], json.dumps(v["gaps"]), _now()],
        ).lastrowid

    def list_vendors(self) -> list[dict[str, Any]]:
        out = []
        for r in self.query("SELECT * FROM vendors ORDER BY residual_risk DESC"):
            d = dict(r)
            d["answers"] = json.loads(d["answers"])
            d["gaps"] = json.loads(d["gaps"])
            out.append(d)
        return out

    def delete_vendor(self, vendor_id: int) -> bool:
        return self.execute("DELETE FROM vendors WHERE id = ?", (vendor_id,)).rowcount > 0

    def vendor_count(self) -> int:
        return self.query("SELECT COUNT(*) AS n FROM vendors")[0]["n"]


_JSON_COLUMNS = ("config", "mapping", "state")


def _encode(data: dict[str, Any]) -> dict[str, Any]:
    out = dict(data)
    for k in _JSON_COLUMNS:
        if k in out and not isinstance(out[k], str):
            out[k] = json.dumps(out[k])
    for k in ("enabled", "demo"):
        if k in out:
            out[k] = int(bool(out[k]))
    return out


def _decode(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    for k in _JSON_COLUMNS:
        d[k] = json.loads(d[k] or "{}")
    d["enabled"] = bool(d["enabled"])
    d["demo"] = bool(d["demo"])
    return d


def row_to_event(r: sqlite3.Row) -> Event:
    e = Event(
        integration_id=r["integration_id"], tool=r["tool"], source_id=r["source_id"],
        timestamp=datetime.fromisoformat(r["timestamp"]), host=r["host"], message=r["message"],
        severity=r["severity"], category=r["category"], src_ip=r["src_ip"], dst_ip=r["dst_ip"], user=r["user"],
        rule=r["rule"], action=r["action"], mitre_tactic=r["mitre_tactic"], mitre_technique=r["mitre_technique"],
        raw=json.loads(r["raw"]),
    )
    e.risk_score = r["risk_score"]
    e.risk_factors = json.loads(r["risk_factors"])
    return e
