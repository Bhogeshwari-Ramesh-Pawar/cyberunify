"""SQLite storage for alerts, ingest runs and vendor assessments."""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import Alert

SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id              TEXT PRIMARY KEY,
    source          TEXT NOT NULL,
    source_id       TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    host            TEXT NOT NULL,
    rule_id         TEXT NOT NULL,
    title           TEXT NOT NULL,
    category        TEXT NOT NULL,
    severity        INTEGER NOT NULL,
    src_ip          TEXT,
    dst_ip          TEXT,
    user            TEXT,
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    raw             TEXT NOT NULL,
    risk_score      REAL NOT NULL DEFAULT 0,
    risk_factors    TEXT NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'open',
    ingested_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts   ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_host ON alerts(host);

CREATE TABLE IF NOT EXISTS ingest_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT NOT NULL,
    status      TEXT NOT NULL,
    fetched     INTEGER NOT NULL DEFAULT 0,
    skipped     INTEGER NOT NULL DEFAULT 0,
    error       TEXT
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

ALERT_STATUSES = ("open", "acknowledged", "closed", "false_positive")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # One shared connection; the lock keeps the background ingester and API requests from colliding.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def _query(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, tuple(params)).fetchall()

    def _execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        with self._lock, self._conn:
            return self._conn.execute(sql, tuple(params)).lastrowid or 0

    # ---------- alerts ----------

    def upsert_alerts(self, alerts: Iterable[Alert]) -> int:
        rows = [
            (a.id, a.source, a.source_id, a.timestamp.isoformat(), a.host, a.rule_id, a.title, a.category,
             a.severity, a.src_ip, a.dst_ip, a.user, a.mitre_tactic, a.mitre_technique,
             json.dumps(a.raw, default=str), a.risk_score, json.dumps(a.risk_factors), _now())
            for a in alerts
        ]
        # On conflict, refresh everything except the analyst's triage status.
        sql = """
        INSERT INTO alerts (id, source, source_id, timestamp, host, rule_id, title, category, severity,
                            src_ip, dst_ip, user, mitre_tactic, mitre_technique, raw, risk_score,
                            risk_factors, ingested_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            timestamp=excluded.timestamp, host=excluded.host, rule_id=excluded.rule_id,
            title=excluded.title, category=excluded.category, severity=excluded.severity,
            src_ip=excluded.src_ip, dst_ip=excluded.dst_ip, user=excluded.user,
            mitre_tactic=excluded.mitre_tactic, mitre_technique=excluded.mitre_technique,
            raw=excluded.raw, risk_score=excluded.risk_score, risk_factors=excluded.risk_factors,
            ingested_at=excluded.ingested_at
        """
        with self._lock, self._conn:
            self._conn.executemany(sql, rows)
        return len(rows)

    def alerts_since(self, since: datetime) -> list[Alert]:
        rows = self._query("SELECT * FROM alerts WHERE timestamp >= ? ORDER BY timestamp", [since.isoformat()])
        return [row_to_alert(r) for r in rows]

    def alert_statuses(self, ids: Iterable[str]) -> dict[str, str]:
        ids = list(ids)
        if not ids:
            return {}
        result: dict[str, str] = {}
        for i in range(0, len(ids), 500):  # stay under SQLite's parameter limit
            chunk = ids[i:i + 500]
            marks = ",".join("?" * len(chunk))
            for r in self._query(f"SELECT id, status FROM alerts WHERE id IN ({marks})", chunk):
                result[r["id"]] = r["status"]
        return result

    def get_alert(self, alert_id: str) -> tuple[Alert, str] | None:
        rows = self._query("SELECT * FROM alerts WHERE id = ?", [alert_id])
        return (row_to_alert(rows[0]), rows[0]["status"]) if rows else None

    def set_alert_status(self, alert_id: str, status: str) -> bool:
        if status not in ALERT_STATUSES:
            raise ValueError(f"status must be one of {ALERT_STATUSES}")
        with self._lock, self._conn:
            cur = self._conn.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
            return cur.rowcount > 0

    def latest_alert_time(self, source: str) -> datetime | None:
        rows = self._query("SELECT MAX(timestamp) AS ts FROM alerts WHERE source = ?", [source])
        ts = rows[0]["ts"] if rows else None
        return datetime.fromisoformat(ts) if ts else None

    # ---------- ingest runs ----------

    def record_run(self, source: str, started: datetime, status: str, fetched: int, skipped: int, error: str | None) -> None:
        self._execute(
            "INSERT INTO ingest_runs (source, started_at, finished_at, status, fetched, skipped, error) VALUES (?,?,?,?,?,?,?)",
            [source, started.isoformat(), _now(), status, fetched, skipped, error],
        )

    def last_runs(self) -> list[dict[str, Any]]:
        rows = self._query(
            """SELECT r.* FROM ingest_runs r
               JOIN (SELECT source, MAX(id) AS id FROM ingest_runs GROUP BY source) last ON last.id = r.id
               ORDER BY r.source"""
        )
        return [dict(r) for r in rows]

    # ---------- vendors ----------

    def add_vendor(self, v: dict[str, Any]) -> int:
        return self._execute(
            """INSERT INTO vendors (name, service, data_sensitivity, access_level, answers, inherent_risk,
                                    control_score, residual_risk, tier, gaps, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            [v["name"], v["service"], v["data_sensitivity"], v["access_level"], json.dumps(v["answers"]),
             v["inherent_risk"], v["control_score"], v["residual_risk"], v["tier"], json.dumps(v["gaps"]), _now()],
        )

    def list_vendors(self) -> list[dict[str, Any]]:
        out = []
        for r in self._query("SELECT * FROM vendors ORDER BY residual_risk DESC"):
            d = dict(r)
            d["answers"] = json.loads(d["answers"])
            d["gaps"] = json.loads(d["gaps"])
            out.append(d)
        return out

    def delete_vendor(self, vendor_id: int) -> bool:
        with self._lock, self._conn:
            return self._conn.execute("DELETE FROM vendors WHERE id = ?", (vendor_id,)).rowcount > 0

    def vendor_count(self) -> int:
        return self._query("SELECT COUNT(*) AS n FROM vendors")[0]["n"]


def row_to_alert(r: sqlite3.Row) -> Alert:
    a = Alert(
        source=r["source"], source_id=r["source_id"], timestamp=datetime.fromisoformat(r["timestamp"]),
        host=r["host"], rule_id=r["rule_id"], title=r["title"], category=r["category"],
        severity=r["severity"], src_ip=r["src_ip"], dst_ip=r["dst_ip"], user=r["user"],
        mitre_tactic=r["mitre_tactic"], mitre_technique=r["mitre_technique"], raw=json.loads(r["raw"]),
    )
    a.risk_score = r["risk_score"]
    a.risk_factors = json.loads(r["risk_factors"])
    return a
