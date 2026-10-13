"""Log explorer search: filters + a small query language, compiled to parameterized SQL.

Query syntax (combine freely, all terms must match):
  brute force            free text: message, host, IPs, user, rule or the raw log contain each word
  "brute force"          exact phrase
  host:web-01            field match (host, user, src, dst, ip, tool, category, rule, action,
                         level, status, technique, tactic); * is a wildcard: host:web-*
  -success  -user:root   exclude
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from typing import Any

from .db import Database
from .models import RISK_LEVELS

FIELD_COLUMNS = {
    "host": ["host"], "user": ["user"], "src": ["src_ip"], "src_ip": ["src_ip"], "dst": ["dst_ip"],
    "dst_ip": ["dst_ip"], "ip": ["src_ip", "dst_ip"], "tool": ["tool"], "category": ["category"],
    "rule": ["rule"], "action": ["action"], "level": ["risk_level"], "status": ["status"],
    "technique": ["mitre_technique"], "tactic": ["mitre_tactic"], "message": ["message"],
}
TEXT_COLUMNS = ["message", "host", "src_ip", "dst_ip", "user", "rule", "raw"]


@dataclass
class Filters:
    since: int | None = None  # epoch seconds
    until: int | None = None
    tools: list[str] = field(default_factory=list)
    levels: list[str] = field(default_factory=list)
    integration_id: int | None = None
    host: str | None = None
    category: str | None = None
    status: str | None = None
    q: str = ""


def _like(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return escaped.replace("*", "%")


def _tokens(q: str) -> list[str]:
    try:
        return shlex.split(q)
    except ValueError:  # unbalanced quote: fall back to whitespace split
        return q.replace('"', " ").split()


def compile_query(q: str) -> tuple[list[str], list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    for token in _tokens(q or "")[:30]:
        negate = token.startswith("-") and len(token) > 1
        if negate:
            token = token[1:]
        m = re.match(r"^([a-z_]+):(.+)$", token)
        if m and m.group(1) in FIELD_COLUMNS:
            value = m.group(2)
            cols = FIELD_COLUMNS[m.group(1)]
            if "*" in value:
                parts = [f"COALESCE({c},'') LIKE ? ESCAPE '\\'" for c in cols]
                params.extend([_like(value)] * len(cols))
            else:
                parts = [f"LOWER(COALESCE({c},'')) = LOWER(?)" for c in cols]
                params.extend([value] * len(cols))
        else:
            parts = [f"COALESCE({c},'') LIKE ? ESCAPE '\\'" for c in TEXT_COLUMNS]
            params.extend([f"%{_like(token)}%"] * len(TEXT_COLUMNS))
        clause = "(" + " OR ".join(parts) + ")"
        clauses.append(f"NOT {clause}" if negate else clause)
    return clauses, params


def where(f: Filters, skip: str | None = None) -> tuple[str, list[Any]]:
    """Build the WHERE clause. `skip` leaves one filter out (so facet counts show alternatives)."""
    clauses: list[str] = []
    params: list[Any] = []
    if f.since is not None:
        clauses.append("ts_epoch >= ?")
        params.append(f.since)
    if f.until is not None:
        clauses.append("ts_epoch <= ?")
        params.append(f.until)
    if f.tools and skip != "tool":
        clauses.append(f"tool IN ({','.join('?' * len(f.tools))})")
        params.extend(f.tools)
    if f.levels and skip != "level":
        clauses.append(f"risk_level IN ({','.join('?' * len(f.levels))})")
        params.extend(f.levels)
    if f.integration_id is not None:
        clauses.append("integration_id = ?")
        params.append(f.integration_id)
    if f.host and skip != "host":
        clauses.append("host = ?")
        params.append(f.host)
    if f.category and skip != "category":
        clauses.append("category = ?")
        params.append(f.category)
    if f.status:
        clauses.append("status = ?")
        params.append(f.status)
    q_clauses, q_params = compile_query(f.q)
    clauses += q_clauses
    params += q_params
    return ("WHERE " + " AND ".join(clauses)) if clauses else "", params


LIST_COLUMNS = ("id, integration_id, tool, timestamp, host, message, severity, category, src_ip, dst_ip, user, "
                "rule, action, mitre_tactic, mitre_technique, risk_score, risk_level, status")


def search(db: Database, f: Filters, sort: str = "time", limit: int = 100, offset: int = 0) -> dict[str, Any]:
    clause, params = where(f)
    order = "risk_score DESC, ts_epoch DESC" if sort == "risk" else "ts_epoch DESC, risk_score DESC"
    total = db.query(f"SELECT COUNT(*) AS n FROM events {clause}", params)[0]["n"]
    rows = db.query(f"SELECT {LIST_COLUMNS} FROM events {clause} ORDER BY {order} LIMIT ? OFFSET ?",
                    [*params, limit, offset])
    return {"total": total, "items": [dict(r) for r in rows]}


def facets(db: Database, f: Filters) -> dict[str, list[tuple[str, int]]]:
    out: dict[str, list[tuple[str, int]]] = {}
    for name, column, top in (("tool", "tool", 50), ("level", "risk_level", 10), ("host", "host", 25),
                              ("category", "category", 20)):
        clause, params = where(f, skip=name)
        rows = db.query(f"SELECT {column} AS k, COUNT(*) AS n FROM events {clause} GROUP BY {column} "
                        f"ORDER BY n DESC LIMIT {top}", params)
        out[name] = [(r["k"], r["n"]) for r in rows]
    order = {lvl: i for i, lvl in enumerate(RISK_LEVELS)}
    out["level"].sort(key=lambda kv: order.get(kv[0], 99))
    return out


def histogram(db: Database, f: Filters, buckets: int = 60) -> dict[str, Any]:
    """Event counts over time per tool (the single-pane timeline)."""
    clause, params = where(f)
    bounds = db.query(f"SELECT MIN(ts_epoch) AS lo, MAX(ts_epoch) AS hi FROM events {clause}", params)[0]
    lo = f.since if f.since is not None else bounds["lo"]
    hi = f.until if f.until is not None else bounds["hi"]
    if lo is None or hi is None:
        return {"start": None, "step": 0, "buckets": 0, "series": {}}
    step = max(60, -(-(hi - lo + 1) // buckets))  # ceil, at least one minute
    rows = db.query(
        f"SELECT tool, (ts_epoch - ?) / ? AS b, COUNT(*) AS n FROM events {clause} GROUP BY tool, b",
        [lo, step, *params],
    )
    n_buckets = int((hi - lo) // step) + 1
    series: dict[str, list[int]] = {}
    for r in rows:
        idx = int(r["b"])
        if 0 <= idx < n_buckets:
            series.setdefault(r["tool"], [0] * n_buckets)[idx] += r["n"]
    return {"start": lo, "step": step, "buckets": n_buckets, "series": series}
