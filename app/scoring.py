"""Risk scoring.

Severity is the anchor. Context can raise an alert toward 100 but never past it,
and low-severity alerts get proportionally less lift, so noise stays noise:

  base   = severity × dampener                    (recon/discovery, low-value assets)
  boost  = 1 − Π(1 − uᵢ)                          (combine independent context signals)
  risk   = base + (100 − base) × boost × base/100

Context signals uᵢ (each 0…~0.3), all shown to the analyst as the score breakdown:
  tactic   how dangerous the MITRE ATT&CK stage is (exfiltration > persistence)
  asset    configured host criticality (domain controller > laptop)
  rarity   rules that rarely fire are more interesting than noisy ones (IDF)
  anomaly  host is far busier than its own hourly baseline (z-score, capped at 3σ)

Host risk = its worst alert, lifted by the next nine: each adds a small share of the
remaining gap (scaled by the worst alert's own risk, like the alert formula), so a
pile of noisy low alerts can't make a quiet host look critical.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from statistics import mean, pstdev

from .models import Event, risk_level

TACTIC_BOOST = {
    "impact": 0.30,
    "exfiltration": 0.30,
    "lateral movement": 0.25,
    "privilege escalation": 0.25,
    "command and control": 0.25,
    "credential access": 0.20,
    "execution": 0.20,
    "persistence": 0.15,
    "defense evasion": 0.15,
    "initial access": 0.15,
    "collection": 0.10,
}
# Early-stage, noisy activity: a scan alone is less urgent than its severity suggests.
TACTIC_DAMPEN = {"reconnaissance": 0.85, "discovery": 0.85}

RARITY_MAX = 0.20
ANOMALY_MAX = 0.25
HOST_SPILLOVER = 0.06  # share of each extra alert's risk that adds to its host's score


def _hour(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


def rarity_signals(alerts: list[Event]) -> dict[str, float]:
    """Inverse document frequency of each rule, scaled to 0 … RARITY_MAX."""
    counts = Counter(a.rule_key for a in alerts)
    total = len(alerts)
    if total <= 1:
        return {rule: 0.0 for rule in counts}
    return {rule: RARITY_MAX * math.log(total / n) / math.log(total) for rule, n in counts.items()}


def anomaly_z_scores(alerts: list[Event]) -> dict[tuple[str, datetime], float]:
    """For each (host, hour): standard deviations above that host's usual hourly alert volume."""
    per_host: dict[str, Counter] = defaultdict(Counter)
    for a in alerts:
        per_host[a.host][_hour(a.timestamp)] += 1

    z: dict[tuple[str, datetime], float] = {}
    for host, hours in per_host.items():
        # The baseline includes quiet hours (zero alerts) across the host's observed span.
        start, end = min(hours), max(hours)
        span = int((end - start).total_seconds() // 3600) + 1
        series = [hours.get(start + timedelta(hours=i), 0) for i in range(span)]
        mu = mean(series)
        sigma = pstdev(series) if len(series) > 1 else 0.0
        for hour, count in hours.items():
            z[(host, hour)] = (count - mu) / sigma if sigma > 0 else 0.0
    return z


def asset_signal(criticality: float) -> tuple[float, float]:
    """(boost, dampener) for a host criticality weight: 1.0 normal, up to 2.0 crown jewels."""
    if criticality >= 1.0:
        return min(0.5, (criticality - 1.0) / 2), 1.0
    return 0.0, max(0.5, criticality)


def combine(signals: list[float]) -> float:
    """Combine independent boosts like probabilities: 1 − Π(1 − u)."""
    remaining = 1.0
    for u in signals:
        remaining *= 1 - max(0.0, min(u, 0.95))
    return 1 - remaining


def score_one(severity: float, tactic: str | None, criticality: float, rarity: float, z: float) -> tuple[float, dict]:
    tactic_u = TACTIC_BOOST.get(tactic or "", 0.0)
    asset_u, asset_dampen = asset_signal(criticality)
    anomaly_u = ANOMALY_MAX * max(0.0, min(z, 3.0)) / 3
    dampen = TACTIC_DAMPEN.get(tactic or "", 1.0) * asset_dampen

    base = severity * dampen
    boost = combine([tactic_u, asset_u, rarity, anomaly_u])
    risk = base + (100 - base) * boost * (base / 100)
    factors = {
        "severity": round(float(severity), 1),
        "dampener": round(dampen, 2),
        "tactic": round(tactic_u, 2),
        "asset": round(asset_u, 2),
        "rarity": round(rarity, 2),
        "anomaly": round(anomaly_u, 2),
        "anomaly_z": round(z, 2),
        "context_boost": round(boost, 2),
    }
    return round(min(100.0, risk), 1), factors


def score_alerts(alerts: list[Event], asset_criticality: dict[str, float] | None = None) -> list[Event]:
    """Score every event in place; the batch provides the rarity and baseline context."""
    asset_criticality = asset_criticality or {}
    rarity = rarity_signals(alerts)
    z = anomaly_z_scores(alerts)
    for a in alerts:
        a.risk_score, a.risk_factors = score_one(
            a.severity,
            a.mitre_tactic,
            asset_criticality.get(a.host, 1.0),
            rarity.get(a.rule_key, 0.0),
            z.get((a.host, _hour(a.timestamp)), 0.0),
        )
    return alerts


def host_risk(alerts: list[Event]) -> list[dict]:
    by_host: dict[str, list[Event]] = defaultdict(list)
    for a in alerts:
        by_host[a.host].append(a)

    rows = []
    for host, items in by_host.items():
        items.sort(key=lambda a: a.risk_score, reverse=True)
        worst = items[0].risk_score
        lift = combine([a.risk_score / 100 * HOST_SPILLOVER for a in items[1:10]])
        score = worst + (100 - worst) * lift * (worst / 100)
        levels = Counter(a.risk_level for a in items)
        rows.append({
            "host": host,
            "risk_score": round(score, 1),
            "risk_level": risk_level(score),
            "alerts": len(items),
            "critical": levels.get("critical", 0),
            "high": levels.get("high", 0),
            "top_alert": items[0].message,
            "last_seen": max(a.timestamp for a in items).isoformat(),
            "tools": sorted({a.tool for a in items}),
        })
    rows.sort(key=lambda r: r["risk_score"], reverse=True)
    return rows
