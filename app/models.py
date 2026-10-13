"""The common alert schema every connector is normalized into."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# Normalized alert categories. Each maps to ISO 27001 controls in compliance.py.
CATEGORIES = (
    "authentication",
    "malware",
    "network_intrusion",
    "reconnaissance",
    "vulnerability",
    "integrity",
    "privilege_escalation",
    "data_exfiltration",
    "policy",
    "other",
)

RISK_LEVELS = ("critical", "high", "medium", "low")


def risk_level(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def alert_id(source: str, source_id: str) -> str:
    """Stable id so re-ingesting the same alert updates it instead of duplicating it."""
    return hashlib.sha1(f"{source}:{source_id}".encode()).hexdigest()[:16]


@dataclass
class Alert:
    source: str  # wazuh | elastic | suricata
    source_id: str  # the id the original tool gave this alert
    timestamp: datetime  # always timezone-aware UTC
    host: str
    rule_id: str
    title: str
    category: str
    severity: int  # 0-100, normalized across tools
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    risk_factors: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        self.severity = max(0, min(100, int(self.severity)))
        if self.category not in CATEGORIES:
            self.category = "other"

    @property
    def id(self) -> str:
        return alert_id(self.source, self.source_id)

    @property
    def risk_level(self) -> str:
        return risk_level(self.risk_score)

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        d = asdict(self)
        d["id"] = self.id
        d["timestamp"] = self.timestamp.isoformat()
        d["risk_level"] = self.risk_level
        if not include_raw:
            d.pop("raw")
        return d
