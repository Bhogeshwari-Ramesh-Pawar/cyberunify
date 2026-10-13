"""The unified event schema every connected tool is mapped into."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

# Normalized categories. Each maps to ISO 27001 controls in compliance.py.
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
    "threat_intel",
    "network_traffic",
    "other",
)

RISK_LEVELS = ("critical", "high", "medium", "low", "info")


def risk_level(score: float) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def event_id(integration_id: int, source_id: str) -> str:
    """Stable id, so receiving the same log twice updates it instead of duplicating it."""
    return hashlib.sha1(f"{integration_id}:{source_id}".encode()).hexdigest()[:20]


@dataclass
class Event:
    integration_id: int
    tool: str  # e.g. "wazuh", "fortigate", "custom"
    source_id: str  # the tool's own id, or a hash of the raw record
    timestamp: datetime  # always timezone-aware UTC
    host: str
    message: str
    severity: int  # 0-100, normalized across tools
    category: str = "other"
    src_ip: str | None = None
    dst_ip: str | None = None
    user: str | None = None
    rule: str | None = None
    action: str | None = None  # allow / block / login_failed ... when the tool reports one
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    risk_factors: dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        self.timestamp = self.timestamp.astimezone(timezone.utc)
        self.severity = max(0, min(100, int(self.severity)))
        if self.category not in CATEGORIES:
            self.category = "other"
        self.host = (self.host or "unknown")[:200]
        self.message = (self.message or "(no message)")[:1000]

    @property
    def id(self) -> str:
        return event_id(self.integration_id, self.source_id)

    @property
    def rule_key(self) -> str:
        """Groups repeats of the same detection, for rarity scoring."""
        return f"{self.tool}:{self.rule or self.message[:80]}"

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
