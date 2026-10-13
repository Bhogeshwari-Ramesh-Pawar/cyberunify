"""Turn raw alerts from Wazuh, Elastic (ECS) and Suricata into the common Alert schema.

Each tool rates severity on its own scale, so everything is mapped onto 0-100:
  - Wazuh rule.level        0-15  (15 = most severe)
  - Suricata alert.severity 1-3   (1 = most severe)
  - Elastic event.severity  0-100 (ECS), or kibana.alert.severity low/medium/high/critical
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from .models import Alert

# ---------- helpers ----------

_TZ_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_timestamp(value: Any) -> datetime:
    """Accept ISO-8601 in the variants these tools emit and return aware UTC."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value / 1000 if value > 1e11 else value, tz=timezone.utc)
    elif isinstance(value, str) and value:
        text = value.strip().replace("Z", "+00:00")
        text = _TZ_NO_COLON.sub(r"\1:\2", text)  # Wazuh/Suricata use +0000
        dt = datetime.fromisoformat(text)
    else:
        raise ValueError(f"unparseable timestamp: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def dig(data: dict[str, Any], path: str, default: Any = None) -> Any:
    """Read a dotted path such as "rule.mitre.tactic" from nested dicts."""
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


# Keyword rules, checked in order, for tools that don't give a usable category.
_CATEGORY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("data_exfiltration", ("exfil", "dns tunnel", "data leak", "large upload", "outbound data", "data transfer", "dlp")),
    ("privilege_escalation", ("privilege", "sudo", "root shell", "escalat", "setuid")),
    ("malware", ("malware", "trojan", "virus", "ransom", "rootkit", "rootcheck", "command and control", "beacon")),
    ("authentication", ("authentication", "login", "logon", "password", "brute", "sshd", "pam", "credential", "mfa")),
    ("reconnaissance", ("scan", "recon", "nmap", "probe", "enumerat", "discovery")),
    ("vulnerability", ("vulnerab", "cve-", "outdated", "patch")),
    ("integrity", ("syscheck", "integrity", "checksum", "file modified", "fim", "file added", "file deleted")),
    ("network_intrusion", ("exploit", "injection", "xss", "attack", "intrusion", "web", "shellcode", "trojan-activity")),
    ("policy", ("policy", "compliance", "unauthorized software", "usb")),
]


def infer_category(*texts: Any) -> str:
    haystack = " ".join(str(t) for t in texts if t).lower()
    for category, words in _CATEGORY_KEYWORDS:
        if any(w in haystack for w in words):
            return category
    return "other"


# When the text gives no clue, the MITRE tactic still says what kind of activity it is.
_TACTIC_CATEGORY = {
    "exfiltration": "data_exfiltration",
    "collection": "data_exfiltration",
    "privilege escalation": "privilege_escalation",
    "credential access": "authentication",
    "initial access": "authentication",
    "reconnaissance": "reconnaissance",
    "discovery": "reconnaissance",
    "lateral movement": "network_intrusion",
    "persistence": "integrity",
    "defense evasion": "integrity",
    "execution": "malware",
    "command and control": "malware",
    "impact": "malware",
}


def categorize(tactic: str | None, *texts: Any) -> str:
    category = infer_category(*texts)
    if category == "other" and tactic:
        return _TACTIC_CATEGORY.get(tactic, "other")
    return category


# MITRE tactic names arrive in different spellings ("Credential Access", "credential-access", "TA0006").
_TACTIC_IDS = {
    "TA0043": "reconnaissance", "TA0042": "resource development", "TA0001": "initial access",
    "TA0002": "execution", "TA0003": "persistence", "TA0004": "privilege escalation",
    "TA0005": "defense evasion", "TA0006": "credential access", "TA0007": "discovery",
    "TA0008": "lateral movement", "TA0009": "collection", "TA0011": "command and control",
    "TA0010": "exfiltration", "TA0040": "impact",
}


def normalize_tactic(value: Any) -> str | None:
    value = first(value)
    if not value:
        return None
    text = str(value).strip()
    if text.upper() in _TACTIC_IDS:
        return _TACTIC_IDS[text.upper()]
    return text.lower().replace("-", " ").replace("_", " ")


# ---------- Wazuh ----------

def from_wazuh(doc: dict[str, Any]) -> Alert:
    """A Wazuh alert, as stored in the wazuh-alerts-* index or alerts.json."""
    src = doc.get("_source", doc)
    level = int(dig(src, "rule.level", 0) or 0)
    groups = dig(src, "rule.groups", []) or []
    description = dig(src, "rule.description", "Wazuh alert")
    tactic = normalize_tactic(dig(src, "rule.mitre.tactic"))
    return Alert(
        source="wazuh",
        source_id=str(doc.get("_id") or src.get("id") or f"{src.get('timestamp')}-{dig(src, 'rule.id')}"),
        timestamp=parse_timestamp(src.get("timestamp") or src.get("@timestamp")),
        host=dig(src, "agent.name") or dig(src, "manager.name") or "unknown",
        rule_id=f"wazuh:{dig(src, 'rule.id', '0')}",
        title=description,
        category=categorize(tactic, " ".join(groups), description),
        severity=round(min(level, 15) / 15 * 100),
        src_ip=dig(src, "data.srcip"),
        dst_ip=dig(src, "data.dstip") or dig(src, "agent.ip"),
        user=dig(src, "data.dstuser") or dig(src, "data.srcuser"),
        mitre_tactic=tactic,
        mitre_technique=first(dig(src, "rule.mitre.id")),
        raw=src,
    )


# ---------- Elastic / ECS ----------

_KIBANA_SEVERITY = {"low": 25, "medium": 50, "high": 75, "critical": 95}


def from_elastic(doc: dict[str, Any]) -> Alert:
    """An Elastic Common Schema document (Elastic Security alert or any ECS log with event.kind=alert)."""
    src = doc.get("_source", doc)
    severity = dig(src, "event.severity")
    if severity is None:
        label = str(dig(src, "kibana.alert.severity") or dig(src, "log.level") or "medium").lower()
        severity = _KIBANA_SEVERITY.get(label, 50)
    title = dig(src, "rule.name") or dig(src, "kibana.alert.rule.name") or dig(src, "message") or "Elastic alert"
    ecs_category = " ".join(map(str, dig(src, "event.category", []) or []))
    tactic = normalize_tactic(dig(src, "threat.tactic.name") or dig(src, "threat.tactic.id"))
    return Alert(
        source="elastic",
        source_id=str(doc.get("_id") or dig(src, "event.id") or f"{src.get('@timestamp')}-{title}"),
        timestamp=parse_timestamp(src.get("@timestamp")),
        host=dig(src, "host.name") or dig(src, "host.hostname") or "unknown",
        rule_id=f"elastic:{dig(src, 'rule.id') or dig(src, 'kibana.alert.rule.uuid') or title}",
        title=title,
        category=categorize(tactic, title, ecs_category, dig(src, "event.action")),
        severity=int(severity),
        src_ip=dig(src, "source.ip"),
        dst_ip=dig(src, "destination.ip"),
        user=dig(src, "user.name"),
        mitre_tactic=tactic,
        mitre_technique=first(dig(src, "threat.technique.id")),
        raw=src,
    )


# ---------- Suricata ----------

_SURICATA_SEVERITY = {1: 90, 2: 60, 3: 30}


def from_suricata(event: dict[str, Any], inventory: dict[str, str] | None = None) -> Alert:
    """One line of Suricata's eve.json with event_type == "alert".

    Suricata only knows IPs, so `inventory` (IP → hostname) links the alert to the
    internal asset involved: the destination for inbound traffic, the source for outbound.
    """
    inventory = inventory or {}
    alert = event.get("alert", {})
    signature = alert.get("signature", "Suricata alert")
    metadata = alert.get("metadata", {}) or {}
    tactic = normalize_tactic(first(metadata.get("mitre_tactic_name")) or first(metadata.get("mitre_tactic_id")))
    technique = first(metadata.get("mitre_technique_id"))
    flow_id = event.get("flow_id") or ""
    return Alert(
        source="suricata",
        source_id=f"{flow_id}-{alert.get('signature_id')}-{event.get('timestamp')}",
        timestamp=parse_timestamp(event.get("timestamp")),
        host=(
            inventory.get(event.get("dest_ip", ""))
            or inventory.get(event.get("src_ip", ""))
            or event.get("dest_ip")
            or event.get("host")
            or "unknown"
        ),
        rule_id=f"suricata:{alert.get('signature_id', 0)}",
        title=signature,
        category=categorize(tactic, signature, alert.get("category")),
        severity=_SURICATA_SEVERITY.get(int(alert.get("severity", 3) or 3), 30),
        src_ip=event.get("src_ip"),
        dst_ip=event.get("dest_ip"),
        mitre_tactic=tactic,
        mitre_technique=technique,
        raw=event,
    )


NORMALIZERS = {"wazuh": from_wazuh, "elastic": from_elastic, "suricata": from_suricata}
