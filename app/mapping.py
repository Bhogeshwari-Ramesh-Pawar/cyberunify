"""Field mapping: how any tool's record becomes a unified Event.

A mapping says where each unified field lives in that tool's records, as dotted
paths with "|" alternatives, e.g.  {"host": "agent.name|manager.name"}.
Fields left out are auto-detected from common names, so an unknown tool still
produces sensible events, and the analyst can refine the mapping in the UI.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

from .models import Event

UNIFIED_FIELDS = ("id", "timestamp", "host", "message", "severity", "category", "src_ip", "dst_ip",
                  "user", "rule", "action", "tactic", "technique")

# Used when a mapping doesn't specify a field (or its paths are empty in this record).
AUTO_CANDIDATES: dict[str, list[str]] = {
    "id": ["_id", "id", "event.id", "uuid", "alert_id", "RayID"],
    "timestamp": ["@timestamp", "timestamp", "_time", "time", "datetime", "Datetime", "EdgeStartTimestamp",
                  "eventtime", "rt", "created_at", "createdAt", "created", "event_time", "detected_at", "ts", "date",
                  "syslog_timestamp"],
    "host": ["host.name", "agent.name", "hostname", "host", "devname", "computer", "device", "dhost",
             "ClientRequestHost", "asset", "source", "syslog_host"],
    "message": ["message", "msg", "rule.description", "rule.name", "alert.signature", "title", "description",
                "name", "event", "Description", "_raw", "syslog_message"],
    "severity": ["severity", "event.severity", "rule.level", "alert.severity", "level", "priority", "urgency",
                 "cef_severity", "syslog_severity"],
    "category": ["category", "event.category", "rule.groups", "alert.category", "type", "subtype", "sourcetype",
                 "event_type"],
    "src_ip": ["source.ip", "src_ip", "srcip", "src", "client_ip", "ClientIP", "ipAddress", "ip"],
    "dst_ip": ["destination.ip", "dest_ip", "dst_ip", "dstip", "dst", "dest"],
    "user": ["user.name", "user", "username", "user_name", "suser", "duser", "data.dstuser", "data.srcuser", "userName"],
    "rule": ["rule.id", "signature_id", "alert.signature_id", "rule_id", "RuleID", "logid", "signature", "rule.name"],
    "action": ["event.action", "action", "Action", "act", "status", "outcome"],
    "tactic": ["threat.tactic.name", "rule.mitre.tactic", "alert.metadata.mitre_tactic_name", "mitre_tactic"],
    "technique": ["threat.technique.id", "rule.mitre.id", "alert.metadata.mitre_technique_id", "mitre_technique"],
}

SEVERITY_SCALES = {
    "auto": "Detect automatically",
    "0-100": "0 to 100 (ECS)",
    "0-15": "0 to 15, higher = worse (Wazuh rule.level)",
    "0-10": "0 to 10, higher = worse (CEF, GTB DLP)",
    "1-5": "1 to 5, higher = worse",
    "1-3-inverted": "1 to 3, 1 = worst (Suricata)",
    "syslog": "Syslog 0 to 7 or names, 0 = emergency",
    "text": "Words: critical / high / medium / low / info",
}

_SEVERITY_WORDS = [
    (("emergency", "emerg", "fatal", "critical", "crit", "severe", "very high"), 95),
    (("alert",), 90),
    (("high", "error", "err", "major"), 75),
    (("medium", "warning", "warn", "moderate", "minor"), 50),
    (("low", "notice"), 25),
    (("info", "informational", "information"), 10),
    (("debug", "trace"), 5),
]

# Some tools (Cloudflare, IAM) report an outcome instead of a severity.
_OUTCOME_SEVERITY = {
    "block": 60, "blocked": 60, "drop": 55, "deny": 55, "denied": 55, "locked": 70,
    "challenge": 40, "jschallenge": 40, "managed_challenge": 40, "failed": 50, "failure": 50,
    "log": 20, "allow": 10, "allowed": 10, "accept": 10, "pass": 10, "success": 10,
}

# ---------- small helpers ----------

_TZ_NO_COLON = re.compile(r"([+-]\d{2})(\d{2})$")


def parse_timestamp(value: Any) -> datetime:
    """ISO-8601 in its many variants, epoch seconds/ms/ns, or BSD syslog "Oct 13 10:00:00"."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)) or (isinstance(value, str) and value.strip().isdigit()):
        n = float(value)
        if n > 1e17:
            n /= 1e9  # nanoseconds (FortiGate eventtime)
        elif n > 1e14:
            n /= 1e6  # microseconds
        elif n > 1e11:
            n /= 1e3  # milliseconds
        dt = datetime.fromtimestamp(n, tz=timezone.utc)
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        try:
            dt = datetime.fromisoformat(_TZ_NO_COLON.sub(r"\1:\2", text.replace("Z", "+00:00")))
        except ValueError:
            for fmt in ("%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z", "%m/%d/%Y %H:%M:%S"):
                try:
                    dt = datetime.strptime(" ".join(text.split()), fmt)
                    break
                except ValueError:
                    continue
            else:
                raise ValueError(f"unrecognised timestamp: {value!r}") from None
            if dt.year == 1900:  # BSD syslog has no year
                now = datetime.now(timezone.utc)
                dt = dt.replace(year=now.year)
                if dt.replace(tzinfo=timezone.utc) > now:
                    dt = dt.replace(year=now.year - 1)
    else:
        raise ValueError(f"unrecognised timestamp: {value!r}")
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def dig(data: Any, path: str) -> Any:
    """Read "a.b.c" from nested dicts; a literal key containing dots ("host.name") wins."""
    if not isinstance(data, dict):
        return None
    if path in data:
        return data[path]
    current: Any = data
    for part in path.split("."):
        if isinstance(current, list):
            current = current[0] if current else None
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _present(value: Any) -> bool:
    return value not in (None, "", [], {}, "-")


_TEMPLATE_FIELD = re.compile(r"\{([^{}]+)\}")


def render(record: dict[str, Any], template: str) -> str | None:
    """Fill "{action} {srcip} → {dstip}" from the record; None if no placeholder had a value."""
    found = False

    def sub(m: re.Match) -> str:
        nonlocal found
        value = first(dig(record, m.group(1).strip()))
        if _present(value):
            found = True
            return str(value)
        return ""

    text = " ".join(_TEMPLATE_FIELD.sub(sub, template).split())
    return text if found else None


# Last resort for unknown tools: recognise fields by the shape of their name.
# Checked against the *last* segment of every dotted path in the record ("device.hostname" → "hostname").
KEY_PATTERNS: dict[str, re.Pattern] = {
    "id": re.compile(r"^(event|alert|detection|incident|log)_?id$|^uuid$", re.I),
    "timestamp": re.compile(r"(^|_)(time|timestamp|datetime|created|date)(_?(at|utc|stamp))?$", re.I),
    "host": re.compile(r"^(host_?name|host|device_?name|computer_?name|machine_?name|endpoint|asset_?name)$", re.I),
    "message": re.compile(r"^(detect|alert|rule|threat|event|incident|signature)_?(name|title|description)$"
                          r"|^(title|summary|description|message|msg)$", re.I),
    "severity": re.compile(r"^(severity|priority|risk|criticality)(_?(name|level|label|score))?$", re.I),
    "category": re.compile(r"^(category|type|classification|event_?type)(_?name)?$", re.I),
    "src_ip": re.compile(r"^(src|source|client|remote|attacker)_?(ip|address|addr)$", re.I),
    "dst_ip": re.compile(r"^(dst|dest|destination|target|server)_?(ip|address|addr)$", re.I),
    "user": re.compile(r"^(user_?name|user|account_?name|account|login|actor)$", re.I),
    "action": re.compile(r"^(action|outcome|result|disposition|status)$", re.I),
    "tactic": re.compile(r"^(mitre_?)?tactics?(_?name)?$", re.I),
    "technique": re.compile(r"^(mitre_?)?techniques?(_?id)?$", re.I),
}


def scalar_paths(data: Any, prefix: str = "", depth: int = 0) -> list[tuple[str, Any]]:
    """Every (dotted.path, value) in the record whose value is a scalar (or list of scalars)."""
    out: list[tuple[str, Any]] = []
    if not isinstance(data, dict) or depth > 4:
        return out
    for key, value in data.items():
        path = f"{prefix}{key}"
        if isinstance(value, dict):
            out += scalar_paths(value, f"{path}.", depth + 1)
        elif _scalar(value):
            out.append((path, value))
    return out


def _scalar(value: Any) -> bool:
    if isinstance(value, list):
        return bool(value) and all(isinstance(v, (str, int, float, bool)) for v in value)
    return isinstance(value, (str, int, float, bool))


def discover(record: dict[str, Any], field: str) -> tuple[Any, str | None]:
    pattern = KEY_PATTERNS.get(field)
    if not pattern:
        return None, None
    for path, value in scalar_paths(record):
        if pattern.search(path.rsplit(".", 1)[-1]) and _present(value):
            return value, path
    return None, None


def resolve(record: dict[str, Any], spec: str | None, candidates: list[str], field: str | None = None) -> tuple[Any, str | None]:
    """Return (value, path it came from): the mapping's paths, then well-known names, then name patterns.

    A path containing {placeholders} is a template that composes a value from several fields.
    Objects are never used as a value (a "device" object is not a hostname).
    """
    for path in [p.strip() for p in (spec or "").split("|") if p.strip()] + candidates:
        value = render(record, path) if "{" in path else dig(record, path)
        if _present(value) and _scalar(value):
            return value, path
    if field:
        return discover(record, field)
    return None, None


def severity_to_100(value: Any, scale: str = "auto") -> int:
    value = first(value)
    if value is None:
        return 30
    text = str(value).strip().lower()
    number: float | None
    try:
        number = float(text)
    except ValueError:
        number = None

    if number is None or scale == "text":
        if text in _OUTCOME_SEVERITY:
            return _OUTCOME_SEVERITY[text]
        for words, score in _SEVERITY_WORDS:
            if text in words or any(text.startswith(w) for w in words):
                return score
        return 30

    if scale == "0-100":
        return round(number)
    if scale == "0-15":
        return round(min(number, 15) / 15 * 100)
    if scale == "0-10":
        return round(min(number, 10) * 10)
    if scale == "1-5":
        return round((min(max(number, 1), 5) - 1) / 4 * 100)
    if scale == "1-3-inverted":
        return {1: 90, 2: 60, 3: 30}.get(int(number), 30)
    if scale == "syslog":
        return [100, 90, 85, 75, 50, 25, 10, 5][max(0, min(7, int(number)))]
    # auto
    if number > 15:
        return round(min(number, 100))
    if number > 10:
        return round(number / 15 * 100)
    return round(number * 10)


# ---------- categories ----------

_CATEGORY_KEYWORDS: list[tuple[str, tuple[str, ...]]] = [
    ("threat_intel", ("leaked credential", "credential leak", "phishing domain", "dark web", "impersonat",
                      "brand abuse", "threat intel", "ioc match", "typosquat")),
    ("data_exfiltration", ("exfil", "dns tunnel", "data leak", "large upload", "outbound data", "data transfer",
                           "dlp", "sensitive data", "pii", "aadhaar", "credit card number")),
    ("privilege_escalation", ("privilege", "sudo", "root shell", "escalat", "setuid", "admin role")),
    ("malware", ("malware", "trojan", "virus", "ransom", "rootkit", "rootcheck", "command and control", "beacon", "botnet")),
    ("authentication", ("authentication", "login", "logon", "log in", "log on", "logged on", "locked out", "lockout",
                        "password", "brute", "sshd", "pam", "credential", "mfa", "sso", "otp", "sign-in", "signin")),
    ("reconnaissance", ("scan", "recon", "nmap", "probe", "enumerat", "discovery")),
    ("vulnerability", ("vulnerab", "cve-", "outdated", "patch")),
    ("integrity", ("syscheck", "integrity", "checksum", "file modified", "fim", "file added", "file deleted")),
    ("network_intrusion", ("exploit", "injection", "sqli", "xss", "attack", "intrusion", "shellcode", "waf", "ips",
                           "firewall rule")),
    ("policy", ("policy", "compliance", "unauthorized software", "usb")),
    ("network_traffic", ("traffic", "connection", "session", "netflow", "forward")),
]

_TACTIC_IDS = {
    "TA0043": "reconnaissance", "TA0042": "resource development", "TA0001": "initial access",
    "TA0002": "execution", "TA0003": "persistence", "TA0004": "privilege escalation",
    "TA0005": "defense evasion", "TA0006": "credential access", "TA0007": "discovery",
    "TA0008": "lateral movement", "TA0009": "collection", "TA0011": "command and control",
    "TA0010": "exfiltration", "TA0040": "impact",
}

_TACTIC_CATEGORY = {
    "exfiltration": "data_exfiltration", "collection": "data_exfiltration",
    "privilege escalation": "privilege_escalation", "credential access": "authentication",
    "initial access": "authentication", "reconnaissance": "reconnaissance", "discovery": "reconnaissance",
    "lateral movement": "network_intrusion", "persistence": "integrity", "defense evasion": "integrity",
    "execution": "malware", "command and control": "malware", "impact": "malware",
}


def infer_category(*texts: Any) -> str:
    haystack = " ".join(" ".join(map(str, t)) if isinstance(t, list) else str(t) for t in texts if t).lower()
    for category, words in _CATEGORY_KEYWORDS:
        if any(w in haystack for w in words):
            return category
    return "other"


def normalize_tactic(value: Any) -> str | None:
    value = first(value)
    if not _present(value):
        return None
    text = str(value).strip()
    return _TACTIC_IDS.get(text.upper()) or text.lower().replace("-", " ").replace("_", " ")


def categorize(tactic: str | None, default: str | None, hint: Any, *texts: Any) -> str:
    """Most specific signal first: MITRE tactic, then the tool's own category field,
    then keywords in the message/rule, then the integration's default."""
    if tactic and tactic in _TACTIC_CATEGORY:
        return _TACTIC_CATEGORY[tactic]
    for candidate in (infer_category(hint), infer_category(*texts)):
        if candidate != "other":
            return candidate
    return default or "other"


# ---------- the mapping itself ----------

def unwrap(record: dict[str, Any]) -> dict[str, Any]:
    """Elasticsearch/OpenSearch hits keep the document in _source; flatten so paths are simple."""
    if isinstance(record.get("_source"), dict):
        return {**record["_source"], "_id": record.get("_id"), "_index": record.get("_index")}
    return record


def map_record(
    record: dict[str, Any],
    *,
    integration_id: int,
    tool: str,
    mapping: dict[str, str] | None = None,
    severity_scale: str = "auto",
    default_category: str | None = None,
    inventory: dict[str, str] | None = None,
    fallback_host: str = "unknown",
) -> tuple[Event, dict[str, str | None]]:
    """Map one raw record to an Event. Returns the event and, per field, which path was used."""
    mapping = mapping or {}
    inventory = inventory or {}
    rec = unwrap(record)
    trace: dict[str, str | None] = {}

    def get(name: str) -> Any:
        value, path = resolve(rec, mapping.get(name), AUTO_CANDIDATES[name], name)
        trace[name] = path
        return value

    raw_ts = get("timestamp")
    timestamp = parse_timestamp(raw_ts) if raw_ts is not None else datetime.now(timezone.utc)
    src_ip, dst_ip = get("src_ip"), get("dst_ip")
    src_ip = str(first(src_ip)) if _present(src_ip) else None
    dst_ip = str(first(dst_ip)) if _present(dst_ip) else None

    # "@asset" in a host mapping means: the internal asset involved, found from the IPs via the
    # inventory. Firewalls and IDSs report their own name, but the analyst cares about the endpoint.
    host = None
    host_spec = mapping.get("host") or ""
    for alt in [p.strip() for p in host_spec.split("|") if p.strip()]:
        if alt == "@asset":
            host = inventory.get(dst_ip or "") or inventory.get(src_ip or "")
            if host:
                trace["host"] = "@asset"
                break
        else:
            value = first(dig(rec, alt))
            if _present(value) and _scalar(value):
                host, trace["host"] = str(value), alt
                break
    if not host:
        value = first(get("host")) if "@asset" not in host_spec else None
        host = str(value) if _present(value) else None
    if host and host in inventory:  # IPs and aliases ("shop.example.com") → asset name
        host = inventory[host]
    if not host:
        host = inventory.get(dst_ip or "") or inventory.get(src_ip or "") or dst_ip or src_ip or fallback_host

    message = first(get("message"))
    rule = first(get("rule"))
    tactic = normalize_tactic(get("tactic"))
    category_hint = get("category")
    action = first(get("action"))
    user = first(get("user"))
    technique = first(get("technique"))
    record_id = first(get("id"))
    if not _present(record_id):
        record_id = hashlib.sha1(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()

    event = Event(
        integration_id=integration_id,
        tool=tool,
        source_id=str(record_id),
        timestamp=timestamp,
        host=host,
        message=str(message) if _present(message) else json.dumps(rec, default=str)[:300],
        severity=severity_to_100(get("severity"), severity_scale),
        category=categorize(tactic, default_category, category_hint, message, rule),
        src_ip=src_ip,
        dst_ip=dst_ip,
        user=str(user) if _present(user) else None,
        rule=str(rule) if _present(rule) else None,
        action=str(action) if _present(action) else None,
        mitre_tactic=tactic,
        mitre_technique=str(technique) if _present(technique) else None,
        raw=record,
    )
    return event, trace
