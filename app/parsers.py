"""Turn whatever a tool sends — JSON, NDJSON, CSV, syslog, CEF, key=value — into dict records.

Every record ends up as a flat-or-nested dict, so one field-mapping engine (mapping.py)
can handle every tool.
"""

from __future__ import annotations

import csv
import io
import json
import re
from typing import Any

SYSLOG_SEVERITIES = ["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]

# <PRI>1 2026-10-13T10:00:00Z host app procid msgid [sd] message      (RFC 5424)
_RFC5424 = re.compile(
    r"^<(?P<pri>\d{1,3})>1 (?P<ts>\S+) (?P<host>\S+) (?P<app>\S+) (?P<procid>\S+) (?P<msgid>\S+) "
    r"(?P<sd>-|(?:\[[^\]]*\])+) ?(?P<msg>.*)$",
    re.S,
)
# <PRI>Oct 13 10:00:00 host tag[pid]: message                         (RFC 3164 / BSD)
_RFC3164 = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (?P<host>\S+) "
    r"(?:(?P<app>[\w./-]{1,48})(?:\[(?P<procid>\d+)\])?: )?(?P<msg>.*)$",  # TAG is a short program name
    re.S,
)
# key=value or key="quoted value" (FortiGate, many firewalls)
_KV = re.compile(r'(?:^|\s)([A-Za-z_][\w.\-]*)=("(?:[^"\\]|\\.)*"|\S*)')
# CEF extension keys: values may contain spaces, so split on the next "key="
_CEF_KEY = re.compile(r"(?:^|(?<=\s))([A-Za-z0-9_.\[\]\-]+)=")


def parse_kv(text: str) -> dict[str, str]:
    out = {}
    for key, value in _KV.findall(text):
        if value.startswith('"') and value.endswith('"') and len(value) >= 2:
            value = value[1:-1].replace('\\"', '"')
        out[key] = value
    return out


def _cef_unescape(value: str) -> str:
    return value.replace("\\=", "=").replace("\\|", "|").replace("\\\\", "\\").replace("\\n", "\n").strip()


def parse_cef(text: str) -> dict[str, Any]:
    """CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|key=value key=value ..."""
    start = text.find("CEF:")
    body = text[start + 4:]
    parts: list[str] = []
    buf, i = "", 0
    while i < len(body) and len(parts) < 7:  # split the 7 header fields on unescaped pipes
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            buf += body[i:i + 2]
            i += 2
            continue
        if ch == "|":
            parts.append(buf)
            buf = ""
        else:
            buf += ch
        i += 1
    if len(parts) < 7:
        raise ValueError("not a CEF record")
    extension = body[i:]
    record: dict[str, Any] = {
        "cef_version": parts[0], "device_vendor": _cef_unescape(parts[1]), "device_product": _cef_unescape(parts[2]),
        "device_version": _cef_unescape(parts[3]), "signature_id": _cef_unescape(parts[4]),
        "name": _cef_unescape(parts[5]), "cef_severity": _cef_unescape(parts[6]),
    }
    keys = list(_CEF_KEY.finditer(extension))
    for n, m in enumerate(keys):
        end = keys[n + 1].start() if n + 1 < len(keys) else len(extension)
        record[m.group(1)] = _cef_unescape(extension[m.end():end])
    return record


def parse_syslog(text: str) -> dict[str, Any] | None:
    for pattern in (_RFC5424, _RFC3164):
        m = pattern.match(text)
        if m:
            pri = int(m.group("pri"))
            return {
                "syslog_facility": pri // 8,
                "syslog_severity": SYSLOG_SEVERITIES[pri % 8],
                "syslog_timestamp": m.group("ts"),
                "syslog_host": m.group("host"),
                "syslog_app": m.groupdict().get("app") or None,
                "message": m.group("msg").strip(),
            }
    return None


def parse_line(text: str) -> dict[str, Any]:
    """Best-effort parse of one log line in any of the supported text formats."""
    text = text.strip().lstrip("﻿")
    if not text:
        raise ValueError("empty line")
    if text.startswith("{"):
        value = json.loads(text)
        if isinstance(value, dict):
            return value
        raise ValueError("JSON line is not an object")

    record: dict[str, Any] = {}
    body = text
    header = parse_syslog(text)
    if header:
        body = header.pop("message")
        record.update(header)
        record["syslog_message"] = body  # the raw payload, always kept
        if body.startswith("{"):
            try:
                record.update(json.loads(body))
                return record
            except json.JSONDecodeError:
                pass

    # Structured payloads get their own fields; only free text becomes "message".
    if "CEF:" in body:
        record.update(parse_cef(body))
        return record
    kv = parse_kv(body)
    if len(kv) >= 3:  # looks like key=value logging, not prose with a stray "="
        record.update(kv)
    else:
        record["message"] = body
    return record


def records_at(value: Any, path: str | None) -> list[dict[str, Any]]:
    """Pull the list of records out of an API response, e.g. path "hits.hits" or "data.alerts"."""
    if path:
        for part in path.split("."):
            if isinstance(value, dict):
                value = value.get(part)
            else:
                value = None
                break
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    raise ValueError("records path does not point to an object or a list")


def parse_payload(body: bytes | str, fmt: str = "auto", records_path: str | None = None) -> list[dict[str, Any]]:
    """Parse a webhook body or file contents into records.

    fmt: auto | json | ndjson | csv | text (one syslog/CEF/kv line per record)
    """
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else body
    text = text.strip().lstrip("﻿")
    if not text:
        return []

    if fmt == "csv":
        return [dict(row) for row in csv.DictReader(io.StringIO(text))]

    if fmt in ("auto", "json") and text[0] in "[{":
        try:
            return records_at(json.loads(text), records_path)
        except json.JSONDecodeError:
            if fmt == "json":
                raise
            # fall through: probably NDJSON

    records = []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            records.append(parse_line(line))
        except (ValueError, json.JSONDecodeError):
            continue
    return records
