from datetime import timezone

import pytest

from app.demo import DEMO_TOOLS, Simulator
from app.mapping import map_record, parse_timestamp, render, severity_to_100
from app.presets import PRESETS

INVENTORY = {"10.0.1.10": "web-01", "10.0.2.20": "db-01", "shop.example.com": "web-01"}


def m(record, tool="custom", **kw):
    preset = PRESETS[tool]
    kw.setdefault("mapping", preset["mapping"])
    kw.setdefault("severity_scale", preset.get("severity_scale", "auto"))
    kw.setdefault("default_category", preset.get("default_category"))
    kw.setdefault("inventory", INVENTORY)
    return map_record(record, integration_id=1, tool=tool, **kw)


@pytest.mark.parametrize("raw,hour", [
    ("2026-10-13T10:15:00.123+0000", 10), ("2026-10-13T10:15:00Z", 10), ("2026-10-13T15:45:00+05:30", 10),
    (1791886500, 10), (1791886500000, 10), (1791886500000000000, 10), ("2026-10-13 10:15:00", 10),
])
def test_timestamps(raw, hour):
    ts = parse_timestamp(raw)
    assert ts.tzinfo == timezone.utc and ts.hour == hour


def test_bsd_syslog_timestamp_gets_a_year():
    assert parse_timestamp("Oct 13 10:00:00").year >= 2025


def test_bad_timestamp_raises():
    with pytest.raises(ValueError):
        parse_timestamp("yesterday-ish")


@pytest.mark.parametrize("value,scale,expected", [
    (15, "0-15", 100), (10, "0-15", 67), (1, "1-3-inverted", 90), (3, "1-3-inverted", 30), (8, "0-10", 80),
    (5, "1-5", 100), (0, "syslog", 100), ("warning", "syslog", 50), ("critical", "text", 95), ("block", "text", 60),
    ("SUCCESS", "text", 10), (73, "auto", 73), (12, "auto", 80), ("medium", "auto", 50), (None, "auto", 30),
])
def test_severity_scales(value, scale, expected):
    assert severity_to_100(value, scale) == expected


def test_unknown_tool_is_auto_detected():
    rec = {"time": "2026-10-13T10:00:00Z", "hostname": "srv9", "description": "Reverse shell detected",
           "level": "critical", "src_ip": "185.220.101.47", "username": "www-data"}
    ev, trace = m(rec, mapping={})
    assert (ev.host, ev.message, ev.severity, ev.src_ip, ev.user) == ("srv9", "Reverse shell detected", 95, "185.220.101.47", "www-data")
    assert trace["host"] == "hostname" and trace["severity"] == "level"


def test_template_and_alternatives():
    rec = {"type": "traffic", "action": "deny", "srcip": "10.0.1.10", "dstip": "8.8.8.8"}
    assert render(rec, "{type} {action}: {srcip} → {dstip}") == "traffic deny: 10.0.1.10 → 8.8.8.8"
    assert render(rec, "{nothing} {missing}") is None
    ev, trace = m({**rec, "date": "2026-10-13"}, mapping={"message": "msg|{action} {srcip}"})
    assert ev.message == "deny 10.0.1.10" and trace["message"] == "{action} {srcip}"


def test_asset_host_comes_from_ip_inventory():
    ev, trace = m({"timestamp": "2026-10-13T10:00:00Z", "devname": "FGT-01", "srcip": "10.0.2.20", "dstip": "1.2.3.4",
                   "level": "notice", "type": "traffic", "action": "accept"}, tool="fortigate")
    assert ev.host == "db-01" and trace["host"] == "@asset"
    ev, _ = m({"timestamp": "2026-10-13T10:00:00Z", "devname": "FGT-01", "srcip": "9.9.9.9", "dstip": "1.2.3.4"}, tool="fortigate")
    assert ev.host == "FGT-01"  # no internal asset involved: fall back to the device


def test_hostname_alias():
    ev, _ = m({"RayID": "r1", "Datetime": "2026-10-13T10:00:00Z", "ClientRequestHost": "shop.example.com",
               "Action": "block", "Description": "SQLi", "ClientRequestPath": "/x"}, tool="cloudflare")
    assert ev.host == "web-01" and ev.severity == 60 and ev.category == "network_intrusion"


def test_category_priority_tactic_then_hint_then_text_then_default():
    base = {"timestamp": "2026-10-13T10:00:00Z", "host": "h"}
    assert m({**base, "message": "x", "threat": {"tactic": {"name": "Exfiltration"}}}, tool="elastic")[0].category == "data_exfiltration"
    assert m({**base, "message": "Malware found", "category": "Leaked Credentials"})[0].category == "threat_intel"
    assert m({**base, "message": "An account failed to log on"})[0].category == "authentication"
    assert m({**base, "message": "something"}, default_category="policy")[0].category == "policy"


def test_id_is_stable_and_falls_back_to_content_hash():
    rec = {"timestamp": "2026-10-13T10:00:00Z", "message": "hi"}
    assert m(rec)[0].id == m(dict(rec))[0].id
    assert m(rec)[0].id != m({**rec, "message": "other"})[0].id
    assert m({**rec, "id": "abc"})[0].source_id == "abc"


def test_elasticsearch_hit_is_unwrapped():
    ev, _ = m({"_id": "x1", "_source": {"timestamp": "2026-10-13T10:00:00.000+0000", "agent": {"name": "web-01"},
                                        "rule": {"level": 12, "description": "Brute force", "id": "5712"}}}, tool="wazuh")
    assert (ev.source_id, ev.host, ev.severity, ev.rule) == ("x1", "web-01", 80, "5712")


@pytest.mark.parametrize("tool", DEMO_TOOLS)
def test_every_preset_maps_its_tools_native_logs(tool):
    """The demo emits each tool's real format; every record must map with a real host/message/time."""
    records = Simulator().records_for(tool)
    assert records, tool
    for rec in records:
        ev, _ = m(rec, tool=tool)
        assert ev.host and ev.host != "unknown"
        assert ev.message and not ev.message.startswith("{")
        assert 0 <= ev.severity <= 100


def test_unknown_tool_with_unusual_field_names_is_discovered_by_pattern():
    rec = {"event_id": "cs-001", "created": "2026-10-13T17:39:13Z", "device": {"hostname": "hr-laptop-07", "local_ip": "10.0.3.47"},
           "detect_name": "Credential dumping via LSASS", "severity_name": "High", "user_name": "priya.s",
           "tactic": "Credential Access", "technique_id": "T1003.001"}
    ev, trace = m(rec, mapping={})
    assert (ev.host, ev.message, ev.severity, ev.user, ev.source_id) == ("hr-laptop-07", "Credential dumping via LSASS", 75, "priya.s", "cs-001")
    assert ev.mitre_technique == "T1003.001" and ev.category == "authentication"
    assert trace["host"] == "device.hostname" and trace["message"] == "detect_name"


def test_objects_are_never_used_as_values():
    ev, _ = m({"timestamp": "2026-10-13T10:00:00Z", "host": {"name": "x"}, "message": "m"}, mapping={})
    assert ev.host == "x" or not ev.host.startswith("{")
