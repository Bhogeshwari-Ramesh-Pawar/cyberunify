from datetime import datetime, timezone

import pytest

from app.normalize import from_elastic, from_suricata, from_wazuh, infer_category, normalize_tactic, parse_timestamp


@pytest.mark.parametrize("raw", [
    "2026-10-13T10:15:00.123+0000",   # Wazuh
    "2026-10-13T10:15:00.123456+0000",  # Suricata
    "2026-10-13T10:15:00.123Z",       # ECS
    "2026-10-13T15:45:00.123+05:30",  # explicit offset
])
def test_parse_timestamp_variants_to_utc(raw):
    ts = parse_timestamp(raw)
    assert ts.tzinfo == timezone.utc
    assert (ts.hour, ts.minute) == (10, 15)


def test_parse_timestamp_rejects_garbage():
    with pytest.raises(ValueError):
        parse_timestamp(None)


def test_wazuh_alert():
    doc = {"_id": "abc", "_source": {
        "timestamp": "2026-10-13T10:00:00.000+0000",
        "rule": {"id": "5712", "level": 10, "description": "sshd: brute force trying to get access to the system.",
                 "groups": ["syslog", "sshd", "authentication_failures"],
                 "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]}},
        "agent": {"name": "web-01", "ip": "10.0.1.10"},
        "data": {"srcip": "185.220.101.47", "dstuser": "admin"},
    }}
    a = from_wazuh(doc)
    assert a.source == "wazuh" and a.source_id == "abc"
    assert a.host == "web-01"
    assert a.severity == 67  # level 10 of 15
    assert a.category == "authentication"
    assert a.mitre_tactic == "credential access" and a.mitre_technique == "T1110"
    assert a.src_ip == "185.220.101.47" and a.user == "admin"


def test_wazuh_level_15_is_max_severity():
    a = from_wazuh({"timestamp": "2026-10-13T10:00:00Z", "rule": {"level": 15, "description": "x"}, "agent": {"name": "h"}})
    assert a.severity == 100


def test_elastic_kibana_severity_label_fallback():
    doc = {"_id": "e1", "_source": {
        "@timestamp": "2026-10-13T10:00:00Z",
        "kibana": {"alert": {"severity": "critical", "rule": {"name": "Ransomware behaviour"}}},
        "host": {"name": "fs-02"},
        "threat": {"tactic": {"id": "TA0040"}},
    }}
    a = from_elastic(doc)
    assert a.severity == 95
    assert a.title == "Ransomware behaviour"
    assert a.category == "malware"
    assert a.mitre_tactic == "impact"  # mapped from the tactic id


def test_suricata_maps_ip_to_internal_host():
    event = {
        "timestamp": "2026-10-13T10:00:00.000000+0000", "flow_id": 1, "event_type": "alert",
        "src_ip": "10.0.2.20", "dest_ip": "203.0.113.9",
        "alert": {"signature_id": 2027863, "signature": "ET POLICY Possible DNS Tunneling", "severity": 1, "category": "x"},
    }
    a = from_suricata(event, {"10.0.2.20": "db-01"})
    assert a.host == "db-01"  # outbound: the internal source is the asset at risk
    assert a.severity == 90
    assert a.category == "data_exfiltration"


def test_suricata_without_inventory_falls_back_to_destination_ip():
    event = {"timestamp": "2026-10-13T10:00:00Z", "event_type": "alert", "dest_ip": "10.9.9.9", "alert": {"signature": "ET SCAN", "severity": 3}}
    assert from_suricata(event).host == "10.9.9.9"


@pytest.mark.parametrize("text,expected", [
    ("sshd: authentication failed", "authentication"),
    ("ET SCAN Nmap", "reconnaissance"),
    ("Trojan detected", "malware"),
    ("Integrity checksum changed.", "integrity"),
    ("CVE-2024-6387 affects openssh-server", "vulnerability"),
    ("Successful sudo to ROOT executed", "privilege_escalation"),
    ("AWS EC2 instance started", "other"),  # "ec2" must not look like C2 malware traffic
])
def test_infer_category(text, expected):
    assert infer_category(text) == expected


def test_normalize_tactic_spellings():
    assert normalize_tactic(["Credential-Access"]) == "credential access"
    assert normalize_tactic("ta0010") == "exfiltration"
    assert normalize_tactic([]) is None


def test_naive_timestamps_become_utc():
    a = from_wazuh({"timestamp": datetime(2026, 1, 1, 12).isoformat(), "rule": {"level": 3}, "agent": {"name": "h"}})
    assert a.timestamp.tzinfo is not None


def test_tactic_fills_in_category_when_text_has_no_clue():
    doc = {"_id": "x", "_source": {"@timestamp": "2026-10-13T10:00:00Z", "rule": {"name": "Rare destination traffic spike"},
                                   "host": {"name": "db-01"}, "threat": {"tactic": {"name": "Exfiltration"}}}}
    assert from_elastic(doc).category == "data_exfiltration"


def test_text_keywords_win_over_tactic():
    doc = {"_id": "x", "_source": {"@timestamp": "2026-10-13T10:00:00Z", "rule": {"name": "Malware detected"},
                                   "host": {"name": "h"}, "threat": {"tactic": {"name": "Exfiltration"}}}}
    assert from_elastic(doc).category == "malware"
