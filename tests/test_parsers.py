from app.parsers import parse_cef, parse_kv, parse_line, parse_payload


def test_rfc3164_syslog_with_kv_body():
    rec = parse_line('<189>Oct 13 10:00:00 fw01 date=2026-10-13 time=10:00:00 devname="FGT 1" srcip=10.0.0.1 action="accept"')
    assert rec["syslog_host"] == "fw01"
    assert rec["syslog_severity"] == "notice"  # 189 % 8 == 5
    assert rec["devname"] == "FGT 1"  # quoted value with a space
    assert rec["srcip"] == "10.0.0.1"
    assert "message" not in rec  # structured payload: no free-text message
    assert rec["syslog_message"].startswith("date=")


def test_rfc5424_syslog_free_text():
    rec = parse_line("<34>1 2026-10-13T10:00:00Z host01 sshd 123 ID47 - Failed password for root from 1.2.3.4")
    assert rec["syslog_app"] == "sshd"
    assert rec["syslog_severity"] == "critical"
    assert rec["message"] == "Failed password for root from 1.2.3.4"


def test_cef_header_and_extension_with_spaces_and_escapes():
    rec = parse_cef(r"CEF:0|GTB|Inspector|15.6|DLP-1|Data \| leak found|8|src=10.0.0.5 suser=a b fname=q3 report.pdf msg=x\=y")
    assert rec["device_vendor"] == "GTB"
    assert rec["name"] == "Data | leak found"
    assert rec["cef_severity"] == "8"
    assert rec["suser"] == "a b"
    assert rec["fname"] == "q3 report.pdf"
    assert rec["msg"] == "x=y"


def test_cef_inside_syslog():
    rec = parse_line("<134>Oct 13 10:00:00 gtb CEF:0|GTB|Inspector|15|DLP-9|Card numbers sent|9|src=10.0.3.12 act=Blocked")
    assert rec["name"] == "Card numbers sent" and rec["act"] == "Blocked" and rec["syslog_host"] == "gtb"


def test_json_inside_syslog():
    rec = parse_line('<14>Oct 13 10:00:00 app01 {"event": "login", "user": "bob"}')
    assert rec["event"] == "login" and rec["user"] == "bob"


def test_prose_with_a_stray_equals_is_not_kv():
    rec = parse_line("<14>Oct 13 10:00:00 h app: user changed setting x=1")
    assert rec["message"] == "user changed setting x=1"


def test_kv_parser():
    assert parse_kv('a=1 b="two words" c=') == {"a": "1", "b": "two words", "c": ""}


def test_payload_json_array_object_and_records_path():
    assert len(parse_payload('[{"a": 1}, {"a": 2}, "junk"]')) == 2
    assert parse_payload('{"a": 1}') == [{"a": 1}]
    assert len(parse_payload('{"data": {"alerts": [{"x": 1}, {"x": 2}]}}', records_path="data.alerts")) == 2


def test_payload_ndjson_skips_bad_lines():
    body = '{"a": 1}\nnot json at all {{\n{"a": 3}\n\n'
    recs = parse_payload(body, "ndjson")
    assert [r.get("a") for r in recs if "a" in r] == [1, 3]


def test_payload_csv():
    recs = parse_payload("time,host,msg\n2026-10-13T10:00:00Z,web-01,hello\n", "csv")
    assert recs == [{"time": "2026-10-13T10:00:00Z", "host": "web-01", "msg": "hello"}]


def test_payload_handles_bytes_and_bom():
    assert parse_payload('﻿{"a": 1}'.encode()) == [{"a": 1}]
    assert parse_payload(b"") == []
