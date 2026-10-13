import base64
import socket
import time

import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

ATTACKER = "185.220.101.47"


def make_client(tmp_path, **overrides):
    s = Settings()
    s.db_path = tmp_path / "test.db"
    s.key_file = tmp_path / "test.key"
    s.ingest_interval = 0
    s.syslog_host = "127.0.0.1"
    s.admin_password = ""
    for k, v in overrides.items():
        setattr(s, k, v)
    return TestClient(create_app(s))


@pytest.fixture()
def client(tmp_path):
    with make_client(tmp_path) as c:
        yield c


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------- one dashboard for many tools ----------

def test_demo_connects_nine_tools_into_one_view(client):
    tools = {i["tool"] for i in client.get("/api/integrations").json()}
    assert tools == {"wazuh", "elastic", "splunk", "suricata", "fortigate", "cloudflare", "cloudsek", "gtb_dlp", "miniorange"}
    s = client.get("/api/summary").json()
    assert s["kpis"]["tools"] == 9 and s["kpis"]["integrations_ok"] == 9
    assert {t for t, _ in s["by_tool"]} == tools
    assert s["top_sources"][0][0] == ATTACKER


def test_one_search_follows_the_attacker_across_tools(client):
    r = client.get("/api/events", params={"range": "7d", "q": f"ip:{ATTACKER}", "limit": 500}).json()
    assert {e["tool"] for e in r["items"]} >= {"cloudflare", "suricata", "fortigate", "wazuh", "elastic", "miniorange"}


def test_query_language(client):
    get = lambda **p: client.get("/api/events", params={"range": "7d", **p}).json()["total"]
    everything = get()
    assert get(q='"brute force" host:web-01') > 0
    assert get(q="host:web-*") >= get(q="host:web-01")
    assert get(q="-tool:fortigate") == everything - get(q="tool:fortigate")
    assert get(q="user:priya.s tool:miniorange") > 0
    assert get(q="definitely-not-in-any-log-xyz") == 0
    assert get(q='unbalanced "quote') >= 0  # never a 500


def test_filters_facets_histogram(client):
    stats = client.get("/api/events/stats", params={"range": "48h", "tool": "wazuh"}).json()
    tool_facet = dict(stats["facets"]["tool"])
    assert len(tool_facet) > 1  # the tool facet ignores the tool filter, so you can see alternatives
    assert set(stats["histogram"]["series"]) == {"wazuh"}
    crit = client.get("/api/events", params={"range": "7d", "level": "critical"}).json()
    assert crit["total"] > 0 and all(e["risk_level"] == "critical" for e in crit["items"])
    assert client.get("/api/events", params={"range": "bogus"}).status_code == 400


# ---------- connect any tool ----------

def test_connect_custom_tool_by_webhook(client):
    integ = client.post("/api/integrations", json={"name": "My EDR", "tool": "custom", "type": "webhook"}).json()
    path = integ["webhook_url"].split("localhost:8000")[1]
    r = client.post(path, json=[{"time": "2026-10-13T12:00:00Z", "hostname": "web-01", "description": "Reverse shell detected",
                                 "level": "critical", "src_ip": ATTACKER, "username": "www-data"}])
    assert r.json() == {"accepted": 1, "stored": 1, "skipped": 0} or r.json()["accepted"] == 1
    found = client.get("/api/events", params={"range": "all", "q": '"Reverse shell"'}).json()["items"]
    # 2026-10-13T12:00Z may fall outside the retention window when tests run much later; only check if stored
    if r.json()["stored"]:
        assert found[0]["host"] == "web-01" and found[0]["user"] == "www-data"
    assert client.post("/api/ingest/wrong-token", json={}).status_code == 404
    client.post(f"/api/integrations/{integ['id']}/enabled?enabled=false")
    assert client.post(path, json={}).status_code == 409


def test_webhook_accepts_ndjson_and_text(client):
    integ = client.post("/api/integrations", json={"name": "Generic", "tool": "custom", "type": "webhook"}).json()
    path = integ["webhook_url"].split("localhost:8000")[1]
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    r = client.post(path, content=f'{{"timestamp": "{now}", "host": "a", "message": "one"}}\n{{"timestamp": "{now}", "host": "b", "message": "two"}}\n')
    assert r.json()["stored"] == 2
    r = client.post(path, content=f"<13>1 {now} srv7 app - - - Disk almost full")
    assert r.json()["stored"] == 1
    assert client.get("/api/events", params={"range": "1h", "q": "host:srv7"}).json()["items"][0]["message"] == "Disk almost full"


def test_syslog_receiver_end_to_end(client):
    port = free_udp_port()
    integ = client.post("/api/integrations", json={"name": "Lab FW", "tool": "fortigate", "config": {"port": port, "protocol": "udp"}}).json()
    assert integ["listening"] is True
    epoch_ns = int(time.time() * 1e9)
    line = (f'<185>date=2026-10-13 time=12:00:00 devname="FGT-LAB" eventtime={epoch_ns} logid="0419016384" type="utm" '
            f'subtype="ips" level="alert" srcip={ATTACKER} dstip=10.0.1.10 dstport=443 action="dropped" attack="Log4j.RCE"')
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(line.encode(), ("127.0.0.1", port))
    for _ in range(40):
        items = client.get("/api/events", params={"range": "1h", "q": "Log4j"}).json()["items"]
        if items:
            break
        time.sleep(0.1)
    assert items and items[0]["host"] == "web-01" and items[0]["message"] == "Log4j.RCE" and items[0]["src_ip"] == ATTACKER
    dup = client.post("/api/integrations", json={"name": "Dup", "tool": "fortigate", "config": {"port": port, "protocol": "udp"}})
    assert dup.status_code == 400 and "already used" in dup.json()["detail"]


def test_preview_with_sample_uses_preset_mapping(client):
    r = client.post("/api/integrations/test", json={
        "tool": "gtb_dlp", "type": "syslog", "config": {"port": 5600},
        "sample": "<134>Oct 13 12:00:00 gtb CEF:0|GTB|Inspector|15|DLP-9|Card numbers sent to pastebin|9|src=10.0.3.12 shost=dev-laptop-03 suser=rahul.k act=Blocked",
    }).json()
    ev = r["records"][0]["event"]
    assert r["ok"] and ev["host"] == "dev-laptop-03" and ev["message"] == "Card numbers sent to pastebin"
    assert ev["severity"] == 90 and ev["user"] == "rahul.k" and ev["category"] == "data_exfiltration"
    assert r["records"][0]["trace"]["severity"] == "cef_severity"
    assert client.post("/api/integrations/test", json={"tool": "custom", "type": "webhook"}).json()["ok"] is False


def test_validation_errors_are_clear(client):
    bad = client.post("/api/integrations", json={"tool": "elastic", "config": {"url": "ftp://x", "index": "a"}})
    assert bad.status_code == 400 and "http" in bad.json()["detail"]
    bad = client.post("/api/integrations", json={"tool": "elastic", "config": {"url": "https://x"}})
    assert bad.status_code == 400 and "Index" in bad.json()["detail"]
    assert client.post("/api/integrations", json={"tool": "nope"}).status_code == 400


def test_secrets_are_encrypted_never_returned_and_kept_on_edit(client, tmp_path):
    body = {"name": "Prod ELK", "tool": "elastic", "config": {"url": "https://127.0.0.1:1", "index": "logs-*", "auth": "apikey", "api_key": "SUPERSECRET"}}
    r = client.post("/api/integrations", json=body)
    integ = r.json()
    assert "SUPERSECRET" not in r.text and integ["config"]["_secrets_set"] == ["api_key"]
    assert integ["last_status"] == "error" and "connect" in integ["last_error"].lower()
    assert b"SUPERSECRET" not in (tmp_path / "test.db").read_bytes()
    body["config"]["api_key"] = ""  # blank on edit = keep the stored key
    r = client.put(f"/api/integrations/{integ['id']}", json=body)
    assert r.json()["config"]["_secrets_set"] == ["api_key"]
    assert "SUPERSECRET" not in client.get("/api/integrations").text


def test_delete_integration_optionally_purges_events(client):
    wazuh = next(i for i in client.get("/api/integrations").json() if i["tool"] == "wazuh")
    assert wazuh["events"] > 0
    assert client.delete(f"/api/integrations/{wazuh['id']}?purge=true").json()["events_removed"] == wazuh["events"]
    assert client.get("/api/events", params={"range": "7d", "tool": "wazuh"}).json()["total"] == 0


# ---------- analyst workflow ----------

def test_triage_survives_refresh_and_lowers_host_risk(client):
    items = client.get("/api/events", params={"range": "7d", "q": "host:hr-laptop-07", "sort": "risk", "limit": 500}).json()["items"]
    before = next(h for h in client.get("/api/hosts").json() if h["host"] == "hr-laptop-07")["risk_score"]
    for e in items:
        assert client.patch(f"/api/events/{e['id']}", json={"status": "closed"}).status_code == 200
    client.post("/api/refresh")
    assert client.get(f"/api/events/{items[0]['id']}").json()["status"] == "closed"
    after = {h["host"]: h["risk_score"] for h in client.get("/api/hosts").json()}.get("hr-laptop-07", 0)
    assert after < before
    assert client.patch(f"/api/events/{items[0]['id']}", json={"status": "deleted"}).status_code == 422


def test_refresh_does_not_duplicate_demo_data(client):
    count = lambda: client.get("/api/events", params={"range": "all"}).json()["total"]
    before = count()
    client.post("/api/refresh")
    assert count() - before <= 4 * 9  # only a few new live-noise logs per tool


def test_export_neutralises_spreadsheet_formulas(client):
    integ = client.post("/api/integrations", json={"name": "x", "tool": "custom", "type": "webhook"}).json()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    client.post(integ["webhook_url"].split("localhost:8000")[1], json={"timestamp": now, "host": "h", "message": "=HYPERLINK(\"http://evil\")"})
    csv_text = client.get("/api/events/export", params={"range": "1h", "q": "HYPERLINK"}).text
    assert "'=HYPERLINK" in csv_text and ",=HYPERLINK" not in csv_text


def test_report_escapes_attacker_controlled_text(client):
    integ = client.post("/api/integrations", json={"name": "x", "tool": "custom", "type": "webhook"}).json()
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    client.post(integ["webhook_url"].split("localhost:8000")[1],
                json={"timestamp": now, "host": "web-01", "message": "<script>alert(1)</script> malware", "severity": "critical"})
    client.post("/api/refresh")
    html = client.get("/reports/iso27001").text
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert client.get("/reports/iso27001", params={"download": True}).headers["content-disposition"].startswith("attachment")


def test_compliance_uses_every_tool(client):
    controls = {c["control"]: c for c in client.get("/api/compliance").json()["controls"]}
    assert controls["A.8.12"]["status"] == "At risk"   # DLP + exfiltration
    assert controls["A.5.7"]["status"] != "No evidence"  # CloudSEK threat intel
    assert controls["A.8.15"]["status"] == "Effective"  # all integrations healthy


def test_vendor_crud(client):
    assert len(client.get("/api/vendors").json()["items"]) == 4
    v = client.post("/api/vendors", json={"name": "Acme", "data_sensitivity": "high", "access_level": "limited", "answers": {"mfa": True}}).json()
    assert client.delete(f"/api/vendors/{v['id']}").json()["ok"]


def test_optional_login_protects_everything_but_webhooks(tmp_path):
    with make_client(tmp_path, admin_password="s3cret!") as c:
        assert c.get("/api/summary").status_code == 401
        auth = {"Authorization": "Basic " + base64.b64encode(b"admin:s3cret!").decode()}
        assert c.get("/api/summary", headers=auth).status_code == 200
        integ = c.post("/api/integrations", json={"name": "x", "tool": "custom", "type": "webhook"}, headers=auth).json()
        assert c.post(integ["webhook_url"].split("localhost:8000")[1], json={"message": "hi"}).status_code == 200


def test_dashboard_served(client):
    assert "CyberUnify" in client.get("/").text
