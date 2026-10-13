import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app


@pytest.fixture()
def client(tmp_path):
    settings = Settings()
    settings.db_path = tmp_path / "test.db"
    settings.demo_mode = True
    settings.ingest_interval = 0  # no background loop in tests
    settings.wazuh_url = settings.elastic_url = settings.suricata_eve_path = ""
    with TestClient(create_app(settings)) as c:
        yield c


def test_summary_has_demo_data(client):
    s = client.get("/api/summary").json()
    assert s["kpis"]["alerts"] > 100
    assert s["kpis"]["critical"] > 0
    assert {src for src, _ in s["by_source"]} == {"wazuh", "elastic", "suricata"}
    assert s["top_hosts"][0]["risk_level"] == "critical"


def test_reingest_does_not_duplicate(client):
    before = client.get("/api/summary").json()["kpis"]["alerts"]
    assert client.post("/api/ingest").json()["ok"]
    assert client.get("/api/summary").json()["kpis"]["alerts"] == before


def test_alert_filters_and_detail(client):
    data = client.get("/api/alerts", params={"host": "db-01", "level": "critical"}).json()
    assert data["total"] > 0
    assert all(a["host"] == "db-01" and a["risk_level"] == "critical" for a in data["items"])
    detail = client.get(f"/api/alerts/{data['items'][0]['id']}").json()
    assert "raw" in detail and "risk_factors" in detail


def test_triage_status_survives_reingest_and_lowers_host_risk(client):
    top = client.get("/api/alerts", params={"host": "hr-laptop-07", "sort": "risk"}).json()["items"]
    before = next(h for h in client.get("/api/hosts").json() if h["host"] == "hr-laptop-07")["risk_score"]
    for a in top:
        assert client.patch(f"/api/alerts/{a['id']}", json={"status": "closed"}).status_code == 200
    client.post("/api/ingest")
    assert client.get(f"/api/alerts/{top[0]['id']}").json()["status"] == "closed"
    hosts = {h["host"]: h["risk_score"] for h in client.get("/api/hosts").json()}
    assert hosts.get("hr-laptop-07", 0) < before


def test_invalid_status_rejected(client):
    alert_id = client.get("/api/alerts").json()["items"][0]["id"]
    assert client.patch(f"/api/alerts/{alert_id}", json={"status": "deleted"}).status_code == 422


def test_unknown_alert_404(client):
    assert client.get("/api/alerts/doesnotexist").status_code == 404


def test_compliance_and_report(client):
    report = client.get("/api/compliance").json()
    assert report["summary"]["controls"] == 15
    html = client.get("/reports/iso27001")
    assert html.status_code == 200 and "ISO/IEC 27001:2022" in html.text
    download = client.get("/reports/iso27001", params={"download": True})
    assert "attachment" in download.headers["content-disposition"]


def test_report_escapes_html_from_alert_data(client):
    # Titles come from external tools (an attacker can put markup in a username or user-agent).
    from datetime import datetime, timezone

    from app.models import Alert

    evil = Alert(source="wazuh", source_id="xss", timestamp=datetime.now(timezone.utc), host="web-01",
                 rule_id="wazuh:1", title="<script>alert(1)</script> login", category="malware", severity=100)
    evil.risk_score = 100
    client.app.state.db.upsert_alerts([evil])
    html = client.get("/reports/iso27001").text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_vendor_crud(client):
    seeded = client.get("/api/vendors").json()
    assert len(seeded["items"]) == 4 and len(seeded["questions"]) == 10
    created = client.post("/api/vendors", json={"name": "Acme", "service": "CRM", "data_sensitivity": "high",
                                                "access_level": "limited", "answers": {"mfa": True}}).json()
    assert created["tier"] in {"Critical", "High", "Medium", "Low"}
    assert client.delete(f"/api/vendors/{created['id']}").json()["ok"]
    assert client.post("/api/vendors", json={"name": "Bad", "data_sensitivity": "huge", "access_level": "none"}).status_code == 422


def test_dashboard_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "CyberUnify" in r.text
