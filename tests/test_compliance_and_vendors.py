from datetime import datetime, timezone

import pytest

from app.compliance import assess
from app.models import Alert
from app.vendors import QUESTIONS, assess_vendor


def alert(category, risk, sid="1"):
    a = Alert(source="t", source_id=sid, timestamp=datetime.now(timezone.utc), host="h", rule_id="r",
              title="t", category=category, severity=50)
    a.risk_score = risk
    return a


def controls(report):
    return {c["control"]: c for c in report["controls"]}


def test_open_critical_malware_puts_malware_control_at_risk():
    a = alert("malware", 95)
    c = controls(assess([a], {}, [{"source": "demo", "status": "ok"}]))
    assert c["A.8.7"]["status"] == "At risk"
    assert c["A.8.7"]["recommendation"]


def test_closing_the_alert_makes_the_control_effective():
    a = alert("malware", 95)
    c = controls(assess([a], {a.id: "closed"}, [{"source": "demo", "status": "ok"}]))
    assert c["A.8.7"]["status"] == "Effective"


def test_unmapped_control_is_no_evidence_not_a_pass():
    c = controls(assess([alert("malware", 20)], {}, []))
    assert c["A.8.8"]["status"] == "No evidence"


def test_failing_log_source_flags_logging_control():
    c = controls(assess([], {}, [{"source": "wazuh", "status": "error"}, {"source": "elastic", "status": "ok"}]))
    assert c["A.8.15"]["status"] == "Needs review"
    c = controls(assess([], {}, [{"source": "wazuh", "status": "error"}]))
    assert c["A.8.15"]["status"] == "At risk"


def test_posture_score_counts_only_assessed_controls():
    report = assess([alert("malware", 10)], {}, [{"source": "demo", "status": "ok"}])
    s = report["summary"]
    assert s["controls"] == s["at_risk"] + s["needs_review"] + s["effective"] + s["no_evidence"]
    assert 0 <= s["posture_score"] <= 100


ALL_YES = {key: True for key, _, _ in QUESTIONS}


def test_vendor_with_all_controls_keeps_some_residual_risk():
    v = assess_vendor("Bank", "Payments", "high", "privileged", ALL_YES)
    assert v["inherent_risk"] == 100
    assert v["control_score"] == 100
    assert v["residual_risk"] == pytest.approx(20)
    assert v["gaps"] == []


def test_vendor_with_no_controls_is_critical_and_lists_gaps():
    v = assess_vendor("Shadow IT", "Unknown", "high", "privileged", {})
    assert v["tier"] == "Critical"
    assert len(v["gaps"]) == len(QUESTIONS)
    assert v["gaps"][0].startswith("Holds a current ISO 27001")  # highest-weight gaps first


def test_low_impact_vendor_is_low_risk_even_without_controls():
    assert assess_vendor("Printer", "Printing", "low", "none", {})["tier"] == "Low"


def test_vendor_validation():
    with pytest.raises(ValueError):
        assess_vendor("X", "", "extreme", "none", {})
    with pytest.raises(ValueError):
        assess_vendor("  ", "", "low", "none", {})
