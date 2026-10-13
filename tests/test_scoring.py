from datetime import datetime, timedelta, timezone

from app.models import Alert, risk_level
from app.scoring import anomaly_z_scores, host_risk, rarity_signals, score_alerts, score_one

NOW = datetime(2026, 10, 13, 12, tzinfo=timezone.utc)


def make(severity=50, host="h1", rule="r1", tactic=None, minutes_ago=0, i=0):
    return Alert(source="test", source_id=f"{rule}-{host}-{i}-{minutes_ago}", timestamp=NOW - timedelta(minutes=minutes_ago),
                 host=host, rule_id=rule, title=rule, category="other", severity=severity, mitre_tactic=tactic)


def test_score_never_exceeds_100_even_with_every_boost():
    risk, _ = score_one(100, "exfiltration", 2.0, 0.2, 10)
    assert risk == 100.0


def test_no_context_means_risk_equals_severity():
    risk, factors = score_one(40, None, 1.0, 0.0, 0.0)
    assert risk == 40.0
    assert factors["context_boost"] == 0


def test_context_lifts_high_severity_more_than_low():
    low_gain = score_one(20, "exfiltration", 1.6, 0.2, 3)[0] - 20
    high_gain = score_one(70, "exfiltration", 1.6, 0.2, 3)[0] - 70
    assert high_gain > low_gain  # noise stays noise


def test_dangerous_tactic_outranks_recon_at_equal_severity():
    assert score_one(60, "exfiltration", 1.0, 0, 0)[0] > score_one(60, None, 1.0, 0, 0)[0] > score_one(60, "reconnaissance", 1.0, 0, 0)[0]


def test_low_value_asset_dampens():
    assert score_one(60, None, 0.6, 0, 0)[0] < 60


def test_rarity_rare_rule_scores_higher():
    alerts = [make(rule="noisy", i=i) for i in range(20)] + [make(rule="rare")]
    r = rarity_signals(alerts)
    assert r["rare"] > r["noisy"] >= 0


def test_anomaly_detects_burst_hour():
    quiet = [make(host="h1", minutes_ago=60 * h + 1, i=h) for h in range(1, 24)]  # ~1 alert/hour
    burst = [make(host="h1", minutes_ago=5, i=100 + i) for i in range(15)]
    z = anomaly_z_scores(quiet + burst)
    burst_hour = (NOW - timedelta(minutes=5)).replace(minute=0, second=0, microsecond=0)
    assert z[("h1", burst_hour)] > 3


def test_score_alerts_records_explainable_factors():
    alerts = score_alerts([make(severity=67, tactic="credential access")], {"h1": 1.5})
    f = alerts[0].risk_factors
    assert f["tactic"] == 0.2 and f["asset"] == 0.25
    assert alerts[0].risk_score > 67


def test_host_risk_orders_hosts_and_does_not_saturate_on_noise():
    alerts = [make(severity=95, host="breached", rule="malware")]
    alerts += [make(severity=20, host="noisy", rule="pam", i=i) for i in range(50)]
    for a in alerts:
        a.risk_score = a.severity
    rows = host_risk(alerts)
    assert [r["host"] for r in rows] == ["breached", "noisy"]
    assert risk_level(rows[1]["risk_score"]) == "low"  # 50 low alerts don't make a host critical
