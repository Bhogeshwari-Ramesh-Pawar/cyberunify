"""ISO/IEC 27001:2022 Annex A control assessment, driven by SOC alert evidence.

Each alert category maps to the Annex A controls it provides evidence about.
A control's status reflects the worst *unresolved* alert mapped to it:

  At risk       open critical/high alerts — the control is failing in practice
  Needs review  open medium alerts
  Effective     only low/resolved alerts — the control is monitored and holding
  No evidence   nothing mapped yet (not a pass: you can't show it works)

Logging (A.8.15) and monitoring (A.8.16) are assessed from data-source health.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .models import Alert

CONTROLS: dict[str, str] = {
    "A.5.7": "Threat intelligence",
    "A.5.17": "Authentication information",
    "A.5.19": "Information security in supplier relationships",
    "A.5.24": "Incident management planning and preparation",
    "A.5.26": "Response to information security incidents",
    "A.8.2": "Privileged access rights",
    "A.8.5": "Secure authentication",
    "A.8.7": "Protection against malware",
    "A.8.8": "Management of technical vulnerabilities",
    "A.8.9": "Configuration management",
    "A.8.12": "Data leakage prevention",
    "A.8.15": "Logging",
    "A.8.16": "Monitoring activities",
    "A.8.20": "Networks security",
    "A.8.1": "User endpoint devices",
}

CATEGORY_CONTROLS: dict[str, list[str]] = {
    "authentication": ["A.5.17", "A.8.5"],
    "malware": ["A.8.7", "A.8.1"],
    "network_intrusion": ["A.8.20", "A.5.7"],
    "reconnaissance": ["A.8.20", "A.5.7"],
    "vulnerability": ["A.8.8"],
    "integrity": ["A.8.9"],
    "privilege_escalation": ["A.8.2"],
    "data_exfiltration": ["A.8.12", "A.8.20"],
    "policy": ["A.8.1"],
}

RECOMMENDATIONS: dict[str, str] = {
    "A.5.17": "Rotate credentials for targeted accounts and enforce a strong password policy.",
    "A.8.5": "Enforce MFA and key-based SSH; add fail2ban or account lockout for repeated failures.",
    "A.8.7": "Isolate infected endpoints, re-image them, and confirm EDR coverage on every device.",
    "A.8.1": "Enforce endpoint hardening and device-control policy (USB, unapproved software).",
    "A.8.20": "Block offending IPs at the firewall/WAF and review exposed services and segmentation.",
    "A.5.7": "Feed observed IOCs (IPs, hashes, domains) into threat-intel blocklists.",
    "A.8.8": "Patch the listed CVEs within SLA, prioritising internet-facing assets.",
    "A.8.9": "Review unexpected file changes against approved change records; restore baselines.",
    "A.8.2": "Review sudo/admin rights, remove unneeded privileges and alert on new admin sessions.",
    "A.8.12": "Investigate outbound transfers, enable DLP/egress filtering and DNS tunnelling detection.",
    "A.8.15": "Restore failing log sources so security events are captured continuously.",
    "A.8.16": "Triage open high-risk alerts and keep detection rules tuned.",
    "A.5.26": "Run the incident response playbook for open critical alerts and record lessons learned.",
    "A.5.19": "Remediate supplier control gaps or add compensating controls in the contract.",
}

STATUS_ORDER = {"At risk": 0, "Needs review": 1, "No evidence": 2, "Effective": 3}
RESOLVED = {"closed", "false_positive"}


@dataclass
class ControlResult:
    control: str
    name: str
    status: str
    alerts: int = 0
    open_alerts: int = 0
    max_risk: float = 0.0
    evidence: list[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict:
        return self.__dict__.copy()


def _status_for(open_levels: Counter) -> str:
    if open_levels.get("critical") or open_levels.get("high"):
        return "At risk"
    if open_levels.get("medium"):
        return "Needs review"
    return "Effective"


def assess(
    alerts: list[Alert],
    statuses: dict[str, str],
    source_health: list[dict],
    vendors: list[dict] | None = None,
) -> dict:
    vendors = vendors or []
    by_control: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        for control in CATEGORY_CONTROLS.get(a.category, []):
            by_control[control].append(a)

    results: list[ControlResult] = []
    for control, name in CONTROLS.items():
        items = by_control.get(control, [])
        open_items = [a for a in items if statuses.get(a.id, "open") not in RESOLVED]
        res = ControlResult(control, name, "No evidence", alerts=len(items), open_alerts=len(open_items))
        if items:
            res.status = _status_for(Counter(a.risk_level for a in open_items))
            res.max_risk = max(a.risk_score for a in items)
            # Top three *distinct* findings (the same rule firing 40 times is one finding).
            seen: dict[tuple[str, str], tuple[Alert, int]] = {}
            for a in sorted(open_items or items, key=lambda a: a.risk_score, reverse=True):
                key = (a.host, a.title)
                first_seen, n = seen.get(key, (a, 0))
                seen[key] = (first_seen, n + 1)
            res.evidence = [
                f"{a.host}: {a.title} (risk {a.risk_score:.0f}{f', ×{n}' if n > 1 else ''})"
                for a, n in list(seen.values())[:3]
            ]
        results.append(res)

    by_id = {r.control: r for r in results}

    # A.8.15 Logging: are the data sources actually delivering?
    logging_ctl = by_id["A.8.15"]
    failing = [s["source"] for s in source_health if s.get("status") != "ok"]
    healthy = [s["source"] for s in source_health if s.get("status") == "ok"]
    logging_ctl.alerts = len(alerts)
    if not source_health:
        logging_ctl.status = "No evidence"
    elif failing:
        logging_ctl.status = "At risk" if not healthy else "Needs review"
        logging_ctl.evidence = [f"Failing source: {s}" for s in failing]
    else:
        logging_ctl.status = "Effective"
        logging_ctl.evidence = [f"{len(healthy)} source(s) ingesting: {', '.join(healthy)}"]

    # A.8.16 Monitoring and A.5.26 Response: is anything high-risk left untriaged?
    open_high = [a for a in alerts if statuses.get(a.id, "open") == "open" and a.risk_level in ("critical", "high")]
    for key in ("A.8.16", "A.5.26"):
        ctl = by_id[key]
        ctl.alerts = len(alerts)
        ctl.open_alerts = len(open_high)
        ctl.status = ("At risk" if open_high else "Effective") if alerts else "No evidence"
        ctl.max_risk = max((a.risk_score for a in open_high), default=0.0)
        ctl.evidence = [f"{len(open_high)} critical/high alert(s) awaiting triage"] if open_high else ["All high-risk alerts triaged"]

    # A.5.24 Incident planning: evidenced by having alerting + triage workflow in place.
    planning = by_id["A.5.24"]
    planning.status = "Effective" if alerts else "No evidence"
    planning.evidence = ["Alert triage workflow in use (open → acknowledged → closed)"] if alerts else []

    # A.5.19 Supplier relationships: from the third-party risk module.
    supplier = by_id["A.5.19"]
    if vendors:
        worst = max(vendors, key=lambda v: v["residual_risk"])
        tiers = Counter(v["tier"] for v in vendors)
        supplier.alerts = len(vendors)
        supplier.max_risk = worst["residual_risk"]
        supplier.status = "At risk" if tiers.get("Critical") or tiers.get("High") else (
            "Needs review" if tiers.get("Medium") else "Effective")
        supplier.evidence = [f"{v['name']}: {v['tier']} residual risk ({v['residual_risk']:.0f})"
                             for v in sorted(vendors, key=lambda v: v["residual_risk"], reverse=True)[:3]]

    for r in results:
        if r.status in ("At risk", "Needs review"):
            r.recommendation = RECOMMENDATIONS.get(r.control, "")

    results.sort(key=lambda r: (STATUS_ORDER[r.status], r.control))
    counts = Counter(r.status for r in results)
    assessed = len(results) - counts.get("No evidence", 0)
    return {
        "framework": "ISO/IEC 27001:2022 Annex A",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "controls": len(results),
            "at_risk": counts.get("At risk", 0),
            "needs_review": counts.get("Needs review", 0),
            "effective": counts.get("Effective", 0),
            "no_evidence": counts.get("No evidence", 0),
            "posture_score": round(100 * counts.get("Effective", 0) / assessed) if assessed else 0,
        },
        "controls": [r.to_dict() for r in results],
    }
