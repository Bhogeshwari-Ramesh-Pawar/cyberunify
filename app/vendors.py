"""Third-party (vendor) risk assessment.

  inherent risk  = how much damage the vendor *could* do  (data sensitivity × access level)
  control score  = weighted % of security controls the vendor has in place
  residual risk  = inherent × (1 − 0.8 × control score)

Even a vendor with every control keeps 20% of its inherent risk: controls
reduce risk, they never remove it.
"""

from __future__ import annotations

from typing import Any

SENSITIVITY = {"low": 1, "medium": 2, "high": 3}
ACCESS = {"none": 1, "limited": 2, "privileged": 3}

# (key, question, weight) — weights reflect how much each control reduces real-world risk.
QUESTIONS: list[tuple[str, str, int]] = [
    ("iso27001", "Holds a current ISO 27001 or SOC 2 Type II certification", 3),
    ("mfa", "Enforces MFA for all staff accessing our data or systems", 3),
    ("encryption_rest", "Encrypts our data at rest", 2),
    ("encryption_transit", "Encrypts data in transit (TLS 1.2+)", 2),
    ("incident_response", "Has a tested incident response plan", 2),
    ("breach_72h", "Commits to notify breaches within 72 hours (DPDPA / GDPR)", 3),
    ("data_residency", "Stores personal data in approved regions (data localisation)", 2),
    ("pentest", "Runs an independent penetration test at least yearly", 2),
    ("subprocessors", "Discloses all sub-processors handling our data", 1),
    ("access_reviews", "Reviews user access rights at least quarterly", 1),
]
QUESTION_TEXT = {key: text for key, text, _ in QUESTIONS}
MAX_WEIGHT = sum(w for _, _, w in QUESTIONS)


def tier(score: float) -> str:
    if score >= 60:
        return "Critical"
    if score >= 40:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


def assess_vendor(name: str, service: str, data_sensitivity: str, access_level: str, answers: dict[str, bool]) -> dict[str, Any]:
    if data_sensitivity not in SENSITIVITY:
        raise ValueError(f"data_sensitivity must be one of {list(SENSITIVITY)}")
    if access_level not in ACCESS:
        raise ValueError(f"access_level must be one of {list(ACCESS)}")
    name, service = name.strip(), service.strip()
    if not name:
        raise ValueError("name is required")

    inherent = SENSITIVITY[data_sensitivity] * ACCESS[access_level] / 9 * 100  # 11 … 100
    met = sum(w for key, _, w in QUESTIONS if answers.get(key))
    control_score = met / MAX_WEIGHT
    residual = inherent * (1 - 0.8 * control_score)
    gaps = [QUESTION_TEXT[key] for key, _, w in sorted(QUESTIONS, key=lambda q: -q[2]) if not answers.get(key)]
    return {
        "name": name,
        "service": service or "—",
        "data_sensitivity": data_sensitivity,
        "access_level": access_level,
        "answers": {key: bool(answers.get(key)) for key, _, _ in QUESTIONS},
        "inherent_risk": round(inherent, 1),
        "control_score": round(control_score * 100, 1),
        "residual_risk": round(residual, 1),
        "tier": tier(residual),
        "gaps": gaps,
    }


DEMO_VENDORS = [
    ("PayFlow Payments", "Payment processing", "high", "limited",
     {"iso27001": True, "mfa": True, "encryption_rest": True, "encryption_transit": True, "incident_response": True,
      "breach_72h": True, "data_residency": True, "pentest": True, "subprocessors": True, "access_reviews": True}),
    ("CloudHR Suite", "HR & payroll SaaS", "high", "privileged",
     {"iso27001": True, "encryption_transit": True, "encryption_rest": True, "subprocessors": True}),
    ("QuickPrint Services", "Office printing", "low", "none",
     {"encryption_transit": True}),
    ("DevOps Contractors Ltd", "Outsourced infrastructure support", "medium", "privileged",
     {"encryption_transit": True, "incident_response": True}),
]
