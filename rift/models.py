"""Modelo de hallazgos, severidades y resumen de riesgo."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_LABEL = {
    "critical": "Critica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "info": "Info",
}


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    cvss: float
    cwe: str
    owasp: str
    technique: str
    target: str
    description: str
    evidence: list[str] = field(default_factory=list)
    remediation: str = ""
    confidence: str = "alta"
    kind: str = "pasivo"
    poc: str = ""
    vector: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_ORDER.get(item.severity, 9),
            -item.cvss,
            item.id,
        ),
    )


def severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {key: 0 for key in SEVERITY_ORDER}
    for finding in findings:
        severity = str(finding.get("severity") or "info")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def global_risk(findings: list[dict]) -> str:
    if not findings:
        return "sin hallazgos"
    worst = min(
        findings,
        key=lambda item: SEVERITY_ORDER.get(str(item.get("severity") or "info"), 9),
    )
    return SEVERITY_LABEL.get(str(worst.get("severity") or "info"), "Info").lower()


def summarize(findings: list[Finding]) -> dict:
    data = [finding.to_dict() for finding in findings]
    return {
        "total": len(data),
        "counts": severity_counts(data),
        "risk": global_risk(data),
        "active": sum(1 for item in data if item.get("kind") == "activo"),
        "passive": sum(1 for item in data if item.get("kind") != "activo"),
    }
