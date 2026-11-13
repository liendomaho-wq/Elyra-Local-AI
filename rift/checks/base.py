"""Contexto y utilidades compartidas por los checks."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Finding
from ..util import sha256_hex


@dataclass
class CheckContext:
    base_url: str
    host: str
    port: int
    scheme: str
    surface: dict
    fetch: object
    options: object
    probe_budget: int
    probes_used: int = 0
    findings: list[Finding] = field(default_factory=list)

    def remaining_probes(self) -> int:
        return max(0, self.probe_budget - self.probes_used)

    def consume_probe(self) -> bool:
        if self.probes_used >= self.probe_budget:
            return False
        self.probes_used += 1
        return True

    def finding(
        self,
        title: str,
        severity: str,
        cvss: float,
        cwe: str,
        owasp: str,
        technique: str,
        description: str,
        evidence: list[str] | None = None,
        remediation: str = "",
        confidence: str = "alta",
        kind: str = "pasivo",
        poc: str = "",
        vector: str = "",
    ) -> Finding:
        evidence = evidence or []
        digest = sha256_hex(
            "|".join([title, self.base_url, *evidence, poc, technique])
        )[:10].upper()
        return Finding(
            id=f"RIFT-{digest}",
            title=title,
            severity=severity,
            cvss=cvss,
            cwe=cwe,
            owasp=owasp,
            technique=technique,
            target=self.base_url,
            description=description,
            evidence=evidence,
            remediation=remediation,
            confidence=confidence,
            kind=kind,
            poc=poc,
            vector=vector,
        )


def header_map(response: dict) -> dict[str, str]:
    return {str(key).lower(): str(value) for key, value in (response.get("headers") or {}).items()}


def cookies_from(response: dict) -> list[str]:
    raw = response.get("set_cookie") or []
    if isinstance(raw, str):
        return [raw]
    return [str(item) for item in raw]


def body_of(response: dict) -> str:
    return str(response.get("body_excerpt") or "")


def content_type(response: dict) -> str:
    return str(header_map(response).get("content-type") or "").lower()


def is_html(response: dict) -> bool:
    return "html" in content_type(response) or "<html" in body_of(response).lower()
