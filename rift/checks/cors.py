"""CORS permisivo: configuracion pasiva y reflejo de Origin controlado."""

from __future__ import annotations

from urllib.parse import urlsplit

from .base import header_map

TEST_ORIGIN = "https://rift.invalid"


def run(ctx, response=None, **_):
    findings = []
    checked = set()
    seen_headers = False
    endpoints = [
        str(item.get("url"))
        for item in ctx.surface.get("endpoints") or []
        if item.get("url")
    ]
    interesting = [
        item for item in endpoints
        if any(marker in item.lower() for marker in ("/api", "/admin", "/login", "graphql", "/user"))
    ]
    candidates = [ctx.base_url, *interesting, *endpoints]
    for candidate in candidates:
        if not candidate or candidate in checked:
            continue
        checked.add(candidate)
        if len(checked) > 5 or ctx.remaining_probes() < 1:
            break
        ctx.consume_probe()
        result = ctx.fetch(candidate, headers={"Origin": TEST_ORIGIN})
        headers = header_map(result)
        allow_origin = headers.get("access-control-allow-origin", "")
        allow_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
        if not allow_origin:
            continue
        seen_headers = True
        reflected = allow_origin.strip() == TEST_ORIGIN
        if reflected and allow_credentials:
            findings.append(
                ctx.finding(
                    "CORS refleja cualquier Origin con credenciales",
                    "high",
                    8.1,
                    "CWE-942",
                    "A05:2021 Security Misconfiguration",
                    "T1190",
                    "El servidor confia en un Origin arbitrario y permite credenciales; un sitio malicioso puede leer respuestas autenticadas.",
                    [
                        f"endpoint: {candidate}",
                        f"Access-Control-Allow-Origin: {allow_origin}",
                        "Access-Control-Allow-Credentials: true",
                    ],
                    "Valida una allowlist estricta de Origins y no reflejes el header recibido.",
                    confidence="alta",
                    kind="activo",
                    poc=f'curl -s -H "Origin: {TEST_ORIGIN}" -i "{candidate}"',
                )
            )
        elif reflected:
            findings.append(
                ctx.finding(
                    "CORS refleja un Origin arbitrario",
                    "medium",
                    5.3,
                    "CWE-942",
                    "A05:2021 Security Misconfiguration",
                    "T1190",
                    "El servidor acepta un Origin no confiable para lectura cruzada de respuestas.",
                    [
                        f"endpoint: {candidate}",
                        f"Access-Control-Allow-Origin: {allow_origin}",
                    ],
                    "Usa una allowlist de Origins confiables y evita el reflejo automatico.",
                    confidence="alta",
                    kind="activo",
                    poc=f'curl -s -H "Origin: {TEST_ORIGIN}" -i "{candidate}"',
                )
            )
        elif allow_origin.strip() == "*":
            findings.append(
                ctx.finding(
                    "CORS comodin en un endpoint",
                    "low",
                    3.1,
                    "CWE-942",
                    "A05:2021 Security Misconfiguration",
                    "T1190",
                    "El endpoint permite lectura desde cualquier Origin; si expone datos sensibles amplifica la fuga.",
                    [f"endpoint: {candidate}", "Access-Control-Allow-Origin: *"],
                    "Restringe CORS a origenes concretos si el endpoint devuelve datos de usuario.",
                    confidence="alta",
                    kind="pasivo",
                )
            )
        if seen_headers and len(findings) >= 3:
            break
    if not seen_headers and response:
        headers = header_map(response)
        if headers.get("access-control-allow-origin", "").strip() == "*":
            findings.append(
                ctx.finding(
                    "CORS comodin en la respuesta principal",
                    "low",
                    3.1,
                    "CWE-942",
                    "A05:2021 Security Misconfiguration",
                    "T1190",
                    "La respuesta permite lectura desde cualquier Origin.",
                    ["Access-Control-Allow-Origin: *"],
                    "Restringe CORS a origenes concretos si el endpoint devuelve datos de usuario.",
                )
            )
    return findings
