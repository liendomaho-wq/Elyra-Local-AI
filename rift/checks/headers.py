"""Cabeceras de seguridad y divulgacion de tecnologia."""

from __future__ import annotations

import re

from .base import header_map

VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)?")


def _missing(ctx, headers, name, label, severity, cvss, cwe, owasp, technique, description, remediation):
    if name in headers:
        return None
    return ctx.finding(
        f"Falta {label}",
        severity,
        cvss,
        cwe,
        owasp,
        technique,
        description,
        [f"cabecera ausente: {name}", f"objetivo: {ctx.base_url}"],
        remediation,
        kind="pasivo",
    )


def run(ctx, response=None, **_):
    if not response or response.get("error"):
        return []
    headers = header_map(response)
    findings = []
    checks = (
        (
            "content-security-policy",
            "Content-Security-Policy",
            "medium",
            4.3,
            "CWE-693",
            "A05:2021 Security Misconfiguration",
            "T1190",
            "Sin CSP el navegador no limita origenes de scripts, estilos ni frames, lo que amplifica el impacto de una inyeccion HTML.",
            "Define una CSP restrictiva y elimina 'unsafe-inline'/'unsafe-eval'.",
        ),
        (
            "x-content-type-options",
            "X-Content-Type-Options",
            "low",
            3.1,
            "CWE-16",
            "A05:2021 Security Misconfiguration",
            "T1190",
            "La ausencia de nosniff permite que el navegador interprete respuestas con un tipo distinto al declarado.",
            "Envia X-Content-Type-Options: nosniff en todas las respuestas.",
        ),
        (
            "x-frame-options",
            "X-Frame-Options",
            "low",
            3.1,
            "CWE-1021",
            "A05:2021 Security Misconfiguration",
            "T1189",
            "Sin proteccion de framing la aplicacion puede ser embebida y utilizada en clickjacking.",
            "Envia X-Frame-Options: DENY o SAMEORIGIN, o usa frame-ancestors en CSP.",
        ),
        (
            "referrer-policy",
            "Referrer-Policy",
            "info",
            0.0,
            "CWE-200",
            "A05:2021 Security Misconfiguration",
            "T1592",
            "La politica de referer por defecto puede filtrar rutas y parametros a terceros.",
            "Envia Referrer-Policy: strict-origin-when-cross-origin o no-referrer.",
        ),
        (
            "permissions-policy",
            "Permissions-Policy",
            "info",
            0.0,
            "CWE-16",
            "A05:2021 Security Misconfiguration",
            "T1592",
            "No se limita el acceso a APIs sensibles del navegador como camara, microfono o geolocalizacion.",
            "Define Permissions-Policy segun las capacidades reales de la aplicacion.",
        ),
    )
    for name, label, severity, cvss, cwe, owasp, technique, description, remediation in checks:
        finding = _missing(
            ctx, headers, name, label, severity, cvss, cwe, owasp, technique, description, remediation
        )
        if finding:
            findings.append(finding)
    if ctx.scheme == "https" and "strict-transport-security" not in headers:
        findings.append(
            ctx.finding(
                "Falta Strict-Transport-Security",
                "low",
                3.1,
                "CWE-319",
                "A02:2021 Cryptographic Failures",
                "T1040",
                "Sin HSTS el cliente puede ser degradado a HTTP en futuras conexiones.",
                ["cabecera ausente: strict-transport-security"],
                "Envia Strict-Transport-Security con max-age suficiente y includeSubDomains.",
            )
        )
    server = headers.get("server", "")
    if server and VERSION_RE.search(server):
        findings.append(
            ctx.finding(
                "Version de servidor expuesta",
                "low",
                3.7,
                "CWE-200",
                "A05:2021 Security Misconfiguration",
                "T1592",
                "La cabecera Server revela producto y version, facilitando la seleccion de exploits conocidos.",
                [f"Server: {server}"],
                "Reduce la cabecera Server a un valor generico y manten el software actualizado.",
            )
        )
    powered = headers.get("x-powered-by", "")
    if powered:
        findings.append(
            ctx.finding(
                "Tecnologia expuesta en X-Powered-By",
                "low",
                3.7,
                "CWE-200",
                "A05:2021 Security Misconfiguration",
                "T1592",
                "La cabecera X-Powered-By facilita el fingerprinting del stack.",
                [f"X-Powered-By: {powered}"],
                "Elimina la cabecera X-Powered-By en el servidor o proxy.",
            )
        )
    aspnet = headers.get("x-aspnet-version", "")
    if aspnet:
        findings.append(
            ctx.finding(
                "Version de ASP.NET expuesta",
                "low",
                3.7,
                "CWE-200",
                "A05:2021 Security Misconfiguration",
                "T1592",
                "La version exacta de ASP.NET reduce el coste de identificar vulnerabilidades conocidas.",
                [f"X-AspNet-Version: {aspnet}"],
                "Deshabilita la cabecera X-AspNet-Version.",
            )
        )
    return findings
