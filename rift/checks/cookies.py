"""Atributos de seguridad en cookies de sesion."""

from __future__ import annotations

import re

from .base import cookies_from

NAME_RE = re.compile(r"^\s*([^=;\s]+)\s*=")
SESSION_HINTS = ("sess", "session", "auth", "token", "jwt", "sid", "remember")


def _parse(raw: str) -> tuple[str, set[str]]:
    parts = [item.strip() for item in raw.split(";") if item.strip()]
    name_match = NAME_RE.match(raw)
    name = name_match.group(1) if name_match else "cookie"
    attributes = {item.lower() for item in parts[1:]}
    return name, attributes


def run(ctx, response=None, **_):
    if not response or response.get("error"):
        return []
    findings = []
    for raw in cookies_from(response):
        name, attributes = _parse(raw)
        lowered = name.lower()
        is_session = any(hint in lowered for hint in SESSION_HINTS)
        if "httponly" not in attributes and is_session:
            findings.append(
                ctx.finding(
                    f"Cookie de sesion sin HttpOnly: {name}",
                    "medium",
                    5.3,
                    "CWE-1004",
                    "A05:2021 Security Misconfiguration",
                    "T1059.007",
                    "Una cookie de sesion accesible desde JavaScript puede ser robada mediante XSS.",
                    [f"cookie: {name}", "atributo ausente: HttpOnly"],
                    "Marca las cookies de sesion con HttpOnly y evita almacenar secretos en JavaScript.",
                )
            )
        if ctx.scheme == "https" and "secure" not in attributes:
            findings.append(
                ctx.finding(
                    f"Cookie sin atributo Secure: {name}",
                    "low",
                    3.1,
                    "CWE-614",
                    "A02:2021 Cryptographic Failures",
                    "T1040",
                    "La cookie puede enviarse por HTTP y quedar expuesta a interceptacion.",
                    [f"cookie: {name}", "atributo ausente: Secure"],
                    "Marca todas las cookies con Secure cuando la aplicacion usa HTTPS.",
                )
            )
        if "samesite" not in attributes:
            findings.append(
                ctx.finding(
                    f"Cookie sin SameSite: {name}",
                    "low",
                    3.5,
                    "CWE-1275",
                    "A01:2021 Broken Access Control",
                    "T1189",
                    "Sin SameSite el navegador puede adjuntar la cookie en peticiones cruzadas, habilitando CSRF.",
                    [f"cookie: {name}", "atributo ausente: SameSite"],
                    "Usa SameSite=Lax o Strict salvo que la cookie requiera contexto cruzado.",
                )
            )
    return findings
