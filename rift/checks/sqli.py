"""Deteccion segura de errores SQL inducidos por comilla simple."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

SIGNATURES = (
    re.compile(r"you have an error in your sql syntax"),
    re.compile(r"unterminated quoted string"),
    re.compile(r"quoted string not properly terminated"),
    re.compile(r"sqlstate\[[a-z0-9]+\]"),
    re.compile(r"ora-\d{4,5}"),
    re.compile(r"postgresql.{0,40}error"),
    re.compile(r"sqlite.{0,40}error"),
    re.compile(r"microsoft ole db.{0,40}error"),
    re.compile(r"odbc sql server driver"),
    re.compile(r"syntax error at or near"),
)


def _with_param(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = [(key, value if key == name else original) for key, original in parse_qsl(parsed.query, keep_blank_values=True)]
    if not any(key == name for key, _ in pairs):
        pairs.append((name, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), ""))


def _signature(text: str) -> str:
    lowered = text.lower()
    for pattern in SIGNATURES:
        match = pattern.search(lowered)
        if match:
            return match.group(0)
    return ""


def run(ctx, **_):
    findings = []
    tested: set[tuple[str, str]] = set()
    baseline_cache: dict[str, str] = {}
    for item in (ctx.surface.get("parameters") or [])[:6]:
        if ctx.remaining_probes() < 2:
            break
        endpoint = str(item.get("endpoint") or item.get("url") or ctx.base_url)
        name = str(item.get("name") or "")
        url = str(item.get("url") or ctx.base_url)
        if not name or (endpoint, name) in tested:
            continue
        tested.add((endpoint, name))
        if url not in baseline_cache:
            ctx.consume_probe()
            baseline = ctx.fetch(url)
            baseline_cache[url] = str(baseline.get("body_excerpt") or "").lower()
        baseline = baseline_cache[url]
        payload = f"{item.get('sample') or '1'}'"
        candidate = _with_param(url, name, payload)
        ctx.consume_probe()
        result = ctx.fetch(candidate)
        if result.get("error"):
            continue
        signature = _signature(str(result.get("body_excerpt") or ""))
        if signature and signature not in baseline:
            findings.append(
                ctx.finding(
                    f"Posible inyeccion SQL por error en parametro {name}",
                    "high",
                    8.1,
                    "CWE-89",
                    "A03:2021 Injection",
                    "T1190",
                    "Una comilla simple provoco una firma de error de base de datos distinta a la linea base. Es evidencia de validacion, no se extrajeron datos.",
                    [
                        f"endpoint: {candidate}",
                        f"parametro: {name}",
                        f"firma: {signature}",
                        f"status: {result.get('status')}",
                    ],
                    "Usa consultas parametrizadas, valida tipos y evita concatenar entrada en SQL.",
                    confidence="media",
                    kind="activo",
                    poc=candidate,
                    vector="parametro de entrada",
                )
            )
    return findings
