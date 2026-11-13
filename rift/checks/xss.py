"""Validacion segura de reflejo HTML; no ejecuta JavaScript."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ..util import sha256_hex
from .base import is_html

FORM_TYPES = {"text", "search", "email", "url", "tel", "password", "textarea", "number"}


def _marker(ctx, name: str, endpoint: str) -> str:
    return "riftx" + sha256_hex(f"{ctx.base_url}|{name}|{endpoint}")[:8]


def _replace_param(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = [(key, value if key == name else original) for key, original in parse_qsl(parsed.query, keep_blank_values=True)]
    if not any(key == name for key, _ in pairs):
        pairs.append((name, value))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), ""))


def _snippet(body: str, marker: str) -> str:
    tag = f"<{marker}>"
    index = body.find(tag)
    if index < 0:
        return ""
    start = max(0, index - 70)
    end = min(len(body), index + len(tag) + 70)
    return " ".join(body[start:end].split())


def _finding(ctx, method, endpoint, name, poc, snippet):
    return ctx.finding(
        f"Reflejo HTML sin escapar en parametro {name}",
        "medium",
        6.1,
        "CWE-79",
        "A03:2021 Injection",
        "T1059.007",
        "Un valor controlado por el usuario se refleja como HTML sin escapar. No se ejecuto JavaScript; la evidencia demuestra inyeccion potencial que requiere validacion manual.",
        [
            f"metodo: {method}",
            f"endpoint: {endpoint}",
            f"parametro: {name}",
            f"contexto: {snippet}",
        ],
        "Escapa la salida segun el contexto, valida la entrada y aplica una CSP estricta.",
        confidence="media",
        kind="activo",
        poc=poc,
        vector="parametro de entrada",
    )


def run(ctx, **_):
    findings = []
    tested: set[tuple[str, str]] = set()
    parameters = list(ctx.surface.get("parameters") or [])[:5]
    for item in parameters:
        if ctx.remaining_probes() < 1:
            break
        endpoint = str(item.get("endpoint") or item.get("url") or ctx.base_url)
        name = str(item.get("name") or "")
        url = str(item.get("url") or ctx.base_url)
        if not name or (endpoint, name) in tested:
            continue
        tested.add((endpoint, name))
        marker = _marker(ctx, name, endpoint)
        payload = f'"><{marker}>'
        candidate = _replace_param(url, name, payload)
        ctx.consume_probe()
        result = ctx.fetch(candidate)
        if result.get("error") or not is_html(result):
            continue
        if f"<{marker}>" in str(result.get("body_excerpt") or ""):
            findings.append(
                _finding(
                    ctx,
                    "GET",
                    candidate,
                    name,
                    candidate,
                    _snippet(str(result.get("body_excerpt") or ""), marker),
                )
            )
    for form in (ctx.surface.get("forms") or [])[:2]:
        if str(form.get("method") or "").upper() != "POST" or ctx.remaining_probes() < 1:
            continue
        action = str(form.get("action") or ctx.base_url)
        fields = [
            field for field in form.get("inputs") or []
            if field.get("name") and str(field.get("type") or "text").lower() in FORM_TYPES
        ]
        for field in fields[:1]:
            if ctx.remaining_probes() < 1:
                break
            name = str(field["name"])
            marker = _marker(ctx, name, action)
            payload = f'"><{marker}>'
            data = {}
            for other in form.get("inputs") or []:
                other_name = str(other.get("name") or "")
                if other_name:
                    data[other_name] = str(other.get("value") or "")
            data[name] = payload
            encoded = urlencode(data)
            ctx.consume_probe()
            result = ctx.fetch(
                action,
                method="POST",
                data=encoded,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if result.get("error") or not is_html(result):
                continue
            if f"<{marker}>" in str(result.get("body_excerpt") or ""):
                findings.append(
                    _finding(
                        ctx,
                        "POST",
                        action,
                        name,
                        f"curl -s -X POST '{action}' --data '{encoded}'",
                        _snippet(str(result.get("body_excerpt") or ""), marker),
                    )
                )
    return findings
