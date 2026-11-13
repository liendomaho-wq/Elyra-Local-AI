"""Open redirect controlado sin seguir el destino externo."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDIRECT_NAMES = {
    "next", "url", "redirect", "redirect_url", "return", "returnurl", "return_url",
    "continue", "dest", "destination", "target", "to", "out", "link", "callback",
}
PAYLOAD = "https://rift.invalid/poc"


def _with_param(url: str, name: str, value: str) -> str:
    parsed = urlsplit(url)
    pairs = [(key, value if key == name else original) for key, original in parse_qsl(parsed.query, keep_blank_values=True)]
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(pairs), ""))


def run(ctx, **_):
    findings = []
    tested = set()
    candidates = [
        item for item in (ctx.surface.get("parameters") or [])
        if str(item.get("name") or "").lower() in REDIRECT_NAMES
    ]
    for item in candidates[:3]:
        if ctx.remaining_probes() < 1:
            break
        name = str(item.get("name") or "").lower()
        url = str(item.get("url") or ctx.base_url)
        if (url, name) in tested or "?" not in url:
            continue
        tested.add((url, name))
        candidate = _with_param(url, name, PAYLOAD)
        ctx.consume_probe()
        result = ctx.fetch(candidate, allow_redirects=False)
        location = str((result.get("headers") or {}).get("location") or "")
        status = result.get("status")
        if status in (300, 301, 302, 303, 307, 308) and location:
            parsed = urlsplit(location)
            if (parsed.hostname or "").lower() == "rift.invalid":
                findings.append(
                    ctx.finding(
                        f"Open redirect en parametro {name}",
                        "medium",
                        6.1,
                        "CWE-601",
                        "A01:2021 Broken Access Control",
                        "T1566",
                        "La aplicacion redirige a un destino externo controlado por el usuario; puede abusarse en campanas de phishing.",
                        [
                            f"endpoint: {candidate}",
                            f"status: {status}",
                            f"Location: {location}",
                        ],
                        "Valida destinos contra una allowlist y usa rutas internas o identificadores firmados.",
                        confidence="alta",
                        kind="activo",
                        poc=candidate,
                        vector="parametro de redireccion",
                    )
                )
    return findings
