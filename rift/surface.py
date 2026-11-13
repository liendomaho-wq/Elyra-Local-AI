"""Construccion de la superficie de ataque a partir del reconocimiento."""

from __future__ import annotations

from urllib.parse import urlsplit

from .util import endpoint_key, origin, utcnow

DEFAULT_SCHEMES = {443: "https", 8443: "https", 9443: "https"}


def _origin_for(host: str, port: int, scheme: str) -> str:
    chosen = DEFAULT_SCHEMES.get(port, scheme)
    display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default = (chosen == "https" and port == 443) or (chosen == "http" and port == 80)
    return f"{chosen}://{display_host}" + ("" if default else f":{port}")


def build(
    base_url: str,
    host: str,
    port: int,
    scheme: str,
    recon: dict,
    scope,
) -> dict:
    ports_data = recon.get("ports") or {}
    http_data = recon.get("http") or {}
    crawl_data = recon.get("crawl") or {}
    content_data = recon.get("content") or {}
    open_ports = list(ports_data.get("open") or [])
    if port not in open_ports:
        open_ports.append(port)
    ports = []
    for open_port in sorted(set(open_ports)):
        if open_port not in scope.ports_set:
            continue
        ports.append(
            {
                "port": open_port,
                "service": (ports_data.get("services") or {}).get(str(open_port), ""),
                "url": _origin_for(host, open_port, scheme),
                "primary": open_port == port,
            }
        )
    endpoints = list(crawl_data.get("endpoints") or [])
    if not any(item.get("url") == base_url for item in endpoints):
        endpoints.insert(
            0,
            {
                "url": base_url,
                "method": "GET",
                "status": http_data.get("status"),
                "content_type": (http_data.get("headers") or {}).get("content-type", ""),
                "title": http_data.get("title") or "",
                "has_params": bool(urlsplit(base_url).query),
                "source": "objetivo",
            },
        )
    parameters = []
    for item in crawl_data.get("parameters") or []:
        url = str(item.get("url") or "")
        if url and origin(url) == origin(base_url):
            parameters.append(item)
    for item in endpoints:
        url = str(item.get("url") or "")
        if "?" not in url:
            continue
        from urllib.parse import parse_qsl

        for name, value in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            parameters.append(
                {
                    "name": name,
                    "sample": value,
                    "endpoint": endpoint_key(item.get("method") or "GET", url),
                    "url": url,
                    "source": item.get("source") or "endpoint",
                }
            )
    unique_params = {}
    for item in parameters:
        unique_params.setdefault((item.get("endpoint"), item.get("name")), item)
    findings = [
        item
        for item in content_data.get("results") or []
        if item.get("matched")
    ]
    return {
        "target": base_url,
        "host": host,
        "port": port,
        "scheme": scheme,
        "origin": origin(base_url),
        "ports": ports,
        "technologies": recon.get("technologies") or [],
        "endpoints": endpoints,
        "parameters": list(unique_params.values()),
        "forms": crawl_data.get("forms") or [],
        "scripts": crawl_data.get("scripts") or [],
        "comments": crawl_data.get("comments") or [],
        "interesting_paths": findings,
        "tls": recon.get("tls") or {},
        "dns": recon.get("dns") or {},
        "crawl_errors": crawl_data.get("errors") or [],
        "built_at": utcnow(),
    }
