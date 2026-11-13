"""Descubrimiento opt-in de rutas y artefactos expuestos."""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin

from ..util import utcnow

PATHS = (
    ("/.env", "env"),
    ("/.git/HEAD", "git"),
    ("/robots.txt", "robots"),
    ("/sitemap.xml", "sitemap"),
    ("/.well-known/security.txt", "security-txt"),
    ("/backup/", "backup-dir"),
    ("/backup.zip", "backup-file"),
    ("/db.sql", "sql-dump"),
    ("/config.php", "config"),
    ("/debug", "debug"),
    ("/admin", "admin"),
    ("/login", "login"),
    ("/phpinfo.php", "phpinfo"),
    ("/server-status", "server-status"),
    ("/actuator/env", "actuator"),
    ("/swagger.json", "swagger"),
    ("/openapi.json", "openapi"),
    ("/api", "api"),
)


def _json_flags(text: str) -> str:
    try:
        data = json.loads(text)
    except ValueError:
        return ""
    if isinstance(data, dict):
        keys = {str(key).lower() for key in data}
        if "openapi" in keys or "swagger" in keys or "paths" in keys:
            return "api-spec"
        if "propertysources" in keys or "activeprofiles" in keys:
            return "actuator"
    return ""


def classify(kind: str, result: dict) -> tuple[bool, str]:
    if result.get("error") or result.get("status") not in (200, 401, 403):
        return False, ""
    status = int(result.get("status") or 0)
    body = str(result.get("body_excerpt") or "")
    lowered = body.lower()
    ctype = str((result.get("headers") or {}).get("content-type") or "").lower()
    if kind == "env":
        matched = bool(re.search(r"(?m)^\s*[A-Z][A-Z0-9_]{2,}\s*=\s*\S+", body))
        return matched, "variables clave=valor"
    if kind == "git":
        matched = body.startswith("ref:") or "refs/heads" in body[:200]
        return matched, "referencia de repositorio Git"
    if kind == "robots":
        return "disallow:" in lowered, "politica de rastreo"
    if kind == "sitemap":
        return "<urlset" in lowered, "mapa de URLs"
    if kind == "security-txt":
        return status == 200 and "contact:" in lowered, "contacto de seguridad"
    if kind == "backup-dir":
        return "index of /" in lowered, "listado de respaldos"
    if kind == "backup-file":
        return body.startswith("PK") or "zip" in ctype, "archivo comprimido"
    if kind == "sql-dump":
        return bool(re.search(r"insert into|create table", lowered)), "volcado SQL"
    if kind == "config":
        return status == 200 and ("<?php" in lowered or "password" in lowered), "configuracion PHP"
    if kind == "debug":
        return any(
            marker in lowered
            for marker in ("traceback (most recent call last)", "debug mode", "werkzeug debugger", "stack trace")
        ), "interfaz de depuracion"
    if kind == "admin":
        return status == 200 and (
            ("admin" in lowered and ("panel" in lowered or "login" in lowered))
            or "dashboard" in lowered
        ), "panel administrativo"
    if kind == "login":
        return status == 200 and ('type="password"' in lowered or "type='password'" in lowered), "formulario de acceso"
    if kind == "phpinfo":
        return "php version" in lowered and "phpinfo" in lowered, "phpinfo"
    if kind == "server-status":
        return "apache server status" in lowered, "estado del servidor"
    if kind == "actuator":
        return _json_flags(body) == "actuator", "actuator/env"
    if kind in ("swagger", "openapi"):
        return _json_flags(body) == "api-spec", "especificacion de API"
    if kind == "api":
        return status == 200 and ("json" in ctype or body.lstrip().startswith(("{", "["))), "API expuesta"
    return False, ""


def discover(base_url: str, fetch, timeout: float = 6.0) -> dict:
    results = []
    for path, kind in PATHS:
        url = urljoin(base_url, path)
        result = fetch(url, timeout=timeout)
        matched, marker = classify(kind, result)
        results.append(
            {
                "path": path,
                "kind": kind,
                "url": url,
                "final_url": result.get("final_url"),
                "status": result.get("status"),
                "content_type": (result.get("headers") or {}).get("content-type", ""),
                "bytes": result.get("body_bytes", 0),
                "matched": matched,
                "marker": marker,
                "body_excerpt": str(result.get("body_excerpt") or "")[:1200],
                "error": result.get("error"),
            }
        )
    return {"base_url": base_url, "results": results, "probed_at": utcnow()}
