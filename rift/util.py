"""Utilidades compartidas: tiempo, JSON, hashes, slugs y tokens."""

from __future__ import annotations

import datetime as _dt
import hashlib
import json
import re
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


def utcnow() -> str:
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    return now.isoformat().replace("+00:00", "Z")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value).strip()).strip("-").lower()
    return slug or "workspace"


def token(prefix: str = "rift", size: int = 8) -> str:
    return f"{prefix}{secrets.token_hex(size // 2)}"


def origin(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.hostname:
        return ""
    port = parsed.port
    default = 443 if parsed.scheme == "https" else 80
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    return f"{parsed.scheme}://{host}" + ("" if not port or port == default else f":{port}")


def endpoint_key(method: str, url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path or "/"
    query = "&".join(sorted(parsed.query.split("&"))) if parsed.query else ""
    return f"{method.upper()} {path}" + (f"?{query}" if query else "")


def human_bytes(value: int) -> str:
    amount = float(value)
    for unit in ("B", "KB", "MB", "GB"):
        if amount < 1024 or unit == "GB":
            return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{value} B"
