"""Cliente HTTP de reconocimiento con redirecciones limitadas al alcance."""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from urllib.parse import urljoin

from ..util import sha256_hex, utcnow

USER_AGENT = "RIFT/0.1 (authorized-pentest)"
MAX_BODY = 131072
EXCERPT = 8000
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class RedirectBlocked(Exception):
    """Una redireccion intento abandonar el alcance declarado."""


class _ScopedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, validator):
        super().__init__()
        self.validator = validator
        self.redirects: list[dict] = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        absolute = urljoin(req.full_url, newurl)
        if not self.validator(absolute):
            raise RedirectBlocked(f"redireccion bloqueada fuera de alcance: {absolute}")
        self.redirects.append({"status": code, "from": req.full_url, "to": absolute})
        return super().redirect_request(req, fp, code, msg, headers, absolute)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _unverified() -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _opener(allow_redirects: bool, unverified: bool, validator):
    handler = _ScopedRedirect(validator or (lambda candidate: True)) if allow_redirects else _NoRedirect()
    opener = urllib.request.build_opener(
        urllib.request.HTTPHandler(),
        urllib.request.HTTPSHandler(context=_unverified() if unverified else None),
        handler,
    )
    return opener, handler


def _title(text: str) -> str:
    match = TITLE_RE.search(text)
    return re.sub(r"\s+", " ", match.group(1)).strip()[:200] if match else ""


def _from_response(response, url: str, redirects: list[dict], verified) -> dict:
    raw = response.read(MAX_BODY)
    headers = {key.lower(): value for key, value in response.headers.items()}
    set_cookie = response.headers.get_all("Set-Cookie") or []
    try:
        text = raw.decode("utf-8", "replace")
    except Exception:
        text = ""
    final_url = response.geturl()
    return {
        "url": url,
        "final_url": final_url,
        "status": response.getcode(),
        "reason": getattr(response, "reason", ""),
        "headers": headers,
        "set_cookie": set_cookie,
        "redirects": redirects,
        "body_excerpt": text[:EXCERPT],
        "body_sha256": sha256_hex(raw),
        "body_bytes": len(raw),
        "title": _title(text),
        "tls_verified": verified if url.lower().startswith("https://") else None,
        "error": None,
        "fetched_at": utcnow(),
    }


def _error(url: str, exc: Exception, tls_verified=None) -> dict:
    return {
        "url": url,
        "final_url": url,
        "status": None,
        "reason": "",
        "headers": {},
        "set_cookie": [],
        "redirects": [],
        "body_excerpt": "",
        "body_sha256": None,
        "body_bytes": 0,
        "title": "",
        "tls_verified": tls_verified,
        "error": str(exc),
        "fetched_at": utcnow(),
    }


def _fetch_once(
    url: str,
    timeout: float,
    headers: dict,
    allow_redirects: bool,
    validator,
    unverified: bool,
    method: str,
    data: bytes | None = None,
) -> dict:
    request = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)
    opener, handler = _opener(allow_redirects, unverified, validator)
    try:
        with opener.open(request, timeout=timeout) as response:
            return _from_response(
                response,
                url,
                getattr(handler, "redirects", []),
                None if unverified else True,
            )
    except urllib.error.HTTPError as exc:
        try:
            return _from_response(
                exc,
                url,
                getattr(handler, "redirects", []),
                None if unverified else True,
            )
        finally:
            exc.close()
    except RedirectBlocked:
        raise
    except Exception:
        raise


def fetch(
    url: str,
    timeout: float = 8.0,
    headers: dict | None = None,
    allow_redirects: bool = True,
    validator=None,
    method: str = "GET",
    data: bytes | str | None = None,
) -> dict:
    request_headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/json,*/*;q=0.8",
    }
    if headers:
        request_headers.update({str(key): str(value) for key, value in headers.items()})
    body = data.encode("utf-8") if isinstance(data, str) else data
    try:
        return _fetch_once(
            url, timeout, request_headers, allow_redirects, validator, False, method, body
        )
    except RedirectBlocked as exc:
        return _error(url, exc)
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLCertVerificationError):
            try:
                result = _fetch_once(
                    url, timeout, request_headers, allow_redirects, validator, True, method, body
                )
                result["tls_verified"] = False
                return result
            except Exception as retry_exc:
                return _error(url, retry_exc, tls_verified=False)
        return _error(url, exc)
    except Exception as exc:
        return _error(url, exc)


def probe_options(
    url: str,
    timeout: float = 8.0,
    validator=None,
    headers: dict | None = None,
) -> dict:
    result = fetch(
        url,
        timeout=timeout,
        allow_redirects=False,
        validator=validator,
        method="OPTIONS",
        headers=headers,
    )
    allow = str((result.get("headers") or {}).get("allow") or "")
    methods = [item.strip().upper() for item in allow.split(",") if item.strip()]
    result["allow"] = allow
    result["methods"] = methods
    return result
