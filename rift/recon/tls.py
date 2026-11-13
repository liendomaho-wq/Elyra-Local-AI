"""Inspeccion TLS: cadena, certificado, expiracion y protocolo."""

from __future__ import annotations

import socket
import ssl
import time

from ..util import utcnow


def _name(parts) -> str:
    values = []
    for item in parts or []:
        for key, value in item:
            if key in ("commonName", "organizationName"):
                values.append(f"{key}={value}")
    return ", ".join(values)


def _cert_info(cert: dict, host: str) -> dict:
    not_after = cert.get("notAfter")
    days_left = None
    if not_after:
        try:
            days_left = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
        except (TypeError, ValueError):
            pass
    san = [
        value
        for kind, value in cert.get("subjectAltName") or []
        if kind.lower() in ("dns", "ip address")
    ]
    common = ""
    for item in cert.get("subject") or []:
        for key, value in item:
            if key == "commonName":
                common = value
    hostname_ok = True
    matcher = getattr(ssl, "match_hostname", None)
    if host and san and matcher is not None:
        try:
            matcher(cert, host)
        except ssl.CertificateError:
            hostname_ok = False
    return {
        "subject": _name(cert.get("subject")),
        "issuer": _name(cert.get("issuer")),
        "common_name": common,
        "san": san,
        "not_before": cert.get("notBefore"),
        "not_after": not_after,
        "days_left": days_left,
        "hostname_matches": hostname_ok,
        "serial": cert.get("serialNumber"),
    }


def _handshake(host: str, port: int, timeout: float, unverified: bool) -> dict:
    context = ssl.create_default_context()
    if unverified:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            cert = tls.getpeercert() or {}
            cipher = tls.cipher()
            return {
                "protocol": tls.version(),
                "cipher": cipher[0] if cipher else "",
                "cert": _cert_info(cert, host) if cert else {},
            }


def inspect(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    data = {
        "host": host,
        "port": port,
        "verified": None,
        "protocol": "",
        "cipher": "",
        "cert": {},
        "days_left": None,
        "san": [],
        "self_signed": False,
        "hostname_mismatch": False,
        "verify_error": "",
        "error": None,
        "fetched_at": utcnow(),
    }
    try:
        result = _handshake(host, port, timeout, unverified=False)
        data.update(result)
        data["verified"] = True
        data["days_left"] = (data.get("cert") or {}).get("days_left")
        data["san"] = (data.get("cert") or {}).get("san") or []
        return data
    except ssl.SSLCertVerificationError as exc:
        data["verified"] = False
        data["verify_error"] = str(exc)
        lowered = str(exc).lower()
        data["self_signed"] = "self-signed" in lowered or "self signed" in lowered
        data["hostname_mismatch"] = "hostname mismatch" in lowered or "doesn't match" in lowered
        try:
            result = _handshake(host, port, timeout, unverified=True)
            data.update(result)
            data["days_left"] = (data.get("cert") or {}).get("days_left")
            data["san"] = (data.get("cert") or {}).get("san") or []
            data["hostname_mismatch"] = data["hostname_mismatch"] or not (
                data.get("cert") or {}
            ).get("hostname_matches", True)
        except Exception as retry_exc:
            data["error"] = f"{exc}; reintento: {retry_exc}"
        return data
    except Exception as exc:
        data["error"] = str(exc)
        return data
