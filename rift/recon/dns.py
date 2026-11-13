"""Enumeracion DNS via DoH con fallback al resolver del sistema."""

from __future__ import annotations

import json
import os
import socket
import urllib.parse
import urllib.request

from ..util import utcnow

DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"
RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT")


def _doh(host: str, record_type: str, timeout: float) -> list[str]:
    query = urllib.parse.urlencode({"name": host, "type": record_type})
    request = urllib.request.Request(
        f"{DOH_ENDPOINT}?{query}",
        headers={"Accept": "application/dns-json", "User-Agent": "RIFT/0.1"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read(65536).decode("utf-8", "replace"))
    records = []
    for answer in payload.get("Answer") or []:
        data = str(answer.get("data") or "").strip()
        if data:
            records.append(data)
    return records


def _system(host: str) -> dict[str, list[str]]:
    records: dict[str, list[str]] = {"A": [], "AAAA": []}
    try:
        for item in socket.getaddrinfo(host, None):
            family, address = item[0], item[4][0]
            if family == socket.AF_INET and address not in records["A"]:
                records["A"].append(address)
            elif family == socket.AF_INET6 and address not in records["AAAA"]:
                records["AAAA"].append(address)
    except OSError:
        pass
    return records


def lookup(host: str, timeout: float = 5.0) -> dict:
    data = {
        "host": host,
        "source": "",
        "records": {},
        "ptr": [],
        "error": None,
        "fetched_at": utcnow(),
    }
    use_doh = os.environ.get("RIFT_DOH", "1") != "0"
    errors = []
    if use_doh:
        data["source"] = "doh"
        for record_type in RECORD_TYPES:
            try:
                values = _doh(host, record_type, timeout)
            except Exception as exc:
                errors.append(f"{record_type}: {exc}")
                continue
            if values:
                data["records"][record_type] = values
    if not data["records"]:
        data["source"] = "sistema"
        system_records = _system(host)
        data["records"] = {key: value for key, value in system_records.items() if value}
    try:
        hostname, aliases, addresses = socket.gethostbyaddr(host)
        data["ptr"] = sorted({hostname, *aliases, *addresses})
    except OSError:
        pass
    if errors and not data["records"]:
        data["error"] = "; ".join(errors[:3])
    return data
