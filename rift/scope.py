"""Alcance declarado, pertenencia de hosts y validacion de objetivos."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .util import read_json, utcnow, write_json

DEFAULT_PORTS = "80,443,8000-8100"
DEFAULT_ACTIONS = ("dns", "tls", "http", "port_scan", "crawl", "probe")
ALL_ACTIONS = ("dns", "tls", "http", "port_scan", "crawl", "content", "probe")
LOCAL_SUFFIXES = (".local", ".test", ".lab", ".internal", ".lan", ".localhost")


def parse_ports(value: str) -> set[int]:
    ports: set[int] = set()
    for chunk in str(value or "").replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"rango de puertos invalido: {chunk}")
            for port in range(start, end + 1):
                if not 1 <= port <= 65535:
                    raise ValueError(f"puerto fuera de rango: {port}")
                ports.add(port)
        else:
            port = int(chunk)
            if not 1 <= port <= 65535:
                raise ValueError(f"puerto fuera de rango: {port}")
            ports.add(port)
    if not ports:
        raise ValueError("El alcance no contiene puertos validos")
    return ports


def format_ports(ports: set[int]) -> str:
    ordered = sorted(ports)
    ranges: list[str] = []
    start = previous = ordered[0]
    for port in ordered[1:]:
        if port == previous + 1:
            previous = port
            continue
        ranges.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = port
    ranges.append(str(start) if start == previous else f"{start}-{previous}")
    return ",".join(ranges)


def split_target(value: str) -> tuple[str, int, str]:
    text = str(value).strip()
    if not text:
        raise ValueError("El objetivo esta vacio")
    if "://" not in text:
        text = "http://" + text
    parsed = urlparse(text)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        raise ValueError("Solo se admite http o https")
    host = (parsed.hostname or "").strip("[]").lower().rstrip(".")
    if not host:
        raise ValueError("El objetivo no contiene un host valido")
    port = parsed.port or (443 if scheme == "https" else 80)
    return host, port, scheme


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(str(value).strip("[]"))
        return True
    except ValueError:
        return False


def is_public_host(host: str) -> bool:
    candidate = str(host).strip("[]").lower().rstrip(".")
    if candidate in ("localhost", "127.0.0.1", "::1"):
        return False
    if candidate.endswith(LOCAL_SUFFIXES):
        return False
    if is_ip(candidate):
        return ipaddress.ip_address(candidate).is_global
    if "." not in candidate:
        return False
    return True


@dataclass
class Scope:
    name: str
    hosts: list[str]
    ports: str
    actions: list[str]
    authorized: bool = False
    attestation: str = ""
    allow_public: bool = False
    rate_limit: int = 240
    max_crawl_pages: int = 20
    probe_budget: int = 24
    notes: str = ""
    target: str = ""
    created_at: str = field(default_factory=utcnow)

    def __post_init__(self) -> None:
        self.hosts = [str(host).strip().lower().rstrip(".") for host in self.hosts if str(host).strip()]
        self.actions = [str(action).strip().lower() for action in self.actions]
        self.ports = format_ports(parse_ports(self.ports))
        self.rate_limit = max(10, int(self.rate_limit))
        self.probe_budget = max(1, min(200, int(self.probe_budget)))
        self.max_crawl_pages = max(1, min(200, int(self.max_crawl_pages)))

    @property
    def ports_set(self) -> set[int]:
        return parse_ports(self.ports)

    def host_allowed(self, host: str) -> bool:
        candidate = str(host).strip("[]").lower().rstrip(".")
        for entry in self.hosts:
            if entry == candidate:
                return True
            if entry.startswith("*."):
                base = entry[2:]
                if candidate.endswith("." + base):
                    return True
            if "/" in entry and is_ip(candidate):
                try:
                    if ipaddress.ip_address(candidate) in ipaddress.ip_network(entry, strict=False):
                        return True
                except ValueError:
                    continue
        return False

    def check_target(self, target: str) -> tuple[bool, str]:
        try:
            host, port, _ = split_target(target)
        except ValueError as exc:
            return False, str(exc)
        if not self.host_allowed(host):
            return False, f"host fuera de alcance: {host}"
        if port not in self.ports_set:
            return False, f"puerto fuera de alcance: {port}"
        if is_public_host(host) and not self.allow_public:
            return False, "objetivo publico bloqueado; habilita allow_public"
        if not self.authorized:
            return False, "falta autorizacion explicita en el workspace"
        return True, "ok"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "hosts": self.hosts,
            "ports": self.ports,
            "actions": self.actions,
            "authorized": self.authorized,
            "attestation": self.attestation,
            "allow_public": self.allow_public,
            "rate_limit": self.rate_limit,
            "max_crawl_pages": self.max_crawl_pages,
            "probe_budget": self.probe_budget,
            "notes": self.notes,
            "target": self.target,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        return cls(
            name=str(data.get("name") or "workspace"),
            hosts=list(data.get("hosts") or []),
            ports=str(data.get("ports") or DEFAULT_PORTS),
            actions=list(data.get("actions") or DEFAULT_ACTIONS),
            authorized=bool(data.get("authorized")),
            attestation=str(data.get("attestation") or ""),
            allow_public=bool(data.get("allow_public")),
            rate_limit=int(data.get("rate_limit") or 240),
            max_crawl_pages=int(data.get("max_crawl_pages") or 20),
            probe_budget=int(data.get("probe_budget") or 24),
            notes=str(data.get("notes") or ""),
            target=str(data.get("target") or ""),
            created_at=str(data.get("created_at") or utcnow()),
        )


def new_scope(
    name: str,
    hosts: list[str],
    ports: str = DEFAULT_PORTS,
    actions: list[str] | None = None,
    authorized: bool = False,
    attestation: str = "",
    allow_public: bool = False,
    rate_limit: int = 240,
    max_crawl_pages: int = 20,
    probe_budget: int = 24,
    notes: str = "",
    target: str = "",
) -> Scope:
    selected = list(actions or DEFAULT_ACTIONS)
    invalid = sorted(set(selected) - set(ALL_ACTIONS))
    if invalid:
        raise ValueError("Acciones desconocidas: " + ", ".join(invalid))
    if not selected:
        raise ValueError("El alcance debe incluir al menos una accion")
    if not hosts:
        raise ValueError("El alcance debe incluir al menos un host")
    return Scope(
        name=name,
        hosts=hosts,
        ports=ports,
        actions=selected,
        authorized=authorized,
        attestation=attestation,
        allow_public=allow_public,
        rate_limit=rate_limit,
        max_crawl_pages=max_crawl_pages,
        probe_budget=probe_budget,
        notes=notes,
        target=target,
    )


def save_scope(workspace, scope: Scope) -> None:
    write_json(workspace / "scope.json", scope.to_dict())


def load_scope(workspace) -> Scope:
    data = read_json(workspace / "scope.json")
    if not isinstance(data, dict):
        raise FileNotFoundError(f"No hay scope.json en {workspace}")
    return Scope.from_dict(data)
