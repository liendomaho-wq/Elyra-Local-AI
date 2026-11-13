"""Escaneo TCP connect acotado sobre los puertos declarados."""

from __future__ import annotations

import asyncio

from ..util import utcnow

COMMON_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 2049, 2375, 3000, 3306, 3389, 5432, 5900, 6379, 8000,
    8008, 8009, 8080, 8081, 8082, 8443, 8888, 9000, 9090, 9200, 9443,
    10000, 27017,
)
SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker", 3000: "dev-server",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc",
    6379: "redis", 8000: "http-alt", 8008: "http-alt", 8080: "http-alt",
    8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "http-alt",
    9090: "http-alt", 9200: "elasticsearch", 9443: "https-alt",
    10000: "webmin", 27017: "mongodb",
}


async def _probe(host: str, port: int, timeout: float) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except (OSError, asyncio.TimeoutError):
        return False


async def _scan(host: str, ports: list[int], timeout: float, concurrency: int) -> list[int]:
    semaphore = asyncio.Semaphore(concurrency)

    async def limited(port):
        async with semaphore:
            return port if await _probe(host, port, timeout) else None

    results = await asyncio.gather(*(limited(port) for port in ports))
    return sorted(port for port in results if port)


def scan(host: str, ports: list[int], timeout: float = 1.3, concurrency: int = 80) -> dict:
    selected = sorted(set(int(port) for port in ports))
    if not selected:
        return {"host": host, "open": [], "services": {}, "scanned": 0, "error": None, "scanned_at": utcnow()}
    try:
        open_ports = asyncio.run(_scan(host, selected, timeout, concurrency))
        error = None
    except Exception as exc:
        open_ports, error = [], str(exc)
    return {
        "host": host,
        "open": open_ports,
        "services": {str(port): SERVICES.get(port, "desconocido") for port in open_ports},
        "scanned": len(selected),
        "error": error,
        "scanned_at": utcnow(),
    }
