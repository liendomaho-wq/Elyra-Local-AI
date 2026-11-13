"""Exposicion de servicios de red sensibles."""

from __future__ import annotations

RISKY = {
    "ftp": ("medium", 5.3, "CWE-306"),
    "telnet": ("high", 7.5, "CWE-319"),
    "smtp": ("low", 3.7, "CWE-16"),
    "rpcbind": ("medium", 5.3, "CWE-16"),
    "netbios": ("medium", 5.3, "CWE-16"),
    "smb": ("medium", 5.9, "CWE-16"),
    "mssql": ("medium", 5.3, "CWE-306"),
    "oracle": ("medium", 5.3, "CWE-306"),
    "nfs": ("medium", 5.3, "CWE-16"),
    "docker": ("high", 8.6, "CWE-306"),
    "mysql": ("medium", 5.3, "CWE-306"),
    "rdp": ("medium", 5.9, "CWE-307"),
    "postgres": ("medium", 5.3, "CWE-306"),
    "vnc": ("high", 7.5, "CWE-306"),
    "redis": ("high", 8.1, "CWE-306"),
    "elasticsearch": ("medium", 6.5, "CWE-306"),
    "webmin": ("medium", 5.3, "CWE-16"),
    "mongodb": ("high", 8.1, "CWE-306"),
}


def run(ctx, ports=None, **_):
    if not ports or not ports.get("open"):
        return []
    findings = []
    for port in ports["open"]:
        service = str((ports.get("services") or {}).get(str(port), "desconocido"))
        if service not in RISKY:
            continue
        severity, cvss, cwe = RISKY[service]
        findings.append(
            ctx.finding(
                f"Servicio expuesto: {service} en {port}/tcp",
                severity,
                cvss,
                cwe,
                "A05:2021 Security Misconfiguration",
                "T1046",
                f"El servicio {service} responde en la red y amplia la superficie de ataque.",
                [f"puerto: {port}", f"servicio: {service}", "verificacion: TCP connect"],
                "Restringe el servicio a redes administrativas, exige autenticacion y mantenlo actualizado.",
            )
        )
    return findings
