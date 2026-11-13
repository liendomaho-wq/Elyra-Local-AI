"""Hallazgos de configuracion y validez TLS."""

from __future__ import annotations


def run(ctx, tls=None, **_):
    if not tls or not ctx.scheme == "https":
        return []
    findings = []
    host = f"{ctx.host}:{ctx.port}"
    if tls.get("error") and not tls.get("protocol"):
        findings.append(
            ctx.finding(
                "Error al establecer TLS",
                "medium",
                5.3,
                "CWE-295",
                "A02:2021 Cryptographic Failures",
                "T1040",
                "No fue posible completar una sesion TLS valida contra el servicio.",
                [f"objetivo: {host}", f"error: {tls.get('error')}"],
                "Revisa cadena, protocolo y configuracion del servicio TLS.",
                confidence="media",
            )
        )
        return findings
    if tls.get("verified") is False:
        if tls.get("self_signed"):
            title = "Certificado TLS autofirmado"
            description = "El certificado no encadena a una CA de confianza y permite suplantacion."
            cwe = "CWE-295"
        elif tls.get("hostname_mismatch"):
            title = "Certificado TLS no coincide con el host"
            description = "El nombre del certificado no valida el host consultado."
            cwe = "CWE-297"
        else:
            title = "Certificado TLS no verificado"
            description = "La cadena de certificacion no es valida para el cliente."
            cwe = "CWE-295"
        findings.append(
            ctx.finding(
                title,
                "medium",
                5.9,
                cwe,
                "A02:2021 Cryptographic Failures",
                "T1557",
                description,
                [f"objetivo: {host}", f"detalle: {tls.get('verify_error') or 'sin detalle'}"],
                "Usa un certificado emitido por una CA de confianza y valida la cadena completa.",
            )
        )
    cert = tls.get("cert") or {}
    days_left = cert.get("days_left")
    if isinstance(days_left, int):
        if days_left < 0:
            findings.append(
                ctx.finding(
                    "Certificado TLS expirado",
                    "high",
                    7.4,
                    "CWE-298",
                    "A02:2021 Cryptographic Failures",
                    "T1040",
                    "El certificado TLS esta vencido y obliga a los clientes a ignorar la validacion o interrumpir el servicio.",
                    [f"not_after: {cert.get('not_after')}", f"dias: {days_left}"],
                    "Renueva el certificado y automatiza la renovacion.",
                )
            )
        elif days_left < 30:
            findings.append(
                ctx.finding(
                    "Certificado TLS proximo a expirar",
                    "low",
                    3.1,
                    "CWE-298",
                    "A02:2021 Cryptographic Failures",
                    "T1040",
                    "El certificado expirara en menos de 30 dias.",
                    [f"not_after: {cert.get('not_after')}", f"dias: {days_left}"],
                    "Renueva el certificado antes de su expiracion.",
                )
            )
    protocol = str(tls.get("protocol") or "")
    if protocol in ("TLSv1", "TLSv1.0", "TLSv1.1", "SSLv2", "SSLv3"):
        findings.append(
            ctx.finding(
                f"Protocolo TLS obsoleto: {protocol}",
                "medium",
                5.9,
                "CWE-326",
                "A02:2021 Cryptographic Failures",
                "T1040",
                "El servicio acepta una version de TLS con debilidades conocidas.",
                [f"protocolo: {protocol}", f"cipher: {tls.get('cipher') or 'desconocido'}"],
                "Requiere TLS 1.2 o superior y deshabilita cifrados debiles.",
            )
        )
    return findings
