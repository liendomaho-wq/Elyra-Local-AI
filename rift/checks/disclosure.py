"""Hallazgos derivados del descubrimiento de rutas y artefactos."""

from __future__ import annotations

MAPPING = {
    "env": ("critical", 9.1, "CWE-538", "variables de entorno expuestas"),
    "git": ("high", 7.5, "CWE-538", "metadatos del repositorio Git expuestos"),
    "sql-dump": ("high", 8.2, "CWE-538", "volcado de base de datos expuesto"),
    "backup-file": ("high", 7.5, "CWE-538", "archivo de respaldo expuesto"),
    "backup-dir": ("high", 7.5, "CWE-548", "listado de respaldos expuesto"),
    "config": ("high", 7.5, "CWE-538", "configuracion sensible expuesta"),
    "debug": ("medium", 6.5, "CWE-489", "modo de depuracion activo"),
    "phpinfo": ("medium", 5.3, "CWE-200", "pagina phpinfo expuesta"),
    "server-status": ("medium", 5.3, "CWE-200", "estado interno del servidor expuesto"),
    "actuator": ("medium", 6.5, "CWE-200", "endpoint de actuator expuesto"),
    "admin": ("low", 3.7, "CWE-284", "panel administrativo accesible"),
    "login": ("info", 0.0, "CWE-16", "formulario de acceso identificado"),
    "swagger": ("low", 3.7, "CWE-200", "documentacion Swagger expuesta"),
    "openapi": ("low", 3.7, "CWE-200", "especificacion OpenAPI expuesta"),
    "api": ("low", 3.7, "CWE-200", "interfaz de API expuesta"),
    "robots": ("info", 0.0, "CWE-200", "politica de rastreo expuesta"),
    "sitemap": ("info", 0.0, "CWE-200", "mapa del sitio expuesto"),
    "security-txt": ("info", 0.0, "CWE-16", "contacto de seguridad publicado"),
}

REMEDIATION = {
    "env": "Elimina el archivo del webroot, rota los secretos y bloquea dotfiles en el servidor.",
    "git": "Bloquea /.git/, elimina metadatos del webroot y rota credenciales historicas.",
    "sql-dump": "Elimina respaldos del webroot, restringe el acceso y rota credenciales.",
    "backup-file": "Mueve respaldos fuera del webroot y exige autenticacion.",
    "backup-dir": "Deshabilita listados de directorio y mueve respaldos fuera del webroot.",
    "config": "Mueve configuracion fuera del webroot y rota los secretos expuestos.",
    "debug": "Deshabilita el modo debug en produccion y revisa la fuga de trazas.",
    "phpinfo": "Elimina phpinfo() del entorno de produccion.",
    "server-status": "Restringe /server-status a localhost o deshabilitalo.",
    "actuator": "Restringe actuator a la red administrativa y deshabilita endpoints sensibles.",
    "admin": "Exige autenticacion multifactor y restringe el panel por red.",
    "login": "Aplica rate limiting, MFA y proteccion contra fuerza bruta.",
    "swagger": "Restringe la documentacion de API en produccion.",
    "openapi": "Restringe la especificacion de API en produccion.",
    "api": "Exige autenticacion y autorizacion en todos los endpoints de API.",
    "robots": "No dependas de robots.txt para ocultar rutas sensibles.",
    "sitemap": "Revisa que el mapa no exponga rutas administrativas.",
    "security-txt": "Manten el contacto de seguridad actualizado.",
}


def run(ctx, content=None, **_):
    if not content:
        return []
    findings = []
    for item in content.get("results") or []:
        if not item.get("matched"):
            continue
        kind = str(item.get("kind") or "")
        mapping = MAPPING.get(kind)
        if not mapping:
            continue
        severity, cvss, cwe, label = mapping
        findings.append(
            ctx.finding(
                f"Exposicion detectada: {label}",
                severity,
                cvss,
                cwe,
                "A05:2021 Security Misconfiguration",
                "T1083" if kind not in ("env", "git", "sql-dump", "backup-file") else "T1552.001",
                f"El objetivo responde con evidencia de {label}. Debe revisarse si el contenido es accesible sin autorizacion.",
                [
                    f"ruta: {item.get('path')}",
                    f"url final: {item.get('final_url') or item.get('url')}",
                    f"status: {item.get('status')}",
                    f"marcador: {item.get('marker') or 'coincidencia'}",
                ],
                REMEDIATION.get(kind, "Restringe el acceso al recurso y revisa su necesidad en produccion."),
                confidence="alta" if item.get("status") == 200 else "media",
                kind="activo" if kind in ("env", "git", "sql-dump", "backup-file", "backup-dir", "debug", "actuator") else "pasivo",
                poc=str(item.get("url") or ""),
            )
        )
    return findings
