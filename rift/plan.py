"""Plan de validacion ofensiva mapeado a MITRE ATT&CK."""

from __future__ import annotations

from collections import defaultdict

from .util import utcnow

BASE_TECHNIQUES = {
    "T1595": {
        "name": "Active Scanning",
        "tactic": "Reconocimiento",
        "reason": "Enumeracion controlada de endpoints, parametros y servicios del alcance.",
        "steps": [
            "Confirmar el alcance y la ventana de pruebas.",
            "Ejecutar recon HTTP/DNS/TLS con rate limit.",
            "Revisar la superficie y priorizar activos expuestos.",
        ],
    },
    "T1592": {
        "name": "Gather Victim Host Information",
        "tactic": "Reconocimiento",
        "reason": "Fingerprinting de tecnologias, cabeceras y versiones.",
        "steps": [
            "Correlacionar cabeceras, cookies y firmas del cuerpo.",
            "Registrar versiones solo como evidencia, sin explotarlas.",
        ],
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Descubrimiento",
        "reason": "Identificacion de puertos y servicios alcanzables dentro del alcance.",
        "steps": [
            "Validar que cada puerto pertenece al scope.",
            "Revisar servicios administrativos o de datos expuestos.",
        ],
    },
    "T1083": {
        "name": "File and Directory Discovery",
        "tactic": "Descubrimiento",
        "reason": "Busqueda opt-in de rutas y artefactos comunes.",
        "steps": [
            "Revisar las rutas coincidentes sin descargar datos sensibles.",
            "Confirmar si el contenido requiere autenticacion.",
        ],
    },
}


def _value(item, key, default=""):
    if isinstance(item, dict):
        return item.get(key, default)
    return getattr(item, key, default)


def _priority(findings: list) -> str:
    severities = {str(_value(item, "severity", "info")) for item in findings}
    if severities & {"critical", "high"}:
        return "alta"
    if "medium" in severities:
        return "media"
    return "baja"


def _add(selected, technique_id, findings, reason, steps):
    bucket = selected.setdefault(
        technique_id,
        {
            **BASE_TECHNIQUES.get(
                technique_id,
                {"name": technique_id, "tactic": "Validacion", "reason": reason, "steps": []},
            ),
            "reason": reason,
            "finding_ids": [],
            "priority": "baja",
        },
    )
    for finding in findings:
        identifier = _value(finding, "id")
        if identifier and identifier not in bucket["finding_ids"]:
            bucket["finding_ids"].append(identifier)
    if steps:
        bucket["steps"] = list(dict.fromkeys([*bucket.get("steps", []), *steps]))
    bucket["priority"] = _priority(findings) if findings else bucket["priority"]


def build(surface: dict, findings: list) -> dict:
    selected: dict[str, dict] = {}
    base_findings = []
    if surface.get("endpoints") or surface.get("parameters"):
        _add(
            selected,
            "T1595",
            base_findings,
            "Enumeracion controlada de endpoints, parametros y servicios del alcance.",
            [],
        )
    if surface.get("technologies"):
        _add(
            selected,
            "T1592",
            base_findings,
            "Huella tecnologica obtenida de cabeceras, cookies y firmas de respuesta.",
            [],
        )
    if surface.get("ports"):
        _add(
            selected,
            "T1046",
            base_findings,
            f"Se identificaron {len(surface.get('ports') or [])} puerto(s) en alcance.",
            [],
        )
    if surface.get("interesting_paths") or surface.get("comments"):
        _add(
            selected,
            "T1083",
            base_findings,
            "El descubrimiento opt-in encontro rutas o artefactos que requieren revision.",
            [],
        )
    for finding in findings:
        cwe = str(_value(finding, "cwe")).upper()
        kind = str(_value(finding, "kind"))
        technique = str(_value(finding, "technique"))
        title = str(_value(finding, "title")).lower()
        if "CWE-79" in cwe:
            _add(
                selected,
                "T1059.007",
                [finding],
                "Reflejo HTML controlado por entrada del usuario; validar ejecucion solo en el navegador de laboratorio.",
                ["Reproducir el reflejo con un marcador inerte.", "Confirmar el contexto de salida y el escaping."],
            )
        if "CWE-89" in cwe:
            _add(
                selected,
                "T1190",
                [finding],
                "La aplicacion devolvio errores de base de datos ante entrada manipulada.",
                ["Confirmar con una prueba booleana no destructiva.", "Revisar consultas parametrizadas."],
            )
        elif "CWE-601" in cwe:
            _add(
                selected,
                "T1566",
                [finding],
                "Redireccion externa controlable; riesgo de abuso en phishing.",
                ["Confirmar allowlist de destinos.", "Probar solo con rift.invalid."],
            )
        elif "CWE-942" in cwe:
            _add(
                selected,
                "T1190",
                [finding],
                "Configuracion CORS que permite lectura cruzada desde origenes no confiables.",
                ["Revisar allowlist de Origins.", "Comprobar si el endpoint devuelve datos autenticados."],
            )
        elif "CWE-538" in cwe or "CWE-548" in cwe:
            _add(
                selected,
                "T1552.001",
                [finding],
                "Posibles credenciales o datos sensibles en archivos accesibles.",
                ["Verificar acceso no autenticado sin descargar el contenido.", "Rotar cualquier secreto expuesto."],
            )
            _add(
                selected,
                "T1005",
                [finding],
                "Exposicion de datos almacenados localmente en el servidor.",
                ["Determinar el alcance del dato y notificar al propietario."],
            )
        elif "CWE-284" in cwe or "admin" in title:
            _add(
                selected,
                "T1078",
                [finding],
                "Panel o funcion administrativa accesible; revisar autenticacion y autorizacion.",
                ["Comprobar MFA y control de acceso por rol."],
            )
        if technique and technique.startswith("T"):
            _add(
                selected,
                technique,
                [finding],
                f"Hallazgo relacionado: {_value(finding, 'title')}.",
                [],
            )
        if kind == "activo":
            _add(
                selected,
                "T1595",
                [finding],
                "Validacion activa controlada sobre la superficie declarada.",
                [],
            )
    techniques = []
    for technique_id, data in selected.items():
        techniques.append(
            {
                "id": technique_id,
                "name": data.get("name") or technique_id,
                "tactic": data.get("tactic") or "Validacion",
                "reason": data.get("reason") or "",
                "priority": data.get("priority") or "baja",
                "finding_ids": data.get("finding_ids") or [],
                "steps": data.get("steps") or [],
            }
        )
    order = {"alta": 0, "media": 1, "baja": 2}
    techniques.sort(key=lambda item: (order.get(item["priority"], 3), item["id"]))
    by_tactic: dict[str, list[str]] = defaultdict(list)
    for item in techniques:
        by_tactic[item["tactic"]].append(item["id"])
    return {
        "target": surface.get("target"),
        "generated_at": utcnow(),
        "summary": {
            "techniques": len(techniques),
            "high_priority": sum(1 for item in techniques if item["priority"] == "alta"),
            "tactics": dict(by_tactic),
        },
        "techniques": techniques,
        "guardrails": [
            "Solo objetivos y acciones incluidos en el scope autorizado.",
            "Sin exploits destructivos, persistencia, movimiento lateral ni exfiltracion.",
            "Las validaciones activas usan marcadores inertes y destinos internos.",
            "Toda prueba debe ser revisada por una persona antes de ejecutarse.",
        ],
    }
