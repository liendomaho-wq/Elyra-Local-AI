"""Huella tecnologica heuristica a partir de cabeceras, cuerpo y puertos."""

from __future__ import annotations

SIGNATURES = (
    ("wordpress", "WordPress", ("wp-content", "wp-includes", "wordpress")),
    ("drupal", "Drupal", ("drupal-settings-json", "sites/default/files")),
    ("joomla", "Joomla", ("/media/system/js/", "joomla")),
    ("nextjs", "Next.js", ("__next_data__", "_next/static")),
    ("react", "React", ("data-reactroot", "react-dom", "react.production")),
    ("angular", "Angular", ("ng-version", "angular.min.js")),
    ("vue", "Vue.js", ("vue.js", "data-v-")),
    ("django", "Django", ("csrfmiddlewaretoken", "django")),
    ("laravel", "Laravel", ("laravel_session", "laravel")),
    ("spring", "Spring", ("whitelabel error page", "springframework")),
    ("express", "Express", ("x-powered-by: express",)),
    ("flask", "Flask", ("werkzeug", "flask")),
    ("php", "PHP", ("php/", "phpsessid")),
    ("nginx", "Nginx", ("server: nginx",)),
    ("apache", "Apache", ("server: apache",)),
    ("iis", "IIS", ("server: microsoft-iis",)),
    ("tomcat", "Tomcat", ("coyote", "tomcat")),
    ("swagger", "Swagger UI", ("swagger-ui", "swagger.json")),
)


def detect(http_data: dict | None, ports_data: dict | None = None) -> list[dict]:
    if not http_data:
        return []
    headers = http_data.get("headers") or {}
    body = str(http_data.get("body_excerpt") or "").lower()
    cookies = " ".join(http_data.get("set_cookie") or []).lower()
    combined = "\n".join(
        [
            f"server: {headers.get('server', '')}".lower(),
            f"x-powered-by: {headers.get('x-powered-by', '')}".lower(),
            body,
            cookies,
        ]
    )
    technologies = []
    server = str(headers.get("server") or "").strip()
    if server:
        technologies.append({"name": server, "evidence": "cabecera Server"})
    powered = str(headers.get("x-powered-by") or "").strip()
    if powered:
        technologies.append({"name": powered, "evidence": "cabecera X-Powered-By"})
    for _key, name, needles in SIGNATURES:
        if any(needle in combined for needle in needles):
            if not any(item["name"].lower() == name.lower() for item in technologies):
                technologies.append({"name": name, "evidence": "firma en respuesta"})
    for port in (ports_data or {}).get("open") or []:
        service = (ports_data or {}).get("services", {}).get(str(port), "")
        if service and service not in ("http", "http-alt", "https", "https-alt"):
            technologies.append({"name": f"{service} (puerto {port})", "evidence": "puerto abierto"})
    return technologies
