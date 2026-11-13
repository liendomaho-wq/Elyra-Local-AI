"""Servidor de laboratorio vulnerable, solo para 127.0.0.1."""

from __future__ import annotations

import html
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

USERS = [
    {"id": 1, "name": "Ana", "role": "admin"},
    {"id": 2, "name": "Luis", "role": "analyst"},
]
PRODUCTS = {1: "Analizador de paquetes", 2: "Sensor de laboratorio"}


class LabHandler(BaseHTTPRequestHandler):
    server_version = "RiftLab"
    sys_version = "1.0"
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        self.server.requests.append(format % args)

    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8", headers=None):
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        if self.path.split("?")[0] in ("/", "/login"):
            self.send_header("Set-Cookie", "rift_session=demo-session; Path=/")
        self.end_headers()
        self.wfile.write(payload)

    def _options(self, origin: str | None):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, TRACE, PUT, DELETE")
        self.send_header("Content-Length", "0")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_OPTIONS(self):
        self._options(self.headers.get("Origin"))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path or "/"
        query = parse_qs(parsed.query, keep_blank_values=True)
        if path == "/":
            body = """<!doctype html><html><head><title>RIFT Lab</title></head><body>
<h1>RIFT Lab</h1>
<p>Objetivo de practicas autorizado. No contiene datos reales.</p>
<ul>
<li><a href="/search?q=hello">Buscar</a></li>
<li><a href="/product?id=1">Producto</a></li>
<li><a href="/redirect?next=/">Redireccion</a></li>
<li><a href="/api/users?id=1">API de usuarios</a></li>
<li><a href="/login">Acceso</a></li>
<li><a href="/admin">Administracion</a></li>
</ul>
<form method="GET" action="/search"><input name="q" value="hola"><button>Buscar</button></form>
</body></html>"""
            self._send(200, body)
        elif path == "/search":
            value = (query.get("q") or [""])[0]
            body = f"<html><head><title>Busqueda</title></head><body><h1>Resultados</h1><p>Consulta: {value}</p></body></html>"
            self._send(200, body)
        elif path == "/product":
            value = (query.get("id") or ["1"])[0]
            if "'" in value or '"' in value:
                self._send(
                    500,
                    "<html><body><h1>Error interno</h1><pre>sqlite3.OperationalError: near \"'\": syntax error</pre></body></html>",
                )
            else:
                try:
                    product_id = int(value)
                except ValueError:
                    product_id = 0
                product = PRODUCTS.get(product_id)
                if product:
                    body = f"<html><head><title>Producto</title></head><body><h1>{html.escape(product)}</h1></body></html>"
                    self._send(200, body)
                else:
                    self._send(404, "<html><body>Producto no encontrado</body></html>")
        elif path == "/redirect":
            target = (query.get("next") or ["/"])[0]
            self._send(302, "", headers={"Location": target})
        elif path == "/api/users":
            payload = json.dumps({"users": USERS, "requested": (query.get("id") or ["1"])[0]})
            headers = {"Access-Control-Allow-Origin": "*"}
            origin = self.headers.get("Origin")
            if origin:
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
            self._send(200, payload, "application/json", headers)
        elif path == "/admin":
            self._send(
                200,
                "<html><head><title>Admin</title></head><body><h1>Admin panel</h1><p>Dashboard sin autenticacion.</p></body></html>",
            )
        elif path == "/debug":
            self._send(
                200,
                "<html><head><title>Debug</title></head><body><h1>Debug mode</h1><pre>Traceback (most recent call last): demo stack trace</pre></body></html>",
            )
        elif path == "/.env":
            self._send(
                200,
                "APP_ENV=lab\nDEMO_API_KEY=not-a-real-secret\nDATABASE_URL=sqlite:///lab.db\n",
                "text/plain",
            )
        elif path == "/backup/db.sql":
            self._send(
                200,
                "CREATE TABLE users (id INT, name TEXT);\nINSERT INTO users VALUES (1, 'demo');\n",
                "text/plain",
            )
        elif path == "/backup/":
            self._send(200, "<html><body><h1>Index of /backup/</h1><a href='db.sql'>db.sql</a></body></html>")
        elif path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\nDisallow: /debug\n", "text/plain")
        elif path == "/swagger.json":
            self._send(200, json.dumps({"openapi": "3.0.0", "paths": {"/api/users": {}}}), "application/json")
        elif path == "/login":
            self._send(
                200,
                """<html><head><title>Login</title></head><body>
<h1>Acceso</h1><form method="POST" action="/login">
<input type="text" name="username" value="demo">
<input type="password" name="password" value="">
<button>Entrar</button></form></body></html>""",
            )
        elif path == "/health":
            self._send(200, json.dumps({"ok": True, "lab": True}), "application/json")
        else:
            self._send(404, "<html><body>No encontrado</body></html>")

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        form = parse_qs(raw, keep_blank_values=True)
        if parsed.path == "/login":
            username = (form.get("username") or [""])[0]
            body = f"<html><head><title>Login</title></head><body><p>Usuario: {username}</p><p>Credenciales de laboratorio aceptadas.</p></body></html>"
            self._send(200, body)
        elif parsed.path == "/api/users":
            self._send(200, json.dumps({"ok": True, "users": USERS}), "application/json")
        else:
            self._send(404, "<html><body>No encontrado</body></html>")


class LabServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        if host not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("El laboratorio solo puede escuchar en loopback")
        self.httpd = ThreadingHTTPServer((host, port), LabHandler)
        self.httpd.daemon_threads = True
        self.httpd.requests = []
        self.thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return self.httpd.server_address[0]

    @property
    def port(self) -> int:
        return int(self.httpd.server_address[1])

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"

    @property
    def requests(self) -> list[str]:
        return self.httpd.requests

    def start(self):
        if self.thread and self.thread.is_alive():
            return self
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        if self.thread:
            self.thread.join(timeout=2)
        return self

    def __enter__(self):
        return self.start()

    def __exit__(self, exc_type, exc, tb):
        self.stop()
        return False


def serve(port: int = 8765):
    server = LabServer(port=port)
    print(f"RIFT Range en {server.url}", flush=True)
    print("Solo loopback. Pulsa Ctrl+C para detener.", flush=True)
    try:
        server.httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()
    return server
