"""Dashboard local de solo lectura para artefactos RIFT."""

from __future__ import annotations

import html
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .config import resolve_workspace
from .models import SEVERITY_LABEL
from .report import build as build_report
from .util import read_json

COLORS = {"critical": "#8b1e3f", "high": "#d9480f", "medium": "#b7791f", "low": "#2b6cb0", "info": "#4a5568"}


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "RIFT-Dashboard"
    protocol_version = "HTTP/1.1"
    workspace: Path

    def log_message(self, format, *args):
        pass

    def _send(self, status: int, body: bytes, content_type: str):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status=200):
        self._send(status, json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/health":
            self._json({"ok": True, "workspace": self.workspace.name})
        elif path == "/api/results":
            self._json(read_json(self.workspace / "results.json", {"error": "sin resultados"}))
        elif path == "/api/surface":
            self._json(read_json(self.workspace / "surface.json", {"error": "sin superficie"}))
        elif path == "/api/plan":
            self._json(read_json(self.workspace / "plan.json", {"error": "sin plan"}))
        elif path == "/api/findings":
            self._json(read_json(self.workspace / "findings.json", []))
        elif path == "/api/audit":
            lines = []
            audit_path = self.workspace / "audit.jsonl"
            if audit_path.exists():
                lines = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self._json(lines)
        elif path in ("/report", "/report.html"):
            report_path = self.workspace / "report.html"
            if not report_path.exists():
                try:
                    build_report(self.workspace)
                except FileNotFoundError:
                    pass
            if report_path.exists():
                self._send(200, report_path.read_bytes(), "text/html; charset=utf-8")
            else:
                self._send(404, b"No hay informe. Ejecuta rift scan y rift report.", "text/plain; charset=utf-8")
        elif path == "/report.md":
            report_path = self.workspace / "report.md"
            if not report_path.exists():
                try:
                    build_report(self.workspace)
                except FileNotFoundError:
                    pass
            if report_path.exists():
                self._send(200, report_path.read_bytes(), "text/markdown; charset=utf-8")
            else:
                self._send(404, b"No hay informe. Ejecuta rift scan y rift report.", "text/plain; charset=utf-8")
        elif path == "/":
            self._dashboard()
        else:
            self._send(404, b"No encontrado", "text/plain; charset=utf-8")

    def _dashboard(self):
        results = read_json(self.workspace / "results.json", {}) or {}
        findings = read_json(self.workspace / "findings.json", []) or []
        plan = read_json(self.workspace / "plan.json", {}) or {}
        summary = results.get("summary") or {}
        counts = summary.get("counts") or {}
        esc = html.escape

        def rows(items):
            if not items:
                return '<tr><td colspan="4">Sin datos</td></tr>'
            output = []
            for finding in items:
                severity = str(finding.get("severity") or "info")
                output.append(
                    f"<tr><td><span class='badge' style='background:{COLORS.get(severity, '#4a5568')}'>"
                    f"{esc(SEVERITY_LABEL.get(severity, severity))}</span></td>"
                    f"<td>{esc(str(finding.get('title')))}</td><td><code>{esc(str(finding.get('id')))}</code></td>"
                    f"<td>{esc(str(finding.get('technique')))}</td></tr>"
                )
            return "".join(output)

        techniques = "".join(
            f"<li><code>{esc(str(item.get('id')))}</code> {esc(str(item.get('name')))} "
            f"<span class='muted'>({esc(str(item.get('priority')))})</span></li>"
            for item in plan.get("techniques") or []
        )
        body = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>RIFT Dashboard</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1a202c}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:.6rem;margin:1rem 0}}
.card{{border:1px solid #e2e8f0;border-radius:6px;padding:.6rem;text-align:center}}.card b{{display:block;font-size:1.5rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border-bottom:1px solid #e2e8f0;padding:.5rem;text-align:left;font-size:.93rem}}
.badge{{color:white;border-radius:4px;padding:.1rem .35rem;font-size:.72rem;text-transform:uppercase}}
.muted{{color:#718096}}nav a{{margin-right:1rem}}code{{font-family:ui-monospace,monospace}}
</style></head><body><h1>RIFT Dashboard</h1>
<p><b>Workspace:</b> {esc(self.workspace.name)} &middot; <b>Objetivo:</b> {esc(str(results.get('target') or 'sin scan'))}</p>
<nav><a href="/">Resumen</a><a href="/report">Informe</a><a href="/api/results">results.json</a>
<a href="/api/surface">surface.json</a><a href="/api/plan">plan.json</a><a href="/api/audit">audit.jsonl</a></nav>
<div class="cards">
<div class="card"><b>{counts.get('critical',0)}</b>Critica</div><div class="card"><b>{counts.get('high',0)}</b>Alta</div>
<div class="card"><b>{counts.get('medium',0)}</b>Media</div><div class="card"><b>{counts.get('low',0)}</b>Baja</div>
<div class="card"><b>{counts.get('info',0)}</b>Info</div><div class="card"><b>{esc(str(summary.get('risk') or '-'))}</b>Riesgo</div></div>
<h2>Hallazgos</h2><table><thead><tr><th>Severidad</th><th>Titulo</th><th>ID</th><th>ATT&amp;CK</th></tr></thead>
<tbody>{rows(findings)}</tbody></table>
<h2>Plan MITRE ATT&amp;CK</h2><ul>{techniques or '<li>Sin plan</li>'}</ul>
<p class="muted">Contenido local de solo lectura. No expongas este dashboard fuera de loopback.</p>
</body></html>"""
        self._send(200, body.encode("utf-8"), "text/html; charset=utf-8")


def create_server(workspace: str | Path | None = None, port: int = 8787, host: str = "127.0.0.1"):
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("El dashboard solo puede escuchar en loopback")
    path = Path(workspace) if workspace else resolve_workspace()
    handler = type("BoundDashboardHandler", (DashboardHandler,), {"workspace": path})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    return httpd


def serve(workspace: str | Path | None = None, port: int = 8787, host: str = "127.0.0.1"):
    httpd = create_server(workspace, port=port, host=host)
    print(f"RIFT Dashboard en http://{host}:{httpd.server_address[1]}", flush=True)
    print(f"Workspace: {httpd.RequestHandlerClass.workspace}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return httpd
