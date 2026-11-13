"""Orquestador de reconocimiento, validacion y evidencias."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Callable

from .. import __version__
from ..audit import AuditLog
from ..checks import REGISTRY
from ..checks.base import CheckContext
from ..config import resolve_workspace
from ..models import Finding, sort_findings, summarize
from ..plan import build as build_plan
from ..policy import PolicyDenied, PolicyEngine
from ..scope import Scope, is_ip, load_scope, split_target
from ..surface import build as build_surface
from ..util import utcnow, write_json
from . import content, crawl, dns, fingerprint, http, ports, tls

ACTIVE_CHECKS = {"xss", "sqli", "redirect", "cors", "methods"}
DEFAULT_CHECK_ORDER = (
    "headers", "cookies", "tls", "ports", "disclosure",
    "cors", "methods", "xss", "sqli", "redirect",
)


def _error_result(url: str, message: str) -> dict:
    return {
        "url": url,
        "final_url": url,
        "status": None,
        "reason": "",
        "headers": {},
        "set_cookie": [],
        "redirects": [],
        "body_excerpt": "",
        "body_sha256": None,
        "body_bytes": 0,
        "title": "",
        "tls_verified": None,
        "error": message,
        "fetched_at": utcnow(),
    }


class Runner:
    def __init__(self, workspace: Path, scope: Scope, progress: Callable[[str], None] | None = None):
        self.workspace = Path(workspace)
        self.scope = scope
        self.progress = progress or (lambda message: None)
        self.audit = AuditLog(self.workspace / "audit.jsonl")
        self.policy = PolicyEngine(scope, self.audit, workspace=str(self.workspace))
        self.workspace_name = self.workspace.name

    def emit(self, message: str) -> None:
        self.progress(message)

    def fetch_for(self, action: str):
        def fetcher(url: str, timeout: float = 6.0, **kwargs):
            decision = self.policy.check(action, url)
            if not decision.allowed:
                return _error_result(url, f"politica: {decision.reason}")
            validator = lambda candidate: self.policy.check(  # noqa: E731
                action, candidate, record=False
            ).allowed
            try:
                return http.fetch(url, timeout=timeout, validator=validator, **kwargs)
            except PolicyDenied as exc:
                return _error_result(url, f"politica: {exc}")

        return fetcher

    def options_for(self, action: str = "probe"):
        def options(url: str):
            decision = self.policy.check(action, url)
            if not decision.allowed:
                return _error_result(url, f"politica: {decision.reason}")
            validator = lambda candidate: self.policy.check(  # noqa: E731
                action, candidate, record=False
            ).allowed
            return http.probe_options(url, validator=validator)

        return options

    def _target_base(self, target: str) -> tuple[str, str, int, str]:
        host, port, scheme = split_target(target)
        display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
        base = f"{scheme}://{display_host}" + ("" if default else f":{port}")
        return host, base, port, scheme

    def recon(self, target: str) -> dict:
        host, base, port, scheme = self._target_base(target)
        self.emit(f"Reconocimiento de {base}")
        raw: dict = {
            "target": base,
            "host": host,
            "port": port,
            "scheme": scheme,
            "started_at": utcnow(),
        }
        base_action = "http" if "http" in self.scope.actions else next(
            (action for action in ("crawl", "probe") if action in self.scope.actions), "http"
        )
        self.emit("Obteniendo respuesta HTTP base")
        raw["http"] = self.fetch_for(base_action)(base)
        if not raw["http"].get("error"):
            self.emit("Analizando cabeceras y tecnologias")
        if "tls" in self.scope.actions and (scheme == "https" or port in (443, 8443, 9443)):
            self.emit("Inspeccionando TLS")
            raw["tls"] = tls.inspect(host, port)
        if "dns" in self.scope.actions and not is_ip(host):
            self.emit("Enumerando DNS")
            raw["dns"] = dns.lookup(host)
        if "port_scan" in self.scope.actions:
            selected = sorted(self.scope.ports_set)
            if len(selected) > 512:
                selected = [candidate for candidate in ports.COMMON_PORTS if candidate in self.scope.ports_set]
                if port not in selected:
                    selected.append(port)
                self.emit(f"Limite de puertos aplicado: {len(selected)} puertos comunes en alcance")
            decision = self.policy.check(
                "port_scan",
                base,
                details={"ports": len(selected), "mode": "scope"},
            )
            if decision.allowed:
                self.emit(f"Escaneando {len(selected)} puerto(s)")
                raw["ports"] = ports.scan(host, selected)
            else:
                raw["ports"] = {"host": host, "open": [], "services": {}, "scanned": 0, "error": decision.reason}
        if "crawl" in self.scope.actions and not raw["http"].get("error"):
            self.emit(f"Crawling hasta {self.scope.max_crawl_pages} paginas")
            raw["crawl"] = crawl.crawl(
                base,
                self.fetch_for("crawl"),
                max_pages=self.scope.max_crawl_pages,
            )
        if "content" in self.scope.actions and not raw["http"].get("error"):
            self.emit("Descubrimiento opt-in de rutas")
            raw["content"] = content.discover(base, self.fetch_for("content"))
        raw["technologies"] = fingerprint.detect(raw.get("http"), raw.get("ports"))
        raw["finished_at"] = utcnow()
        return raw

    def scan(
        self,
        target: str,
        checks: list[str] | None = None,
        actions: list[str] | None = None,
    ) -> dict:
        allowed, reason = self.scope.check_target(target)
        if not allowed:
            self.audit.record(
                action="scan", target=target, decision="deny", reason=reason, workspace=str(self.workspace)
            )
            raise PolicyDenied(reason)
        selected_actions = actions or self.scope.actions
        active = bool(set(selected_actions) & ACTIVE_CHECKS) or "probe" in selected_actions
        names = checks or list(DEFAULT_CHECK_ORDER)
        invalid = [name for name in names if name not in REGISTRY]
        if invalid:
            raise ValueError("Checks desconocidos: " + ", ".join(invalid))
        self.audit.record(
            action="scan.start",
            target=target,
            decision="allow",
            reason="inicio de evaluacion",
            details={"checks": names, "actions": selected_actions},
            workspace=str(self.workspace),
        )
        recon = self.recon(target)
        surface = build_surface(
            recon["target"], recon["host"], recon["port"], recon["scheme"], recon, self.scope
        )
        ctx = CheckContext(
            base_url=recon["target"],
            host=recon["host"],
            port=recon["port"],
            scheme=recon["scheme"],
            surface=surface,
            fetch=self.fetch_for("probe"),
            options=self.options_for("probe"),
            probe_budget=self.scope.probe_budget,
        )
        findings: list[Finding] = []
        check_stats: dict[str, int] = {}
        for name in names:
            if name in ACTIVE_CHECKS and not active:
                check_stats[name] = -1
                continue
            self.emit(f"Check: {name}")
            kwargs = {
                "response": recon.get("http"),
                "tls": recon.get("tls"),
                "ports": recon.get("ports"),
                "content": recon.get("content"),
            }
            try:
                produced = REGISTRY[name](ctx, **kwargs)
            except Exception as exc:
                self.audit.record(
                    action="check.error",
                    target=target,
                    decision="deny",
                    reason=str(exc),
                    details={"check": name},
                    workspace=str(self.workspace),
                )
                produced = []
            findings.extend(produced or [])
            check_stats[name] = len(produced or [])
        unique: dict[str, Finding] = {}
        for finding in findings:
            unique.setdefault(finding.id, finding)
        ordered = sort_findings(list(unique.values()))
        plan = build_plan(surface, ordered)
        data = self._persist(target, recon, surface, ordered, plan, check_stats, ctx.probes_used)
        self.audit.record(
            action="scan.finish",
            target=target,
            decision="allow",
            reason="evaluacion completada",
            details={"findings": len(ordered), "probes": ctx.probes_used},
            workspace=str(self.workspace),
        )
        data["audit"] = self.audit.verify()
        write_json(self.workspace / "results.json", data)
        return data

    def _persist(self, target, recon, surface, findings, plan, check_stats, probes_used):
        write_json(self.workspace / "recon.json", recon)
        write_json(self.workspace / "surface.json", surface)
        finding_data = [finding.to_dict() for finding in findings]
        write_json(self.workspace / "findings.json", finding_data)
        write_json(self.workspace / "plan.json", plan)
        artifacts = {
            "recon": "recon.json",
            "surface": "surface.json",
            "findings": "findings.json",
            "plan": "plan.json",
            "results": "results.json",
            "audit": "audit.jsonl",
        }
        return {
            "tool": "RIFT",
            "version": __version__,
            "workspace": self.workspace.name,
            "target": target,
            "generated_at": utcnow(),
            "actions": self.scope.actions,
            "probes_used": probes_used,
            "probe_budget": self.scope.probe_budget,
            "check_stats": check_stats,
            "summary": summarize(findings),
            "findings": finding_data,
            "surface_summary": {
                "ports": len(surface.get("ports") or []),
                "endpoints": len(surface.get("endpoints") or []),
                "parameters": len(surface.get("parameters") or []),
                "forms": len(surface.get("forms") or []),
                "technologies": [item.get("name") for item in surface.get("technologies") or []],
            },
            "artifacts": artifacts,
        }


def run(
    workspace: str | Path | None = None,
    target: str | None = None,
    checks: list[str] | None = None,
    actions: list[str] | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict:
    path = Path(workspace) if workspace else resolve_workspace()
    scope = load_scope(path)
    if target is None:
        target = scope.target
    if target is None or not str(target).strip():
        if not scope.hosts:
            raise ValueError("El workspace no define hosts")
        target = f"http://{scope.hosts[0]}:{sorted(scope.ports_set)[0]}"
    runner = Runner(path, scope, progress=progress)
    return runner.scan(target, checks=checks, actions=actions)
