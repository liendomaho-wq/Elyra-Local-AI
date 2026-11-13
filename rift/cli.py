"""Interfaz de linea de comandos de RIFT."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import TAGLINE, TOOL_NAME, __version__
from .config import list_workspaces, resolve_workspace, workspace_dir
from .models import SEVERITY_LABEL
from .plan import build as build_plan
from .policy import PolicyDenied
from .recon.engine import Runner, run as run_scan
from .report import build as build_report
from .report import verify as verify_report
from .scope import (
    DEFAULT_ACTIONS,
    DEFAULT_PORTS,
    Scope,
    is_public_host,
    load_scope,
    new_scope,
    parse_ports,
    save_scope,
    split_target,
)
from .surface import build as build_surface
from .util import read_json, slugify, utcnow, write_json


def _normalize_target(value: str) -> tuple[str, str, int, str]:
    text = value.strip()
    if "://" not in text:
        text = "http://" + text
    host, port, scheme = split_target(text)
    display = f"[{host}]" if ":" in host and not host.startswith("[") else host
    default = (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    return f"{scheme}://{display}" + ("" if default else f":{port}"), host, port, scheme


def _actions(value: str) -> list[str]:
    return [item.strip().lower() for item in str(value).split(",") if item.strip()]


def _format_scope(scope: Scope) -> str:
    lines = [
        f"Workspace: {scope.name}",
        f"Objetivo: {scope.target or '(no definido)'}",
        f"Hosts: {', '.join(scope.hosts)}",
        f"Puertos: {scope.ports}",
        f"Acciones: {', '.join(scope.actions)}",
        f"Autorizado: {'si' if scope.authorized else 'no'}",
        f"Atestacion: {scope.attestation or '(vacia)'}",
        f"Rate limit: {scope.rate_limit}/min | Probes: {scope.probe_budget} | Crawl: {scope.max_crawl_pages}",
        f"Creado: {scope.created_at}",
    ]
    return "\n".join(lines)


def _print_summary(data: dict) -> None:
    summary = data.get("summary") or {}
    counts = summary.get("counts") or {}
    print(f"Objetivo: {data.get('target')}")
    print(f"Riesgo: {summary.get('risk', '-')} | Hallazgos: {summary.get('total', 0)}")
    print(
        "Severidad: "
        + " | ".join(
            f"{SEVERITY_LABEL.get(key, key)}={counts.get(key, 0)}"
            for key in ("critical", "high", "medium", "low", "info")
        )
    )
    print(f"Probes activos: {data.get('probes_used', 0)}/{data.get('probe_budget', 0)}")
    print(f"Artefactos: {data.get('artifacts')}")


def command_init(args) -> int:
    if not args.authorized:
        print("error: debes confirmar autorizacion explicita con --authorized", file=sys.stderr)
        return 2
    if not args.attestation.strip():
        print("error: --attestation es obligatorio para dejar constancia de la autorizacion", file=sys.stderr)
        return 2
    try:
        target, host, port, _ = _normalize_target(args.target)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    hosts = [host]
    for item in args.host or []:
        try:
            _, extra_host, _, _ = _normalize_target(item)
            if extra_host not in hosts:
                hosts.append(extra_host)
        except ValueError as exc:
            print(f"error en --host: {exc}", file=sys.stderr)
            return 2
    selected_actions = _actions(args.actions) if args.actions else list(DEFAULT_ACTIONS)
    ports = args.ports or DEFAULT_PORTS
    try:
        scope_ports = parse_ports(ports)
        if port not in scope_ports:
            ports = f"{ports},{port}"
        scope = new_scope(
            name=args.name,
            hosts=hosts,
            ports=ports,
            actions=selected_actions,
            authorized=True,
            attestation=args.attestation.strip(),
            allow_public=args.allow_public,
            rate_limit=args.rate_limit,
            max_crawl_pages=args.max_crawl_pages,
            probe_budget=args.probe_budget,
            notes=args.notes,
            target=target,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    path = workspace_dir(scope.name)
    if (path / "scope.json").exists() and not args.force:
        print(f"error: el workspace ya existe: {path}; usa --force para sobrescribir", file=sys.stderr)
        return 2
    path.mkdir(parents=True, exist_ok=True)
    save_scope(path, scope)
    print(f"Workspace creado: {path}")
    print(_format_scope(scope))
    if is_public_host(host) and not scope.allow_public:
        print("Aviso: objetivo publico bloqueado hasta usar --allow-public.", file=sys.stderr)
    return 0


def command_list(args) -> int:
    names = list_workspaces()
    if not names:
        print("No hay workspaces. Crea uno con: rift init --name lab --target URL --authorized --attestation '...'")
        return 0
    for name in names:
        path = workspace_dir(name)
        scope = load_scope(path)
        results = read_json(path / "results.json", {}) or {}
        summary = results.get("summary") or {}
        print(
            f"{name}: {scope.target or '-'} | riesgo={summary.get('risk', '-')} | "
            f"hallazgos={summary.get('total', 0)}"
        )
    return 0


def command_show(args) -> int:
    path = resolve_workspace(args.workspace)
    scope = load_scope(path)
    print(_format_scope(scope))
    results = read_json(path / "results.json")
    if results:
        print("")
        _print_summary(results)
    else:
        print("\nSin evaluaciones. Ejecuta: rift scan")
    return 0


def command_recon(args) -> int:
    path = resolve_workspace(args.workspace)
    scope = load_scope(path)
    target = args.target or scope.target or f"http://{scope.hosts[0]}:{sorted(scope.ports_set)[0]}"
    allowed, reason = scope.check_target(target)
    if not allowed:
        print(f"error: {reason}", file=sys.stderr)
        return 2
    runner = Runner(path, scope, progress=lambda message: print(f"[recon] {message}", file=sys.stderr))
    recon = runner.recon(target)
    surface = build_surface(recon["target"], recon["host"], recon["port"], recon["scheme"], recon, scope)
    write_json(path / "recon.json", recon)
    write_json(path / "surface.json", surface)
    print(f"Recon completado: {recon['target']}")
    print(
        f"Endpoints: {len(surface.get('endpoints') or [])} | "
        f"Parametros: {len(surface.get('parameters') or [])} | "
        f"Puertos: {len(surface.get('ports') or [])} | "
        f"Tecnologias: {len(surface.get('technologies') or [])}"
    )
    print(f"Artefactos: {path / 'recon.json'}, {path / 'surface.json'}")
    return 0


def command_scan(args) -> int:
    path = resolve_workspace(args.workspace)
    checks = _actions(args.checks) if args.checks else None
    try:
        data = run_scan(
            workspace=path,
            target=args.target,
            checks=checks,
            progress=lambda message: print(f"[scan] {message}", file=sys.stderr),
        )
    except (PolicyDenied, ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _print_summary(data)
    print(f"Resultados: {path / 'results.json'}")
    return 0


def command_plan(args) -> int:
    path = resolve_workspace(args.workspace)
    surface = read_json(path / "surface.json")
    findings = read_json(path / "findings.json")
    if not isinstance(surface, dict) or findings is None:
        print("error: no hay datos; ejecuta rift scan primero", file=sys.stderr)
        return 2
    plan = build_plan(surface, findings)
    write_json(path / "plan.json", plan)
    print(f"Plan generado: {path / 'plan.json'}")
    for technique in plan.get("techniques") or []:
        print(f"- {technique.get('priority')}: {technique.get('id')} {technique.get('name')} ({technique.get('tactic')})")
    return 0


def command_report(args) -> int:
    path = resolve_workspace(args.workspace)
    formats = _actions(args.formats) if args.formats else ["json", "md", "html"]
    try:
        result = build_report(path, formats=formats)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Informe generado en {path}")
    print(f"Manifiesto: {result['manifest']}")
    print(f"SHA-256 manifiesto: {result['manifest_sha256']}")
    for item in result["files"]:
        print(f"- {item}")
    return 0


def command_verify(args) -> int:
    path = resolve_workspace(args.workspace)
    result = verify_report(path)
    print(f"Integridad: {'OK' if result['ok'] else 'FALLO'}")
    print(f"Archivos verificados: {result.get('files', 0)} | Entradas de auditoria: {result.get('audit_entries', 0)}")
    print(f"Raiz de auditoria: {result.get('audit_root', '-')}")
    for error in result.get("errors") or []:
        print(f"- {error}")
    return 0 if result["ok"] else 1


def command_range(args) -> int:
    from .range import serve

    serve(port=args.port)
    return 0


def command_web(args) -> int:
    from .web import serve

    path = resolve_workspace(args.workspace)
    serve(workspace=path, port=args.port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=f"{TAGLINE} Herramienta de pentesting autorizado.",
        epilog="RIFT solo debe usarse contra objetivos con autorizacion escrita.",
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init", help="crea un workspace autorizado")
    init.add_argument("--name", required=True)
    init.add_argument("--target", required=True, help="URL o host:puerto objetivo")
    init.add_argument("--host", action="append", help="host adicional dentro del alcance")
    init.add_argument("--ports", default=DEFAULT_PORTS, help="puertos permitidos, ej. 80,443,8000-8100")
    init.add_argument("--actions", default="", help="acciones: dns,tls,http,port_scan,crawl,content,probe")
    init.add_argument("--authorized", action="store_true", help="confirmacion explicita de autorizacion")
    init.add_argument("--attestation", default="", help="texto de autorizacion y responsable")
    init.add_argument("--allow-public", action="store_true")
    init.add_argument("--rate-limit", type=int, default=240)
    init.add_argument("--max-crawl-pages", type=int, default=20)
    init.add_argument("--probe-budget", type=int, default=24)
    init.add_argument("--notes", default="")
    init.add_argument("--force", action="store_true")
    init.set_defaults(func=command_init)

    listing = sub.add_parser("list", help="lista workspaces")
    listing.set_defaults(func=command_list)

    show = sub.add_parser("show", help="muestra un workspace")
    show.add_argument("--workspace")
    show.set_defaults(func=command_show)

    recon = sub.add_parser("recon", help="solo reconocimiento y superficie")
    recon.add_argument("--workspace")
    recon.add_argument("--target")
    recon.set_defaults(func=command_recon)

    scan = sub.add_parser("scan", help="recon + checks + plan")
    scan.add_argument("--workspace")
    scan.add_argument("--target")
    scan.add_argument("--checks", default="", help="lista separada por comas; por defecto todas")
    scan.set_defaults(func=command_scan)
    scan_alias = sub.add_parser("run", help="alias de scan")
    scan_alias.add_argument("--workspace")
    scan_alias.add_argument("--target")
    scan_alias.add_argument("--checks", default="")
    scan_alias.set_defaults(func=command_scan)

    plan = sub.add_parser("plan", help="regenera el plan MITRE ATT&CK")
    plan.add_argument("--workspace")
    plan.set_defaults(func=command_plan)

    report = sub.add_parser("report", help="genera informes y manifiesto")
    report.add_argument("--workspace")
    report.add_argument("--formats", default="json,md,html")
    report.set_defaults(func=command_report)

    verify = sub.add_parser("verify", help="verifica informes y audit log")
    verify.add_argument("--workspace")
    verify.set_defaults(func=command_verify)

    range_parser = sub.add_parser("range", help="inicia el laboratorio local")
    range_parser.add_argument("--port", type=int, default=8765)
    range_parser.set_defaults(func=command_range)

    web = sub.add_parser("web", help="dashboard local de solo lectura")
    web.add_argument("--workspace")
    web.add_argument("--port", type=int, default=8787)
    web.set_defaults(func=command_web)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 2
    try:
        return int(args.func(args))
    except KeyboardInterrupt:
        print("Interrumpido.", file=sys.stderr)
        return 130
    except (PolicyDenied, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
