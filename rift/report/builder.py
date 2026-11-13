"""Generacion de informes JSON, Markdown y HTML sin dependencias externas."""

from __future__ import annotations

import html
import json
from pathlib import Path

from ..audit import AuditLog
from ..util import canonical_json, read_json, sha256_hex, sha256_file, utcnow, write_json

REPORT_FILES = ("report.json", "report.md", "report.html")
MANIFEST = "report-manifest.json"
SEVERITY_LABEL = {
    "critical": "Critica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "info": "Info",
}
SEVERITY_COLOR = {
    "critical": "#8b1e3f",
    "high": "#d9480f",
    "medium": "#b7791f",
    "low": "#2b6cb0",
    "info": "#4a5568",
}


def _load(workspace: Path) -> tuple[dict, list[dict], dict, dict]:
    results = read_json(workspace / "results.json")
    findings = read_json(workspace / "findings.json", [])
    surface = read_json(workspace / "surface.json", {})
    plan = read_json(workspace / "plan.json", {})
    if not isinstance(results, dict):
        raise FileNotFoundError("No hay results.json; ejecuta rift scan primero")
    return results, findings if isinstance(findings, list) else [], surface or {}, plan or {}


def _md_escape(value) -> str:
    return str(value or "").replace("|", "\\|").replace("\n", " ")


def _json_report(results, findings, surface, plan) -> dict:
    return {
        "tool": results.get("tool", "RIFT"),
        "version": results.get("version"),
        "workspace": results.get("workspace"),
        "target": results.get("target"),
        "generated_at": results.get("generated_at"),
        "report_generated_at": utcnow(),
        "summary": results.get("summary") or {},
        "probes_used": results.get("probes_used"),
        "probe_budget": results.get("probe_budget"),
        "surface": {
            "ports": surface.get("ports") or [],
            "technologies": surface.get("technologies") or [],
            "endpoints": surface.get("endpoints") or [],
            "parameters": surface.get("parameters") or [],
            "forms": surface.get("forms") or [],
        },
        "findings": findings,
        "plan": plan,
        "disclaimer": "Evaluacion de seguridad solo para objetivos autorizados. RIFT no ejecuta exploits destructivos ni exfiltra datos.",
    }


def _markdown(report: dict) -> str:
    summary = report.get("summary") or {}
    counts = summary.get("counts") or {}
    lines = [
        f"# Informe RIFT: {report.get('target')}",
        "",
        f"- Workspace: `{report.get('workspace')}`",
        f"- Generado: `{report.get('report_generated_at')}`",
        f"- Riesgo global: **{str(summary.get('risk') or 'sin hallazgos').upper()}**",
        f"- Hallazgos: **{summary.get('total', 0)}**",
        "- Distribucion: " + ", ".join(
            f"{SEVERITY_LABEL.get(key, key)}={counts.get(key, 0)}"
            for key in ("critical", "high", "medium", "low", "info")
        ),
        "",
        "## Resumen ejecutivo",
        "",
        "RIFT reconocio la superficie declarada y ejecuto validaciones no destructivas.",
        "Los hallazgos son evidencia para revision manual; no sustituyen una auditoria completa.",
        "",
        "## Hallazgos",
        "",
    ]
    findings = report.get("findings") or []
    if not findings:
        lines.append("No se registraron hallazgos en esta ejecucion.")
    for finding in findings:
        lines.extend(
            [
                f"### {finding.get('severity', 'info').upper()} - {finding.get('title')}",
                "",
                f"- ID: `{finding.get('id')}`",
                f"- CVSS: {finding.get('cvss')} | CWE: `{finding.get('cwe')}` | OWASP: {finding.get('owasp')}",
                f"- MITRE ATT&CK: `{finding.get('technique')}`",
                f"- Confianza: {finding.get('confidence')} | Tipo: {finding.get('kind')}",
                "",
                str(finding.get("description") or ""),
                "",
                "Evidencia:",
            ]
        )
        for evidence in finding.get("evidence") or []:
            lines.append(f"- {evidence}")
        if finding.get("poc"):
            lines.extend(["", "PoC de validacion:", "", "```text", str(finding["poc"]), "```"])
        if finding.get("remediation"):
            lines.extend(["", f"Remediacion: {finding['remediation']}"])
        lines.append("")
    plan = report.get("plan") or {}
    lines.extend(["## Plan de validacion MITRE ATT&CK", ""])
    for technique in plan.get("techniques") or []:
        lines.extend(
            [
                f"### `{technique.get('id')}` {technique.get('name')}",
                "",
                f"- Tactica: {technique.get('tactic')}",
                f"- Prioridad: {technique.get('priority')}",
                f"- Razon: {technique.get('reason')}",
            ]
        )
        if technique.get("finding_ids"):
            lines.append("- Hallazgos: " + ", ".join(f"`{item}`" for item in technique["finding_ids"]))
        for step in technique.get("steps") or []:
            lines.append(f"- Paso: {step}")
        lines.append("")
    lines.extend(
        [
            "## Superficie",
            "",
            f"- Puertos en alcance: {len((report.get('surface') or {}).get('ports') or [])}",
            f"- Endpoints: {len((report.get('surface') or {}).get('endpoints') or [])}",
            f"- Parametros: {len((report.get('surface') or {}).get('parameters') or [])}",
            "- Tecnologias: " + ", ".join(
                str(item.get("name")) for item in (report.get("surface") or {}).get("technologies") or []
            ),
            "",
            "## Alcance y limites",
            "",
            str(report.get("disclaimer") or ""),
            "",
        ]
    )
    return "\n".join(lines)


def _html(report: dict) -> str:
    summary = report.get("summary") or {}
    counts = summary.get("counts") or {}
    esc = html.escape
    findings_html = []
    for finding in report.get("findings") or []:
        severity = str(finding.get("severity") or "info")
        color = SEVERITY_COLOR.get(severity, "#4a5568")
        evidence = "".join(f"<li>{esc(str(item))}</li>" for item in finding.get("evidence") or [])
        poc = ""
        if finding.get("poc"):
            poc = f"<h4>PoC de validacion</h4><pre>{esc(str(finding['poc']))}</pre>"
        findings_html.append(
            f"""<details class="finding" open>
<summary><span class="badge" style="background:{color}">{esc(SEVERITY_LABEL.get(severity, severity))}</span>
<strong>{esc(str(finding.get('title') or ''))}</strong> <code>{esc(str(finding.get('id') or ''))}</code></summary>
<p><b>CVSS:</b> {esc(str(finding.get('cvss')))} &middot; <b>CWE:</b> {esc(str(finding.get('cwe')))} &middot;
<b>OWASP:</b> {esc(str(finding.get('owasp')))} &middot; <b>ATT&amp;CK:</b> {esc(str(finding.get('technique')))}</p>
<p>{esc(str(finding.get('description') or ''))}</p>
<h4>Evidencia</h4><ul>{evidence}</ul>
{poc}
<h4>Remediacion</h4><p>{esc(str(finding.get('remediation') or ''))}</p>
</details>"""
        )
    plan_html = []
    for technique in (report.get("plan") or {}).get("techniques") or []:
        steps = "".join(f"<li>{esc(str(step))}</li>" for step in technique.get("steps") or [])
        plan_html.append(
            f"<div class='technique'><h3><code>{esc(str(technique.get('id')))}</code> {esc(str(technique.get('name')))}</h3>"
            f"<p><b>Tactica:</b> {esc(str(technique.get('tactic')))} &middot; <b>Prioridad:</b> {esc(str(technique.get('priority')))}</p>"
            f"<p>{esc(str(technique.get('reason') or ''))}</p><ul>{steps}</ul></div>"
        )
    technologies = ", ".join(
        esc(str(item.get("name"))) for item in (report.get("surface") or {}).get("technologies") or []
    )
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>RIFT - {esc(str(report.get('target')))}</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1a202c;line-height:1.55}}
h1,h2,h3{{line-height:1.2}} code,pre{{font-family:ui-monospace,SFMono-Regular,Consolas,monospace}}
.hero{{border-left:6px solid #2b6cb0;padding:1rem 1.25rem;background:#f7fafc;border-radius:6px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.7rem;margin:1rem 0}}
.card{{border:1px solid #e2e8f0;border-radius:6px;padding:.7rem;text-align:center}}
.card b{{display:block;font-size:1.6rem}} .finding{{border:1px solid #e2e8f0;border-radius:6px;margin:1rem 0;padding:.8rem}}
.badge{{color:white;border-radius:4px;padding:.15rem .45rem;font-size:.75rem;text-transform:uppercase}}
pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#edf2f7;padding:.8rem;border-radius:4px}}
.technique{{border-top:1px solid #e2e8f0;padding:.6rem 0}} footer{{margin-top:3rem;color:#4a5568;font-size:.9rem}}
</style></head><body>
<div class="hero"><h1>Informe RIFT</h1><p><b>Objetivo:</b> {esc(str(report.get('target')))}<br>
<b>Workspace:</b> {esc(str(report.get('workspace')))}<br>
<b>Generado:</b> {esc(str(report.get('report_generated_at')))}</p>
<p><b>Riesgo global:</b> {esc(str(summary.get('risk') or 'sin hallazgos'))} &middot;
<b>Hallazgos:</b> {esc(str(summary.get('total', 0)))} &middot; <b>Probes:</b> {esc(str(report.get('probes_used')))}</p></div>
<div class="cards">
<div class="card"><b>{counts.get('critical',0)}</b>Critica</div>
<div class="card"><b>{counts.get('high',0)}</b>Alta</div>
<div class="card"><b>{counts.get('medium',0)}</b>Media</div>
<div class="card"><b>{counts.get('low',0)}</b>Baja</div>
<div class="card"><b>{counts.get('info',0)}</b>Info</div>
</div>
<h2>Hallazgos</h2>
{''.join(findings_html) or '<p>No se registraron hallazgos.</p>'}
<h2>Plan de validacion MITRE ATT&amp;CK</h2>
{''.join(plan_html) or '<p>Sin tecnicas priorizadas.</p>'}
<h2>Superficie</h2><p><b>Tecnologias:</b> {technologies or 'no identificadas'}</p>
<h2>Alcance y limites</h2><p>{esc(str(report.get('disclaimer') or ''))}</p>
<footer>Generado por RIFT. Las pruebas activas son no destructivas y requieren revision humana.</footer>
</body></html>
"""


def _write_reports(workspace: Path, report: dict, formats: set[str]) -> list[Path]:
    written = []
    if "json" in formats:
        path = workspace / "report.json"
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written.append(path)
    if "md" in formats:
        path = workspace / "report.md"
        path.write_text(_markdown(report), encoding="utf-8")
        written.append(path)
    if "html" in formats:
        path = workspace / "report.html"
        path.write_text(_html(report), encoding="utf-8")
        written.append(path)
    return written


def build(workspace: str | Path, formats: list[str] | None = None) -> dict:
    path = Path(workspace)
    formats = [str(item).lower() for item in (formats or ["json", "md", "html"])]
    invalid = sorted(set(formats) - {"json", "md", "html"})
    if invalid:
        raise ValueError("Formatos no soportados: " + ", ".join(invalid))
    results, findings, surface, plan = _load(path)
    report = _json_report(results, findings, surface, plan)
    written = _write_reports(path, report, set(formats))
    files = {}
    for item in written:
        files[item.name] = {"sha256": sha256_file(item), "bytes": item.stat().st_size}
    manifest = {
        "tool": "RIFT",
        "target": report.get("target"),
        "generated_at": utcnow(),
        "files": files,
    }
    manifest_path = path / MANIFEST
    manifest_path.write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    manifest_hash = sha256_hex(canonical_json(manifest))
    (path / "REPORT-SHA256SUMS").write_text(
        "\n".join(
            [
                *[f"{item['sha256']}  {name}" for name, item in sorted(files.items())],
                f"{manifest_hash}  {MANIFEST}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return {
        "manifest": str(manifest_path),
        "manifest_sha256": manifest_hash,
        "files": [str(item) for item in written],
        "report": report,
    }


def verify(workspace: str | Path) -> dict:
    path = Path(workspace)
    manifest = read_json(path / MANIFEST)
    errors = []
    checked = []
    if not isinstance(manifest, dict):
        return {"ok": False, "errors": ["no existe report-manifest.json"], "checked": []}
    for name, expected in (manifest.get("files") or {}).items():
        target = path / name
        if not target.exists():
            errors.append(f"falta archivo: {name}")
            continue
        actual = sha256_file(target)
        checked.append(name)
        if actual != expected.get("sha256"):
            errors.append(f"hash invalido: {name}")
    audit = AuditLog(path / "audit.jsonl").verify()
    if not audit.get("ok"):
        errors.extend(f"audit: {item}" for item in audit.get("errors") or [])
    return {
        "ok": not errors,
        "checked": checked,
        "files": len(checked),
        "audit_entries": audit.get("entries", 0),
        "audit_root": audit.get("root"),
        "errors": errors,
    }
