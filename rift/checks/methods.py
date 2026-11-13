"""Metodos HTTP anunciados por el servidor."""

from __future__ import annotations

DANGEROUS = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}


def run(ctx, **_):
    if ctx.remaining_probes() < 1:
        return []
    ctx.consume_probe()
    result = ctx.options(ctx.base_url)
    if result.get("error") or result.get("status") is None:
        return []
    allow = str(result.get("allow") or "")
    methods = {str(item).upper() for item in result.get("methods") or [] if item}
    if not methods and allow:
        methods = {item.strip().upper() for item in allow.split(",") if item.strip()}
    findings = []
    advertised = sorted(methods & DANGEROUS)
    if "TRACE" in advertised:
        findings.append(
            ctx.finding(
                "Metodo TRACE anunciado",
                "medium",
                5.3,
                "CWE-693",
                "A05:2021 Security Misconfiguration",
                "T1190",
                "TRACE puede facilitar Cross-Site Tracing y reflejar cabeceras de autenticacion.",
                [f"endpoint: {ctx.base_url}", f"Allow: {allow}"],
                "Deshabilita TRACE en el servidor o proxy.",
                kind="pasivo",
            )
        )
    write_methods = sorted(set(advertised) - {"TRACE"})
    if write_methods:
        findings.append(
            ctx.finding(
                "Metodos de escritura anunciados",
                "low",
                3.7,
                "CWE-749",
                "A05:2021 Security Misconfiguration",
                "T1190",
                "El servidor anuncia metodos que pueden modificar recursos; verifica autorizacion y controles por metodo.",
                [f"endpoint: {ctx.base_url}", f"metodos: {', '.join(write_methods)}", f"Allow: {allow}"],
                "Deshabilita metodos no necesarios y aplica autorizacion por endpoint y verbo.",
                kind="pasivo",
            )
        )
    return findings
