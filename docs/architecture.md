# Arquitectura de RIFT

RIFT separa alcance, politicas, reconocimiento, checks, evidencia y presentacion.
Cada peticion de red pasa por el motor de politicas antes de salir.

## Flujo

```text
CLI
  -> resolve_workspace / load_scope
  -> Runner
       -> PolicyEngine (accion, host, puerto, rate limit, auditoria)
       -> recon: http, dns, tls, ports, crawl, content, fingerprint
       -> surface.build
       -> CheckContext -> checks pasivos/activos
       -> plan.build (MITRE ATT&CK)
       -> persistencia: recon.json, surface.json, findings.json, plan.json, results.json
       -> report.build: JSON/MD/HTML + manifiesto
       -> report.verify: hashes + audit chain
```

## Componentes

### Scope y politicas

`scope.py` normaliza hosts, puertos y acciones. `policy.py` deniega cualquier
peticion fuera de alcance, sin autorizacion o por encima del rate limit. Cada
decision se envia a `audit.py`.

### Reconocimiento

- `recon/http.py`: cliente HTTP con User-Agent identificable, limite de cuerpo,
  redirecciones validadas contra el scope y fallback TLS no verificado solo para
  inspeccion.
- `recon/dns.py`: DoH con fallback al resolutor del sistema; omite IPs.
- `recon/tls.py`: certificado, SAN, expiracion, protocolo y errores de validacion.
- `recon/ports.py`: TCP connect concurrente con timeout y limite de puertos.
- `recon/crawl.py`: BFS del mismo origen, formularios, parametros, scripts y comentarios.
- `recon/content.py`: descubrimiento opt-in de rutas comunes.
- `recon/engine.py`: orquestacion y persistencia.

### Checks

Pasivos: cabeceras, cookies, TLS, puertos, exposicion de rutas.
Activos, solo con accion `probe`:

- Reflejo HTML con marcador inerte (sin ejecutar JavaScript).
- Error SQL inducido con comilla simple; no se extraen datos.
- Open redirect con destino `https://rift.invalid/poc`, sin seguirlo.
- CORS con `Origin: https://rift.invalid`.
- Metodos anunciados mediante `OPTIONS`.

El presupuesto evita que un check consuma todas las peticiones activas.

### Evidencia

Los artefactos se escriben en el workspace. `results.json` incluye resumen,
hallazgos, estadisticas de checks y referencias a artefactos. `report-manifest.json`
contiene SHA-256 de los informes; `audit.jsonl` es una cadena append-only cuyo
root se verifica con `rift verify`.

## Extension

Para agregar un check:

1. Crea una funcion `run(ctx, **kwargs)` en `rift/checks/`.
2. Devuelve una lista de `Finding`.
3. Registralo en `REGISTRY` y, si es activo, en `ACTIVE_CHECKS`.
4. Anade pruebas contra el Range.
