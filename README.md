# RIFT

**Recon, superficie de ataque y validacion segura para pentesting autorizado.**

RIFT es una herramienta de linea de comandos y dashboard local para evaluar la
seguridad de aplicaciones web dentro de un alcance explicitamente autorizado. Une
reconocimiento, crawling, descubrimiento opt-in, validaciones no destructivas,
mapeo MITRE ATT&CK, un laboratorio local y un informe con auditoria verificable.

> **Uso responsable.** RIFT solo debe ejecutarse contra sistemas propios o con
> autorizacion escrita. No incluye exploits destructivos, persistencia, movimiento
> lateral, fuerza bruta ni exfiltracion de datos. El laboratorio incluido escucha
> unicamente en loopback y usa datos ficticios.

## Caracteristicas

- **Scope-lock:** autorizacion explicita, hosts, puertos, acciones, rate limit y
  presupuesto de probes activos.
- **Reconocimiento:** HTTP, DNS via DoH con fallback al sistema, TLS, TCP connect,
  crawling acotado y descubrimiento opt-in de rutas.
- **Superficie de ataque:** endpoints, parametros GET, formularios, scripts,
  tecnologias, puertos y rutas interesantes.
- **Validacion segura:** reflejo HTML con marcador inerte, errores SQL inducidos,
  open redirect sin seguir el destino, CORS reflejado, metodos HTTP, cookies,
  cabeceras y exposicion de archivos.
- **Plan MITRE ATT&CK:** tecnicas priorizadas y pasos de validacion seguros.
- **Evidencia:** `results.json`, `surface.json`, `plan.json`, informes JSON/Markdown/HTML,
  manifiesto SHA-256 y audit log encadenado.
- **Dashboard local:** solo lectura, enlazado a `127.0.0.1`.
- **Range:** laboratorio HTTP vulnerable para practicar sin salir de loopback.
- **Sin dependencias obligatorias:** Python 3.11+ y biblioteca estandar.

## Instalacion

```bash
git clone https://github.com/liendomaho-wq/Elyra-Local-AI.git
cd Elyra-Local-AI
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
rift --version
```

Tambien puede ejecutarse sin instalar:

```bash
python3 -m rift --help
```

## Inicio rapido con el laboratorio

Terminal 1:

```bash
rift range --port 8765
```

Terminal 2:

```bash
export RIFT_HOME="$HOME/.rift"
rift init \
  --name lab \
  --target http://127.0.0.1:8765 \
  --ports 8765 \
  --actions http,crawl,content,probe \
  --authorized \
  --attestation "Tengo autorizacion para probar el laboratorio local"

rift scan --workspace lab
rift report --workspace lab
rift verify --workspace lab
```

El resultado queda en `$RIFT_HOME/workspaces/lab/`:

```text
scope.json               alcance autorizado
recon.json               evidencia cruda del reconocimiento
surface.json             endpoints, parametros, formularios y tecnologias
findings.json            hallazgos normalizados
plan.json                plan MITRE ATT&CK priorizado
results.json             resumen completo del scan
audit.jsonl              cadena de decisiones allow/deny
report.json/.md/.html    informes
report-manifest.json     hashes de los informes
REPORT-SHA256SUMS        sumas SHA-256
```

Dashboard local:

```bash
rift web --workspace lab --port 8787
# http://127.0.0.1:8787
```

## Comandos

```text
rift init       Crea un workspace y guarda el alcance autorizado.
rift list       Lista workspaces y su ultimo riesgo.
rift show       Muestra alcance y ultimo resumen.
rift recon      Ejecuta solo reconocimiento y superficie.
rift scan       Recon + checks + plan MITRE (alias: run).
rift plan       Regenera el plan a partir de hallazgos existentes.
rift report     Genera JSON, Markdown, HTML y manifiesto.
rift verify     Verifica informes y audit log.
rift range      Inicia el laboratorio local en loopback.
rift web        Dashboard local de solo lectura.
```

### Acciones del scope

| Accion | Efecto |
|---|---|
| `dns` | Consulta A/AAAA/CNAME/MX/NS/TXT via DoH o resolutor local. |
| `tls` | Inspecciona certificado, cadena, expiracion y protocolo. |
| `http` | Obtiene la respuesta base y cabeceras. |
| `port_scan` | TCP connect sobre los puertos permitidos. |
| `crawl` | Sigue enlaces del mismo origen y extrae formularios/parametros. |
| `content` | **Opt-in:** prueba una lista corta de rutas sensibles comunes. |
| `probe` | Habilita validaciones activas no destructivas. |

`content` y `probe` son deliberadamente opt-in. El scope por defecto incluye
`dns,http,tls,port_scan,crawl,probe`; agrega `content` solo cuando el alcance lo
permita.

## Controles de seguridad

- `rift init` exige `--authorized` y un texto en `--attestation`.
- Todo host/puerto debe pertenecer al scope; las redirecciones externas se bloquean.
- Objetivos publicos requieren `--allow-public`.
- El rate limit y el presupuesto de probes se aplican a cada ejecucion.
- El contenido se descubre solo con la accion `content`.
- Los checks activos no ejecutan JavaScript, no escriben datos, no intentan
  autenticarse y no extraen informacion de bases de datos.
- El Range y el dashboard solo pueden escuchar en loopback.
- Cada decision del motor de politicas se registra en `audit.jsonl` con cadena
  SHA-256. `rift verify` comprueba informes y auditoria.

## Arquitectura

```text
rift/
  cli.py             interfaz de comandos
  config.py          RIFT_HOME y workspaces
  scope.py           alcance, hosts, puertos y autorizacion
  policy.py          decisiones allow/deny, rate limit
  audit.py           audit log encadenado
  surface.py         correlacion de reconocimiento
  plan.py            mapeo MITRE ATT&CK
  recon/             http, dns, tls, ports, crawl, content, fingerprint, engine
  checks/            headers, cookies, tls, ports, disclosure, cors, methods, xss, sqli, redirect
  report/            informes y manifiesto
  range/             laboratorio local + misiones
  web.py             dashboard de solo lectura
```

Mas detalle en [docs/architecture.md](docs/architecture.md) y
[docs/safety.md](docs/safety.md).

## Desarrollo

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q rift
python3 -m pip wheel . --no-deps -w /tmp/rift-wheel
```

Las pruebas levantan el Range en un puerto efimero y verifican hallazgos,
presupuesto de probes, audit log, informes, deteccion de manipulacion y dashboard.

## Limites conocidos

- No es un escaner de infraestructura completo ni un framework de explotacion.
- No implementa ataques de fuerza bruta, credential stuffing, shells, persistencia,
  movimiento lateral ni exfiltracion.
- Los hallazgos activos son evidencia para revision manual; no confirman por si
  solos explotabilidad completa.
- El descubrimiento de contenido usa una lista corta y conservadora.
- TLS y DNS dependen de las capacidades y de la red del entorno.

## Licencia

MIT. Consulta [LICENSE](LICENSE).
