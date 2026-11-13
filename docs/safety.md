# Seguridad y uso autorizado

RIFT es una herramienta de evaluacion defensiva-ofensiva para profesionales. El
uso no autorizado puede ser ilegal y causar dano.

## Reglas de uso

1. Ten autorizacion escrita y define el alcance con el propietario.
2. Ejecuta `rift init` con `--authorized` y una atestacion verificable.
3. Limita hosts, puertos, acciones y ventana de pruebas.
4. Empieza con reconocimiento pasivo; habilita `content` y `probe` de forma
   consciente.
5. Deten la prueba si observas degradacion, datos reales o un efecto no previsto.
6. Reporta los hallazgos por el canal acordado y rota secretos expuestos.

## Que hace RIFT

- Envia peticiones HTTP/DNS/TLS/TCP dentro del scope.
- Refleja marcadores inertes para detectar HTML sin escapar.
- Provoca errores SQL con una comilla simple y compara con una linea base.
- Comprueba redirecciones externas sin seguirlas.
- Prueba CORS con un Origin reservado (`rift.invalid`).
- Lee cabeceras, cookies, formularios, enlaces publicos y unas pocas rutas comunes.

## Que no hace RIFT

- No ejecuta JavaScript ni payloads de navegador.
- No usa exploits, shells, persistencia, movimiento lateral ni exfiltracion.
- No realiza fuerza bruta, credential stuffing ni password spraying.
- No modifica datos mediante PUT/DELETE/PATCH.
- No sigue redirecciones fuera del scope.
- No descubre contenido salvo que se habilite `content`.

## Datos y evidencia

El audit log registra decision, objetivo, motivo y hash, no cuerpos completos de
respuesta. Los informes pueden contener rutas y fragmentos de evidencia; tratalos
como material sensible. No publiques reportes de clientes sin autorizacion.

## Range

`rift range` escucha solo en `127.0.0.1` o `localhost`. Contiene datos ficticios y
errores deliberados. No lo expongas a Internet ni lo ejecutes en produccion.
