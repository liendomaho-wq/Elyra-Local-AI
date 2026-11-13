# RIFT Range: misiones de pentesting autorizado

Este laboratorio escucha solo en loopback y contiene datos ficticios. El objetivo es
practicar reconocimiento, correlacion de superficie y validacion segura.

## Mision 1: superficie

1. Abre el laboratorio con `rift range`.
2. Crea un workspace autorizado apuntando a la URL mostrada. Incluye el puerto en
   `--ports` y las acciones `dns,http,crawl,content,probe`.
3. Ejecuta `rift scan` y revisa `surface.json`: endpoints, parametros, formularios y
   tecnologias.

## Mision 2: hallazgos pasivos

1. Revisa cabeceras de seguridad, cookies y metodos anunciados.
2. Explica por que la falta de CSP, HttpOnly o SameSite importa.
3. Comprueba que el auditor registra cada decision en `audit.jsonl`.

## Mision 3: validacion activa segura

1. Confirma el reflejo HTML de `/search?q=` con el marcador inerte de RIFT.
2. Reproduce el error SQL de `/product?id=` sin extraer datos.
3. Comprueba el open redirect de `/redirect?next=` sin seguir el destino externo.
4. Revisa CORS en `/api/users` con un Origin de prueba.

## Mision 4: plan de ataque

1. Abre `plan.json` y relaciona cada hallazgo con su tecnica MITRE ATT&CK.
2. Ordena las acciones por prioridad y escribe una remediacion verificable.
3. No ejecutes persistencia, movimiento lateral ni exfiltracion: el laboratorio no
   lo necesita y RIFT no lo implementa.

## Consultas de ejemplo

```bash
curl -i "http://127.0.0.1:8765/search?q=hola"
curl -i "http://127.0.0.1:8765/product?id=1%27"
curl -i "http://127.0.0.1:8765/redirect?next=https://rift.invalid/poc"
curl -i -H "Origin: https://rift.invalid" "http://127.0.0.1:8765/api/users?id=1"
```
