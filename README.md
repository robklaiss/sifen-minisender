# sifen-minisender

Repo Python minimal para enviar un lote async a SIFEN (rEnvioLote) y dejar artifacts reproducibles.

## Requisitos

- Python 3.9
- Dependencias: `requests`, `lxml`
- mTLS (PEM):
  - `SIFEN_CERT_PATH` (cert.pem)
  - `SIFEN_KEY_PATH` (key.pem)

## Instalación

```bash
python3.9 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

## Variables de entorno

- `SIFEN_CERT_PATH` y `SIFEN_KEY_PATH`: requeridos para mTLS.
- Endpoint envío de lote (`recibe-lote`) (prioridad):
  - `SIFEN_RECIBE_LOTE_ENDPOINT`
  - `SIFEN_WSDL_RECIBE_LOTE` (se usa el mismo URL pero sin query string `?wsdl`)
  - defaults:
    - TEST: `https://sifen-test.set.gov.py/de/ws/async/recibe-lote.wsdl`
    - PROD: `https://sifen.set.gov.py/de/ws/async/recibe-lote.wsdl`
- Endpoint consulta de resultado de lote (`consulta-lote`) (prioridad):
  - `SIFEN_CONSULTA_LOTE_ENDPOINT` (URL real del endpoint, sin `?wsdl`)
  - `SIFEN_WSDL_CONSULTA_LOTE` (WSDL; se deriva endpoint quitando `?wsdl` si existe)
  - defaults:
    - TEST: `https://sifen-test.set.gov.py/de/ws/consultas/consulta-lote.wsdl`
    - PROD: `https://sifen.set.gov.py/de/ws/consultas/consulta-lote.wsdl`
- Control de endpoint para consulta-lote:
  - `SIFEN_STRIP_WSDL_ENDPOINTS=1` para forzar quitar el sufijo `.wsdl` antes de POST (por defecto se respeta el `soap:address` del WSDL).
- Fallback WSDL local (si el GET remoto devuelve vacío o falla):
  - `SIFEN_WSDL_CONSULTA_LOTE_LOCAL=/ruta/al/wsdl.xml`
  - Si no se setea, se intenta con `artifacts/_wsdl_consulta_lote_curl.wsdl.xml` y `artifacts/_wsdl_probe_requests_ua.wsdl.xml` si existen.
  - Para `--env prod`, por defecto NO se usa el `soap:address` del WSDL local (usar `SIFEN_USE_WSDL_ADDRESS=1` si querés forzarlo).
- TLS:
  - `SIFEN_FORCE_TLS12=1` (default) para forzar TLS 1.2 en consulta-lote.
- Lote/rDE:
  - `SIFEN_STRIP_XSI=1` para remover `xmlns:xsi` y `xsi:schemaLocation` del `rDE` dentro del lote (por defecto se conservan, recomendado).

**Guardrail PROD**: para `--env prod` se requiere `SIFEN_CONFIRM_PROD=YES`.

## Uso

### 1) Enviar lote (`send`)

Ejemplo usando el `signed_rde.xml` ya existente en `tesaka-if`:

```bash
python -m sifen_minisender send \
  --env test \
  artifacts/fix_20260206/signed_rde_valid_cdc.xml
```

Por defecto usa ZIP `deflated` (recomendado; con `stored` vimos rechazos `XML Mal Formado` en test). Para forzar `stored`:

```bash
python -m sifen_minisender send --env test --zip stored \
  artifacts/fix_20260206/signed_rde_valid_cdc.xml
```

Cada corrida crea un directorio `artifacts/run_YYYYmmdd_HHMMSS/` con:

- `soap_last_request.xml`
- `soap_last_response.xml`
- `lote.xml`
- `zip_sent.bin`
- `meta.json`

Nota: si en `consult` aparece `1101 TEST - Número de timbrado inválido`, el XML firmado tiene un timbrado no vigente para el emisor. Hay que **re-generar y re-firmar** el `signed_rde.xml` con un `dNumTim` válido (y `dFeIniT` correspondiente). Este repo no firma: el timbrado correcto debe venir del generador que produce el XML.

### 2) Inspeccionar artifacts (`inspect`)

```bash
python -m sifen_minisender inspect artifacts/run_YYYYmmdd_HHMMSS
```

El comando:

- Muestra resumen de request/response.
- Extrae `lote.xml` desde `xDE` (Base64 -> ZIP) y lo escribe como `lote_extracted.xml`.

### 3) Consultar resultado de lote (`consult`)

Dado un `dProtConsLote` devuelto por `send`, consulta el estado del lote usando SOAP 1.2 con mTLS y deja artifacts reproducibles.

```bash
python -m sifen_minisender consult --env test --prot 47353168697912368
```

Por defecto escribe en `artifacts/run_YYYYmmdd_HHMMSS_consult/`, guardando:

- `soap_last_request.xml`
- `soap_last_response.xml`
- `wsdl_last.xml`
- `meta.json` (incluye `env`, `wsdl_url`, `endpoint`, `soap_action`, `operation`, `prot`, `http_status`, `response_sha256`, etc.)

## Guardrails (CI + local)

### Ejecutar guardrails manualmente

```bash
.venv/bin/python -m pytest -q tests/test_guardrail_*.py
```

### Instalar hook local (pre-push)

Comando único:

```bash
./tools/install-git-hooks.sh
```

El hook `pre-push` ejecuta automáticamente:

```bash
/Users/robinklaiss/Dev/sifen-minisender/.venv/bin/python -m pytest -q tests/test_guardrail_*.py
```

### CI (GitHub Actions)

El workflow `guardrails.yml` corre en cada `push` y `pull_request`, instala dependencias y ejecuta:

```bash
python -m pytest -q tests/test_guardrail_*.py
```
