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
    - TEST: `https://sifen-test.set.gov.py/de/ws/async/consulta-lote.wsdl`
    - PROD: `https://sifen.set.gov.py/de/ws/async/consulta-lote.wsdl`

**Guardrail PROD**: para `--env prod` se requiere `SIFEN_CONFIRM_PROD=YES`.

## Uso

### 1) Enviar lote (`send`)

Ejemplo usando el `signed_rde.xml` ya existente en `tesaka-if`:

```bash
python -m sifen_minisender send \
  --env test \
  /Users/robinklaiss/Dev/tesaka-if/artifacts/run_20260201_000044/signed_rde.xml
```

Opcional: ZIP con compresión deflated:

```bash
python -m sifen_minisender send --env test --zip deflated \
  /Users/robinklaiss/Dev/tesaka-if/artifacts/run_20260201_000044/signed_rde.xml
```

Cada corrida crea un directorio `artifacts/run_YYYYmmdd_HHMMSS/` con:

- `soap_last_request.xml`
- `soap_last_response.xml`
- `lote.xml`
- `zip_sent.bin`
- `meta.json`

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
