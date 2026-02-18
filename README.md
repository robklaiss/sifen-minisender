# sifen-minisender

Proyecto Python para envío de DE/lotes a SIFEN con WebUI y herramientas CLI.

## Stack operativo (out-of-the-box)

- Docker + Docker Compose
- Makefile con comandos copy/paste
- `.env.example` sin secretos
- Volúmenes estándar:
  - `/secrets` (solo lectura): certs, keys, p12, CA bundle
  - `/data` (persistente): SQLite, artifacts, logs

## Estructura esperada

```text
.
├── .env
├── .env.example
├── secrets/
│   ├── cert.p12
│   └── ca-bundle.pem
└── data/
    ├── webui.db
    ├── artifacts/
    └── logs/
```

## Formato `.env` (importante)

Si un valor tiene espacios, debe ir entre comillas dobles.

Correcto:

```env
SMTP_PASS="rpfg shib ytjp lkka"
```

También correcto (sin espacios):

```env
SMTP_PASS=abc123
```

Incorrecto (rompe `source .env`, típico error `command not found`):

```env
SMTP_PASS=rpfg shib ytjp lkka
```

Validación rápida:

```bash
make check-env
```

## Quick Start (Mac)

1. Copiar variables base:

```bash
cp .env.example .env
```

2. Completar `.env` (especialmente credenciales/certificados).

3. Crear directorios persistentes:

```bash
mkdir -p secrets data data/artifacts data/logs
```

4. Colocar certificados en `secrets/` (ejemplo: `cert.p12`, `ca-bundle.pem`).

5. Levantar servicios:

```bash
make up
```

6. Abrir WebUI:

- [http://localhost:8000](http://localhost:8000)

## Health Check (ALB)

- `GET /health` devuelve HTTP `200` con JSON `{"ok": true}` para health checks de AWS ALB Target Groups.
- `GET /healthz` es alias del mismo handler.

## Deploy EC2 (Ubuntu)

1. Instalar Docker y plugin Compose:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```

2. Clonar repo y entrar al directorio:

```bash
git clone <REPO_URL> sifen-minisender
cd sifen-minisender
```

3. Preparar entorno:

```bash
cp .env.example .env
mkdir -p secrets data data/artifacts data/logs
```

4. Copiar secretos reales a `secrets/` y completar `.env`.

5. Levantar:

```bash
make up
```

6. Ver logs:

```bash
make logs
```

## Variables base (`.env.example`)

```env
SMTP_HOST=
SMTP_PORT=
SMTP_USER=
SMTP_PASS=""
MAIL_FROM=
SIFEN_ENV=test
SIFEN_CERT_PATH=/secrets/cert.p12
SIFEN_CERT_PASSWORD=
SIFEN_USE_MTLS=true
SIFEN_CA_BUNDLE_PATH=/secrets/ca-bundle.pem
SIFEN_DEBUG_SOAP=0
SIFEN_VALIDATE_XSD=0
SIFEN_SOAP_COMPAT=
SIFEN_WEBUI_DB=/data/webui.db
ARTIFACTS_DIR=/data/artifacts
```

## Comandos Make

```bash
make up
make down
make logs
make shell
make test
make check-env
```

### Envío y consulta

Enviar a test (usa `latest` por defecto):

```bash
make send-test
```

Enviar un XML específico:

```bash
make send-test XML=/data/artifacts/mi_rde.xml
```

Poll test con protocolo:

```bash
make poll-test PROTO=47353168697912368
```

Los resultados del poll se guardan en directorios de corrida bajo `/data/artifacts` (contenedor), que en host corresponden a `./data/artifacts/run_*`.

Producción:

```bash
make send-prod XML=/data/artifacts/mi_rde.xml
make poll-prod PROTO=47353168697912368
```

### Flujo recomendado (send lote + poll)

Mac/local (host):

```bash
make send-test XML=data/artifacts/mi_rde.xml
make poll-test PROTO=<DPROTCONSLOTE> RETRIES=6 SLEEP=10
ls -lah data/artifacts/run_*
```

En Docker, `tools/consulta_lote_poll.py` y `tools/consulta_lote_de.py` usan por defecto `SIFEN_ARTIFACTS_DIR`, luego `ARTIFACTS_DIR`, y luego `/data/artifacts`.

### WebUI + artifacts compartidos

La WebUI usa la misma raíz de artifacts que CLI/minisender:

- `SIFEN_ARTIFACTS_DIR` (prioridad 1)
- `ARTIFACTS_DIR` (prioridad 2)
- fallback local: `./data/artifacts`

Esto permite que la WebUI pueda leer resultados del `tools/smoke.py` y de consultas/poll sin hacks de rutas.

## UX de `latest`

`tools/send_sirecepde.py --xml latest` busca `sirecepde_*.xml` en el directorio de artifacts.

Si no existe ninguno:

- usar XML explícito (`--xml /ruta/al/rde.xml`), o
- generar base de ejemplo:

```bash
make sample-xml
```

Helper directo:

```bash
python3 -m tools.prepare_xml_latest --xml latest --artifacts-dir /data/artifacts
```

## Artifacts, debug y dump HTTP

Artifacts persistentes:

- `./data/artifacts`

Activar trazas SOAP/debug en `.env`:

```env
SIFEN_DEBUG_SOAP=1
SIFEN_VALIDATE_XSD=1
```

Luego volver a ejecutar `make send-test` o `make send-prod`.

## Seguridad

- No commitear `.env` real.
- No commitear contenido de `secrets/`.
- Si se filtró una credencial/certificado, rotar inmediatamente.
