# Docker + EC2 (Ubuntu) para sifen-minisender

Este flujo deja un deploy simple en EC2, manteniendo artifacts persistentes y secretos fuera de la imagen.

## 1) Instalar Docker + Compose (Ubuntu 22.04/24.04)

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
newgrp docker
docker --version
docker compose version
```

## 2) Clonar repo en `/opt/sifen-minisender`

```bash
sudo mkdir -p /opt/sifen-minisender
sudo chown -R "$USER":"$USER" /opt/sifen-minisender
git clone <URL-REPO> /opt/sifen-minisender
cd /opt/sifen-minisender
```

## 3) Cargar `.env` y secretos

1. Crear/copiar `.env` productivo en `/opt/sifen-minisender/.env`.
2. Crear carpeta de secretos:

```bash
mkdir -p /opt/sifen-minisender/secrets
chmod 700 /opt/sifen-minisender/secrets
```

3. Copiar certificados mTLS requeridos por runtime:
   - `/opt/sifen-minisender/secrets/cert.pem`
   - `/opt/sifen-minisender/secrets/key.pem`

```bash
chmod 600 /opt/sifen-minisender/secrets/cert.pem /opt/sifen-minisender/secrets/key.pem
```

Notas:
- El `docker-compose.yml` fija en runtime:
  - `SIFEN_CERT_PATH` y `SIFEN_KEY_PATH` desde `.env` apuntando al volumen `/secrets`
- Artifacts persisten en `./data/artifacts` (host) montado como `/data/artifacts` (contenedor).
- `./secrets` se monta read-only como `/secrets`.
- WebUI usa por defecto `sys.executable` para correr `sifen_minisender` (no requiere `/app/.venv`).
- Override opcional: `MINISENDER_PY=/usr/bin/python3` (o `WEBUI_MINISENDER_PY`) en `.env`.

## Fix: SQLite readonly (`webui.db`)

El contenedor corre con `user: "${UID:-1000}:${GID:-1000}"`. El host debe permitir escritura de ese UID/GID sobre `./data` y `./data/webui.db` (incluyendo archivos WAL/SHM que crea SQLite).

En EC2:

```bash
cd /opt/sifen-minisender
export UID=1000 GID=1000
./scripts/fix_data_perms.sh
sudo docker compose up -d --build
```

## 4) Build + run del servicio

```bash
cd /opt/sifen-minisender
docker compose build
docker compose up -d
docker compose ps
docker compose logs -f --tail=200 web
```

Para override rápido de destinatario:

```bash
SIFEN_EMAIL_TO=destino@empresa.com docker compose up -d
```

## 5) Dry-run SMTP/PDF dentro del contenedor

```bash
cd /opt/sifen-minisender
docker compose run --rm cli "python3 -m tools.test_smtp_pdf_flow --dry-run"
```

Esperado: generación de PDF en `/data/artifacts/test_smtp/post_consulta_lote/<CDC>/invoice_<CDC>.pdf`
(host: `/opt/sifen-minisender/data/artifacts/test_smtp/...`).

## 6) Envío real + poll dentro del contenedor

Enviar `siRecepLoteDE`:

```bash
cd /opt/sifen-minisender
make send-test XML=/data/artifacts/archivo_firmado.xml
```

Consultar lote y disparar `post_consulta_lote`:

```bash
cd /opt/sifen-minisender
make poll-test PROTO=<DPROTCONSLOTE> RETRIES=6 SLEEP=10
```

En PROD reemplazar `--env test` por `--env prod`.

Comandos equivalentes en PROD:

```bash
cd /opt/sifen-minisender
make send-prod XML=/data/artifacts/archivo_firmado.xml
make poll-prod PROTO=<DPROTCONSLOTE> RETRIES=6 SLEEP=10
```

Artifacts de cada corrida se guardan en host en:

```bash
ls -lah /opt/sifen-minisender/data/artifacts/run_*
```

## 7) Deploy simple en EC2 (script)

Se incluye script copy/paste:

```bash
cd /opt/sifen-minisender
bash scripts/deploy_ec2.sh
```

El script ejecuta:
1. `git pull --ff-only`
2. `docker compose build`
3. `docker compose up -d`
4. `docker compose logs -f --tail=200`
