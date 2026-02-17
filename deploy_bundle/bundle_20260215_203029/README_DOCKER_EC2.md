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
  - `SIFEN_CERT_PATH=/app/secrets/cert.pem`
  - `SIFEN_KEY_PATH=/app/secrets/key.pem`
- Artifacts persisten en `./artifacts` montado como `/app/artifacts`.
- `./secrets` se monta read-only en `/app/secrets`.

## 4) Build + run del servicio

```bash
cd /opt/sifen-minisender
docker compose build
docker compose up -d
docker compose ps
docker compose logs -f --tail=200 sifen-minisender
```

Para override rápido de destinatario:

```bash
SIFEN_EMAIL_TO=destino@empresa.com docker compose up -d
```

## 5) Dry-run SMTP/PDF dentro del contenedor

```bash
cd /opt/sifen-minisender
docker compose run --rm sifen-minisender python -m tools.test_smtp_pdf_flow --dry-run
```

Esperado: generación de PDF en `/app/artifacts/test_smtp/post_consulta_lote/<CDC>/invoice_<CDC>.pdf`
(host: `/opt/sifen-minisender/artifacts/test_smtp/...`).

## 6) Envío real + poll dentro del contenedor

Enviar `siRecepLoteDE`:

```bash
cd /opt/sifen-minisender
docker compose run --rm sifen-minisender python -m tools.send_sirecepde --env test --xml artifacts/archivo_firmado.xml
```

Consultar lote y disparar `post_consulta_lote`:

```bash
cd /opt/sifen-minisender
docker compose run --rm sifen-minisender python -m tools.consulta_lote_poll --env test --prot <DPROTCONSLOTE> --retries 6 --sleep 10 --email-to "${SIFEN_EMAIL_TO}"
```

En PROD reemplazar `--env test` por `--env prod`.

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
