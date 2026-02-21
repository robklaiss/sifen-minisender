# Deploy en AWS (EC2 simple)

Este directorio contiene scripts y plantillas para desplegar la WebUI en un EC2 Ubuntu.

## Requisitos
- Ubuntu 22.04 LTS
- Un dominio apuntando al EC2 (registro A)
- Puertos abiertos en el Security Group: 22, 80, 443
- Acceso saliente a `sifen.set.gov.py`, `sifen-test.set.gov.py`, `ekuatia.set.gov.py` y SMTP (587/465)

## Pasos rápidos
1) Subir el repo al EC2 (o configurar `REPO_URL` en el script).
2) Configurar `.env` seguro (ver `env.template`).
3) Ejecutar el instalador automático:

```bash
sudo bash deploy/install.sh \
  --domain TU_DOMINIO \
  --email TU_EMAIL \
  --repo https://github.com/tu-org/sifen-minisender.git
```

Si ya clonaste el repo en `/opt/sifen-minisender`, omití `--repo`.

## Opción Docker (recomendada para paridad con local)
Si querés correr exactamente la misma app con `.env`, `secrets/`, `assets/`, `artifacts/` y `backups/` del repo:

```bash
cd /opt/sifen-minisender
docker compose build
docker compose up -d
docker compose logs -f --tail=200
```

Notas:
- El contenedor expone `5055` y carga variables desde `/opt/sifen-minisender/.env`.
- `docker-compose.yml` monta todo el repo en el contenedor para mantener el mismo comportamiento que local.
- Para reiniciar: `docker compose restart`.
- Para actualizar código/dependencias: `git pull && docker compose build --no-cache && docker compose up -d`.

### Instalar Docker en Ubuntu 22.04
```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo $VERSION_CODENAME) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
```

## Archivos
- `install.sh`: instala dependencias, crea usuario, venv, systemd, nginx y certbot.
- `upgrade.sh`: actualiza repo + dependencias y reinicia servicio.
- `healthcheck.sh`: verifica servicio, puerto local y rutas clave.
- `sifen-webui.service`: unidad systemd (plantilla).
- `nginx-site.conf.template`: site Nginx (plantilla).
- `env.template`: plantilla de variables sensibles.

## Notas
- La app escucha en `127.0.0.1:5055` y Nginx publica en 80/443.
- Asegurate de cargar certificados (mTLS + firma) en `/opt/sifen-minisender/secrets` con permisos 600.
- `SIFEN_SIGN_P12_PATH`, `SIFEN_CERT_PATH` y `SIFEN_KEY_PATH` deben apuntar a esos archivos.

## ALB + Cognito (autenticación gestionada)
- La app NO implementa OAuth/OIDC directamente.
- El ALB valida Cognito y reenvía a la app ya autenticada.
- Los datos del usuario llegan en headers OIDC agregados por el ALB.
  - `x-amzn-oidc-identity`
  - `x-amzn-oidc-data`
  - `x-amzn-oidc-accesstoken`

### Detalles actuales
- ALB: `fe-if-alb`
- DNS: `fe-if-alb-902536846.sa-east-1.elb.amazonaws.com`
- ACM ARN: `arn:aws:acm:sa-east-1:105914556288:certificate/e63699f5-f875-4775-90d8-7a61a571c193`
- Cognito domain: `https://sa-east-1aemetxsur.auth.sa-east-1.amazoncognito.com`
- User Pool ID: `sa-east-1_AEMETxsUR`
- App Client ID: `6729u9gs4ua36ul6n5m1hl5lbl`
- Callback URL (ALB): `https://auth.fe.if.com.py/oauth2/idpresponse`
