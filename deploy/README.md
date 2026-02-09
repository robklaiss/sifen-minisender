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
  --repo https://github.com/tu-org/sifen-minisender-2.git
```

Si ya clonaste el repo en `/opt/sifen-minisender-2`, omití `--repo`.

## Archivos
- `install.sh`: instala dependencias, crea usuario, venv, systemd, nginx y certbot.
- `upgrade.sh`: actualiza repo + dependencias y reinicia servicio.
- `healthcheck.sh`: verifica servicio, puerto local y rutas clave.
- `sifen-webui.service`: unidad systemd (plantilla).
- `nginx-site.conf.template`: site Nginx (plantilla).
- `env.template`: plantilla de variables sensibles.

## Notas
- La app escucha en `127.0.0.1:5055` y Nginx publica en 80/443.
- Asegurate de cargar certificados (mTLS + firma) en `/etc/sifen/certs` con permisos 600.
- `SIFEN_SIGN_P12_PATH`, `SIFEN_CERT_PATH` y `SIFEN_KEY_PATH` deben apuntar a esos archivos.
