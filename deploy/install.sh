#!/usr/bin/env bash
set -euo pipefail

APP_USER="sifen"
APP_DIR="/opt/sifen-minisender"
DOMAIN=""
EMAIL=""
REPO_URL=""

usage() {
  echo "Usage: sudo bash deploy/install.sh --domain DOMAIN --email EMAIL [--repo REPO_URL] [--app-dir DIR] [--app-user USER]"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --email) EMAIL="$2"; shift 2 ;;
    --repo) REPO_URL="$2"; shift 2 ;;
    --app-dir) APP_DIR="$2"; shift 2 ;;
    --app-user) APP_USER="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "$DOMAIN" || -z "$EMAIL" ]]; then
  echo "ERROR: --domain and --email are required."
  usage
  exit 1
fi

echo "==> Installing OS deps..."
apt-get update
apt-get install -y \
  git nginx certbot python3-certbot-nginx \
  python3-venv python3-dev build-essential \
  libxml2-dev libxmlsec1-dev libxmlsec1-openssl \
  xmlsec1 libssl-dev libffi-dev pkg-config

echo "==> Creating user $APP_USER (if missing)..."
if ! id -u "$APP_USER" >/dev/null 2>&1; then
  useradd -m -s /bin/bash "$APP_USER"
fi

echo "==> Preparing app dir: $APP_DIR"
if [[ ! -d "$APP_DIR" ]]; then
  if [[ -z "$REPO_URL" ]]; then
    echo "ERROR: $APP_DIR doesn't exist and --repo not provided."
    exit 1
  fi
  git clone "$REPO_URL" "$APP_DIR"
fi

chown -R "$APP_USER":"$APP_USER" "$APP_DIR"

echo "==> Creating venv + installing requirements..."
sudo -u "$APP_USER" bash -lc "
  cd '$APP_DIR' &&
  python3 -m venv .venv &&
  . .venv/bin/activate &&
  pip install --upgrade pip &&
  pip install -r requirements.txt
"

echo "==> Creating runtime dirs"
mkdir -p "$APP_DIR/artifacts" "$APP_DIR/backups" "$APP_DIR/assets" "$APP_DIR/secrets"
chown -R "$APP_USER":"$APP_USER" "$APP_DIR/artifacts" "$APP_DIR/backups" "$APP_DIR/assets" "$APP_DIR/secrets"
chmod 700 "$APP_DIR/secrets"

if [[ ! -f "$APP_DIR/.env" ]]; then
  echo "==> Creating .env from template"
  cp "$APP_DIR/deploy/env.template" "$APP_DIR/.env"
  chown "$APP_USER":"$APP_USER" "$APP_DIR/.env"
fi

echo "==> Installing systemd service"
SERVICE_SRC="$APP_DIR/deploy/sifen-webui.service"
SERVICE_DST="/etc/systemd/system/sifen-webui.service"
sed -e "s|__APP_USER__|$APP_USER|g" -e "s|__APP_DIR__|$APP_DIR|g" "$SERVICE_SRC" > "$SERVICE_DST"
systemctl daemon-reload
systemctl enable --now sifen-webui

echo "==> Configuring nginx site"
NGINX_SITE="/etc/nginx/sites-available/sifen-webui"
sed -e "s|__DOMAIN__|$DOMAIN|g" "$APP_DIR/deploy/nginx-site.conf.template" > "$NGINX_SITE"
ln -sf "$NGINX_SITE" /etc/nginx/sites-enabled/sifen-webui
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

echo "==> Issuing HTTPS certificate (certbot)"
certbot --nginx -d "$DOMAIN" -m "$EMAIL" --agree-tos --non-interactive

echo "==> Done. Check:"
echo "    - systemctl status sifen-webui"
echo "    - journalctl -u sifen-webui -f"
echo "    - nginx status"
echo "    - https://$DOMAIN"
