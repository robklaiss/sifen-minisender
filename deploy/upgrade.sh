#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/sifen-minisender-2"
APP_USER="sifen"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app-dir) APP_DIR="$2"; shift 2 ;;
    --app-user) APP_USER="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

echo "==> Pulling latest code..."
sudo -u "$APP_USER" bash -lc "cd '$APP_DIR' && git pull"

echo "==> Updating dependencies..."
sudo -u "$APP_USER" bash -lc "cd '$APP_DIR' && . .venv/bin/activate && pip install -r requirements.txt"

echo "==> Restarting service..."
systemctl restart sifen-webui
systemctl status sifen-webui --no-pager -l
