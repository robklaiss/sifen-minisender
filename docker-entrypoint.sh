#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/sifen-minisender"
cd "$APP_DIR"

if [[ -f "$APP_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$APP_DIR/.env"
  set +a
fi

mkdir -p "$APP_DIR/artifacts" "$APP_DIR/backups" "$APP_DIR/secrets" "$APP_DIR/assets"

if [[ -n "${SIFEN_WEBUI_DB:-}" ]]; then
  mkdir -p "$(dirname "$SIFEN_WEBUI_DB")"
fi

: "${WEBUI_HOST:=0.0.0.0}"
: "${WEBUI_PORT:=5055}"
: "${WEBUI_WORKERS:=1}"
: "${WEBUI_THREADS:=2}"
: "${WEBUI_TIMEOUT:=120}"

exec gunicorn \
  --bind "${WEBUI_HOST}:${WEBUI_PORT}" \
  --workers "${WEBUI_WORKERS}" \
  --threads "${WEBUI_THREADS}" \
  --timeout "${WEBUI_TIMEOUT}" \
  --access-logfile - \
  --error-logfile - \
  --chdir "$APP_DIR" \
  "webui.app:app"
