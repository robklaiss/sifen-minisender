#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/sifen-minisender"
PORT="5055"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app-dir) APP_DIR="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

echo "==> systemd status"
systemctl is-active --quiet sifen-webui && echo "sifen-webui: active" || (echo "sifen-webui: inactive" && exit 1)

echo "==> local port"
ss -lnt | grep -q ":${PORT} " && echo "port ${PORT}: listening" || (echo "port ${PORT}: not listening" && exit 1)

echo "==> db path"
if [[ -f "${APP_DIR}/webui/data.db" ]]; then
  echo "db: ${APP_DIR}/webui/data.db"
else
  echo "db: not found"
fi

echo "==> curl localhost"
curl -sSf "http://127.0.0.1:${PORT}/" >/dev/null && echo "http: ok" || (echo "http: fail" && exit 1)

echo "OK"
