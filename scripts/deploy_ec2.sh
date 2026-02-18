#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${1:-/opt/sifen-minisender}"

if [[ ! -d "$APP_DIR" ]]; then
  echo "ERROR: no existe el directorio: $APP_DIR" >&2
  exit 1
fi

cd "$APP_DIR"

echo "[1/4] git pull --ff-only"
git pull --ff-only

echo "[2/4] docker compose build"
docker compose build

echo "[3/4] docker compose up -d"
docker compose up -d

echo "[4/4] docker compose logs -f --tail=200"
docker compose logs -f --tail=200
