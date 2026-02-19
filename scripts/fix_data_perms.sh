#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

TARGET_UID="${TARGET_UID:-${PUID:-$(id -u)}}"
TARGET_GID="${TARGET_GID:-${PGID:-$(id -g)}}"

mkdir -p ./data ./data/logs ./data/artifacts

chown -R "${TARGET_UID}:${TARGET_GID}" ./data

chmod 775 ./data ./data/logs ./data/artifacts

if [ -f ./data/webui.db ]; then
  chmod 664 ./data/webui.db
fi

if [ -f ./data/webui.db-wal ]; then
  chmod 664 ./data/webui.db-wal
fi

if [ -f ./data/webui.db-shm ]; then
  chmod 664 ./data/webui.db-shm
fi

ls -la data data/webui.db* || true
