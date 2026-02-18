#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

mkdir -p ./data ./data/logs ./data/artifacts

chown -R "${UID:-1000}:${GID:-1000}" ./data

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
