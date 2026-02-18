#!/usr/bin/env bash
set -euo pipefail

TARGET_UID="${UID:-1000}"
TARGET_GID="${GID:-1000}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DATA_DIR="${REPO_ROOT}/data"

run_with_optional_sudo() {
  if "$@"; then
    return 0
  fi
  if command -v sudo >/dev/null 2>&1; then
    sudo "$@" || true
    return 0
  fi
  return 0
}

maybe_chown() {
  local path="$1"
  local recursive="${2:-false}"
  if [ ! -e "${path}" ]; then
    return 0
  fi
  if [ "${recursive}" = "true" ]; then
    run_with_optional_sudo chown -R "${TARGET_UID}:${TARGET_GID}" "${path}"
  else
    run_with_optional_sudo chown "${TARGET_UID}:${TARGET_GID}" "${path}"
  fi
}

maybe_chmod() {
  local mode="$1"
  local path="$2"
  if [ ! -e "${path}" ]; then
    return 0
  fi
  run_with_optional_sudo chmod "${mode}" "${path}"
}

mkdir -p "${DATA_DIR}"

maybe_chown "${DATA_DIR}" true
maybe_chmod 775 "${DATA_DIR}"

maybe_chown "${DATA_DIR}/webui.db"
maybe_chmod 664 "${DATA_DIR}/webui.db"

maybe_chown "${DATA_DIR}/logs" true
maybe_chmod 775 "${DATA_DIR}/logs"

maybe_chown "${DATA_DIR}/artifacts" true
maybe_chmod 775 "${DATA_DIR}/artifacts"

echo "== ./data =="
ls -la "${DATA_DIR}" || true
echo
echo "== ./data/webui.db =="
ls -la "${DATA_DIR}/webui.db" || true
