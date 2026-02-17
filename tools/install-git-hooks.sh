#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
HOOKS_SRC_DIR="${REPO_ROOT}/tools/git-hooks"
HOOKS_DST_DIR="${REPO_ROOT}/.git/hooks"

if [[ ! -d "$HOOKS_DST_DIR" ]]; then
  echo "No se encontró ${HOOKS_DST_DIR}. Ejecutá este script dentro de un repo git." >&2
  exit 1
fi

if [[ ! -d "$HOOKS_SRC_DIR" ]]; then
  echo "No se encontró ${HOOKS_SRC_DIR}" >&2
  exit 1
fi

installed=0
for hook in "$HOOKS_SRC_DIR"/*; do
  if [[ -f "$hook" ]]; then
    name="$(basename "$hook")"
    install -m 0755 "$hook" "${HOOKS_DST_DIR}/${name}"
    echo "Hook instalado: ${name}"
    installed=1
  fi
done

if [[ "$installed" -ne 1 ]]; then
  echo "No hay hooks para instalar en ${HOOKS_SRC_DIR}" >&2
  exit 1
fi

echo "Hooks instalados en ${HOOKS_DST_DIR}"
