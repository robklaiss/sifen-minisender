#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${PWD}" != "${REPO_ROOT}" ]]; then
  echo "ERROR: Run this script from repo root: ${REPO_ROOT}" >&2
  exit 3
fi

DB_PATH="data/webui.db"
UPLOAD_LOGO="data/uploads/issuer-logo.jpg"
BASE_URL="http://127.0.0.1:8000"

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "ERROR: sqlite3 not found. Install sqlite3 to run pre-deploy checks." >&2
  exit 2
fi

if [[ ! -f "${DB_PATH}" ]]; then
  echo "ERROR: Missing database file: ${DB_PATH}. Create/restore it before deploy." >&2
  exit 10
fi

invoice_count="$(sqlite3 "${DB_PATH}" "SELECT COUNT(*) FROM invoices;" 2>/dev/null || true)"
if [[ -z "${invoice_count}" || ! "${invoice_count}" =~ ^[0-9]+$ ]]; then
  echo "ERROR: Unable to read invoices count from ${DB_PATH}. Ensure it is a valid DB with the invoices table." >&2
  exit 10
fi
if [[ "${invoice_count}" -lt 1 ]]; then
  echo "ERROR: invoices table is empty (count=${invoice_count})." >&2
  exit 10
fi

if [[ ! -f "${UPLOAD_LOGO}" ]]; then
  echo "ERROR: Missing issuer logo file: ${UPLOAD_LOGO}. Add it before deploy." >&2
  exit 11
fi
if [[ ! -s "${UPLOAD_LOGO}" ]]; then
  echo "ERROR: Issuer logo is empty: ${UPLOAD_LOGO}. Replace it with a non-empty file." >&2
  exit 11
fi

if ! docker compose exec -T web sh -lc 'test -s /app/data/webui.db'; then
  echo "ERROR: Container cannot see non-empty /app/data/webui.db. Verify volume mounts and file permissions (do not auto-fix here)." >&2
  exit 12
fi

if ! docker compose exec -T web sh -lc 'test -s /app/data/uploads/issuer-logo.jpg'; then
  echo "ERROR: Container cannot see non-empty /app/data/uploads/issuer-logo.jpg. Verify volume mounts and file permissions (do not auto-fix here)." >&2
  exit 13
fi

retry_http_200() {
  local url="$1"
  local tries="${2:-15}"
  local sleep_sec="${3:-1}"
  local code=""
  local i

  for i in $(seq 1 "${tries}"); do
    code="$(curl -sS -o /dev/null -w "%{http_code}" "${url}" || true)"
    if [[ "${code}" == "200" ]]; then
      echo "OK: ${url} -> ${code}"
      return 0
    fi
    echo "WAIT ${url} -> ${code} (try ${i}/${tries})"
    sleep "${sleep_sec}"
  done

  echo "FAIL ${url} -> ${code}" >&2
  return 1
}

retry_http_200 "${BASE_URL}/health" 15 1
retry_http_200 "${BASE_URL}/invoices" 15 1
retry_http_200 "${BASE_URL}/assets/issuer-logo" 15 1

echo "OK: pre-deploy checks passed."
