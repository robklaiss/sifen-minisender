#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/app"
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

if [[ "$#" -gt 0 ]]; then
  case "$1" in
    help|-h|--help)
      cat <<'EOF'
Usage:
  docker run ... <command>

Examples:
  python -m tools.send_sirecepde --help
  python -m tools.consulta_lote_poll --help
  python -m tools.test_smtp_pdf_flow --dry-run

Default behavior:
  - If /app/webui/app.py exists, starts gunicorn webui on WEBUI_HOST:WEBUI_PORT.
  - Otherwise prints this help.
EOF
      exit 0
      ;;
    webui)
      shift
      exec gunicorn \
        --bind "${WEBUI_HOST}:${WEBUI_PORT}" \
        --workers "${WEBUI_WORKERS}" \
        --threads "${WEBUI_THREADS}" \
        --timeout "${WEBUI_TIMEOUT}" \
        --access-logfile - \
        --error-logfile - \
        --chdir "$APP_DIR" \
        "webui.app:app"
      ;;
    *)
      exec "$@"
      ;;
  esac
fi

if [[ -f "$APP_DIR/webui/app.py" ]]; then
  exec gunicorn \
    --bind "${WEBUI_HOST}:${WEBUI_PORT}" \
    --workers "${WEBUI_WORKERS}" \
    --threads "${WEBUI_THREADS}" \
    --timeout "${WEBUI_TIMEOUT}" \
    --access-logfile - \
    --error-logfile - \
    --chdir "$APP_DIR" \
    "webui.app:app"
fi

cat <<'EOF'
No command provided and /app/webui/app.py was not found.
Try:
  python -m tools.send_sirecepde --help
  python -m tools.consulta_lote_poll --help
  python -m tools.test_smtp_pdf_flow --dry-run
EOF
exit 0
