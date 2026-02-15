#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Uso:
  scripts/run_docker_local.sh <accion>

Acciones:
  build          Construye la imagen.
  up             Levanta servicio en background.
  down           Baja servicio.
  logs           Sigue logs del servicio.
  dry-run        Ejecuta test SMTP/PDF dry-run dentro del contenedor.
  send-help      Muestra ayuda de tools.send_sirecepde.
  poll-help      Muestra ayuda de tools.consulta_lote_poll.
EOF
}

action="${1:-}"

case "$action" in
  build)
    docker compose build
    ;;
  up)
    docker compose up -d
    docker compose ps
    ;;
  down)
    docker compose down
    ;;
  logs)
    docker compose logs -f --tail=200 sifen-minisender
    ;;
  dry-run)
    docker compose run --rm sifen-minisender python -m tools.test_smtp_pdf_flow --dry-run
    ;;
  send-help)
    docker compose run --rm sifen-minisender python -m tools.send_sirecepde --help
    ;;
  poll-help)
    docker compose run --rm sifen-minisender python -m tools.consulta_lote_poll --help
    ;;
  *)
    usage
    exit 1
    ;;
esac
