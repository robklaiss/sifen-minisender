#!/usr/bin/env bash
set -euo pipefail

COMPOSE="/opt/sifen-minisender/docker-compose.prod.yml"
APP="sifen-webui"
IMAGE="sifen-minise:prod"

ts() { date +%Y%m%d_%H%M%S; }

echo "==> [1/7] Pre-check"
cd /opt/sifen-minisender
test -f "$COMPOSE" || { echo "Falta $COMPOSE"; exit 1; }

echo "==> [2/7] Backup DB + artifacts"
mkdir -p prod/backups
if [ -f prod/webui/data.db ]; then
  cp -a "prod/webui/data.db" "prod/backups/data.db.$(ts).bak"
  echo "DB backup: prod/backups/data.db.$(ts).bak (ok)"
else
  echo "No hay prod/webui/data.db (salto backup DB)"
fi

if [ -d prod/artifacts ]; then
  tar -czf "prod/backups/artifacts.$(ts).tgz" -C prod artifacts >/dev/null 2>&1 || true
  echo "Artifacts backup: prod/backups/artifacts.$(ts).tgz (ok/skip warnings)"
fi

echo "==> [3/7] Guardar imagen previa (para rollback)"
PREV_ID="$(docker image inspect -f '{{.Id}}' "$IMAGE" 2>/dev/null || true)"
echo "Prev image id: ${PREV_ID:-<none>}"

echo "==> [4/7] Build nueva imagen"
docker build -t "$IMAGE" .

echo "==> [5/7] Up con compose"
docker compose -f "$COMPOSE" up -d

echo "==> [6/7] Esperar HEALTHY"
ok=""
for i in $(seq 1 40); do
  h="$(docker inspect --format='{{.State.Health.Status}}' "$APP" 2>/dev/null || true)"
  echo "  - health: ${h:-<none>} (try $i/40)"
  if [ "$h" = "healthy" ]; then ok="yes"; break; fi
  sleep 2
done

echo "==> [7/7] Verificar endpoint"
if [ "$ok" = "yes" ] && curl -fsSI http://127.0.0.1:5055/invoices >/dev/null; then
  echo "✅ DEPLOY OK: healthy + /invoices responde"
  exit 0
fi

echo "❌ DEPLOY FALLÓ: mostrando logs..."
docker logs --tail=200 "$APP" || true

if [ -n "${PREV_ID:-}" ]; then
  echo "==> Rollback: volviendo a imagen previa ($PREV_ID)"
  docker tag "$PREV_ID" "$IMAGE" || true
  docker compose -f "$COMPOSE" up -d || true
  docker inspect --format='{{.State.Health.Status}}' "$APP" || true
  echo "Rollback aplicado (revisar logs si sigue mal)."
else
  echo "No hay imagen previa para rollback."
fi

exit 1
