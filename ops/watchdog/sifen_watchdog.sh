#!/usr/bin/env bash
set -euo pipefail

# EC2 paths
APP_DIR="/opt/sifen-minisender"
URL="${SIFEN_WATCHDOG_URL:-http://127.0.0.1:8000/health}"
STATE="/var/run/sifen_watchdog_failcount"
MAX_FAILS="${SIFEN_WATCHDOG_MAX_FAILS:-3}"

failcount=0
if [[ -f "$STATE" ]]; then
  failcount="$(cat "$STATE" 2>/dev/null || echo 0)"
fi

# health check (3s hard timeout)
if curl -fsS --max-time 3 "$URL" >/dev/null; then
  echo 0 > "$STATE"
  exit 0
fi

failcount=$((failcount+1))
echo "$failcount" > "$STATE"

logger -t sifen_watchdog "health FAILED ($failcount/$MAX_FAILS) url=$URL"

if [[ "$failcount" -ge "$MAX_FAILS" ]]; then
  logger -t sifen_watchdog "restarting web via docker compose (failcount=$failcount)"
  cd "$APP_DIR"
  docker compose restart web || docker compose up -d --force-recreate web
  echo 0 > "$STATE"
fi
