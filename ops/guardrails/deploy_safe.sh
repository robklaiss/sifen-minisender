#!/usr/bin/env bash
set -euo pipefail

git config --global --add safe.directory "$(pwd)" || true

COMPOSE="sudo docker compose -f docker-compose.yml -f docker-compose.prod.yml"
$COMPOSE config >/dev/null

bash ops/guardrails/pre_deploy_check.sh

git pull --ff-only
$COMPOSE up -d --build
sleep 2
bash ops/guardrails/pre_deploy_check.sh
$COMPOSE up -d --build

bash ops/guardrails/pre_deploy_check.sh

echo "OK: deploy_safe completed."

# Post-deploy: smoke iTiDE (5 docs)
bash ops/guardrails/smoke_itide.sh
