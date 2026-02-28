#!/usr/bin/env bash
set -euo pipefail

git config --global --add safe.directory "$(pwd)" || true

bash ops/guardrails/pre_deploy_check.sh

git pull --ff-only
docker compose up -d --build web
sleep 2
bash ops/guardrails/pre_deploy_check.sh
docker compose restart web

bash ops/guardrails/pre_deploy_check.sh

echo "OK: deploy_safe completed."

# Post-deploy: smoke iTiDE (5 docs)
bash ops/guardrails/smoke_itide.sh
