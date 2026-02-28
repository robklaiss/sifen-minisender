#!/usr/bin/env bash
set -euo pipefail

bash ops/guardrails/pre_deploy_check.sh

git pull --ff-only
docker compose up -d --build web
docker compose restart web

bash ops/guardrails/pre_deploy_check.sh

echo "OK: deploy_safe completed."
