#!/usr/bin/env bash
set -euo pipefail

./.venv/bin/python -m pytest -q || python3 -m pytest -q

if make -qp | rg -q "^full_check:"; then
  make full_check
else
  echo "WARN: make full_check target not found; skipping"
fi

echo "OK: pre-push guardrails passed"
