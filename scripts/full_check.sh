#!/usr/bin/env bash
set -euo pipefail
INVOICE_ID="${1:-5}"

echo "== full-check: invoice ${INVOICE_ID} =="

echo
echo "== 1) smoke (dry-run XSD) =="
./scripts/smoke.sh "${INVOICE_ID}"

echo
echo "== 2) invariants (CDC/DV/QR/PYG/order) =="
INVOICE_ID="${INVOICE_ID}" python3 ./scripts/full_check.py

echo
echo "✅ DONE: FULL CHECK OK"
