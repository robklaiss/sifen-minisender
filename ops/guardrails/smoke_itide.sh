#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8000}"
TMP="${TMP:-/tmp/smoke_itide.json}"

curl -fsS -X POST "${BASE_URL}/api/smoke" \
  -H "Content-Type: application/json" \
  -d "{}" > "$TMP"

python3 - <<'PY'
import json, sys
from pathlib import Path

j = json.loads(Path("/tmp/smoke_itide.json").read_text(encoding="utf-8"))
dry = (j.get("dry_run") or {})

expected = [
  "Factura electrónica",
  "Autofactura electrónica",
  "Nota de crédito electrónica",
  "Nota de débito electrónica",
  "Nota de remisión electrónica",
]

missing = [k for k in expected if k not in dry]
if missing:
  print("FAIL: faltan keys en dry_run:", missing)
  sys.exit(2)

def must_true(doc, name, key):
  if not bool(doc.get(key)):
    raise SystemExit(f"FAIL: {name}: {key}=False")

for name in expected:
  doc = dry.get(name) or {}
  must_true(doc, name, "ok")
  must_true(doc, name, "qr_ok")
  must_true(doc, name, "qty_decimal_ok")
  must_true(doc, name, "timbrado_override_ok")

  cdc_tail = doc.get("cdc_tail")
  warn_n = len(doc.get("warnings") or [])
  print("OK:", name, "cdc_tail=", cdc_tail, "warnings=", warn_n)

print("✅ SMOKE iTiDE OK (5/5)")
PY
