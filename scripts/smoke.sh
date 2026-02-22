#!/usr/bin/env bash
set -euo pipefail

INVOICE_ID="${1:-5}"
WEB_PORT="${WEB_PORT:-8000}"

echo "== smoke: dry-run invoice ${INVOICE_ID} =="

sudo docker compose exec -T web python3 - <<PY
import json, urllib.request, urllib.error, sys

invoice_id = int("${INVOICE_ID}")
url = f"http://127.0.0.1:${WEB_PORT}/api/invoices/{invoice_id}/dry-run"
data = json.dumps({"persist_source_xml": True}).encode("utf-8")

req = urllib.request.Request(
    url,
    data=data,
    method="POST",
    headers={"Content-Type":"application/json"}
)

try:
    with urllib.request.urlopen(req, timeout=90) as r:
        out = json.loads(r.read().decode("utf-8","replace"))
        ok = bool(out.get("ok"))
        xsd_ok = bool(out.get("xsd_ok"))
        print("HTTP=", r.status)
        print("ok=", ok, "xsd_ok=", xsd_ok)
        print("artifacts_dir=", out.get("artifacts_dir"))
        if not ok or not xsd_ok:
            print("error=", out.get("error"))
            if out.get("details"):
                print("details[0]=", out["details"][0])
            sys.exit(2)
except urllib.error.HTTPError as e:
    body = e.read().decode("utf-8","replace")
    print("HTTP=", e.code)
    print(body)
    sys.exit(3)
PY

echo "✅ SMOKE OK"
