#!/usr/bin/env bash
set -euo pipefail

ENV="${1:-test}"
PROT="${2:-47353168698201554}"

OUTDIR="data/artifacts/run_$(date +%Y%m%d_%H%M%S)_smoke_consulta_lote_${ENV}_${PROT}"
mkdir -p "$OUTDIR"

echo "OUTDIR=$OUTDIR"

docker compose run --rm cli sh -lc \
"python3 tools/consulta_lote_de.py --env '$ENV' --prot '$PROT' --dump-http --artifacts-dir '/data/artifacts/$(basename "$OUTDIR")' || true"

META="$OUTDIR/soap_last_response.meta.json"
HDR="$OUTDIR/soap_last_response.headers.json"
PRE="$OUTDIR/soap_invalid_response_preview.txt"

if [ -f "$META" ] && grep -q '"content_type": "text/html' "$META"; then
  echo "❌ REGRESIÓN: consulta_lote devolvió HTML (BIG-IP/F5). Ver:"
  echo "  $META"
  echo "  $HDR"
  [ -f "$PRE" ] && echo "  $PRE"
  exit 2
fi

echo "✅ OK: no se detectó HTML. (Si igual falló por otra razón, revisá OUTDIR)"
