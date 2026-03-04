#!/usr/bin/env bash
set -euo pipefail

CERT="${CERT:-/opt/sifen-minisender/secrets/cert.pem}"
KEY="${KEY:-/opt/sifen-minisender/secrets/key.pem}"

# Endpoint barato para chequear conectividad mTLS (puede ser consulta.wsdl)
URL="${URL:-https://sifen.set.gov.py/de/ws/consultas/consulta.wsdl}"

# timeouts cortos para no colgar emisión
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
MAX_TIME="${MAX_TIME:-8}"

# 0=OK, 1=DOWN
code="$(
  curl -sS --cert "$CERT" --key "$KEY" \
    --connect-timeout "$CONNECT_TIMEOUT" -m "$MAX_TIME" \
    -o /dev/null -w "%{http_code}" \
    "$URL" || echo "000"
)"

# consideramos OK solo 200 (WSDL) — 302 BigIP/hangup es FAIL
if [[ "$code" == "200" ]]; then
  echo "SIFEN_OK http=$code url=$URL"
  exit 0
fi

echo "SIFEN_DOWN http=$code url=$URL"
exit 1
