#!/usr/bin/env bash
set -euo pipefail

CERT="${CERT:-/opt/sifen-minisender/secrets/cert.pem}"
KEY="${KEY:-/opt/sifen-minisender/secrets/key.pem}"
URL="${URL:-https://sifen.set.gov.py/de/ws/consultas/consulta.wsdl}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
MAX_TIME="${MAX_TIME:-8}"

HDR="$(mktemp)"
BODY="$(mktemp)"
trap "rm -f \"$HDR\" \"$BODY\"" EXIT

code="$(curl -sS --cert "$CERT" --key "$KEY" \
  --connect-timeout "$CONNECT_TIMEOUT" -m "$MAX_TIME" \
  -D "$HDR" -o "$BODY" -w "%{http_code}" \
  "$URL" || echo "000")"

loc="$(grep -i "^Location:" "$HDR" | head -n 1 | sed "s/^[Ll]ocation:[[:space:]]*//" | tr -d "\r" || true)"
srv="$(grep -i "^Server:" "$HDR" | head -n 1 | sed "s/^[Ss]erver:[[:space:]]*//" | tr -d "\r" || true)"

# Detect HTML BIG-IP
if grep -qi "BIG-IP" "$BODY" 2>/dev/null; then
  echo "SIFEN_DOWN reason=BIGIP http=$code server=${srv:-?} location=${loc:-?} url=$URL"
  exit 1
fi

if [[ "$code" == "200" ]]; then
  echo "SIFEN_OK http=$code url=$URL"
  exit 0
fi

echo "SIFEN_DOWN http=$code server=${srv:-?} location=${loc:-?} url=$URL"
exit 1
