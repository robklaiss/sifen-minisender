#!/usr/bin/env bash
set -euo pipefail
cd /Users/robinklaiss/Dev/sifen-minisender-2
set -a; [ -f .env ] && source .env; set +a

export SIFEN_CONFIRM_PROD=YES
export SIFEN_EMAIL_TO="robin@vinculo.com.py"
export SMTP_DEBUG=1

# Passwords (requeridos para firmar)
export SIFEN_CERT_PASSWORD="${SIFEN_CERT_PASSWORD:-}"
export SIFEN_SIGN_P12_PASSWORD="${SIFEN_SIGN_P12_PASSWORD:-$SIFEN_CERT_PASSWORD}"

# Ajustá SOLO si tus rutas cambian
export SIFEN_CERT_PATH="/Users/robinklaiss/Dev/sifen-minisender-2/secrets/cert.pem"
export SIFEN_KEY_PATH="/Users/robinklaiss/Dev/sifen-minisender-2/secrets/key.pem"
P12=$(ls -1 /Users/robinklaiss/Dev/sifen-minisender-2/secrets/*.p12 2>/dev/null | head -n 1)
echo "P12=$P12"; test -n "$P12"
export SIFEN_SIGN_P12_PATH="$P12"

BASE_XML="artifacts/run_20260214_162627/xml_bumped_1162627_20260214_162627.xml"
NEXT_DOC=$(date +%H%M%S); echo "BUMP_DOC=$NEXT_DOC"

./.venv/bin/python -m tools.send_sirecepde --env prod --xml "$BASE_XML" --bump-doc "$NEXT_DOC"

LAST=$(ls -1dt artifacts/run_* 2>/dev/null | head -n 1); echo "LAST_RUN=$LAST"
PROT=$(rg -o "response_dProtConsLote\"\\s*:\\s*\"[0-9]+\"" -m 1 "$LAST"/response_recepcion_*.json | rg -o "[0-9]+" | head -n 1)
echo "PROT=$PROT"; test -n "$PROT"

./.venv/bin/python -m tools.consulta_lote_poll --env prod --prot "$PROT" --retries 8 --sleep 10 --email-to "robin@vinculo.com.py"
