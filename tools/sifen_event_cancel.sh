#!/usr/bin/env bash
set -euo pipefail

# ==========================================
# Evento: Cancelación (SIFEN)
# - Firma gGroupGesEve/rGesEve (Signature como hermano de rEve)
# - Wrapper SOAP: rEnviEventoDe (xsd:)
# ==========================================

# ===== EDITAR / O PASAR POR ENV =====
CDC="${CDC:-01000000000000000000000000000000000000000000}"   # 44 chars
MOTIVO="${MOTIVO:-Cancelación por error de carga}"
AMBIENTE="${AMBIENTE:-PROD}"  # PROD o TEST

# Paths (relativos al repo por defecto)
SECRETS_DIR="${SECRETS_DIR:-./secrets}"
CERT="${CERT:-$SECRETS_DIR/cert.pem}"
KEY="${KEY:-$SECRETS_DIR/key.pem}"

# Cadena para verificación local (opcional)
ISSUER_PEM="${ISSUER_PEM:-$SECRETS_DIR/documenta_issuer.pem}"
ROOT_PEM="${ROOT_PEM:-$SECRETS_DIR/paraguay_root.pem}"

# Directorio de trabajo (por defecto /tmp)
WORKDIR="${WORKDIR:-/tmp}"
# ==========================================

# Guards
if [[ ${#CDC} -ne 44 ]]; then
  echo "ERROR: CDC debe tener 44 caracteres. Tiene: ${#CDC}"
  echo "CDC=$CDC"
  exit 2
fi

test -s "$CERT" || { echo "ERROR: falta CERT=$CERT"; exit 2; }
test -s "$KEY"  || { echo "ERROR: falta KEY=$KEY"; exit 2; }

# Endpoint
if [[ "$AMBIENTE" == "PROD" ]]; then
  ENDPOINT="https://sifen.set.gov.py/de/ws/eventos/evento.wsdl"
elif [[ "$AMBIENTE" == "TEST" ]]; then
  ENDPOINT="https://sifen-test.set.gov.py/de/ws/eventos/evento.wsdl"
else
  echo "ERROR: AMBIENTE inválido: $AMBIENTE (usar PROD o TEST)"
  exit 2
fi

# Identificadores (dId <= 15 dígitos; rEve@Id <= 10 dígitos)
DID="$(date -u +%Y%m%d%H%M%S)"
EVE_ID="${DID: -10}"
EVE_ID="$(echo "$EVE_ID" | sed "s/^0*//")"
[[ -n "$EVE_ID" ]] || EVE_ID="1"

# Fecha firma (hora PY, sin timezone)
TS="$(TZ=America/Asuncion date +%Y-%m-%dT%H:%M:%S)"

REQ="$WORKDIR/sifen_cancel_event_to_sign.xml"
SIGNED="$WORKDIR/sifen_cancel_event_signed.xml"
SOAP="$WORKDIR/sifen_cancel_event_soap.xml"
OUT="$WORKDIR/sifen_cancel_event_out.xml"

echo "== sanity inputs =="
echo "AMBIENTE=$AMBIENTE"
echo "ENDPOINT=$ENDPOINT"
echo "CDC=$CDC"
echo "DID=$DID EVE_ID=$EVE_ID TS=$TS"
echo "CERT=$CERT"
echo "KEY=$KEY"
echo

cat > "$REQ" <<XML
<gGroupGesEve xmlns="http://ekuatia.set.gov.py/sifen/xsd"
              xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://ekuatia.set.gov.py/sifen/xsd siRecepEvento_v150.xsd">
  <rGesEve xsi:schemaLocation="http://ekuatia.set.gov.py/sifen/xsd siRecepEvento_v150.xsd">
    <rEve Id="${EVE_ID}">
      <dFecFirma>${TS}</dFecFirma>
      <dVerFor>150</dVerFor>
      <gGroupTiEvt>
        <rGeVeCan>
          <Id>${CDC}</Id>
          <mOtEve>${MOTIVO}</mOtEve>
        </rGeVeCan>
      </gGroupTiEvt>
    </rEve>

    <ds:Signature>
      <ds:SignedInfo>
        <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
        <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
        <ds:Reference URI="#${EVE_ID}">
          <ds:Transforms>
            <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
            <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
          </ds:Transforms>
          <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
          <ds:DigestValue></ds:DigestValue>
        </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue></ds:SignatureValue>
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate></ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </ds:Signature>
  </rGesEve>
</gGroupGesEve>
XML

# Firmar (xmlsec1)
xmlsec1 --sign \
  --privkey-pem "$KEY","$CERT" \
  --id-attr:Id rEve \
  --output "$SIGNED" \
  "$REQ"

# Verificación local (opcional si hay chain)
if test -s "$ISSUER_PEM" && test -s "$ROOT_PEM"; then
  xmlsec1 --verify --id-attr:Id rEve --trusted-pem "$ROOT_PEM" --untrusted-pem "$ISSUER_PEM" "$SIGNED" >/dev/null
  echo "OK: verify local (root trusted + issuer untrusted)"
else
  echo "WARN: saltando verify local (faltan ISSUER_PEM/ROOT_PEM)"
fi

# SOAP wrapper (xsd: style) + embed solo gGroupGesEve
cat > "$SOAP" <<XML
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:xsd="http://ekuatia.set.gov.py/sifen/xsd">
  <soap:Body>
    <xsd:rEnviEventoDe>
      <xsd:dId>${DID}</xsd:dId>
      <xsd:dEvReg>
$(sed "1{/^<\?xml/d}" "$SIGNED" | sed -n "/<gGroupGesEve/,/<\/gGroupGesEve>/p")
      </xsd:dEvReg>
    </xsd:rEnviEventoDe>
  </soap:Body>
</soap:Envelope>
XML

# POST (mTLS)
curl -sS --http1.1 -m 30 --connect-timeout 10 \
  --cert "$CERT" --key "$KEY" \
  -H "Content-Type: application/soap+xml;charset=UTF-8" \
  --data-binary @"$SOAP" \
  "$ENDPOINT" -o "$OUT" || true

echo
echo "== RESULT =="
grep -nE "rRetEnviEventoDe|dCodRes|dMsgRes|dEstRes|dProtAut" "$OUT" || true
echo
echo "OUT=$OUT"
