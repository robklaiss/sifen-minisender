#!/usr/bin/env bash
set -euo pipefail

CDC="${1:-}"
if [[ -z "$CDC" ]]; then
  echo "Usage: $0 <CDC>" >&2
  exit 2
fi

CERT="/opt/sifen-minisender/secrets/cert.pem"
KEY="/opt/sifen-minisender/secrets/key.pem"
WSDL="https://sifen.set.gov.py/de/ws/consultas/consulta.wsdl"
REQ="/tmp/consulta_req.xml"
OUT="/tmp/consulta_out.xml"

DID="$(python3 - <<'PY'
from datetime import datetime
import random
print(datetime.now().strftime("%Y%m%d%H%M%S") + str(random.randint(0,9)))
PY
)"

cat > "$REQ" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope" xmlns:sifen="http://ekuatia.set.gov.py/sifen/xsd">
  <env:Header/><env:Body>
    <sifen:rEnviConsDeRequest>
      <sifen:dId>${DID}</sifen:dId>
      <sifen:dCDC>${CDC}</sifen:dCDC>
    </sifen:rEnviConsDeRequest>
  </env:Body></env:Envelope>
XML

curl -sk --http1.1 --connect-timeout 10 -m 30 \
  --cert "$CERT" --key "$KEY" \
  -H "Content-Type: application/soap+xml; charset=UTF-8; action=\"\"" \
  --data-binary "@$REQ" \
  "$WSDL" -o "$OUT"

python3 - <<'PY'
from pathlib import Path
import re, xml.etree.ElementTree as ET

raw = Path("/tmp/consulta_out.xml").read_text(encoding="utf-8", errors="replace")
ns={"s":"http://ekuatia.set.gov.py/sifen/xsd"}
root=ET.fromstring(raw)

print("dFecProc="+(root.findtext(".//s:dFecProc",default="",namespaces=ns) or ""))
print("dCodRes="+(root.findtext(".//s:dCodRes",default="",namespaces=ns) or ""))
print("dMsgRes="+(root.findtext(".//s:dMsgRes",default="",namespaces=ns) or ""))

m=re.search(r"&lt;\s*(?:[A-Za-z0-9_]+:)?dProtAut\s*>\s*([0-9]+)\s*&lt;\s*/\s*(?:[A-Za-z0-9_]+:)?dProtAut\s*>", raw, flags=re.S) or \
  re.search(r"&lt;\s*(?:[A-Za-z0-9_]+:)?dProtAut\s*&gt;\s*([0-9]+)\s*&lt;\s*/\s*(?:[A-Za-z0-9_]+:)?dProtAut\s*&gt;", raw, flags=re.S) or \
  re.search(r"<\s*(?:[A-Za-z0-9_]+:)?dProtAut\s*>\s*([0-9]+)\s*</\s*(?:[A-Za-z0-9_]+:)?dProtAut\s*>", raw, flags=re.S)

print("dProtAut="+(m.group(1) if m else ""))
PY
