#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
import json
import re
import sys
import xml.etree.ElementTree as ET

NS = {
    "env": "http://www.w3.org/2003/05/soap-envelope",
    "s": "http://ekuatia.set.gov.py/sifen/xsd",
}

PATTERNS = [
    # Escapado parcial: &lt;dProtAut>3025...&lt;/dProtAut>
    r"&lt;\s*(?:[A-Za-z0-9_]+:)?dProtAut\s*>\s*([0-9]+)\s*&lt;\s*/\s*(?:[A-Za-z0-9_]+:)?dProtAut\s*>",
    # Escapado completo: &lt;dProtAut&gt;...&lt;/dProtAut&gt;
    r"&lt;\s*(?:[A-Za-z0-9_]+:)?dProtAut\s*&gt;\s*([0-9]+)\s*&lt;\s*/\s*(?:[A-Za-z0-9_]+:)?dProtAut\s*&gt;",
    # Sin escapar: <dProtAut>...</dProtAut>
    r"<\s*(?:[A-Za-z0-9_]+:)?dProtAut\s*>\s*([0-9]+)\s*</\s*(?:[A-Za-z0-9_]+:)?dProtAut\s*>",
]

def extract_dprot_aut(raw: str) -> str:
    for pat in PATTERNS:
        m = re.search(pat, raw, flags=re.S)
        if m:
            return m.group(1)
    return ""

def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: tools/extract_consulta_fields.py /path/to/consulta_out.xml", file=sys.stderr)
        return 2

    p = Path(sys.argv[1])
    raw = p.read_text(encoding="utf-8", errors="replace")

    try:
        root = ET.fromstring(raw)
        dFecProc = root.findtext(".//s:dFecProc", default="", namespaces=NS) or ""
        dCodRes  = root.findtext(".//s:dCodRes",  default="", namespaces=NS) or ""
        dMsgRes  = root.findtext(".//s:dMsgRes",  default="", namespaces=NS) or ""
    except Exception:
        dFecProc = dCodRes = dMsgRes = ""

    out = {
        "dFecProc": dFecProc,
        "dCodRes": dCodRes,
        "dMsgRes": dMsgRes,
        "dProtAut": extract_dprot_aut(raw),
        "source_file": str(p),
    }
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
