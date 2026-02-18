#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from datetime import datetime
import re
import requests

SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"
SOAP12_NS = "http://www.w3.org/2003/05/soap-envelope"

def build_envelope(body_tag: str, did: str, prot: str) -> bytes:
    xml = (
        f"<?xml version='1.0' encoding='UTF-8'?>"
        f"<soap:Envelope xmlns:soap='{SOAP12_NS}'>"
        f"<soap:Header/>"
        f"<soap:Body>"
        f"<{body_tag} xmlns='{SIFEN_NS}'>"
        f"<dId>{did}</dId>"
        f"<dProtConsLote>{prot}</dProtConsLote>"
        f"</{body_tag}>"
        f"</soap:Body>"
        f"</soap:Envelope>"
    )
    return xml.encode("utf-8")

def parse_cod_msg(xml_text: str) -> tuple[str|None, str|None]:
    # Busca dCodRes y dMsgRes donde sea
    cod = None
    msg = None
    m1 = re.search(r"<(?:\w+:)?dCodRes>\s*([^<]+)\s*</(?:\w+:)?dCodRes>", xml_text)
    m2 = re.search(r"<(?:\w+:)?dMsgRes>\s*([^<]+)\s*</(?:\w+:)?dMsgRes>", xml_text)
    if m1: cod = m1.group(1).strip()
    if m2: msg = m2.group(1).strip()
    return cod, msg

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True, help="POST URL (ej: https://.../consulta-lote)")
    ap.add_argument("--did", required=True)
    ap.add_argument("--prot", required=True)
    ap.add_argument("--cert", required=True, help="cert PEM path")
    ap.add_argument("--key", required=True, help="key PEM path")
    ap.add_argument("--verify", default=None, help="CA bundle path (opcional)")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--artifacts-dir", default=None)
    args = ap.parse_args()

    art = Path(args.artifacts_dir) if args.artifacts_dir else Path("artifacts") / f"try_consulta_lote_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    art.mkdir(parents=True, exist_ok=True)

    variants = [
        "rEnviConsLoteDe",
        "rEnviConsLoteDE",
        "rEnviConsLoteDeRequest",
        "rEnviConsLoteDERequest",
    ]

    headers_base = {
        "Accept": "application/soap+xml",
    }
    content_types = [
        "application/soap+xml; charset=utf-8",
        'application/soap+xml; charset=utf-8; action=""',
    ]

    verify = args.verify if args.verify else True

    print("URL:", args.url)
    print("ART:", art)
    print("DID:", args.did)
    print("PROT:", args.prot)
    print("CERT:", args.cert)
    print("KEY:", args.key)
    print("VERIFY:", verify)

    sess = requests.Session()

    for i, tag in enumerate(variants, start=1):
        for j, ct in enumerate(content_types, start=1):
            label = f"v{i:02d}_{tag}__ct{j:02d}"
            req_path = art / f"{label}_request.xml"
            resp_path = art / f"{label}_response.xml"
            http_path = art / f"{label}_http.txt"

            soap_bytes = build_envelope(tag, args.did, args.prot)
            req_path.write_bytes(soap_bytes)

            headers = dict(headers_base)
            headers["Content-Type"] = ct

            try:
                r = sess.post(
                    args.url,
                    data=soap_bytes,
                    headers=headers,
                    cert=(args.cert, args.key),
                    verify=verify,
                    timeout=args.timeout,
                )
                resp_text = r.text if r.content else ""
                resp_path.write_text(resp_text, encoding="utf-8", errors="replace")
                cod, msg = parse_cod_msg(resp_text)

                http_path.write_text(
                    f"status={r.status_code}\ncontent_type={ct}\nbody_tag={tag}\ndCodRes={cod}\ndMsgRes={msg}\n",
                    encoding="utf-8"
                )

                print(f"[{label}] HTTP {r.status_code} dCodRes={cod} dMsgRes={msg}")
            except Exception as e:
                http_path.write_text(
                    f"ERROR={repr(e)}\ncontent_type={ct}\nbody_tag={tag}\n",
                    encoding="utf-8"
                )
                print(f"[{label}] ERROR {repr(e)}")

    print("\n✅ Listo. Revisá:", art)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
