#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"
SOAP12_NS = "http://www.w3.org/2003/05/soap-envelope"
SOAP11_NS = "http://schemas.xmlsoap.org/soap/envelope/"


def _build_children(did: str, prot: str, mode: str, prefix: str) -> str:
    if mode == "default":
        return f"<dId>{did}</dId><dProtConsLote>{prot}</dProtConsLote>"
    if mode == "prefixed":
        return f"<{prefix}:dId>{did}</{prefix}:dId><{prefix}:dProtConsLote>{prot}</{prefix}:dProtConsLote>"
    if mode == "none":
        return f"<dId xmlns=\"\">{did}</dId><dProtConsLote xmlns=\"\">{prot}</dProtConsLote>"
    raise ValueError(f"unknown child mode: {mode}")


def build_body_xml(body_variant: str, child_mode: str, did: str, prot: str) -> str:
    prefix = "sifen"
    children = _build_children(did, prot, child_mode, prefix)

    if body_variant == "A":
        if child_mode == "prefixed":
            return (
                f"<{prefix}:rEnviConsLoteDe xmlns:{prefix}=\"{SIFEN_NS}\">"
                f"{children}"
                f"</{prefix}:rEnviConsLoteDe>"
            )
        return f"<rEnviConsLoteDe xmlns=\"{SIFEN_NS}\">{children}</rEnviConsLoteDe>"

    if body_variant == "B":
        if child_mode == "prefixed":
            return (
                f"<{prefix}:siConsLoteDE xmlns:{prefix}=\"{SIFEN_NS}\">"
                f"<{prefix}:rEnviConsLoteDe>{children}</{prefix}:rEnviConsLoteDe>"
                f"</{prefix}:siConsLoteDE>"
            )
        return (
            f"<siConsLoteDE xmlns=\"{SIFEN_NS}\">"
            f"<rEnviConsLoteDe>{children}</rEnviConsLoteDe>"
            f"</siConsLoteDE>"
        )

    if body_variant == "C":
        if child_mode == "prefixed":
            return (
                f"<{prefix}:rEnviConsLoteDeRequest xmlns:{prefix}=\"{SIFEN_NS}\">"
                f"{children}"
                f"</{prefix}:rEnviConsLoteDeRequest>"
            )
        return f"<rEnviConsLoteDeRequest xmlns=\"{SIFEN_NS}\">{children}</rEnviConsLoteDeRequest>"

    raise ValueError(f"unknown body variant: {body_variant}")


def build_envelope_xml(soap_version: str, body_xml: str) -> bytes:
    if soap_version == "1.2":
        env_ns = SOAP12_NS
    elif soap_version == "1.1":
        env_ns = SOAP11_NS
    else:
        raise ValueError(f"unknown soap version: {soap_version}")

    xml = (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        f"<soap:Envelope xmlns:soap=\"{env_ns}\">"
        "<soap:Header/>"
        f"<soap:Body>{body_xml}</soap:Body>"
        "</soap:Envelope>"
    )
    return xml.encode("utf-8")


def parse_xml_fields(text: str) -> Dict[str, Optional[str]]:
    fields = {
        "dCodRes": None,
        "dMsgRes": None,
        "dCodResLot": None,
        "dMsgResLot": None,
        "dEstRes": None,
    }
    for key in fields:
        pat = rf"<(?:\\w+:)?{key}>\\s*([^<]+)\\s*</(?:\\w+:)?{key}>"
        m = re.search(pat, text, flags=re.DOTALL)
        if m:
            fields[key] = m.group(1).strip()
    if any(v is None for v in fields.values()):
        try:
            import xml.etree.ElementTree as ET
            root = ET.fromstring(text)
            for elem in root.iter():
                tag = elem.tag
                if "}" in tag:
                    tag = tag.split("}", 1)[1]
                if tag in fields and fields[tag] is None and elem.text:
                    fields[tag] = elem.text.strip()
        except Exception:
            pass
    return fields


def is_soapish(text: str) -> bool:
    lower = text.lower()
    return "<envelope" in lower or "soap-envelope" in lower


def run_curl(
    *,
    url: str,
    cert: str,
    key: str,
    ca: str,
    headers: Dict[str, str],
    req_path: Path,
    resp_bin_path: Path,
    verbose_path: Path,
    timeout: int,
) -> Tuple[int, str]:
    cmd = [
        "curl",
        "-sS",
        "-v",
        "--http1.1",
        "--tlsv1.2",
        "--cert",
        cert,
        "--key",
        key,
        "--cacert",
        ca,
        "--data-binary",
        f"@{req_path}",
        "--output",
        str(resp_bin_path),
        "--write-out",
        "http_code=%{http_code}\ncontent_type=%{content_type}\nsize_download=%{size_download}\n",
        "--max-time",
        str(timeout),
    ]
    for k, v in headers.items():
        cmd.extend(["-H", f"{k}: {v}"])
    cmd.append(url)

    with verbose_path.open("w", encoding="utf-8", errors="replace") as vf:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=vf, text=True)
    return proc.returncode, proc.stdout


def main() -> int:
    ap = argparse.ArgumentParser(description="Probe consulta-lote SOAP variants via curl.")
    ap.add_argument("--did", required=True)
    ap.add_argument("--prot", required=True)
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--ca", required=True)
    ap.add_argument("--timeout", type=int, default=25)
    ap.add_argument("--artifacts-root", default="artifacts")
    args = ap.parse_args()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    art_dir = Path(args.artifacts_root) / f"consulta_lote_matrix_{ts}"
    art_dir.mkdir(parents=True, exist_ok=True)

    urls = [
        "https://sifen-test.set.gov.py/de/ws/consultas/consulta-lote",
        "https://sifen-test.set.gov.py/de/ws/consultas/consulta-lote.wsdl",
        "https://sifen-test.set.gov.py/de/ws/async/consulta-lote",
        "https://sifen-test.set.gov.py/de/ws/async/consulta-lote.wsdl",
    ]

    soap_versions = ["1.2", "1.1"]
    body_variants = ["A", "B", "C"]
    ns_modes = ["default", "prefixed", "none"]

    header_variants = {
        "1.2": [
            ("ct_action_empty", "application/soap+xml; charset=utf-8; action=\"\"", None),
            ("ct_no_action", "application/soap+xml; charset=utf-8", None),
            ("ct_action_rEnviConsLoteDe", "application/soap+xml; charset=utf-8; action=\"rEnviConsLoteDe\"", None),
            ("ct_action_siConsLoteDE", "application/soap+xml; charset=utf-8; action=\"siConsLoteDE\"", None),
        ],
        "1.1": [
            ("ct_textxml_soapaction_empty", "text/xml; charset=utf-8", ""),
        ],
    }

    accept_variants = [
        ("accept_soap", "application/soap+xml"),
        ("accept_any", "*/*"),
    ]

    summary_rows = []
    best_label = None

    for url_idx, url in enumerate(urls, start=1):
        for soap_ver in soap_versions:
            for body_variant in body_variants:
                for ns_mode in ns_modes:
                    for hdr_label, content_type, soap_action in header_variants[soap_ver]:
                        for acc_label, accept_val in accept_variants:
                            label = f"u{url_idx}_s{soap_ver.replace('.', '')}_{body_variant}_ns{ns_mode[:3]}_{hdr_label}_{acc_label}"

                            req_path = art_dir / f"{label}_request.xml"
                            resp_bin_path = art_dir / f"{label}_response.bin"
                            resp_xml_path = art_dir / f"{label}_response.xml"
                            verbose_path = art_dir / f"{label}_curl_verbose.txt"
                            meta_path = art_dir / f"{label}_meta.json"

                            body_xml = build_body_xml(body_variant, ns_mode, args.did, args.prot)
                            envelope = build_envelope_xml(soap_ver, body_xml)
                            req_path.write_bytes(envelope)

                            headers = {
                                "Content-Type": content_type,
                                "Accept": accept_val,
                            }
                            if soap_ver == "1.1":
                                headers["SOAPAction"] = soap_action if soap_action is not None else ""

                            exit_code = 0
                            write_out = ""
                            error = None
                            try:
                                exit_code, write_out = run_curl(
                                    url=url,
                                    cert=args.cert,
                                    key=args.key,
                                    ca=args.ca,
                                    headers=headers,
                                    req_path=req_path,
                                    resp_bin_path=resp_bin_path,
                                    verbose_path=verbose_path,
                                    timeout=args.timeout,
                                )
                            except Exception as exc:
                                error = repr(exc)

                            resp_bytes = b""
                            if resp_bin_path.exists():
                                resp_bytes = resp_bin_path.read_bytes()

                            http_code = None
                            content_type_resp = None
                            size_download = None
                            if write_out:
                                for line in write_out.strip().splitlines():
                                    if line.startswith("http_code="):
                                        http_code = line.split("=", 1)[1].strip() or None
                                    elif line.startswith("content_type="):
                                        content_type_resp = line.split("=", 1)[1].strip() or None
                                    elif line.startswith("size_download="):
                                        size_download = line.split("=", 1)[1].strip() or None

                            resp_text = ""
                            if resp_bytes:
                                resp_text = resp_bytes.decode("utf-8", errors="replace")
                                if "<" in resp_text and ">" in resp_text:
                                    resp_xml_path.write_text(resp_text, encoding="utf-8", errors="replace")

                            fields = parse_xml_fields(resp_text) if resp_text else {
                                "dCodRes": None,
                                "dMsgRes": None,
                                "dCodResLot": None,
                                "dMsgResLot": None,
                                "dEstRes": None,
                            }
                            if resp_xml_path.exists() and any(v is None for v in fields.values()):
                                try:
                                    resp_text2 = resp_xml_path.read_text(encoding="utf-8", errors="replace")
                                    fields2 = parse_xml_fields(resp_text2)
                                    for k, v in fields2.items():
                                        if fields.get(k) is None and v is not None:
                                            fields[k] = v
                                except Exception:
                                    pass

                            hit = False
                            if fields.get("dCodRes") and fields["dCodRes"] != "0160":
                                hit = True
                            elif http_code and http_code != "400" and is_soapish(resp_text):
                                hit = True

                            meta = {
                                "label": label,
                                "url": url,
                                "soap_version": soap_ver,
                                "body_variant": body_variant,
                                "ns_mode": ns_mode,
                                "headers": headers,
                                "http_code": http_code,
                                "content_type_resp": content_type_resp,
                                "bytes": len(resp_bytes),
                                "size_download": size_download,
                                "exit_code": exit_code,
                                "error": error,
                                **fields,
                                "hit": hit,
                                "request_path": str(req_path),
                                "response_bin_path": str(resp_bin_path),
                                "response_xml_path": str(resp_xml_path if resp_xml_path.exists() else ""),
                                "curl_verbose_path": str(verbose_path),
                            }
                            meta_path.write_text(json.dumps(meta, indent=2, ensure_ascii=True), encoding="utf-8")

                            summary_rows.append(
                                {
                                    "label": label,
                                    "http": http_code or "",
                                    "content_type": content_type_resp or "",
                                    "bytes": str(len(resp_bytes)),
                                    "dCodRes": fields.get("dCodRes") or "",
                                    "dMsgRes": fields.get("dMsgRes") or "",
                                    "hit": "YES" if hit else "",
                                }
                            )

                            print(
                                f"{label} | http={http_code} | bytes={len(resp_bytes)} | dCodRes={fields.get('dCodRes')} | hit={hit}"
                            )

                            if hit:
                                best_label = label
                                break
                        if best_label:
                            break
                    if best_label:
                        break
                if best_label:
                    break
            if best_label:
                break
        if best_label:
            break

    print("\nSUMMARY")
    print("label | http | content-type | bytes | dCodRes | dMsgRes | HIT")
    for row in summary_rows:
        print(
            f"{row['label']} | {row['http']} | {row['content_type']} | {row['bytes']} | {row['dCodRes']} | {row['dMsgRes']} | {row['hit']}"
        )

    if best_label:
        print(f"\nBEST: {best_label}")
    else:
        print("\nBEST: (none)")
    print(f"ART_DIR: {art_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
