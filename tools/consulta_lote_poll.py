#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from lxml import etree

SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"
SOAP12_NS = "http://www.w3.org/2003/05/soap-envelope"

ENDPOINTS = {
    "prod": "https://sifen.set.gov.py/de/ws/consultas/consulta-lote.wsdl",
    "test": "https://sifen-test.set.gov.py/de/ws/consultas/consulta-lote.wsdl",
}


def generate_did() -> str:
    """Genera dId numérico con formato YYYYMMDDHHMMSS."""
    return datetime.now().strftime("%Y%m%d%H%M%S")


def build_consulta_lote_soap_12(did: str, prot: str) -> bytes:
    """Construye SOAP 1.2 para rEnviConsLoteDe."""
    did_value = (did or "").strip()
    prot_value = (prot or "").strip()
    if not did_value.isdigit():
        raise ValueError(f"dId inválido (debe ser solo dígitos): {did_value!r}")
    if not prot_value:
        raise ValueError("dProtConsLote no puede ser vacío")

    envelope = etree.Element(etree.QName(SOAP12_NS, "Envelope"), nsmap={"soap": SOAP12_NS})
    etree.SubElement(envelope, etree.QName(SOAP12_NS, "Header"))
    body = etree.SubElement(envelope, etree.QName(SOAP12_NS, "Body"))

    req = etree.SubElement(body, etree.QName(SIFEN_NS, "rEnviConsLoteDe"), nsmap={None: SIFEN_NS})
    d_id = etree.SubElement(req, etree.QName(SIFEN_NS, "dId"))
    d_id.text = did_value
    d_prot = etree.SubElement(req, etree.QName(SIFEN_NS, "dProtConsLote"))
    d_prot.text = prot_value

    return etree.tostring(envelope, xml_declaration=True, encoding="UTF-8", pretty_print=False)


def _first_text(node: etree._Element, xpath_expr: str) -> Optional[str]:
    values = node.xpath(xpath_expr)
    if not values:
        return None
    first = values[0]
    if isinstance(first, etree._Element):
        txt = first.text
    else:
        txt = str(first)
    if txt is None:
        return None
    txt = txt.strip()
    return txt if txt else None


def _payload_root(xml_root: etree._Element) -> etree._Element:
    if etree.QName(xml_root).localname != "Envelope":
        return xml_root
    body_nodes = xml_root.xpath("//*[local-name()='Body']")
    if not body_nodes:
        return xml_root
    for child in body_nodes[0]:
        if isinstance(getattr(child, "tag", None), str):
            return child
    return xml_root


def parse_consulta_lote_response(xml_bytes: bytes, http_status: Optional[int] = None) -> Dict[str, Any]:
    """Parsea respuesta SOAP de consulta lote y normaliza campos relevantes."""
    root = etree.fromstring(xml_bytes)
    payload = _payload_root(root)
    root_tag = etree.QName(payload).localname

    d_cod_res_lot = _first_text(payload, './/*[local-name()="dCodResLot"]')
    if not d_cod_res_lot:
        d_cod_res_lot = _first_text(payload, './/*[local-name()="dCodRes"]')
    d_msg_res_lot = _first_text(payload, './/*[local-name()="dMsgResLot"]')
    if not d_msg_res_lot:
        d_msg_res_lot = _first_text(payload, './/*[local-name()="dMsgRes"]')

    rows: List[Dict[str, Optional[str]]] = []
    for lote in payload.xpath('.//*[local-name()="gResProcLote"]'):
        lote_id = (
            _first_text(lote, './*[local-name()="id"]')
            or _first_text(lote, './*[local-name()="dId"]')
            or _first_text(lote, './*[local-name()="dCDC"]')
            or _first_text(lote, './*[local-name()="dNumDoc"]')
            or _first_text(lote, './/*[local-name()="id"]')
        )
        d_est_res = _first_text(lote, './*[local-name()="dEstRes"]') or _first_text(
            lote, './/*[local-name()="dEstRes"]'
        )
        d_cod_res = _first_text(lote, './/*[local-name()="dCodRes"]')
        d_msg_res = _first_text(lote, './/*[local-name()="dMsgRes"]')
        rows.append(
            {
                "id": lote_id,
                "dEstRes": d_est_res,
                "dCodRes": d_cod_res,
                "dMsgRes": d_msg_res,
            }
        )

    return {
        "http_status": http_status,
        "root_tag": root_tag,
        "dCodResLot": d_cod_res_lot,
        "dMsgResLot": d_msg_res_lot,
        "gResProcLote": rows,
    }


def _resolve_cert_and_key() -> tuple[str, str]:
    cert_path = (os.getenv("SIFEN_CERT_PATH") or "").strip()
    key_path = (os.getenv("SIFEN_KEY_PATH") or "").strip()
    if not cert_path or not key_path:
        raise SystemExit("ERROR: definir SIFEN_CERT_PATH y SIFEN_KEY_PATH para mTLS.")
    cert = Path(cert_path).expanduser()
    key = Path(key_path).expanduser()
    if not cert.is_file():
        raise SystemExit(f"ERROR: SIFEN_CERT_PATH no existe: {cert}")
    if not key.is_file():
        raise SystemExit(f"ERROR: SIFEN_KEY_PATH no existe: {key}")
    return str(cert), str(key)


def _safe_for_path(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip()) or "prot"


def _write_headers_file(
    output_path: Path,
    endpoint: str,
    request_headers: Dict[str, str],
    response: Optional[requests.Response],
    error: Optional[str],
) -> None:
    lines: List[str] = [f"POST {endpoint}"]
    lines.append("REQUEST_HEADERS:")
    for key in sorted(request_headers):
        lines.append(f"{key}: {request_headers[key]}")

    if response is not None:
        lines.append(f"HTTP_STATUS: {response.status_code}")
        lines.append("RESPONSE_HEADERS:")
        for key in sorted(response.headers.keys()):
            lines.append(f"{key}: {response.headers.get(key)}")
    if error:
        lines.append(f"ERROR: {error}")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_parsed_file(output_path: Path, parsed: Dict[str, Any]) -> None:
    lines = [
        f"HTTP={parsed.get('http_status')}",
        f"root_tag={parsed.get('root_tag')}",
        f"dCodResLot={parsed.get('dCodResLot')}",
        f"dMsgResLot={parsed.get('dMsgResLot')}",
    ]
    for item in parsed.get("gResProcLote", []):
        lines.append(
            "gResProcLote: "
            f"id={item.get('id')}, "
            f"dEstRes={item.get('dEstRes')}, "
            f"dCodRes={item.get('dCodRes')}, "
            f"dMsgRes={item.get('dMsgRes')}"
        )
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Poll de consulta-lote SIFEN con artifacts por intento.")
    ap.add_argument("--env", required=True, choices=["prod", "test"])
    ap.add_argument("--prot", required=True, help="Valor dProtConsLote")
    ap.add_argument("--retries", type=int, default=6)
    ap.add_argument("--sleep", type=int, default=10, dest="sleep_seconds")
    args = ap.parse_args()

    if args.retries < 1:
        raise SystemExit("ERROR: --retries debe ser >= 1")
    if args.sleep_seconds < 0:
        raise SystemExit("ERROR: --sleep debe ser >= 0")

    cert, key = _resolve_cert_and_key()
    endpoint = ENDPOINTS[args.env]
    stop_codes = {"0362", "0365"}
    prot_safe = _safe_for_path(args.prot)
    final_code: Optional[str] = None

    for attempt in range(1, args.retries + 1):
        did = generate_did()
        soap_bytes = build_consulta_lote_soap_12(did=did, prot=args.prot)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        run_dir = Path("artifacts") / f"run_{ts}_consult_{args.env}_{prot_safe}"
        run_dir.mkdir(parents=True, exist_ok=True)

        req_path = run_dir / "req.xml"
        resp_path = run_dir / "resp.xml"
        headers_path = run_dir / "headers.txt"
        parsed_path = run_dir / "parsed.txt"
        req_path.write_bytes(soap_bytes)

        request_headers = {
            "Content-Type": 'application/soap+xml; charset=utf-8; action=""',
            "Accept": "application/soap+xml, text/xml, */*",
        }

        response: Optional[requests.Response] = None
        parsed: Dict[str, Any]
        error: Optional[str] = None
        try:
            response = requests.post(
                endpoint,
                data=soap_bytes,
                headers=request_headers,
                cert=(cert, key),
                timeout=(15, 45),
            )
            resp_path.write_bytes(response.content or b"")
            parsed = parse_consulta_lote_response(response.content or b"", response.status_code)
        except Exception as exc:
            error = str(exc)
            resp_path.write_text(f"ERROR: {error}\n", encoding="utf-8")
            parsed = {
                "http_status": None,
                "root_tag": None,
                "dCodResLot": None,
                "dMsgResLot": error,
                "gResProcLote": [],
            }

        _write_headers_file(headers_path, endpoint, request_headers, response, error)
        _write_parsed_file(parsed_path, parsed)

        final_code = parsed.get("dCodResLot")
        print(
            f"[{attempt}/{args.retries}] dir={run_dir} "
            f"HTTP={parsed.get('http_status')} dCodResLot={parsed.get('dCodResLot')} "
            f"dMsgResLot={parsed.get('dMsgResLot')}"
        )

        if final_code in stop_codes:
            print(f"Stop: dCodResLot={final_code}")
            return 0

        if attempt < args.retries:
            time.sleep(args.sleep_seconds)

    print(f"Fin de reintentos. Último dCodResLot={final_code!r}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
