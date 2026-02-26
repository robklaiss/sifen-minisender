#!/usr/bin/env python3
import os
import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo
import xml.etree.ElementTree as ET

from webui.app import (
    _build_invoice_xml_from_template,
    _default_template_path,
    _validate_rde_xsd_or_raise,
    _xml_contains_nre_pricing,
    _validate_nre_geo_descriptions,
    sign_de_with_p12,
    _update_qr_in_signed_xml,
)


def _env_or_fail(*keys: str) -> str:
    for key in keys:
        val = (os.getenv(key) or "").strip()
        if val:
            return val
    raise RuntimeError(f"Falta {' o '.join(keys)} en el entorno.")


def main() -> int:
    artifacts_root = Path("/data/artifacts")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = artifacts_root / f"webui_dryrun_nre_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    template_path = _default_template_path("7")
    if not template_path or not Path(template_path).exists():
        print(f"ERROR: template NRE no encontrado: {template_path}", file=sys.stderr)
        return 2

    customer = {"name": "Cliente DryRun", "ruc": "1234567-8"}
    lines = [
        {
            "qty": 1,
            "price_unit": 1000,
            "line_total": 1000,
            "description": "Item prueba",
        }
    ]
    extra_json = {
        "transporte": {
            "iTipTrans": "1",
            "iRespFlete": "1",
            "transportista": {
                "tipo": "1",
                "ruc": "1234567-8",
                "direccionTr": "S/D",
                "nombre": "Transportista",
                "numeroCh": "1",
                "nombreCh": "Chofer",
                "direccionCh": "S/D",
            },
        },
        "remision": {"iMotEmiNR": "1", "kmEstimado": 10},
    }

    build = _build_invoice_xml_from_template(
        template_path=template_path,
        invoice_id=999001,
        customer=customer,
        lines=lines,
        doc_number="0000001",
        doc_type="7",
        extra_json=extra_json,
        issue_dt=datetime.now(ZoneInfo("America/Asuncion")),
        codseg="123456789",
        establishment="001",
        point_exp="001",
    )

    pre_xml = build["xml_bytes"]
    pre_text = pre_xml.decode("utf-8", errors="ignore")
    if _xml_contains_nre_pricing(pre_text):
        print("ERROR: pre-sign contiene gValorItem/dPUniProSer", file=sys.stderr)
        return 1

    _validate_rde_xsd_or_raise(pre_xml, out_dir, "pre-sign rDE")

    p12_path = _env_or_fail("SIFEN_SIGN_P12_PATH", "SIFEN_P12_PATH", "SIFEN_CERT_PATH")
    p12_password = _env_or_fail("SIFEN_SIGN_P12_PASSWORD", "SIFEN_P12_PASSWORD", "SIFEN_CERT_PASSWORD")
    signed_bytes = sign_de_with_p12(pre_xml, p12_path, p12_password)

    csc = _env_or_fail("SIFEN_CSC")
    csc_id = (os.getenv("SIFEN_CSC_ID") or "0001").strip()
    signed_qr_text, _ = _update_qr_in_signed_xml(signed_bytes.decode("utf-8", errors="ignore"), csc, csc_id)

    out_path = out_dir / "rde_signed_qr_TEST.xml"
    out_path.write_text(signed_qr_text, encoding="utf-8")

    if _xml_contains_nre_pricing(signed_qr_text):
        print(f"ERROR: gValorItem/dPUniProSer presente en {out_path}", file=sys.stderr)
        return 1
    try:
        xml_root = ET.fromstring(signed_qr_text)
    except ET.ParseError:
        print(f"ERROR: XML firmado inválido en {out_path}", file=sys.stderr)
        return 1
    ns = {"s": "http://ekuatia.set.gov.py/sifen/xsd"}
    geo_errors = _validate_nre_geo_descriptions(xml_root, ns)
    if geo_errors:
        print(f"ERROR: {geo_errors[0]}", file=sys.stderr)
        return 1
    for path in [
        ".//s:gTransp/s:gCamSal/s:dDesCiuSal",
        ".//s:gTransp/s:gCamEnt/s:dDesCiuEnt",
    ]:
        el = xml_root.find(path, ns)
        if el is not None and (el.text or "").strip() == "CIUDAD":
            print(f"ERROR: dDesCiu* placeholder CIUDAD en {out_path}", file=sys.stderr)
            return 1

    print(f"OK: no gValorItem y geo OK ({out_path})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
