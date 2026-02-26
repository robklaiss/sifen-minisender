#!/usr/bin/env python3
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo
import xml.etree.ElementTree as ET

import webui.app as webui_app
from webui.app import (
    _build_invoice_xml_from_template,
    _default_template_path,
    _load_geo_lookup,
    _norm_geo_code,
    _validate_rde_xsd_or_raise,
    _xml_contains_nre_pricing,
    _validate_nre_geo_descriptions,
    sign_de_with_p12,
    _update_qr_in_signed_xml,
)


NS_URI = "http://ekuatia.set.gov.py/sifen/xsd"
NS = {"s": NS_URI}


def _env_or_fail(*keys: str) -> str:
    for key in keys:
        val = (os.getenv(key) or "").strip()
        if val:
            return val
    raise RuntimeError(f"Falta {' o '.join(keys)} en el entorno.")

def _pick_geo_entry(lookup: dict, dep_name: Optional[str] = None) -> dict:
    for (dep, dis, ciu), (dep_desc, dis_desc, ciu_desc) in lookup.items():
        if dep_name is None or dep_desc == dep_name:
            return {
                "dep": dep,
                "dis": dis,
                "ciu": ciu,
                "dep_desc": dep_desc,
                "dis_desc": dis_desc,
                "ciu_desc": ciu_desc,
            }
    if dep_name is not None:
        return _pick_geo_entry(lookup, None)
    raise RuntimeError("Tabla geo oficial vacía o sin entradas válidas.")


def _assert_geo_xml(xml_text: str, label: str) -> ET.Element:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise RuntimeError(f"{label}: XML inválido ({exc})")

    for loc_tag in ["gCamSal", "gCamEnt"]:
        if root.find(f".//s:gTransp/s:{loc_tag}", NS) is None:
            raise RuntimeError(f"{label}: falta gTransp/{loc_tag}.")

    geo_errors = _validate_nre_geo_descriptions(root, NS)
    if geo_errors:
        raise RuntimeError(f"{label}: {geo_errors[0]}")

    for path in [
        ".//s:gTransp/s:gCamSal/s:dDesCiuSal",
        ".//s:gTransp/s:gCamEnt/s:dDesCiuEnt",
    ]:
        el = root.find(path, NS)
        if el is not None and (el.text or "").strip() == "CIUDAD":
            raise RuntimeError(f"{label}: dDesCiu* placeholder CIUDAD.")

    return root


def _extract_loc_info(xml_root: ET.Element, loc_tag: str) -> dict:
    loc = xml_root.find(f".//s:gTransp/s:{loc_tag}", NS)
    if loc is None:
        return {}
    def _get(tag: str) -> str:
        el = loc.find(f"s:{tag}", NS)
        return (el.text or "").strip() if el is not None else ""
    dep = _norm_geo_code(_get("cDepSal" if loc_tag == "gCamSal" else "cDepEnt"))
    dis = _norm_geo_code(_get("cDisSal" if loc_tag == "gCamSal" else "cDisEnt"))
    ciu = _norm_geo_code(_get("cCiuSal" if loc_tag == "gCamSal" else "cCiuEnt"))
    dep_desc = _get("dDesDepSal" if loc_tag == "gCamSal" else "dDesDepEnt")
    dis_desc = _get("dDesDisSal" if loc_tag == "gCamSal" else "dDesDisEnt")
    ciu_desc = _get("dDesCiuSal" if loc_tag == "gCamSal" else "dDesCiuEnt")
    return {
        "dep": dep,
        "dis": dis,
        "ciu": ciu,
        "dep_desc": dep_desc,
        "dis_desc": dis_desc,
        "ciu_desc": ciu_desc,
    }


def main() -> int:
    artifacts_root = Path("/data/artifacts")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = artifacts_root / f"webui_dryrun_nre_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    template_path = _default_template_path("7")
    if not template_path or not Path(template_path).exists():
        print(f"ERROR: template NRE no encontrado: {template_path}", file=sys.stderr)
        return 2

    try:
        lookup = _load_geo_lookup()
    except RuntimeError as exc:
        print(f"ERROR: loader geo: {exc}", file=sys.stderr)
        return 1
    info = getattr(webui_app, "_GEO_LOOKUP_INFO", {}) or {}
    info_path = info.get("path")
    info_rows = info.get("rows")
    info_lines = info.get("lines")
    if info_path:
        if info_lines is not None:
            print(f"geo_lookup: path={info_path} rows={info_rows} lines={info_lines}")
        else:
            print(f"geo_lookup: path={info_path} rows={info_rows}")
    else:
        print(f"geo_lookup: rows={len(lookup)}")
    if not lookup:
        print("ERROR: tabla geo oficial vacía o no disponible.", file=sys.stderr)
        return 1

    salida_geo = _pick_geo_entry(lookup, "CENTRAL")
    entrega_geo = _pick_geo_entry(lookup, "CAPITAL")

    salida = {
        "departamento": str(salida_geo["dep"]),
        "distrito": str(salida_geo["dis"]),
        "ciudad": str(salida_geo["ciu"]),
        "dirLoc": "Ruta 2 Km 21",
        "numCasa": "0",
        "tel": "021000000",
    }
    entrega = {
        "departamento": str(entrega_geo["dep"]),
        "distrito": str(entrega_geo["dis"]),
        "ciudad": str(entrega_geo["ciu"]),
        "dirLoc": "Av. Mariscal Lopez 123",
        "numCasa": "123",
        "tel": "021111111",
    }

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
            "iModTrans": "1",
            "iRespFlete": "1",
            "salida": salida,
            "entrega": entrega,
            "transportista": {
                "tipo": "1",
                "numeroTr": "1234567-8",
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
    try:
        _assert_geo_xml(pre_text, "pre-sign")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
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
        xml_root = _assert_geo_xml(signed_qr_text, "signed")
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    for tag in ["gOpeCom", "gCamCond", "gValorItem", "gTotSub"]:
        if xml_root.find(f".//s:{tag}", NS) is not None:
            print(f"ERROR: tag prohibido <{tag}> presente en {out_path}", file=sys.stderr)
            return 1

    sal_info = _extract_loc_info(xml_root, "gCamSal") or salida_geo
    ent_info = _extract_loc_info(xml_root, "gCamEnt") or entrega_geo
    print(
        "OK: geo sal/ent "
        f"sal=dep={sal_info.get('dep')} dis={sal_info.get('dis')} ciu={sal_info.get('ciu')} "
        f"'{sal_info.get('dep_desc')}'/'{sal_info.get('dis_desc')}'/'{sal_info.get('ciu_desc')}' "
        f"ent=dep={ent_info.get('dep')} dis={ent_info.get('dis')} ciu={ent_info.get('ciu')} "
        f"'{ent_info.get('dep_desc')}'/'{ent_info.get('dis_desc')}'/'{ent_info.get('ciu_desc')}'"
    )
    print(f"XML firmado: {out_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
