#!/usr/bin/env python3
import copy
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional
from zoneinfo import ZoneInfo
import xml.etree.ElementTree as ET

from webui.app import (
    _build_invoice_xml_from_template,
    _default_extra_json_for,
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


def _first_transport(extra_json: dict) -> dict:
    transporte = extra_json.get("transporte")
    if isinstance(transporte, list):
        return transporte[0] if transporte else {}
    if isinstance(transporte, dict):
        return transporte
    return {}


def _load_default_transport_or_fail() -> dict:
    extra = _default_extra_json_for("7") or {}
    if not isinstance(extra, dict):
        extra = {}
    transporte = _first_transport(extra)
    if not isinstance(transporte, dict) or not transporte:
        raise RuntimeError(
            "No se encontró transporte default en json-ejemplos-tipos-de-factura/data2.1.json (remision)."
        )
    return copy.deepcopy(transporte)


def _find_direct_child_ns(parent: ET.Element, tag: str, ns_uri: str) -> Optional[ET.Element]:
    target = f"{{{ns_uri}}}{tag}"
    for child in list(parent):
        if child.tag == target:
            return child
    return None


def _ensure_desc_after_code(
    loc: ET.Element,
    code_tag: str,
    desc_tag: str,
    value: str,
    ns_uri: str,
) -> None:
    code_el = _find_direct_child_ns(loc, code_tag, ns_uri)
    if code_el is None:
        raise RuntimeError(f"Falta {code_tag} en {loc.tag}.")
    desc_el = _find_direct_child_ns(loc, desc_tag, ns_uri)
    if desc_el is None:
        desc_el = ET.Element(f"{{{ns_uri}}}{desc_tag}")
        children = list(loc)
        if code_el in children:
            loc.insert(children.index(code_el) + 1, desc_el)
        else:
            loc.append(desc_el)
    desc_el.text = value


def _require_text(loc: ET.Element, tag: str, ns_uri: str, label: str) -> str:
    el = _find_direct_child_ns(loc, tag, ns_uri)
    if el is None:
        raise RuntimeError(f"NRE {label}: falta {tag}.")
    text = (el.text or "").strip()
    if not text:
        raise RuntimeError(f"NRE {label}: {tag} vacío.")
    return text


def _ensure_nre_geo_blocks(pre_xml: bytes, lookup: dict) -> tuple[bytes, dict]:
    try:
        root = ET.fromstring(pre_xml)
    except ET.ParseError as exc:
        raise RuntimeError(f"XML pre-sign inválido: {exc}")

    info: dict[str, dict] = {}
    for loc_tag, dep_tag, ddep_tag, dis_tag, ddis_tag, ciu_tag, dciu_tag, ddir_tag, dnum_tag, dtel_tag in [
        ("gCamSal", "cDepSal", "dDesDepSal", "cDisSal", "dDesDisSal", "cCiuSal", "dDesCiuSal", "dDirLocSal", "dNumCasSal", "dTelSal"),
        ("gCamEnt", "cDepEnt", "dDesDepEnt", "cDisEnt", "dDesDisEnt", "cCiuEnt", "dDesCiuEnt", "dDirLocEnt", "dNumCasEnt", "dTelEnt"),
    ]:
        loc = root.find(f".//s:gTransp/s:{loc_tag}", NS)
        if loc is None:
            raise RuntimeError(f"Falta gTransp/{loc_tag} en NRE.")

        _require_text(loc, ddir_tag, NS_URI, loc_tag)
        _require_text(loc, dnum_tag, NS_URI, loc_tag)
        dep_text = _require_text(loc, dep_tag, NS_URI, loc_tag)
        dis_text = _require_text(loc, dis_tag, NS_URI, loc_tag)
        ciu_text = _require_text(loc, ciu_tag, NS_URI, loc_tag)
        _require_text(loc, dtel_tag, NS_URI, loc_tag)

        dep = _norm_geo_code(dep_text)
        dis = _norm_geo_code(dis_text)
        ciu = _norm_geo_code(ciu_text)
        if not (dep and dis and ciu):
            raise RuntimeError(
                f"NRE {loc_tag}: dep/dis/ciu inválidos dep={dep_text!r} dis={dis_text!r} ciu={ciu_text!r}."
            )
        names = lookup.get((dep, dis, ciu)) if lookup else None
        if not names:
            raise RuntimeError(
                f"NRE iTiDE=7 geo code not in official table: dep={dep} dis={dis} ciu={ciu}"
            )
        dep_name, dis_name, ciu_name = names

        _ensure_desc_after_code(loc, dep_tag, ddep_tag, dep_name, NS_URI)
        _ensure_desc_after_code(loc, dis_tag, ddis_tag, dis_name, NS_URI)
        _ensure_desc_after_code(loc, ciu_tag, dciu_tag, ciu_name, NS_URI)

        info[loc_tag] = {
            "dep": dep,
            "dis": dis,
            "ciu": ciu,
            "dep_desc": dep_name,
            "dis_desc": dis_name,
            "ciu_desc": ciu_name,
        }

    return ET.tostring(root, encoding="utf-8", method="xml"), info


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

    lookup = _load_geo_lookup()
    if not lookup:
        print("ERROR: tabla geo oficial vacía o no disponible.", file=sys.stderr)
        return 1

    default_transporte = _load_default_transport_or_fail()
    salida = default_transporte.get("salida") or {}
    entrega = default_transporte.get("entrega") or {}
    if not isinstance(salida, dict) or not salida:
        print("ERROR: transporte default sin salida.", file=sys.stderr)
        return 1
    if not isinstance(entrega, dict) or not entrega:
        print("ERROR: transporte default sin entrega.", file=sys.stderr)
        return 1
    for loc, label in [(salida, "salida"), (entrega, "entrega")]:
        if not str(loc.get("direccion") or "").strip():
            loc["direccion"] = "S/D"
        if not str(loc.get("numCasa") or "").strip():
            loc["numCasa"] = "0"
        if not str(loc.get("telefono") or "").strip():
            loc["telefono"] = "0"
        for key in ("departamento", "distrito", "ciudad"):
            if not str(loc.get(key) or "").strip():
                print(f"ERROR: transporte {label} sin {key}.", file=sys.stderr)
                return 1

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
            "salida": salida,
            "entrega": entrega,
            "transportista": default_transporte.get("transportista") or {
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
    try:
        pre_xml, geo_info = _ensure_nre_geo_blocks(pre_xml, lookup)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

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

    for tag in ["gOpeCom", "gCamCond", "gValorItem", "gTotSub"]:
        if xml_root.find(f".//s:{tag}", NS) is not None:
            print(f"ERROR: tag prohibido <{tag}> presente en {out_path}", file=sys.stderr)
            return 1

    for loc_tag in ["gCamSal", "gCamEnt"]:
        if xml_root.find(f".//s:gTransp/s:{loc_tag}", NS) is None:
            print(f"ERROR: falta gTransp/{loc_tag} en {out_path}", file=sys.stderr)
            return 1

    geo_errors = _validate_nre_geo_descriptions(xml_root, NS)
    if geo_errors:
        print(f"ERROR: {geo_errors[0]}", file=sys.stderr)
        return 1
    for path in [
        ".//s:gTransp/s:gCamSal/s:dDesCiuSal",
        ".//s:gTransp/s:gCamEnt/s:dDesCiuEnt",
    ]:
        el = xml_root.find(path, NS)
        if el is not None and (el.text or "").strip() == "CIUDAD":
            print(f"ERROR: dDesCiu* placeholder CIUDAD en {out_path}", file=sys.stderr)
            return 1

    sal_info = _extract_loc_info(xml_root, "gCamSal") or geo_info.get("gCamSal", {})
    ent_info = _extract_loc_info(xml_root, "gCamEnt") or geo_info.get("gCamEnt", {})
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
