from datetime import datetime, timezone
import re
import xml.etree.ElementTree as ET

import webui.app as webapp
from app.sifen_client.xsd_validator import validate_rde_and_lote

NS = "http://ekuatia.set.gov.py/sifen/xsd"


def _get_text(root: ET.Element, path: str) -> str:
    el = root.find(path)
    return (el.text or "").strip() if el is not None else ""

def test_xsd_presign_all_doc_types_v150():
    # Inicializar app (sin depender de fixture)
    with webapp.app.app_context():
        webapp.init_db()
        webapp.set_setting("timbrado_num", "18578288")
        webapp.set_setting("timbrado_fe_ini", "2026-01-14")

    xsd_dir = webapp._repo_root() / "schemas_sifen"
    assert (xsd_dir / "siRecepDE_v150.xsd").exists(), "Falta siRecepDE_v150.xsd"
    assert (xsd_dir / "DE_v150.xsd").exists(), "Falta DE_v150.xsd"
    assert (xsd_dir / "rDE_prevalidador_v150.xsd").exists(), "Falta rDE_prevalidador_v150.xsd"

    issue_dt = datetime(2026, 2, 25, 12, 0, 0, tzinfo=timezone.utc)

    # iTiDE a validar (NO incluye Nota de Remisión todavía)
    doc_types = ["1", "4", "5", "6", "7"]

    for dt in doc_types:
        doc_number = f"000000{dt}"  # 7 dígitos (minLength=7)

        extra = webapp._default_extra_json_for(dt) or {}
        if dt == "4":
            extra.setdefault("autofactura", {})
            extra["autofactura"].setdefault("documento", "1234567")
            extra["autofactura"].setdefault("nombre", "Vendedor")

        template_name = "rde_factura.xml"
        if dt == "4":
            template_name = "rde_autofactura.xml"
        elif dt == "7":
            template_name = "rde_remision.xml"

        out = webapp._build_invoice_xml_from_template(
            template_path=str(webapp._repo_root() / "templates" / "xml" / template_name),
            invoice_id=990000 + int(dt),
            customer={"name": "Cliente Test", "ruc": "7524653-8"},
            lines=[
                {"description": "Linea 10%", "qty": 1.5, "price_unit": 100, "line_total": 150, "iva_rate": 10},
                {"description": "Linea 5%", "qty": 2, "price_unit": 50, "line_total": 100, "iva_rate": 5},
            ],
            doc_number=doc_number,
            doc_type=dt,
            extra_json=extra,
            issue_dt=issue_dt,
            codseg="123456789",
            establishment="001",
            point_exp="001",
        )

        xmlb = out["xml_bytes"]
        root = ET.fromstring(xmlb)

        dver = _get_text(root, f".//{{{NS}}}dVerFor")
        assert dver == "150", f"Esperaba dVerFor=150 para iTiDE={dt}, vino {dver!r}"

        res = validate_rde_and_lote(xmlb, None, xsd_dir)
        if not res.get("rde_ok"):
            raise AssertionError(
                f"XSD FAIL iTiDE={dt}: schema={res.get('schema_rde')} "
                f"reason={res.get('schema_reason')} errors={res.get('rde_errors')}"
            )

        if dt == "7":
            gdtip = root.find(f".//{{{NS}}}gDtipDE")
            assert gdtip is not None
            tags = [child.tag.split("}")[-1] for child in list(gdtip)]
            item_indices = [i for i, tag in enumerate(tags) if tag == "gCamItem"]
            assert item_indices, f"gCamItem missing for iTiDE=7; order={tags}"
            first_item = item_indices[0]
            last_item = item_indices[-1]
            if "gCamCond" in tags:
                assert tags.index("gCamCond") < first_item, f"gCamCond after items; order={tags}"
            for tag in ("gCamEsp", "gTransp", "gCamRDE"):
                if tag in tags:
                    assert last_item < tags.index(tag), f"{tag} before items; order={tags}"

        dfe = _get_text(root, f".//{{{NS}}}gDatGralOpe/{{{NS}}}dFeEmiDE")
        dfirma = _get_text(root, f".//{{{NS}}}dFecFirma")
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", dfe)
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", dfirma)
        assert "+" not in dfe and "+" not in dfirma
