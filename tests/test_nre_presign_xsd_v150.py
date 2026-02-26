from datetime import datetime, timezone
import xml.etree.ElementTree as ET

import webui.app as webapp
from app.sifen_client.xsd_validator import validate_rde_and_lote

NS = "http://ekuatia.set.gov.py/sifen/xsd"


def _gdtipde_children_order(root: ET.Element) -> list[str]:
    gdtip = root.find(f".//{{{NS}}}gDtipDE")
    if gdtip is None:
        return []
    return [child.tag.split("}")[-1] for child in list(gdtip)]

def test_nre_presign_xsd_v150():
    with webapp.app.app_context():
        webapp.init_db()
        webapp.set_setting("timbrado_num", "18578288")
        webapp.set_setting("timbrado_fe_ini", "2026-01-14")

    xsd_dir = webapp._repo_root() / "schemas_sifen"
    assert (xsd_dir / "rDE_prevalidador_v150.xsd").exists(), "Falta rDE_prevalidador_v150.xsd"

    issue_dt = datetime(2026, 2, 25, 12, 0, 0, tzinfo=timezone.utc)
    doc_number = "1234567"

    extra = webapp._default_extra_json_for("7") or {}
    extra.setdefault("ope", {})
    extra["ope"]["codseg"] = "123456789"

    out = webapp._build_invoice_xml_from_template(
        template_path=str(webapp._repo_root() / "templates" / "xml" / "rde_remision.xml"),
        invoice_id=990007,
        customer={"name": "Cliente Test", "ruc": "7524653-8"},
        lines=[
            {"description": "Linea 10%", "qty": 1.5, "price_unit": 100, "line_total": 150, "iva_rate": 10},
            {"description": "Linea 5%", "qty": 2, "price_unit": 50, "line_total": 100, "iva_rate": 5},
        ],
        doc_number=doc_number,
        doc_type="7",
        extra_json=extra,
        issue_dt=issue_dt,
        establishment="001",
        point_exp="001",
    )

    xmlb = out["xml_bytes"]
    root = ET.fromstring(xmlb)

    res = validate_rde_and_lote(xmlb, None, xsd_dir)
    if not res.get("rde_ok"):
        order = _gdtipde_children_order(root)
        raise AssertionError(
            "XSD FAIL iTiDE=7: "
            f"schema={res.get('schema_rde')} "
            f"reason={res.get('schema_reason')} "
            f"errors={res.get('rde_errors')} "
            f"gDtipDE_order={order}"
        )
