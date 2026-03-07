from datetime import datetime
from pathlib import Path
import json
import re
import sys
import xml.etree.ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


NS = {"s": "http://ekuatia.set.gov.py/sifen/xsd"}


@pytest.fixture()
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", str(tmp_path / "webui_afe.db"))
    with webapp.app.app_context():
        webapp.init_db()
        yield


def test_afe_new_invoice_without_customer_and_builds_vendor(app_ctx):
    client = webapp.app.test_client()

    payload = {
        "doc_type": "4",
        "establishment": "001",
        "point_exp": "001",
        "description": "Servicio",
        "qty": "1",
        "price_unit": "1000",
        "afe_tipo_vendedor": "1",
        "afe_tipo_doc": "2",
        "afe_nro_doc": "A12345",
        "afe_nombre": "Vendedor Test",
        "afe_direccion": "Calle 1",
        "afe_num_casa": "0",
        "afe_departamento": "1",
        "afe_distrito": "1",
        "afe_ciudad": "1",
    }

    resp = client.post("/invoice/new", data=payload, follow_redirects=False)
    assert resp.status_code in (302, 303)

    location = resp.headers.get("Location") or ""
    assert "/invoice/" in location
    invoice_id = int(location.rsplit("/", 1)[-1])

    with webapp.app.app_context():
        con = webapp.get_db()
        inv = con.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        assert inv is not None
        assert inv["doc_type"] == "4"

        extra = webapp._parse_extra_json(inv["doc_extra_json"], "4")
        vendor = webapp._afe_vendor_from_extra(extra)
        assert vendor.get("documento") == "A12345"
        assert vendor.get("nombre") == "Vendedor Test"

        lines = con.execute(
            "SELECT * FROM invoice_lines WHERE invoice_id=? ORDER BY id ASC",
            (invoice_id,),
        ).fetchall()
        assert lines

        build = webapp._build_invoice_xml_from_template(
            template_path=webapp._template_for_doc_type("4"),
            invoice_id=invoice_id,
            customer={"name": "Cliente X", "ruc": "80012345-6"},
            lines=lines,
            doc_number="0000001",
            doc_type="4",
            extra_json=extra,
            issue_dt=datetime(2026, 2, 10, 10, 0, 0),
            codseg="123456789",
            establishment="001",
            point_exp="001",
        )

        root = ET.fromstring(build["xml_bytes"])
        ruc_em = root.findtext(".//s:gEmis/s:dRucEm", default="", namespaces=NS)
        tip_cont_em = root.findtext(".//s:gEmis/s:iTipCont", default="", namespaces=NS)
        ruc_rec = root.findtext(".//s:gDatRec/s:dRucRec", default="", namespaces=NS)
        i_nat_rec = root.findtext(".//s:gDatRec/s:iNatRec", default="", namespaces=NS)
        i_ti_ope = root.findtext(".//s:gDatRec/s:iTiOpe", default="", namespaces=NS)
        i_ti_cont_rec = root.findtext(".//s:gDatRec/s:iTiContRec", default="", namespaces=NS)
        assert ruc_em
        assert ruc_rec == ruc_em
        assert i_nat_rec == "1"
        assert i_ti_ope == "2"
        assert i_ti_cont_rec == tip_cont_em

        gcam = root.find(".//s:gDtipDE/s:gCamAE", NS)
        assert gcam is not None
        assert gcam.findtext("s:dNumIDVen", default="", namespaces=NS) == "A12345"
        assert gcam.findtext("s:dNomVen", default="", namespaces=NS) == "Vendedor Test"

        gdtip = root.find(".//s:gDtipDE", NS)
        assert gdtip is not None
        tags = [el.tag.split("}")[-1] for el in list(gdtip)]
        assert "gCamAE" in tags
        assert "gCamCond" in tags
        assert "gCamItem" in tags
        assert tags.index("gCamAE") < tags.index("gCamCond") < tags.index("gCamItem")


def test_afe_new_invoice_city_select(app_ctx):
    client = webapp.app.test_client()

    resp = client.get("/invoice/new?doc_type=4")
    assert resp.status_code == 200

    html = resp.get_data(as_text=True)
    for field in ("afe_departamento", "afe_distrito", "afe_ciudad"):
        assert re.search(rf'<select[^>]*name="{field}"[^>]*>', html) is not None

    match = re.search(r'<select[^>]*name="afe_ciudad"[^>]*>.*?</select>', html, re.S)
    assert match is not None
    select_html = match.group(0)
    assert "disabled" in select_html
    assert re.search(r'value="1"[^>]*>[^<]*Asunc', select_html, re.I) is not None


def test_georef_tree_contains_asuncion():
    tree = json.loads(Path("data/georef_tree.json").read_text(encoding="utf-8"))
    assert {"dep", "dist_by_dep", "city_by_dist", "city_to_dist", "dist_to_dep"} <= set(tree.keys())
    city_found = False
    for cities in tree.get("city_by_dist", {}).values():
        if not isinstance(cities, dict):
            continue
        for name in cities.values():
            if "ASUNCION" in str(name).upper():
                city_found = True
                break
        if city_found:
            break
    assert city_found
