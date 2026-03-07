from datetime import datetime
from decimal import Decimal
from pathlib import Path
import os
import re
import sys
import xml.etree.ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp
from app.sifen_client.xsd_validator import validate_de_xml_against_xsd


NS = {"s": "http://ekuatia.set.gov.py/sifen/xsd"}


def _doc_extra_afe() -> dict:
    extra = webapp._default_extra_json_for("4") or {}
    extra["documentoAsociado"] = {"tipoDocumentoAsoc": "3"}
    extra.setdefault("autofactura", {})
    extra["autofactura"].setdefault("iNatVen", "1")
    extra["autofactura"].setdefault("iTipIDVen", "1")
    extra["autofactura"].setdefault("documento", "123456")
    extra["autofactura"].setdefault("nombre", "Vendedor AFE")
    extra["autofactura"].setdefault("direccion", "Direccion 123")
    extra["autofactura"].setdefault("numCasa", "0")
    extra["autofactura"].setdefault("departamentoVendedor", "12")
    extra["autofactura"].setdefault("ciudadVendedor", "6106")
    return extra


def _build_afe_xml(invoice_id: int = 39, doc_number: str = "0000010") -> dict:
    template = webapp._repo_root() / "templates" / "xml" / "rde_autofactura.xml"
    lines = [
        {
            "description": "Item autofactura",
            "qty": Decimal("1"),
            "price_unit": Decimal("1000"),
            "line_total": Decimal("1000"),
            "iva_rate": 10,
        }
    ]
    return webapp._build_invoice_xml_from_template(
        template_path=str(template),
        invoice_id=invoice_id,
        customer={"name": "Cliente Test", "ruc": "80012345-0"},
        lines=lines,
        doc_number=doc_number,
        doc_type="4",
        extra_json=_doc_extra_afe(),
        issue_dt=datetime(2026, 2, 19, 9, 0, 0),
        codseg="123456789",
        establishment="001",
        point_exp="001",
    )


def _signed_xml_stub(xml_bytes: bytes, _p12_path: str, _p12_password: str) -> bytes:
    xml_text = xml_bytes.decode("utf-8")
    match = re.search(r'<DE[^>]+Id="([0-9]{44})"', xml_text)
    cdc = match.group(1) if match else "0" * 44
    signature = (
        '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">'
        "<ds:SignedInfo>"
        '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>'
        '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
        f'<ds:Reference URI="#{cdc}">'
        "<ds:Transforms>"
        '<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'
        "</ds:Transforms>"
        '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>'
        "<ds:DigestValue>YWJjZA==</ds:DigestValue>"
        "</ds:Reference>"
        "</ds:SignedInfo>"
        "<ds:SignatureValue>YWJjZA==</ds:SignatureValue>"
        "</ds:Signature>"
    )
    return xml_text.replace("<gCamFuFD>", signature + "<gCamFuFD>", 1).encode("utf-8")


@pytest.fixture()
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", str(tmp_path / "webui_afe_master.db"))
    monkeypatch.setenv("SIFEN_CSC", "A62e367A738D1050E364D9680f9E4a79")
    monkeypatch.setenv("SIFEN_CSC_ID", "1")
    with webapp.app.app_context():
        webapp.init_db()
        webapp.set_setting("timbrado_num", "18578288")
        webapp.set_setting("timbrado_fe_ini", "2026-01-14")
        yield


def test_afe_master_smoke_covers_historical_regressions(app_ctx):
    build = _build_afe_xml()
    root = ET.fromstring(build["xml_bytes"])

    gdtip = root.find(".//s:gDtipDE", NS)
    assert gdtip is not None

    tags = [el.tag.split("}")[-1] for el in list(gdtip)]
    assert tags.index("gCamAE") < tags.index("gCamCond") < tags.index("gCamItem")

    assert root.findtext(".//s:gDatRec/s:iNatRec", default="", namespaces=NS) == "1"
    assert root.findtext(".//s:gDatRec/s:iTiOpe", default="", namespaces=NS) == "2"
    assert root.findtext(".//s:gDatRec/s:iTiContRec", default="", namespaces=NS) == root.findtext(
        ".//s:gEmis/s:iTipCont", default="", namespaces=NS
    )

    gcam_item = root.find(".//s:gDtipDE/s:gCamItem", NS)
    assert gcam_item is not None
    assert gcam_item.find("s:gValorItem", NS) is not None
    assert gcam_item.find("s:gCamIVA", NS) is None

    gcam_assoc = root.find(".//s:gCamDEAsoc", NS)
    assert gcam_assoc is not None
    assert gcam_assoc.findtext("s:iTipDocAso", default="", namespaces=NS) == "3"
    assert gcam_assoc.findtext("s:iTipCons", default="", namespaces=NS) == "1"
    assert gcam_assoc.findtext("s:dDesTipCons", default="", namespaces=NS) == "Constancia de no ser contribuyente"

    signed_xml = _signed_xml_stub(build["xml_bytes"], "", "").decode("utf-8")
    signed_qr_text, _ = webapp._update_qr_in_signed_xml(
        signed_xml,
        os.environ["SIFEN_CSC"],
        os.environ["SIFEN_CSC_ID"],
    )
    ok, errors = validate_de_xml_against_xsd(
        signed_qr_text,
        schemas_dir=webapp._repo_root() / "schemas_sifen",
    )
    assert ok is True, errors
