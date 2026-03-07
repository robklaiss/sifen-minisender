from datetime import datetime
from decimal import Decimal
from pathlib import Path
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp
from app.sifen_client.xsd_validator import validate_de_xml_against_xsd


NS = {"s": "http://ekuatia.set.gov.py/sifen/xsd"}


def _doc_extra_nc() -> dict:
    extra = webapp._default_extra_json_for("5") or {}
    extra["documentoAsociado"] = {
        "tipoDocumentoAsoc": "1",
        "cdcAsociado": "1" * 44,
    }
    extra["iMotEmi"] = "1"
    return extra


def _build_nc_xml(invoice_id: int = 43, doc_number: str = "0000003") -> dict:
    template = webapp._repo_root() / "templates" / "xml" / "rde_nota_credito.xml"
    lines = [
        {
            "description": "Item nota de credito",
            "qty": Decimal("1"),
            "price_unit": Decimal("1000"),
            "line_total": Decimal("1000"),
            "iva_rate": 10,
        }
    ]
    return webapp._build_invoice_xml_from_template(
        template_path=str(template),
        invoice_id=invoice_id,
        customer={"name": "Robin Klaiss", "ruc": "7524653-8"},
        lines=lines,
        doc_number=doc_number,
        doc_type="5",
        extra_json=_doc_extra_nc(),
        issue_dt=datetime(2026, 2, 19, 15, 0, 0),
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


def test_nc_master_smoke_covers_historical_regressions(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", str(tmp_path / "webui_nc_master.db"))
    monkeypatch.setenv("SIFEN_CSC", "A62e367A738D1050E364D9680f9E4a79")
    monkeypatch.setenv("SIFEN_CSC_ID", "1")

    with webapp.app.app_context():
        webapp.init_db()
        webapp.set_setting("timbrado_num", "18578288")
        webapp.set_setting("timbrado_fe_ini", "2026-01-14")

        build = _build_nc_xml()
        root = ET.fromstring(build["xml_bytes"])

        gopecom = root.find(".//s:gDatGralOpe/s:gOpeCom", NS)
        assert gopecom is not None
        assert gopecom.find("s:iTipTra", NS) is None
        assert gopecom.find("s:dDesTipTra", NS) is None
        assert gopecom.findtext("s:iTImp", default="", namespaces=NS) == "1"
        assert gopecom.findtext("s:cMoneOpe", default="", namespaces=NS) == "PYG"

        assert root.find(".//s:gDtipDE/s:gCamCond", NS) is None
        assert root.find(".//s:gDtipDE/s:gTransp", NS) is None

        gcam_nc = root.find(".//s:gDtipDE/s:gCamNCDE", NS)
        assert gcam_nc is not None
        assert gcam_nc.findtext("s:iMotEmi", default="", namespaces=NS) == "1"

        gcam_assoc = root.find(".//s:gCamDEAsoc", NS)
        assert gcam_assoc is not None
        assert gcam_assoc.findtext("s:iTipDocAso", default="", namespaces=NS) == "1"
        assert gcam_assoc.findtext("s:dCdCDERef", default="", namespaces=NS) == "1" * 44

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
