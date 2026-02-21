from datetime import datetime
from decimal import Decimal
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


NS = {"s": "http://ekuatia.set.gov.py/sifen/xsd"}


def _doc_extra_for(doc_type: str) -> dict:
    extra = webapp._default_extra_json_for(doc_type) or {}
    if doc_type == "4":
        extra["documentoAsociado"] = {"tipoDocumentoAsoc": "3"}
        extra.setdefault("autofactura", {})
        extra["autofactura"].setdefault("documento", "123456")
        extra["autofactura"].setdefault("nombre", "Vendedor")
    if doc_type in ("5", "6"):
        extra["documentoAsociado"] = {
            "tipoDocumentoAsoc": "1",
            "cdcAsociado": "0" * 44,
        }
        extra["iMotEmi"] = "1"
    if doc_type == "7":
        extra.setdefault("remision", {"iMotEmiNR": "1", "iRespEmiNR": "1"})
        extra["transporte"] = extra.get("transporte") or {
            "iTipTrans": "1",
            "iModTrans": "1",
            "iRespFlete": "1",
            "salida": {
                "direccion": "Sucursal salida",
                "numCasa": "100",
                "departamento": "12",
                "distrito": "154",
                "ciudad": "5044",
                "telefono": "021000000",
            },
            "entrega": {
                "direccion": "Sucursal entrega",
                "numCasa": "200",
                "departamento": "12",
                "distrito": "154",
                "ciudad": "5044",
                "telefono": "021000001",
            },
            "vehiculo": {
                "tipo": "1",
                "marca": "Toyota",
                "documentoTipo": "1",
                "numeroIden": "ABC123",
            },
        }
    return extra


def _build(doc_type: str, doc_number: str, issue_dt: datetime):
    template = webapp._repo_root() / "templates" / "xml" / {
        "1": "rde_factura.xml",
        "4": "rde_autofactura.xml",
        "5": "rde_nota_credito.xml",
        "6": "rde_nota_debito.xml",
        "7": "rde_remision.xml",
    }[doc_type]
    lines = [
        {"description": "Linea 10%", "qty": Decimal("1.5"), "price_unit": Decimal("100"), "line_total": Decimal("150"), "iva_rate": 10},
        {"description": "Linea 5%", "qty": Decimal("2"), "price_unit": Decimal("50"), "line_total": Decimal("100"), "iva_rate": 5},
    ]
    return webapp._build_invoice_xml_from_template(
        template_path=str(template),
        invoice_id=900000 + int(doc_type),
        customer={"name": "Cliente Test", "ruc": "7524653-8"},
        lines=lines,
        doc_number=doc_number,
        doc_type=doc_type,
        extra_json=_doc_extra_for(doc_type),
        issue_dt=issue_dt,
        codseg="123456789",
        establishment="001",
        point_exp="001",
    )


def _parse(xml_bytes: bytes) -> ET.Element:
    return ET.fromstring(xml_bytes)


@pytest.fixture()
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", str(tmp_path / "webui_test.db"))
    with webapp.app.app_context():
        webapp.init_db()
        yield


def test_builds_all_doc_types_and_cdc_changes(app_ctx):
    webapp.set_setting("timbrado_num", "18578288")
    webapp.set_setting("timbrado_fe_ini", "2026-01-14")
    for doc_type in ["1", "4", "5", "6", "7"]:
        b1 = _build(doc_type, "0000001", datetime(2026, 2, 10, 10, 0, 0))
        b2 = _build(doc_type, "0000002", datetime(2026, 2, 10, 10, 0, 0))
        assert b1["cdc"] != b2["cdc"]

        root = _parse(b1["xml_bytes"])
        de = root.find(".//s:DE", NS)
        assert de is not None
        assert de.attrib.get("Id") == b1["cdc"]


def test_timbrado_override_and_feinit_validation(app_ctx):
    webapp.set_setting("timbrado_num", "18578288")
    webapp.set_setting("timbrado_fe_ini", "2026-01-14")
    webapp.set_setting("est", "002")
    webapp.set_setting("pun", "003")

    with pytest.raises(RuntimeError, match="anterior al inicio de timbrado"):
        _build("1", "0000009", datetime(2026, 1, 13, 8, 0, 0))

    out = _build("1", "0000010", datetime(2026, 2, 10, 8, 0, 0))
    root = _parse(out["xml_bytes"])
    assert root.find(".//s:gTimb/s:dNumTim", NS).text == "18578288"
    assert root.find(".//s:gTimb/s:dFeIniT", NS).text == "2026-01-14"
    assert root.find(".//s:gTimb/s:dEst", NS).text == "001"
    assert root.find(".//s:gTimb/s:dPunExp", NS).text == "001"


def test_decimal_qty_totals_and_qr_update(app_ctx):
    webapp.set_setting("timbrado_num", "18578288")
    webapp.set_setting("timbrado_fe_ini", "2026-01-14")
    out = _build("1", "0000011", datetime(2026, 2, 10, 8, 0, 0))
    root = _parse(out["xml_bytes"])

    qty = root.find(".//s:gDtipDE/s:gCamItem/s:dCantProSer", NS).text
    assert qty.startswith("1.5")

    dsub10 = Decimal(root.find(".//s:gTotSub/s:dSub10", NS).text)
    dsub5 = Decimal(root.find(".//s:gTotSub/s:dSub5", NS).text)
    dtot = Decimal(root.find(".//s:gTotSub/s:dTotGralOpe", NS).text)
    assert dsub10 == Decimal("150")
    assert dsub5 == Decimal("100")
    assert dtot == Decimal("250")

    xml_text = out["xml_bytes"].decode("utf-8")
    # simular digest para cálculo de hash QR sin requerir firma real en test unitario
    xml_text = xml_text.replace("</gCamFuFD>", "</gCamFuFD><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:DigestValue>abc==</ds:DigestValue></ds:Signature>")
    updated, _ = webapp._update_qr_in_signed_xml(xml_text, "A62e367A738D1050E364D9680f9E4a79", "1")
    assert "TESTQRCODE" not in updated
    assert "cHashQR=" in updated


def test_remision_build_populates_gtransp_minimum(app_ctx):
    webapp.set_setting("timbrado_num", "18578288")
    webapp.set_setting("timbrado_fe_ini", "2026-01-14")
    out = _build("7", "0000012", datetime(2026, 2, 10, 8, 0, 0))
    root = _parse(out["xml_bytes"])

    gtransp = root.find(".//s:gDtipDE/s:gTransp", NS)
    assert gtransp is not None
    assert gtransp.find("s:iModTrans", NS) is not None
    assert (gtransp.find("s:iModTrans", NS).text or "").strip() != ""
    assert gtransp.find("s:gCamSal", NS) is not None
    assert gtransp.find("s:gCamEnt", NS) is not None
    assert gtransp.find("s:gVehTras", NS) is not None
