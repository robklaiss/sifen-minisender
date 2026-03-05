from datetime import datetime
from decimal import Decimal
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def _doc_extra_for(doc_type: str) -> dict:
    extra = webapp._default_extra_json_for(doc_type) or {}
    if doc_type == "4":
        extra["documentoAsociado"] = {"tipoDocumentoAsoc": "3"}
        extra.setdefault("autofactura", {})
        extra["autofactura"]["iNatVen"] = "1"
        extra["autofactura"]["iTipIDVen"] = "1"
        extra["autofactura"]["documento"] = "A12345"
        extra["autofactura"]["nombre"] = "Vendedor AFE"
        extra["autofactura"]["direccion"] = "Calle Vendedor"
        extra["autofactura"]["numCasa"] = "10"
        extra["autofactura"]["departamentoVendedor"] = "12"
        extra["autofactura"]["ciudadVendedor"] = "6106"
    if doc_type in ("5", "6"):
        extra["documentoAsociado"] = {
            "tipoDocumentoAsoc": "1",
            "cdcAsociado": "9" * 44,
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


def _build_payload(doc_type: str) -> dict:
    template = webapp._repo_root() / "templates" / "xml" / {
        "1": "rde_factura.xml",
        "4": "rde_autofactura.xml",
        "5": "rde_nota_credito.xml",
        "6": "rde_nota_debito.xml",
        "7": "rde_remision.xml",
    }[doc_type]
    lines = [
        {"description": "Linea 10%", "qty": Decimal("1"), "price_unit": Decimal("100"), "line_total": Decimal("100"), "iva_rate": 10},
    ]
    build = webapp._build_invoice_xml_from_template(
        template_path=str(template),
        invoice_id=800000 + int(doc_type),
        customer={"name": "Cliente Test", "ruc": "7524653-8"},
        lines=lines,
        doc_number="0000001",
        doc_type=doc_type,
        extra_json=_doc_extra_for(doc_type),
        issue_dt=datetime(2026, 2, 10, 10, 0, 0),
        codseg="123456789",
        establishment="001",
        point_exp="001",
    )
    xml_text = build["xml_bytes"].decode("utf-8")
    invoice = {
        "customer_name": "Cliente Test",
        "customer_ruc": "7524653-8",
        "customer_email": "cliente@example.com",
        "establishment": "001",
        "point_exp": "001",
        "doc_type": doc_type,
    }
    payload = webapp._build_pdf_payload(
        invoice=invoice,
        items_for_pdf=build["items_for_pdf"],
        response_xml="",
        cdc=build["cdc"],
        dnumdoc=build["dnumdoc"],
        feemi=build["feemi"],
        total_str=build["total_str"],
        iva_total_str=build["iva_total_str"],
        source_xml_text=xml_text,
    )
    return payload


def _payload_text(payload: dict) -> str:
    parts = []
    title = payload.get("pdf_header_title")
    if title:
        parts.append(str(title))
    for section in payload.get("extra_sections", []):
        if not isinstance(section, dict):
            continue
        if section.get("title"):
            parts.append(str(section.get("title")))
        for item in section.get("items", []):
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                parts.append(str(item[0]))
                parts.append(str(item[1]))
            elif isinstance(item, dict):
                if item.get("label"):
                    parts.append(str(item.get("label")))
                if item.get("value"):
                    parts.append(str(item.get("value")))
    return " ".join(parts)


@pytest.fixture()
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", str(tmp_path / "webui_test.db"))
    with webapp.app.app_context():
        webapp.init_db()
        yield


def test_pdf_payload_doc_type_4(app_ctx):
    webapp.set_setting("timbrado_num", "18578288")
    webapp.set_setting("timbrado_fe_ini", "2026-01-14")
    payload = _build_payload("4")
    text = _payload_text(payload)
    assert "Autofactura electrónica" in text
    assert "Datos del vendedor" in text
    assert "A12345" in text


def test_pdf_payload_doc_type_5(app_ctx):
    webapp.set_setting("timbrado_num", "18578288")
    webapp.set_setting("timbrado_fe_ini", "2026-01-14")
    payload = _build_payload("5")
    text = _payload_text(payload)
    assert "Nota de crédito electrónica" in text
    assert "9" * 44 in text


def test_pdf_payload_doc_type_7(app_ctx):
    webapp.set_setting("timbrado_num", "18578288")
    webapp.set_setting("timbrado_fe_ini", "2026-01-14")
    payload = _build_payload("7")
    text = _payload_text(payload)
    assert "Nota de remisión electrónica" in text
    assert "Transporte" in text or "Toyota" in text
