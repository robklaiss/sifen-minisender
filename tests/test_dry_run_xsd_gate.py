from datetime import datetime
from decimal import Decimal
from pathlib import Path
import json
import os
import re
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp
from app.sifen_client.xsd_validator import validate_de_xml_against_xsd


def _doc_extra_remision() -> dict:
    extra = webapp._default_extra_json_for("7") or {}
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


def _build_remision_xml(invoice_id: int, doc_number: str = "0000070") -> dict:
    template = webapp._repo_root() / "templates" / "xml" / "rde_remision.xml"
    lines = [
        {
            "description": "Item remision",
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
        doc_type="7",
        extra_json=_doc_extra_remision(),
        issue_dt=datetime(2026, 2, 10, 8, 0, 0),
        codseg="123456789",
        establishment="001",
        point_exp="001",
    )


def _signed_xml_stub(xml_bytes: bytes, _p12_path: str, _p12_password: str) -> bytes:
    xml_text = xml_bytes.decode("utf-8")
    m = re.search(r'<DE[^>]+Id="([0-9]{44})"', xml_text)
    cdc = m.group(1) if m else "0" * 44
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
    assert "<gCamFuFD>" in xml_text
    return xml_text.replace("<gCamFuFD>", signature + "<gCamFuFD>", 1).encode("utf-8")


def _seed_invoice_70() -> None:
    con = webapp.get_db()
    customer_id = con.execute(
        "INSERT INTO customers (name, ruc, email, phone, created_at) VALUES (?,?,?,?,?)",
        ("Cliente 70", "80012345-0", "cliente70@test.local", "", webapp.now_iso()),
    ).lastrowid
    con.execute(
        """
        INSERT INTO invoices (
            id, created_at, customer_id, currency, total, status, doc_type, doc_extra_json, establishment, point_exp
        ) VALUES (?,?,?,?,?,?,?,?,?,?)
        """,
        (
            70,
            webapp.now_iso(),
            customer_id,
            "PYG",
            1000,
            "DRAFT",
            "7",
            json.dumps(_doc_extra_remision()),
            "001",
            "001",
        ),
    )
    con.execute(
        "INSERT INTO invoice_lines (invoice_id, description, qty, price_unit, line_total) VALUES (?,?,?,?,?)",
        (70, "Linea remision", 1, 1000, 1000),
    )
    con.commit()


@pytest.fixture()
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", str(tmp_path / "webui_test.db"))
    monkeypatch.setenv("SIFEN_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    monkeypatch.setenv("SIFEN_SIGN_P12_PATH", "/tmp/fake-cert.p12")
    monkeypatch.setenv("SIFEN_SIGN_P12_PASSWORD", "fake-password")
    monkeypatch.setenv("SIFEN_CSC", "A62e367A738D1050E364D9680f9E4a79")
    monkeypatch.setenv("SIFEN_CSC_ID", "1")
    with webapp.app.app_context():
        webapp.init_db()
        webapp.set_setting("timbrado_num", "18578288")
        webapp.set_setting("timbrado_fe_ini", "2026-01-14")
        yield


def test_dry_run_remision_xsd_ok_and_no_error_file(app_ctx, monkeypatch):
    monkeypatch.setattr(webapp, "sign_de_with_p12", _signed_xml_stub)
    _seed_invoice_70()

    client = webapp.app.test_client()
    resp = client.post("/api/invoices/70/dry-run")
    data = resp.get_json() or {}

    assert resp.status_code == 200
    assert data.get("ok") is True
    assert data.get("xsd_ok") is True
    art_dir = Path(data["artifacts_dir"])
    assert art_dir.exists()
    assert not (art_dir / "xsd_errors.txt").exists()


def test_validate_de_xml_against_xsd_fails_if_missing_iModTrans(app_ctx):
    build = _build_remision_xml(invoice_id=7001, doc_number="0007001")
    signed_xml = _signed_xml_stub(build["xml_bytes"], "", "").decode("utf-8")
    signed_qr_text, _ = webapp._update_qr_in_signed_xml(
        signed_xml,
        os.environ["SIFEN_CSC"],
        os.environ["SIFEN_CSC_ID"],
    )
    broken = re.sub(r"<iModTrans>.*?</iModTrans>", "", signed_qr_text, count=1, flags=re.DOTALL)

    ok, errors = validate_de_xml_against_xsd(
        broken,
        schemas_dir=webapp._repo_root() / "schemas_sifen",
    )

    assert ok is False
    assert errors
    assert any("iModTrans" in err for err in errors)
