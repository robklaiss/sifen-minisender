from pathlib import Path
import sys
from typing import Optional
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def _seed_invoice(tmp_path: Path, monkeypatch, doc_type: str, source_xml_path: Optional[str] = None) -> int:
    db_path = tmp_path / "webui_cancel.db"
    monkeypatch.setattr(webapp, "DB_PATH", str(db_path))

    with webapp.app.app_context():
        webapp.init_db()
        con = webapp.get_db()
        con.execute(
            "INSERT INTO customers (name, ruc, created_at) VALUES (?,?,?)",
            ("Cliente Test", "80012345-6", webapp.now_iso()),
        )
        customer_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        con.execute(
            "INSERT INTO invoices (created_at, customer_id, status, doc_type, source_xml_path) VALUES (?,?,?,?,?)",
            (
                webapp.now_iso(),
                customer_id,
                "DRAFT",
                doc_type,
                source_xml_path,
            ),
        )
        invoice_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        con.commit()
    return invoice_id


def test_cancel_event_guardrail_itide(tmp_path, monkeypatch):
    invoice_id = _seed_invoice(tmp_path, monkeypatch, doc_type="4")
    client = webapp.app.test_client()

    resp = client.post(
        f"/api/invoices/{invoice_id}/event/cancel",
        json={"env": "test", "motivo": "Motivo válido"},
    )

    assert resp.status_code == 400
    data = resp.get_json()
    assert data["error"] == "cancel_event_not_allowed"
    assert "iTiDE=4" in data["detail"]


def test_cancel_event_payload_build(tmp_path, monkeypatch):
    cdc = "1" * 44
    xml_path = tmp_path / "signed_de.xml"
    xml_path.write_text(f'<DE Id="{cdc}"></DE>', encoding="utf-8")

    invoice_id = _seed_invoice(tmp_path, monkeypatch, doc_type="1", source_xml_path=str(xml_path))

    artifacts_dir = tmp_path / "artifacts"
    monkeypatch.setenv("SIFEN_ARTIFACTS_DIR", str(artifacts_dir))
    monkeypatch.setenv("SIFEN_SIGN_P12_PATH", str(tmp_path / "dummy.p12"))
    monkeypatch.setenv("SIFEN_SIGN_P12_PASSWORD", "secret")
    monkeypatch.setenv("SIFEN_CERT_PATH", str(tmp_path / "cert.pem"))
    monkeypatch.setenv("SIFEN_KEY_PATH", str(tmp_path / "key.pem"))

    monkeypatch.setattr(webapp, "_make_event_ids", lambda: ("20260301010101", "0101010101"))

    captured = {}

    def fake_sign_event(xml_bytes, p12_path, p12_password):
        root = ET.fromstring(xml_bytes)
        assert webapp._local_name(root.tag) == "gGroupGesEve"
        eve = root.find(f".//{{{webapp.SIFEN_NS}}}rEve")
        assert eve is not None
        eve_id = eve.get("Id")
        assert eve_id
        signed = f"""<gGroupGesEve xmlns=\"{webapp.SIFEN_NS}\" xmlns:ds=\"{webapp.DS_NS}\">
  <rGesEve>
    <rEve Id=\"{eve_id}\"><dFecFirma>2026-03-01T01:40:48</dFecFirma></rEve>
    <ds:Signature>
      <ds:SignedInfo>
        <ds:Reference URI=\"#{eve_id}\"/>
      </ds:SignedInfo>
    </ds:Signature>
  </rGesEve>
</gGroupGesEve>"""
        return signed.encode("utf-8")

    class DummyResp:
        def __init__(self, content: bytes, status_code: int = 200):
            self.content = content
            self.status_code = status_code

    def fake_post(url, data=None, headers=None, cert=None, timeout=None):
        captured["soap"] = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else str(data)
        resp_xml = (
            "<rRetEnviEventoDe>"
            "<dEstRes>Aprobado</dEstRes>"
            "<dCodRes>0600</dCodRes>"
            "<dMsgRes>Evento registrado correctamente</dMsgRes>"
            "<dProtAut>ABC123</dProtAut>"
            "</rRetEnviEventoDe>"
        )
        return DummyResp(resp_xml.encode("utf-8"), 200)

    monkeypatch.setattr(webapp, "sign_event_with_p12", fake_sign_event)
    monkeypatch.setattr(webapp.requests, "post", fake_post)

    client = webapp.app.test_client()
    resp = client.post(
        f"/api/invoices/{invoice_id}/event/cancel",
        json={"env": "test", "motivo": "Motivo válido"},
    )

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["dCodRes"] == "0600"
    assert data["dProtAut"] == "ABC123"

    soap = captured.get("soap")
    assert soap
    assert "<soap:Envelope" in soap
    assert f"xmlns:soap=\"{webapp.SOAP_NS}\"" in soap
    assert f"xmlns:xsd=\"{webapp.SIFEN_NS}\"" in soap
    assert "<xsd:rEnviEventoDe>" in soap
    assert "<xsd:dId>20260301010101</xsd:dId>" in soap
    assert "<xsd:dEvReg>" in soap
    assert "<?xml" not in soap

    root = ET.fromstring(soap)
    ns = {"soap": webapp.SOAP_NS, "xsd": webapp.SIFEN_NS, "s": webapp.SIFEN_NS, "ds": webapp.DS_NS}
    ggroup = root.find(".//s:gGroupGesEve", ns)
    assert ggroup is not None
    rGesEve = ggroup.find("s:rGesEve", ns)
    assert rGesEve is not None
    children = list(rGesEve)
    assert webapp._local_name(children[0].tag) == "rEve"
    assert webapp._local_name(children[1].tag) == "Signature"
    ref = children[1].find(".//ds:Reference", ns)
    assert ref is not None
    assert ref.get("URI") == "#0101010101"
