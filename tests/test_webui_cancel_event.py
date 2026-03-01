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


