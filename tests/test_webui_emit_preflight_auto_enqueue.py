from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def _seed_invoice(tmp_path: Path, monkeypatch) -> int:
    db_path = tmp_path / "webui_emit_preflight.db"
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
            "INSERT INTO invoices (created_at, customer_id, status, doc_type) VALUES (?,?,?,?)",
            (webapp.now_iso(), customer_id, "DRAFT", "1"),
        )
        invoice_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        con.commit()
    return invoice_id


def test_emit_auto_enqueues_when_sifen_down(tmp_path, monkeypatch):
    invoice_id = _seed_invoice(tmp_path, monkeypatch)
    client = webapp.app.test_client()
    calls = {}

    def fake_enqueue(inv_id, env):
        calls["enqueue"] = (inv_id, env)

    def fake_process(*_args, **_kwargs):
        raise AssertionError("should not emit when SIFEN is down")

    monkeypatch.setattr(webapp, "_sifen_preflight_ok", lambda: (False, "down"))
    monkeypatch.setattr(webapp, "_enqueue_invoice", fake_enqueue)
    monkeypatch.setattr(webapp, "_process_invoice_emit", fake_process)

    resp = client.post(
        f"/invoice/{invoice_id}/emit",
        data={"env": "prod", "confirm_emit": "YES"},
    )

    assert resp.status_code in (302, 303)
    assert calls["enqueue"] == (invoice_id, "prod")

    with webapp.app.app_context():
        con = webapp.get_db()
        row = con.execute(
            "SELECT status, queued_at, sifen_env, last_sifen_msg FROM invoices WHERE id=?",
            (invoice_id,),
        ).fetchone()

    assert row["status"] == "QUEUED"
    assert row["queued_at"]
    assert row["sifen_env"] == "prod"
    assert "SIFEN DOWN: encolado automático" in (row["last_sifen_msg"] or "")
