from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


@pytest.fixture()
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", str(tmp_path / "webui_invoice_new_emit.db"))
    with webapp.app.app_context():
        webapp.init_db()
        yield


def _seed_customer() -> int:
    with webapp.app.app_context():
        con = webapp.get_db()
        con.execute(
            "INSERT INTO customers (name, ruc, created_at) VALUES (?,?,?)",
            ("Cliente Test", "80012345-6", webapp.now_iso()),
        )
        customer_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        con.commit()
    return int(customer_id)


def _invoice_payload(customer_id: int) -> dict:
    return {
        "doc_type": "1",
        "customer_id": str(customer_id),
        "establishment": "001",
        "point_exp": "001",
        "description": "Servicio",
        "qty": "2",
        "price_unit": "500",
    }


def _afe_payload() -> dict:
    return {
        "doc_type": "4",
        "establishment": "001",
        "point_exp": "001",
        "description": "Servicio AFE",
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


def test_invoice_new_confirm_emit_uses_existing_emit_flow(app_ctx, monkeypatch):
    customer_id = _seed_customer()
    client = webapp.app.test_client()
    calls = {}

    def fake_process(invoice_id, env, async_mode=False):
        calls["process"] = (invoice_id, env, async_mode)
        return webapp.redirect(webapp.url_for("invoice_detail", invoice_id=invoice_id))

    monkeypatch.setattr(webapp, "_process_invoice_emit", fake_process)

    payload = _invoice_payload(customer_id)
    payload.update({"env": "test", "confirm_emit": "YES"})
    resp = client.post("/invoice/new", data=payload, follow_redirects=False)

    assert resp.status_code in (302, 303)
    invoice_id, env, async_mode = calls["process"]
    assert (env, async_mode) == ("test", False)

    with webapp.app.app_context():
        con = webapp.get_db()
        row = con.execute(
            "SELECT status, total, doc_type FROM invoices WHERE id=?",
            (invoice_id,),
        ).fetchone()

    assert row is not None
    assert row["status"] == "DRAFT"
    assert row["total"] == 1000
    assert row["doc_type"] == "1"


def test_invoice_new_without_confirm_emit_stays_draft(app_ctx, monkeypatch):
    customer_id = _seed_customer()
    client = webapp.app.test_client()

    def fake_process(*_args, **_kwargs):
        raise AssertionError("should not emit without confirm_emit=YES")

    monkeypatch.setattr(webapp, "_process_invoice_emit", fake_process)

    resp = client.post("/invoice/new", data=_invoice_payload(customer_id), follow_redirects=False)

    assert resp.status_code in (302, 303)
    location = resp.headers.get("Location") or ""
    invoice_id = int(location.rsplit("/", 1)[-1])

    with webapp.app.app_context():
        con = webapp.get_db()
        row = con.execute(
            "SELECT status, total, doc_type FROM invoices WHERE id=?",
            (invoice_id,),
        ).fetchone()

    assert row is not None
    assert row["status"] == "DRAFT"
    assert row["total"] == 1000
    assert row["doc_type"] == "1"


def test_invoice_new_confirm_emit_auto_enqueues_when_sifen_down(app_ctx, monkeypatch):
    customer_id = _seed_customer()
    client = webapp.app.test_client()
    calls = {}

    def fake_enqueue(invoice_id, env):
        calls["enqueue"] = (invoice_id, env)

    def fake_process(*_args, **_kwargs):
        raise AssertionError("should not emit when SIFEN is down")

    monkeypatch.setattr(webapp, "_sifen_preflight_ok", lambda: (False, "down"))
    monkeypatch.setattr(webapp, "_enqueue_invoice", fake_enqueue)
    monkeypatch.setattr(webapp, "_process_invoice_emit", fake_process)

    payload = _invoice_payload(customer_id)
    payload.update({"env": "prod", "confirm_emit": "YES"})
    resp = client.post("/invoice/new", data=payload, follow_redirects=False)

    assert resp.status_code in (302, 303)
    location = resp.headers.get("Location") or ""
    invoice_id = int(location.rsplit("/", 1)[-1])
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


def test_afe_invoice_new_confirm_emit_does_not_remain_draft(app_ctx, monkeypatch):
    client = webapp.app.test_client()
    calls = {}

    def fake_process(invoice_id, env, async_mode=False):
        calls["process"] = (invoice_id, env, async_mode)
        with webapp.app.app_context():
            con = webapp.get_db()
            con.execute(
                "UPDATE invoices SET status=?, sifen_env=? WHERE id=?",
                ("SENT", env, invoice_id),
            )
            con.commit()
        return webapp.redirect(webapp.url_for("invoice_detail", invoice_id=invoice_id))

    monkeypatch.setattr(webapp, "_process_invoice_emit", fake_process)

    payload = _afe_payload()
    payload.update({"env": "test", "confirm_emit": "YES"})
    resp = client.post("/invoice/new", data=payload, follow_redirects=False)

    assert resp.status_code in (302, 303)
    invoice_id, env, async_mode = calls["process"]
    assert (env, async_mode) == ("test", False)

    with webapp.app.app_context():
        con = webapp.get_db()
        row = con.execute(
            "SELECT status, doc_type, sifen_env FROM invoices WHERE id=?",
            (invoice_id,),
        ).fetchone()

    assert row is not None
    assert row["doc_type"] == "4"
    assert row["status"] == "SENT"
    assert row["sifen_env"] == "test"
