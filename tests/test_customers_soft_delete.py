from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def _seed_customer(tmp_path: Path, monkeypatch) -> int:
    db_path = tmp_path / "webui_customers.db"
    monkeypatch.setattr(webapp, "DB_PATH", str(db_path))

    with webapp.app.app_context():
        webapp.init_db()
        con = webapp.get_db()
        con.execute(
            "INSERT INTO customers (name, ruc, created_at) VALUES (?,?,?)",
            ("Cliente Eliminar", "80000000-0", webapp.now_iso()),
        )
        customer_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
        con.commit()

    return customer_id


def test_customer_soft_delete_hides_from_list(tmp_path, monkeypatch):
    customer_id = _seed_customer(tmp_path, monkeypatch)
    client = webapp.app.test_client()

    resp = client.post(
        f"/customer/{customer_id}/delete",
        data={"confirm_delete": "YES"},
    )
    assert resp.status_code in (302, 303)

    with webapp.app.app_context():
        con = webapp.get_db()
        row = con.execute(
            "SELECT deleted_at FROM customers WHERE id=?",
            (customer_id,),
        ).fetchone()

    assert row["deleted_at"]

    resp = client.get("/customers")
    assert resp.status_code == 200
    assert "Cliente Eliminar" not in resp.get_data(as_text=True)
