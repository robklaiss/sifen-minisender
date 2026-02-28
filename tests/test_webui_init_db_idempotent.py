from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def test_init_db_is_idempotent_and_pdf_path_exists(tmp_path, monkeypatch):
    db_path = tmp_path / "webui_init.db"
    monkeypatch.setattr(webapp, "DB_PATH", str(db_path))

    with webapp.app.app_context():
        webapp.init_db()

    with webapp.app.app_context():
        webapp.init_db()
        con = webapp.get_db()
        rows = con.execute("PRAGMA table_info(invoices)").fetchall()
        assert any(r[1] == "pdf_path" for r in rows)
