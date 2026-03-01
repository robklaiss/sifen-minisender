from pathlib import Path
import sqlite3
import sys

from flask import g

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def test_get_db_handles_wal_failure(monkeypatch, tmp_path):
    db_path = tmp_path / "webui_test.db"
    monkeypatch.setattr(webapp, "DB_PATH", str(db_path))

    orig_execute = sqlite3.Connection.execute

    def _execute(self, sql, *args, **kwargs):
        if "journal_mode" in sql.lower():
            raise sqlite3.OperationalError("database is locked")
        return orig_execute(self, sql, *args, **kwargs)

    monkeypatch.setattr(sqlite3.Connection, "execute", _execute, raising=True)

    with webapp.app.app_context():
        con = webapp.get_db()

        assert con is not None
        assert g.db is con
