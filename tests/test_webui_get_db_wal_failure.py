from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


class ConnWrapper:
    """
    Wrapper de sqlite3.Connection para poder simular falla en WAL sin
    monkeypatch de métodos built-in (no permitido en CPython).
    """
    def __init__(self, con: sqlite3.Connection):
        self._con = con

    def execute(self, sql, *args, **kwargs):
        if "journal_mode" in str(sql).lower():
            raise sqlite3.OperationalError("database is locked")
        return self._con.execute(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._con, name)


def test_get_db_handles_wal_failure(monkeypatch, tmp_path):
    db_path = tmp_path / "webui_test.db"
    monkeypatch.setattr(webapp, "DB_PATH", str(db_path))

    real_connect = sqlite3.connect

    def fake_connect(*args, **kwargs):
        return ConnWrapper(real_connect(*args, **kwargs))

    monkeypatch.setattr(sqlite3, "connect", fake_connect, raising=True)

    with webapp.app.app_context():
        con = webapp.get_db()
        assert con is not None
        # get_db debe dejar g.db seteado; webapp.get_db retorna g.db
        # (no importamos g aquí para no acoplar el test; basta con que no explote)
