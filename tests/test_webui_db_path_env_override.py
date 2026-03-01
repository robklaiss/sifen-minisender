from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def test_get_db_uses_env_path(monkeypatch, tmp_path):
    tmp_db = tmp_path / "custom_webui.db"
    monkeypatch.setenv("SIFEN_WEBUI_DB", str(tmp_db))
    monkeypatch.setattr(webapp, "DB_PATH", str(tmp_path / "default.db"))

    seen = {}
    real_connect = sqlite3.connect

    def fake_connect(path, *args, **kwargs):
        seen["path"] = path
        return real_connect(path, *args, **kwargs)

    monkeypatch.setattr(webapp.sqlite3, "connect", fake_connect, raising=True)

    with webapp.app.app_context():
        con = webapp.get_db()
        assert con is not None

    assert seen["path"] == str(tmp_db)
    assert webapp.DB_PATH == str(tmp_db)
