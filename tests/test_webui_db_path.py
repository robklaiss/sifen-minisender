from pathlib import Path
import sqlite3
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def test_db_path_defaults_under_repo_root_and_init_db_not_webui(monkeypatch, tmp_path):
    monkeypatch.delenv("WEBUI_DB_PATH", raising=False)
    monkeypatch.delenv("SIFEN_WEBUI_DB_PATH", raising=False)

    db_path = webapp._resolve_db_path()
    repo_root = webapp._repo_root()
    db_path_obj = Path(db_path)

    assert db_path_obj.is_absolute()
    assert repo_root in db_path_obj.parents
    assert db_path_obj.parent == repo_root / "data"

    monkeypatch.setattr(webapp, "DB_PATH", db_path)

    mkdir_calls = []
    orig_mkdir = Path.mkdir

    def _mkdir(self, *args, **kwargs):
        mkdir_calls.append(self)
        assert self != Path("/webui")
        return orig_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", _mkdir, raising=True)

    orig_connect = webapp.sqlite3.connect

    def _connect(path, *args, **kwargs):
        assert path == db_path
        return orig_connect(str(tmp_path / "webui_test.db"))

    monkeypatch.setattr(webapp.sqlite3, "connect", _connect)

    with webapp.app.app_context():
        webapp.init_db()

    assert all(path != Path("/webui") for path in mkdir_calls)
