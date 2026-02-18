from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import webui.app as webapp


def test_webui_app_has_no_hardcoded_venv_python_runner():
    app_py = Path(__file__).resolve().parents[1] / "webui" / "app.py"
    content = app_py.read_text(encoding="utf-8")

    assert "/.venv/bin/python" not in content
    assert "/app/.venv/bin/python" not in content


def test_resolve_minisender_python_uses_sys_executable_by_default(monkeypatch):
    monkeypatch.delenv("MINISENDER_PY", raising=False)
    monkeypatch.delenv("WEBUI_MINISENDER_PY", raising=False)

    assert webapp.resolve_minisender_python() == sys.executable
