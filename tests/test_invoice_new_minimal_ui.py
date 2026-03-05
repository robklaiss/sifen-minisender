from pathlib import Path
import re
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


@pytest.fixture()
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", str(tmp_path / "webui_minimal_ui.db"))
    monkeypatch.delenv("SIFEN_UI_DEBUG", raising=False)
    with webapp.app.app_context():
        webapp.init_db()
        yield


@pytest.mark.parametrize("doc_type", ["1", "4", "7"])
def test_invoice_new_minimal_actions(app_ctx, doc_type):
    client = webapp.app.test_client()
    resp = client.get(f"/invoice/new?doc_type={doc_type}")
    assert resp.status_code == 200

    html = resp.get_data(as_text=True)
    checkbox = re.search(
        r'<input[^>]*name="confirm_emit"[^>]*type="checkbox"|<input[^>]*type="checkbox"[^>]*name="confirm_emit"',
        html,
    )
    assert checkbox is not None

    assert re.search(
        r'<button[^>]*type="submit"[^>]*>\s*Emitir ahora\s*</button>',
        html,
    )

    for needle in ("Dry-run", "Artifacts", "Encolar", "Enviar lote XML"):
        assert needle not in html
