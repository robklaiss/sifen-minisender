from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webui.app import app


def _assert_image_response(response):
    assert response.status_code == 200
    content_type = response.headers.get("Content-Type", "")
    assert content_type.startswith("image/")


def test_issuer_logo_default_path(monkeypatch):
    monkeypatch.delenv("SIFEN_ISSUER_LOGO_PATH", raising=False)
    client = app.test_client()

    for path in ("/assets/issuer-logo", "/issuer_logo"):
        response = client.get(path)
        _assert_image_response(response)


def test_issuer_logo_relative_env(monkeypatch):
    monkeypatch.setenv("SIFEN_ISSUER_LOGO_PATH", "assets/industria-feris-isotipo.jpg")
    client = app.test_client()

    response = client.get("/assets/issuer-logo")
    _assert_image_response(response)
