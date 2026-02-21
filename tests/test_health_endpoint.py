from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webui.app import app


def test_health_returns_200_and_ok_flag():
    client = app.test_client()
    response = client.get("/health")

    assert response.status_code == 200
    assert (response.get_json() or {}).get("ok") is True


def test_healthz_alias_returns_200_and_ok_flag():
    client = app.test_client()
    response = client.get("/healthz")

    assert response.status_code == 200
    assert (response.get_json() or {}).get("ok") is True
