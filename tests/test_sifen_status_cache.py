from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def test_sifen_status_respects_ttl(monkeypatch):
    client = webapp.app.test_client()
    webapp._reset_sifen_status_cache()

    monkeypatch.setenv("SIFEN_STATUS_TTL_SEC", "300")
    monkeypatch.setenv("SIFEN_ENV", "prod")

    calls = {"count": 0}

    def fake_run():
        calls["count"] += 1
        return {"ok": True, "text": "SIFEN_OK", "detail": "ok"}

    monkeypatch.setattr(webapp, "_run_sifen_preflight", fake_run)

    t = 1000.0
    monkeypatch.setattr(webapp.time, "time", lambda: t)

    resp1 = client.get("/api/sifen/status")
    resp2 = client.get("/api/sifen/status")

    assert resp1.status_code == 200
    assert resp2.status_code == 200
    assert calls["count"] == 1

    data2 = resp2.get_json()
    assert data2["cached"] is True
