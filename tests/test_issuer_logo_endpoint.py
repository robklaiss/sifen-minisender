from pathlib import Path
import shutil
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def _set_uploads_dir(monkeypatch, rel_path: str) -> Path:
    monkeypatch.setenv("WEBUI_UPLOADS_DIR", rel_path)
    uploads_dir = webapp._resolve_uploads_dir()
    monkeypatch.setattr(webapp, "UPLOADS_DIR", uploads_dir)
    return uploads_dir


def test_issuer_logo_serves_uploads_file(monkeypatch):
    uploads_dir = _set_uploads_dir(monkeypatch, "data/uploads_test")
    repo_root = webapp._repo_root()
    assert repo_root in uploads_dir.parents
    assert "/temp/" not in str(uploads_dir)

    logo_bytes = b"issuer-logo-bytes"
    try:
        uploads_dir.mkdir(parents=True, exist_ok=True)
        (uploads_dir / "issuer-logo.jpg").write_bytes(logo_bytes)

        client = webapp.app.test_client()
        response = client.get("/assets/issuer-logo")

        assert response.status_code == 200
        assert response.mimetype == "image/jpeg"
        assert response.data == logo_bytes
        assert response.headers.get("Cache-Control") == "public, max-age=3600"
    finally:
        if uploads_dir.exists():
            shutil.rmtree(uploads_dir)


def test_issuer_logo_falls_back_to_assets(monkeypatch):
    uploads_dir = _set_uploads_dir(monkeypatch, "data/uploads_empty")
    repo_root = webapp._repo_root()
    assets_path = repo_root / "assets" / "industria-feris-isotipo.jpg"
    assert assets_path.exists()
    assert "/temp/" not in str(assets_path)

    try:
        if uploads_dir.exists():
            shutil.rmtree(uploads_dir)

        client = webapp.app.test_client()
        response = client.get("/assets/issuer-logo")

        assert response.status_code == 200
        assert response.mimetype == "image/jpeg"
        assert response.data == assets_path.read_bytes()
        assert response.headers.get("Cache-Control") == "public, max-age=3600"
    finally:
        if uploads_dir.exists():
            shutil.rmtree(uploads_dir)


def test_uploads_dir_guard_skips_creation_outside_base(monkeypatch, tmp_path):
    monkeypatch.setenv("WEBUI_UPLOADS_DIR", str(tmp_path))
    monkeypatch.setattr(webapp, "UPLOADS_DIR", webapp._resolve_uploads_dir())

    mkdir_calls = []
    orig_mkdir = Path.mkdir

    def _mkdir(self, *args, **kwargs):
        mkdir_calls.append(self)
        return orig_mkdir(self, *args, **kwargs)

    monkeypatch.setattr(Path, "mkdir", _mkdir, raising=True)

    webapp._ensure_uploads_dir()

    assert mkdir_calls == []
