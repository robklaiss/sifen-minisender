from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def test_artifacts_root_uses_env_dir(monkeypatch, tmp_path: Path):
    artifacts_dir = tmp_path / "artifacts_shared"
    monkeypatch.setenv("SIFEN_ARTIFACTS_DIR", str(artifacts_dir))
    monkeypatch.delenv("ARTIFACTS_DIR", raising=False)

    resolved = webapp._artifacts_root()

    assert resolved == artifacts_dir.resolve()
    assert resolved.is_dir()


def test_latest_send_lote_run_supports_smoke_nested_dirs(monkeypatch, tmp_path: Path):
    monkeypatch.setenv("SIFEN_ARTIFACTS_DIR", str(tmp_path))
    monkeypatch.delenv("ARTIFACTS_DIR", raising=False)

    run_dir = tmp_path / "run_20260217_010203_smoke" / "factura"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "last_lote.xml").write_text("<rLoteDE/>", encoding="utf-8")
    (run_dir / "soap_last_request.xml").write_text("<soap/>", encoding="utf-8")
    (run_dir / "last_xde.zip").write_bytes(b"PK")
    (run_dir / "sifen_response.json").write_text("{}", encoding="utf-8")

    latest = webapp._latest_send_lote_run()

    assert latest is not None
    assert latest["run_dir"] == str(run_dir)
    assert latest["artifacts"]["last_lote_xml"] == str(run_dir / "last_lote.xml")
    assert latest["artifacts"]["soap_request"] == str(run_dir / "soap_last_request.xml")
    assert latest["artifacts"]["response_json"] == str(run_dir / "sifen_response.json")
