from pathlib import Path

from tools.artifacts import make_run_dir, resolve_artifacts_dir


def test_resolve_artifacts_dir_uses_env_priority(monkeypatch, tmp_path: Path):
    env_dir = tmp_path / "env_sifen"
    fallback_dir = tmp_path / "env_artifacts"
    monkeypatch.setenv("SIFEN_ARTIFACTS_DIR", str(env_dir))
    monkeypatch.setenv("ARTIFACTS_DIR", str(fallback_dir))

    resolved = resolve_artifacts_dir()

    assert resolved == env_dir.resolve()
    assert resolved.is_dir()


def test_make_run_dir_creates_run_directory(tmp_path: Path):
    run_dir = make_run_dir(
        "consulta_lote_poll",
        "test",
        prot="47353168698178730",
        did="202602170101010",
        artifacts_dir=tmp_path,
    )

    assert run_dir.is_dir()
    assert run_dir.parent == tmp_path.resolve()
    assert run_dir.name.startswith("run_")
    assert "consulta_lote_poll" in run_dir.name
