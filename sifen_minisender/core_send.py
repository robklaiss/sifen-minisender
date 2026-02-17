from __future__ import annotations

import io
import traceback
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Optional


def _abs_path(p: Path) -> str:
    try:
        return str(p.resolve())
    except Exception:
        return str(p)


def _pick_response_json(run_dir: Path, explicit_path: Optional[str]) -> Optional[str]:
    if explicit_path:
        p = Path(explicit_path).expanduser()
        if p.exists() and p.is_file():
            return _abs_path(p)
    cands = sorted(
        run_dir.glob("response_recepcion_*.json"),
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    )
    if cands:
        return _abs_path(cands[0])
    return None


def _artifact_if_exists(path: Path) -> Optional[str]:
    return _abs_path(path) if path.exists() and path.is_file() else None


def send_lote_from_xml(
    *,
    env: str,
    xml_path: Path,
    dump_http: bool,
    artifacts_dir: Optional[Path] = None,
) -> dict:
    """
    Core importable para envío de lote desde XML firmado, reusando tools/send_sirecepde.py.
    """
    from tools import send_sirecepde as sender

    env_norm = (env or "").strip().lower()
    if env_norm not in ("test", "prod"):
        raise ValueError(f"env inválido: {env!r}. Usar 'test' o 'prod'.")

    if artifacts_dir is not None:
        run_dir = sender._resolve_artifacts_dir(Path(artifacts_dir))
    else:
        run_dir = sender._resolve_run_artifacts_dir(run_id=None, artifacts_dir_override=None)

    xml_file = Path(xml_path).expanduser()
    if not xml_file.is_absolute():
        xml_file = Path.cwd() / xml_file
    xml_file = xml_file.resolve()

    if not xml_file.exists() or not xml_file.is_file():
        return {
            "ok": False,
            "success": False,
            "dCodRes": None,
            "dMsgRes": f"XML no existe o no es archivo: {xml_file}",
            "dProtConsLote": None,
            "run_dir": _abs_path(run_dir),
            "artifacts": {
                "last_lote_xml": _artifact_if_exists(run_dir / "last_lote.xml"),
                "last_xde_zip": _artifact_if_exists(run_dir / "last_xde.zip"),
                "soap_request": _artifact_if_exists(run_dir / "soap_last_request.xml"),
                "response_json": _pick_response_json(run_dir, None),
            },
            "logs": "",
            "meta": {
                "env": env_norm,
                "xml_path": _abs_path(xml_file),
                "error_type": "FileNotFoundError",
            },
        }

    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    try:
        with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
            raw = sender.send_sirecepde(
                xml_path=xml_file,
                env=env_norm,
                artifacts_dir=run_dir,
                dump_http=bool(dump_http),
            )
    except Exception as exc:
        logs = stdout_buf.getvalue() + stderr_buf.getvalue()
        return {
            "ok": False,
            "success": False,
            "dCodRes": None,
            "dMsgRes": str(exc),
            "dProtConsLote": None,
            "run_dir": _abs_path(run_dir),
            "artifacts": {
                "last_lote_xml": _artifact_if_exists(run_dir / "last_lote.xml"),
                "last_xde_zip": _artifact_if_exists(run_dir / "last_xde.zip"),
                "soap_request": _artifact_if_exists(run_dir / "soap_last_request.xml"),
                "response_json": _pick_response_json(run_dir, None),
            },
            "logs": logs,
            "meta": {
                "env": env_norm,
                "xml_path": _abs_path(xml_file),
                "error_type": type(exc).__name__,
                "traceback": traceback.format_exc(),
            },
        }

    response = raw.get("response") or {}
    d_cod_res = response.get("codigo_respuesta") or response.get("dCodRes")
    d_msg_res = response.get("mensaje") or response.get("dMsgRes")
    d_prot = response.get("d_prot_cons_lote") or response.get("dProtConsLote")
    response_json = _pick_response_json(run_dir, raw.get("response_file"))

    logs = stdout_buf.getvalue() + stderr_buf.getvalue()
    success = bool(raw.get("success"))

    return {
        "ok": success,
        "success": success,
        "dCodRes": str(d_cod_res) if d_cod_res is not None else None,
        "dMsgRes": str(d_msg_res) if d_msg_res is not None else None,
        "dProtConsLote": str(d_prot) if d_prot is not None else None,
        "run_dir": _abs_path(run_dir),
        "artifacts": {
            "last_lote_xml": _artifact_if_exists(run_dir / "last_lote.xml"),
            "last_xde_zip": _artifact_if_exists(run_dir / "last_xde.zip"),
            "soap_request": _artifact_if_exists(run_dir / "soap_last_request.xml"),
            "response_json": response_json,
        },
        "logs": logs,
        "meta": {
            "env": env_norm,
            "xml_path": _abs_path(xml_file),
            "error": raw.get("error"),
            "error_type": raw.get("error_type"),
            "response_file": raw.get("response_file"),
        },
    }
