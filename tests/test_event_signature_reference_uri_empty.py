from pathlib import Path
import importlib.util
import os
from typing import Optional

import lxml.etree as etree

APP_PATH = Path(__file__).resolve().parents[1] / "webui" / "app.py"
spec = importlib.util.spec_from_file_location("webui_app", APP_PATH)
webui_app = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(webui_app)

_build_cancel_event_xml = webui_app._build_cancel_event_xml
_make_event_id = webui_app._make_event_id
_normalize_dsig_prefix = webui_app._normalize_dsig_prefix
_sign_event_xml = webui_app._sign_event_xml


def _read_env_from_dotenv(repo_root: Path, key: str) -> Optional[str]:
    env_path = repo_root / ".env"
    if not env_path.exists():
        return None
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if k.strip() != key:
            continue
        value = v.strip()
        if (value.startswith("\"") and value.endswith("\"")) or (
            value.startswith("'") and value.endswith("'")
        ):
            value = value[1:-1]
        return value
    return None


def _ensure_signing_env(repo_root: Path) -> None:
    p12_path = (
        os.getenv("SIFEN_SIGN_P12_PATH")
        or os.getenv("SIFEN_P12_PATH")
        or os.getenv("SIFEN_CERT_PATH")
        or _read_env_from_dotenv(repo_root, "SIFEN_SIGN_P12_PATH")
        or _read_env_from_dotenv(repo_root, "SIFEN_P12_PATH")
        or _read_env_from_dotenv(repo_root, "SIFEN_CERT_PATH")
    )
    p12_password = (
        os.getenv("SIFEN_SIGN_P12_PASSWORD")
        or os.getenv("SIFEN_P12_PASSWORD")
        or os.getenv("SIFEN_CERT_PASSWORD")
        or _read_env_from_dotenv(repo_root, "SIFEN_SIGN_P12_PASSWORD")
        or _read_env_from_dotenv(repo_root, "SIFEN_P12_PASSWORD")
        or _read_env_from_dotenv(repo_root, "SIFEN_CERT_PASSWORD")
    )

    if p12_path:
        p = Path(p12_path)
        if not p.is_absolute():
            p = (repo_root / p).resolve()
        if not p.exists():
            fallback = repo_root / "secrets" / "F1T_65478.p12"
            if fallback.exists():
                p = fallback
        p12_path = str(p)

    if not p12_path or not p12_password:
        raise RuntimeError("Faltan SIFEN_SIGN_P12_PATH/SIFEN_SIGN_P12_PASSWORD para el test")

    os.environ["SIFEN_SIGN_P12_PATH"] = p12_path
    os.environ["SIFEN_SIGN_P12_PASSWORD"] = p12_password


def test_event_signature_reference_uri_empty():
    repo_root = Path(__file__).resolve().parents[1]
    _ensure_signing_env(repo_root)

    cdc = "01045547378001001102593012026012911234567892"
    motivo = "Cancelacion por prueba offline"
    event_id = _make_event_id()

    event_xml = _build_cancel_event_xml(cdc, motivo, event_id)
    signed_event = _sign_event_xml(event_xml)
    normalized = _normalize_dsig_prefix(signed_event)

    ds_ns = "http://www.w3.org/2000/09/xmldsig#"
    ref = etree.fromstring(normalized).find(f".//{{{ds_ns}}}Reference")
    assert ref is not None
    assert ref.get("URI") == ""

    xml_text = normalized.decode("utf-8")
    assert "<ds:Reference" in xml_text
    assert 'URI=""' in xml_text
    assert 'URI="#' not in xml_text
