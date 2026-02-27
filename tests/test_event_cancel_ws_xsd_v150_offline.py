from pathlib import Path
import os
import sys
from typing import Optional

import lxml.etree as etree

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.sifen_client.xsd_validator import load_schema, validate_xml_bytes  # noqa: E402
from webui.app import (  # noqa: E402
    _build_cancel_event_xml,
    _make_did_15,
    _make_event_id,
    _sign_event_xml,
)


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
        raise RuntimeError("Faltan SIFEN_SIGN_P12_PATH/SIFEN_SIGN_P12_PASSWORD para el smoketest")

    os.environ["SIFEN_SIGN_P12_PATH"] = p12_path
    os.environ["SIFEN_SIGN_P12_PASSWORD"] = p12_password


def test_cancel_event_ws_xsd_v150_offline():
    repo_root = Path(__file__).resolve().parents[1]
    _ensure_signing_env(repo_root)

    cdc = "01045547378001001102593012026012911234567892"
    motivo = "Cancelacion por prueba offline"
    event_id = _make_event_id()

    event_xml = _build_cancel_event_xml(cdc, motivo, event_id)
    signed_event = _sign_event_xml(event_xml)

    sifen_ns = "http://ekuatia.set.gov.py/sifen/xsd"
    ds_ns = "http://www.w3.org/2000/09/xmldsig#"
    ns = {"s": sifen_ns, "ds": ds_ns}

    event_root = etree.fromstring(signed_event)

    assert event_root.find(".//ds:Signature", namespaces=ns) is not None
    assert event_root.find(".//s:rGeVeCan/s:Id", namespaces=ns) is not None
    assert event_root.find(".//s:rGeVeCan/s:id", namespaces=ns) is None
    r_envi = etree.Element(f"{{{sifen_ns}}}rEnviEventoDe", nsmap={None: sifen_ns})
    d_id = etree.SubElement(r_envi, f"{{{sifen_ns}}}dId")
    d_id.text = _make_did_15()
    d_ev = etree.SubElement(r_envi, f"{{{sifen_ns}}}dEvReg")
    d_ev.append(event_root)

    xml_bytes = etree.tostring(
        r_envi,
        xml_declaration=True,
        encoding="UTF-8",
        pretty_print=False,
    )

    xsd_dir = repo_root / "schemas_sifen" / "xsd"
    schema = load_schema(xsd_dir / "WS_SiRecepEvento_v150.xsd", xsd_dir)
    ok, errors = validate_xml_bytes(xml_bytes, schema, xsd_dir)
    assert ok, f"XSD v150 inválido: {errors}"
