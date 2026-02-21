from pathlib import Path
import xml.etree.ElementTree as ET

import pytest


def _localname(tag: str) -> str:
    return tag.split("}", 1)[1] if isinstance(tag, str) and "}" in tag else tag


def _pick_latest_last_lote() -> Path:
    artifacts_dir = Path(__file__).resolve().parents[1] / "artifacts"
    direct = artifacts_dir / "last_lote.xml"
    if direct.exists() and direct.is_file():
        return direct

    cands = sorted(
        artifacts_dir.glob("run_*/last_lote.xml"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if cands:
        return cands[0]
    pytest.fail("Ejecutá send_sirecepde para generar artifacts")


def _load_rde() -> ET.Element:
    lote_path = _pick_latest_last_lote()
    root = ET.parse(lote_path).getroot()
    if _localname(root.tag) == "rDE":
        return root
    for el in root.iter():
        if _localname(el.tag) == "rDE":
            return el
    pytest.fail(f"No se encontró rDE dentro de {lote_path}")


def test_guardrail_rde_children_order_and_signature_parent():
    rde = _load_rde()
    children = [_localname(child.tag) for child in list(rde) if isinstance(child.tag, str)]
    expected = ["dVerFor", "DE", "Signature", "gCamFuFD"]
    assert children == expected, f"rDE hijos inválidos. actual={children} expected={expected}"

    signature = next((child for child in list(rde) if _localname(child.tag) == "Signature"), None)
    assert signature is not None, "No se encontró Signature como hijo directo de rDE"
    assert signature in list(rde), "Signature debe tener parent rDE"
