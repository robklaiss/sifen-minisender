import re
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest


SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"


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


def _load_rde_with_path() -> tuple[Path, ET.Element]:
    lote_path = _pick_latest_last_lote()
    root = ET.parse(lote_path).getroot()
    if _localname(root.tag) == "rDE":
        return lote_path, root
    for el in root.iter():
        if _localname(el.tag) == "rDE":
            return lote_path, el
    pytest.fail(f"No se encontró rDE dentro de {lote_path}")


def test_guardrail_rde_schema_location_and_default_namespace():
    lote_path, rde = _load_rde_with_path()
    xml_text = lote_path.read_text(encoding="utf-8", errors="replace")

    rde_ns = rde.tag[1:].split("}", 1)[0] if isinstance(rde.tag, str) and rde.tag.startswith("{") else ""
    assert rde_ns == SIFEN_NS, f"Namespace de rDE inválido: {rde_ns!r}"

    opening = re.search(r"<(?:[A-Za-z_][A-Za-z0-9._-]*:)?rDE\b([^>]*)>", xml_text)
    assert opening is not None, "No se encontró opening tag de rDE"
    attrs = opening.group(1)

    xmlns_match = re.search(r'\bxmlns\s*=\s*"([^"]+)"', attrs)
    assert xmlns_match is not None, "rDE no tiene xmlns default"
    assert xmlns_match.group(1).strip() == SIFEN_NS, "xmlns default de rDE no coincide con SIFEN"

    schema_match = re.search(r'\bxsi:schemaLocation\s*=\s*"([^"]+)"', attrs)
    assert schema_match is not None, "rDE no tiene xsi:schemaLocation"

    schema_tokens = [tok for tok in schema_match.group(1).split() if tok]
    assert len(schema_tokens) >= 2, "xsi:schemaLocation inválido: faltan tokens"
    assert len(schema_tokens) % 2 == 0, "xsi:schemaLocation inválido: tokens impares"
    assert SIFEN_NS in schema_tokens, f"xsi:schemaLocation no contiene namespace SIFEN: {schema_tokens}"
