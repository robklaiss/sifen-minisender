from pathlib import Path
import xml.etree.ElementTree as ET

import pytest


def _localname(tag: str) -> str:
    return tag.split("}", 1)[1] if isinstance(tag, str) and "}" in tag else tag


def _pick_latest_rde_xml() -> Path:
    from pathlib import Path
    from tests._rde_artifact import pick_latest_rde_signed_qr
    return pick_latest_rde_signed_qr(Path(__file__).resolve().parents[1])

def _load_rde() -> ET.Element:
    lote_path = _pick_latest_rde_xml()
    root = ET.parse(lote_path).getroot()
    if _localname(root.tag) == "rDE":
        return root
    for el in root.iter():
        if _localname(el.tag) == "rDE":
            return el
    pytest.fail(f"No se encontró rDE dentro de {lote_path}")


def test_guardrail_signature_reference_uri_matches_de_id():
    rde = _load_rde()

    de = next((child for child in list(rde) if _localname(child.tag) == "DE"), None)
    assert de is not None, "No se encontró DE como hijo directo de rDE"

    de_id = (de.attrib.get("Id") or de.attrib.get("id") or "").strip()
    assert de_id, "DE no tiene atributo Id"

    signature = next((child for child in list(rde) if _localname(child.tag) == "Signature"), None)
    assert signature is not None, "No se encontró Signature como hijo directo de rDE"
    assert signature in list(rde), "Signature debe tener parent rDE"

    reference = next((el for el in signature.iter() if _localname(el.tag) == "Reference"), None)
    assert reference is not None, "No se encontró Reference dentro de Signature"

    uri = (reference.attrib.get("URI") or "").strip()
    assert uri == f"#{de_id}", f"Reference URI inválido: {uri!r} != '#{de_id}'"
