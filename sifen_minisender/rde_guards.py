from __future__ import annotations

import re
import zipfile
from pathlib import Path
from typing import List, Optional

from lxml import etree


SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"


def _local(tag: str) -> str:
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def _find_first_by_local(root: etree._Element, name: str) -> Optional[etree._Element]:
    for el in root.iter():
        if _local(el.tag) == name:
            return el
    return None


def _parse_xml(xml_bytes: bytes, *, context: str = "") -> etree._Element:
    try:
        return etree.fromstring(xml_bytes)
    except Exception as e:
        raise RuntimeError(f"[rde_guard] XML inválido (parse). {context} err={e}")


def _load_rde(xml_bytes: bytes, *, context: str = "") -> etree._Element:
    root = _parse_xml(xml_bytes, context=context)
    rde = _find_first_by_local(root, "rDE")
    if rde is None:
        raise RuntimeError(f"[rde_guard] No se encontró <rDE>. {context}")
    return rde


def assert_rde_children_order_and_gcamfufd(xml_bytes: bytes, *, context: str = "") -> None:
    """
    Guardrail BLINDADO (no muta el XML):
      - rDE hijos EXACTOS: dVerFor, DE, Signature, gCamFuFD
      - gCamFuFD NO puede estar dentro del subtree de DE
    Lanza RuntimeError con mensaje claro si falla.
    """
    rde = _load_rde(xml_bytes, context=context)

    children: List[str] = [_local(c.tag) for c in list(rde)]
    expected = ["dVerFor", "DE", "Signature", "gCamFuFD"]
    if children != expected:
        raise RuntimeError(
            "[rde_guard] Orden rDE incorrecto.\n"
            f"  {context}\n"
            f"  actual:   {children}\n"
            f"  esperado: {expected}"
        )

    de = next((c for c in list(rde) if _local(c.tag) == "DE"), None)
    if de is None:
        raise RuntimeError(f"[rde_guard] <rDE> no contiene hijo directo <DE>. {context}")

    g_inside_de = any(_local(x.tag) == "gCamFuFD" for x in de.iter())
    if g_inside_de:
        raise RuntimeError(f"[rde_guard] gCamFuFD está dentro de <DE> (prohibido). {context}")


def assert_rde_schema_location_and_default_namespace(xml_bytes: bytes, *, context: str = "") -> None:
    rde = _load_rde(xml_bytes, context=context)

    rde_ns = etree.QName(rde).namespace or ""
    if rde_ns != SIFEN_NS:
        raise RuntimeError(f"[rde_guard] Namespace de rDE inválido: {rde_ns!r}. {context}")

    xml_text = xml_bytes.decode("utf-8", errors="replace")
    opening = re.search(r"<(?:[A-Za-z_][A-Za-z0-9._-]*:)?rDE\b([^>]*)>", xml_text)
    if opening is None:
        raise RuntimeError(f"[rde_guard] No se encontró opening tag de rDE. {context}")

    attrs = opening.group(1)
    xmlns_match = re.search(r'\bxmlns\s*=\s*"([^"]+)"', attrs)
    if xmlns_match is None:
        raise RuntimeError(f"[rde_guard] rDE no tiene xmlns default. {context}")
    if xmlns_match.group(1).strip() != SIFEN_NS:
        raise RuntimeError(
            f"[rde_guard] xmlns default de rDE no coincide con SIFEN: {xmlns_match.group(1)!r}. {context}"
        )

    schema_match = re.search(r'\bxsi:schemaLocation\s*=\s*"([^"]+)"', attrs)
    if schema_match is None:
        raise RuntimeError(f"[rde_guard] rDE no tiene xsi:schemaLocation. {context}")

    tokens = [tok for tok in schema_match.group(1).split() if tok]
    if len(tokens) < 2:
        raise RuntimeError(f"[rde_guard] xsi:schemaLocation inválido: faltan tokens. {context}")
    if len(tokens) % 2 != 0:
        raise RuntimeError(f"[rde_guard] xsi:schemaLocation inválido: tokens impares={tokens}. {context}")
    if SIFEN_NS not in tokens:
        raise RuntimeError(
            f"[rde_guard] xsi:schemaLocation no contiene namespace SIFEN: {tokens}. {context}"
        )


def assert_signature_reference_uri_matches_de_id(xml_bytes: bytes, *, context: str = "") -> None:
    rde = _load_rde(xml_bytes, context=context)

    de = next((child for child in list(rde) if _local(child.tag) == "DE"), None)
    if de is None:
        raise RuntimeError(f"[rde_guard] No se encontró DE como hijo directo de rDE. {context}")

    de_id = (de.attrib.get("Id") or de.attrib.get("id") or "").strip()
    if not de_id:
        raise RuntimeError(f"[rde_guard] DE no tiene atributo Id. {context}")

    signature = next((child for child in list(rde) if _local(child.tag) == "Signature"), None)
    if signature is None:
        raise RuntimeError(f"[rde_guard] No se encontró Signature como hijo directo de rDE. {context}")

    sig_ns = etree.QName(signature).namespace or ""
    if sig_ns != DS_NS:
        raise RuntimeError(f"[rde_guard] Signature no está en namespace DSIG: {sig_ns!r}. {context}")

    reference = next((el for el in signature.iter() if _local(el.tag) == "Reference"), None)
    if reference is None:
        raise RuntimeError(f"[rde_guard] No se encontró Reference dentro de Signature. {context}")

    uri = (reference.attrib.get("URI") or "").strip()
    if uri != f"#{de_id}":
        raise RuntimeError(
            f"[rde_guard] Reference URI inválido: {uri!r} != '#{de_id}'. {context}"
        )


def assert_zip_contains_valid_lote(zip_path: Path, *, context: str = "") -> None:
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()
            if "lote.xml" not in names:
                raise RuntimeError(f"[rde_guard] ZIP no contiene lote.xml: {names}. {context}")
            lote_bytes = zf.read("lote.xml")
    except zipfile.BadZipFile as e:
        raise RuntimeError(f"[rde_guard] ZIP inválido: {zip_path}. {context} err={e}")

    lote_root = _parse_xml(lote_bytes, context=f"{context} zip={zip_path}")
    if _local(lote_root.tag) != "rLoteDE":
        raise RuntimeError(
            f"[rde_guard] lote.xml root inválido: {_local(lote_root.tag)!r} (esperado rLoteDE). {context}"
        )

    assert_rde_children_order_and_gcamfufd(lote_bytes, context=f"{context} zip={zip_path}")
    assert_signature_reference_uri_matches_de_id(lote_bytes, context=f"{context} zip={zip_path}")


def run_runtime_guardrails(
    *,
    last_lote_xml: Optional[Path],
    last_xde_zip: Optional[Path] = None,
    context: str = "",
) -> None:
    """
    Ejecuta guardrails runtime sin pytest.
    Solo valida artifacts existentes para no romper flujos que no los generen.
    """
    lote_path = Path(last_lote_xml) if last_lote_xml else None
    zip_path = Path(last_xde_zip) if last_xde_zip else None

    if lote_path is not None and lote_path.exists() and lote_path.is_file():
        lote_bytes = lote_path.read_bytes()
        lote_context = f"{context} lote={lote_path}"
        assert_rde_children_order_and_gcamfufd(lote_bytes, context=lote_context)
        assert_rde_schema_location_and_default_namespace(lote_bytes, context=lote_context)
        assert_signature_reference_uri_matches_de_id(lote_bytes, context=lote_context)

    if zip_path is not None and zip_path.exists() and zip_path.is_file():
        assert_zip_contains_valid_lote(zip_path, context=f"{context} zip={zip_path}")
