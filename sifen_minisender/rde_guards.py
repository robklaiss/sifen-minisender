from __future__ import annotations

from typing import List, Optional
from lxml import etree

def _local(tag: str) -> str:
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag

def _find_first_by_local(root: etree._Element, name: str) -> Optional[etree._Element]:
    for el in root.iter():
        if _local(el.tag) == name:
            return el
    return None

def assert_rde_children_order_and_gcamfufd(xml_bytes: bytes, *, context: str = "") -> None:
    """
    Guardrail BLINDADO (no muta el XML):
      - rDE hijos EXACTOS: dVerFor, DE, Signature, gCamFuFD
      - gCamFuFD NO puede estar dentro del subtree de DE
    Lanza RuntimeError con mensaje claro si falla.
    """
    try:
        root = etree.fromstring(xml_bytes)
    except Exception as e:
        raise RuntimeError(f"[rde_guard] XML inválido (parse). {context} err={e}")

    rde = _find_first_by_local(root, "rDE")
    if rde is None:
        raise RuntimeError(f"[rde_guard] No se encontró <rDE>. {context}")

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
