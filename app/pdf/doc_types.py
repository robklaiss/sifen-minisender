from __future__ import annotations

import re
from typing import Any, Dict


DOC_TYPE_CONFIG: Dict[str, Dict[str, Any]] = {
    "1": {
        "title": "Factura Electr\u00f3nica",
        "prefix": "invoice",
        "show_prices": True,
        "show_totals": True,
        "show_transport": False,
    },
    "4": {
        "title": "Autofactura Electr\u00f3nica",
        "prefix": "afe",
        "show_prices": True,
        "show_totals": True,
        "show_transport": False,
    },
    "5": {
        "title": "Nota de Cr\u00e9dito Electr\u00f3nica",
        "prefix": "nce",
        "show_prices": True,
        "show_totals": True,
        "show_transport": False,
    },
    "6": {
        "title": "Nota de D\u00e9bito Electr\u00f3nica",
        "prefix": "nde",
        "show_prices": True,
        "show_totals": True,
        "show_transport": False,
    },
    "7": {
        "title": "Nota de Remisi\u00f3n Electr\u00f3nica",
        "prefix": "nre",
        "show_prices": False,
        "show_totals": False,
        "show_transport": True,
    },
}

_DOC_TYPE_KEYS = (
    "iTiDE",
    "doc_type",
    "docType",
    "tipo_documento",
    "tipoDocumento",
    "tipoDoc",
)


def normalize_doc_type(value: Any) -> str:
    raw = re.sub(r"\D", "", str(value or "").strip())
    raw = raw.lstrip("0") or "1"
    return raw if raw in DOC_TYPE_CONFIG else "1"


def doc_type_config(value: Any) -> Dict[str, Any]:
    return DOC_TYPE_CONFIG[normalize_doc_type(value)]


def _pick_doc_type_from_mapping(mapping: dict | None) -> str | None:
    if not isinstance(mapping, dict):
        return None
    for key in _DOC_TYPE_KEYS:
        if key in mapping and str(mapping.get(key) or "").strip():
            return normalize_doc_type(mapping.get(key))
    return None


def extract_doc_type(
    data: dict | None,
    parsed_fields: dict | None = None,
    response_xml: str | None = None,
) -> str:
    candidate = _pick_doc_type_from_mapping(parsed_fields)
    if candidate:
        return candidate

    candidate = _pick_doc_type_from_mapping(data)
    if candidate:
        return candidate

    xml = response_xml
    if not xml and isinstance(data, dict):
        xml = data.get("response_xml")
    if not xml and isinstance(parsed_fields, dict):
        xml = parsed_fields.get("xml")

    if xml:
        match = re.search(r"<(?:\w+:)?iTiDE>(.*?)</(?:\w+:)?iTiDE>", str(xml), flags=re.DOTALL)
        if match:
            return normalize_doc_type(match.group(1))

    return "1"
