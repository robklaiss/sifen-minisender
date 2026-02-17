from pathlib import Path
import sys

import lxml.etree as etree

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.sifen_client.soap_client import (  # noqa: E402
    build_consulta_lote_raw_envelope,
    validate_xml_bytes_or_raise,
)


def test_consulta_lote_raw_builder_produces_parseable_xml():
    prot = '47353168698178730"\'<&>'
    soap_bytes = build_consulta_lote_raw_envelope("202602170000001", prot)

    validate_xml_bytes_or_raise(soap_bytes, "test_consulta_lote_raw_builder")

    root = etree.fromstring(soap_bytes)
    d_id = root.xpath('string(.//*[local-name()="dId"][1])')
    d_prot = root.xpath('string(.//*[local-name()="dProtConsLote"][1])')

    assert d_id == "202602170000001"
    assert d_prot == prot


def test_consulta_lote_raw_builder_is_lxml_parseable():
    soap_bytes = build_consulta_lote_raw_envelope("202602170000009", "47353168698201554")
    root = etree.fromstring(soap_bytes)
    assert root.tag.endswith("Envelope")
