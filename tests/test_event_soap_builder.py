from pathlib import Path
import sys

import lxml.etree as etree

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webui.app import _build_event_soap_bytes  # noqa: E402

SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"


def test_event_soap_builder_namespaces():
    signed_event = (
        '<rEve xmlns="http://ekuatia.set.gov.py/sifen/xsd">'
        '<dId>1</dId>'
        "</rEve>"
    )
    soap_bytes = _build_event_soap_bytes(signed_event)

    root = etree.fromstring(soap_bytes)

    assert root.tag == f"{{{SOAP_NS}}}Envelope"
    assert root.nsmap.get(None) != SIFEN_NS
    assert root.nsmap.get("env") == SOAP_NS or root.nsmap.get("soap") == SOAP_NS

    payload = root.find(f".//{{{SIFEN_NS}}}rEnviEventoDe")
    assert payload is not None
