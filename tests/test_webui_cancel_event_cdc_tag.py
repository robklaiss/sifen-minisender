from pathlib import Path
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def test_cancel_event_cdc_tag_is_lowercase():
    cdc = "01234567890123456789012345678901234567890123"
    motivo = "Prueba cancelacion"
    event_id = "EVT-TEST-0001"
    xml_bytes = webapp._build_cancel_event_xml(cdc, motivo, event_id)
    xml_text = xml_bytes.decode("utf-8")

    assert "<id>" in xml_text
    assert "<Id>" not in xml_text

    ns = {"s": "http://ekuatia.set.gov.py/sifen/xsd"}
    root = ET.fromstring(xml_bytes)
    id_el = root.find(".//s:rGeVeCan/s:id", ns)
    assert id_el is not None
    assert (id_el.text or "").strip() == cdc

    bad_el = root.find(".//s:rGeVeCan/s:Id", ns)
    assert bad_el is None
