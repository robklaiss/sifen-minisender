from pathlib import Path
import importlib.util

APP_PATH = Path(__file__).resolve().parents[1] / "webui" / "app.py"
spec = importlib.util.spec_from_file_location("webui_app", APP_PATH)
webui_app = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(webui_app)
_build_event_soap_bytes = webui_app._build_event_soap_bytes


def test_event_soap_bytes_includes_xml_declaration():
    signed_event_xml = '<gGroupGesEve xmlns="http://ekuatia.set.gov.py/sifen/xsd"/>'
    soap_bytes = _build_event_soap_bytes(signed_event_xml)
    assert soap_bytes.startswith(b"<?xml")
    assert b'encoding="UTF-8"' in soap_bytes or b"encoding='UTF-8'" in soap_bytes
