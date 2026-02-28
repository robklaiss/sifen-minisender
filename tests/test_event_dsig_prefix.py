from pathlib import Path
import importlib.util

APP_PATH = Path(__file__).resolve().parents[1] / "webui" / "app.py"
spec = importlib.util.spec_from_file_location("webui_app", APP_PATH)
webui_app = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(webui_app)
_normalize_dsig_prefix = webui_app._normalize_dsig_prefix

def test_normalize_dsig_prefix_adds_ds_prefix():
    xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<rGesEve xmlns="http://ekuatia.set.gov.py/sifen/xsd">'
        b'<rEve Id="abc"><dId>1</dId></rEve>'
        b'<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">'
        b'<SignedInfo></SignedInfo>'
        b'</Signature>'
        b'</rGesEve>'
    )
    out = _normalize_dsig_prefix(xml)
    assert b"<ds:Signature" in out
    assert b'xmlns:ds="http://www.w3.org/2000/09/xmldsig#"' in out
    assert b'<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"' not in out
