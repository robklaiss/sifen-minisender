from pathlib import Path

def test_api_uses_default_namespace_nsmap():
    """
    Regression guard:
    We want nsmap={None: SIFEN_NS} so the generated XML uses the default namespace
    (xmlns="...") instead of a prefixed one (xmlns:xsd="...").
    """
    p = Path("sifen_minisender/api.py")
    txt = p.read_text(encoding="utf-8")

    assert "nsmap={None: SIFEN_NS}" in txt, "Expected nsmap={None: SIFEN_NS} in api.py"
    assert 'nsmap={"xsd": SIFEN_NS}' not in txt, "Old prefixed nsmap still present"
