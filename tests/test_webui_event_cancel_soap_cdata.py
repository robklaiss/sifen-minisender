import webui.app as webapp


def test_strip_xml_decl_removes_bom_and_decl() -> None:
    xml_text = "\ufeff<?xml version='1.0' encoding='UTF-8'?>\n<gGroupGesEve>...</gGroupGesEve>"
    stripped = webapp._strip_xml_decl(xml_text)
    assert "<?xml" not in stripped
    assert stripped.startswith("<gGroupGesEve")


def test_build_event_soap_wraps_signed_xml_in_cdata() -> None:
    signed_xml = "\ufeff<?xml version='1.0' encoding='UTF-8'?>\n<gGroupGesEve>...</gGroupGesEve>"
    soap = webapp._build_event_soap("20260301010101", signed_xml)
    assert b"<xsd:dEvReg><![CDATA[" in soap
    assert b"<?xml" not in soap
    assert b"<gGroupGesEve" in soap
