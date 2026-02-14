from pathlib import Path
import sys

from lxml import etree

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tools.send_sirecepde as send_sirecepde


def _signed_rde_xml(cdc: str) -> bytes:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rDE xmlns="http://ekuatia.set.gov.py/sifen/xsd" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <dVerFor>150</dVerFor>
  <DE Id="{cdc}">
    <gDatGralOpe>
      <dFeEmiDE>2026-02-14T10:00:00</dFeEmiDE>
      <gDatRec>
        <dRucRec>80012345</dRucRec>
      </gDatRec>
    </gDatGralOpe>
    <gDtipDE>
      <gCamItem><dCodInt>1</dCodInt></gCamItem>
      <gCamItem><dCodInt>2</dCodInt></gCamItem>
    </gDtipDE>
    <gTotSub>
      <dTotGralOpe>100000</dTotGralOpe>
      <dTotIVA>0</dTotIVA>
    </gTotSub>
  </DE>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:Reference URI="#{cdc}">
        <ds:DigestValue>abc==</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
  </ds:Signature>
  <gCamFuFD>
    <dCarQR>PLACEHOLDER_QR_PENDING_POST_SIGN</dCarQR>
  </gCamFuFD>
</rDE>
""".encode("utf-8")


def _dcarqr_text(root: etree._Element) -> str:
    nodes = root.xpath(".//*[local-name()='dCarQR']")
    assert nodes, "Debe existir dCarQR"
    return (nodes[0].text or "").strip()


def test_qr_real_sin_placeholder():
    root = etree.fromstring(_signed_rde_xml("01800555311001001000000012026021411123456784"))
    debug = send_sirecepde._update_qr_in_signed_rde_tree(
        root,
        csc="A62e367A738D1050E364D9680f9E4a79",
        csc_id="1",
        env="prod",
    )
    qr = _dcarqr_text(root)

    assert qr == debug["qr_url"]
    assert "cHashQR=" in qr
    assert "https://www.ekuatia.set.gov.py/consultas/qr?" in qr
    assert not send_sirecepde._is_qr_placeholder(qr)


def test_qr_cambia_si_cambia_cdc():
    root_a = etree.fromstring(_signed_rde_xml("01800555311001001000000012026021411123456784"))
    root_b = etree.fromstring(_signed_rde_xml("01800555311001001000000022026021411123456780"))

    debug_a = send_sirecepde._update_qr_in_signed_rde_tree(
        root_a,
        csc="A62e367A738D1050E364D9680f9E4a79",
        csc_id="1",
        env="prod",
    )
    debug_b = send_sirecepde._update_qr_in_signed_rde_tree(
        root_b,
        csc="A62e367A738D1050E364D9680f9E4a79",
        csc_id="1",
        env="prod",
    )

    assert debug_a["qr_url"] != debug_b["qr_url"]
    assert "PLACEHOLDER" not in debug_a["qr_url"].upper()
    assert "PLACEHOLDER" not in debug_b["qr_url"].upper()
