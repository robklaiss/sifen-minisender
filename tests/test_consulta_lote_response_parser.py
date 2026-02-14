from pathlib import Path
import sys

import lxml.etree as etree
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.sifen_client.exceptions import SifenClientError
from app.sifen_client.soap_client import SoapClient


def _client_without_init() -> SoapClient:
    return SoapClient.__new__(SoapClient)


def test_parse_consulta_lote_accepts_expected_root():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
  <env:Body>
    <ns2:rResEnviConsLoteDe xmlns:ns2="http://ekuatia.set.gov.py/sifen/xsd">
      <ns2:dCodResLot>0361</ns2:dCodResLot>
      <ns2:dMsgResLot>OK</ns2:dMsgResLot>
      <ns2:dProtConsLote>123</ns2:dProtConsLote>
    </ns2:rResEnviConsLoteDe>
  </env:Body>
</env:Envelope>
"""
    root = etree.fromstring(xml.encode("utf-8"))
    parsed = _client_without_init()._parse_consulta_lote_response_from_xml(root)
    assert parsed["ok"] is True
    assert parsed["codigo_respuesta"] == "0361"
    assert parsed["mensaje"] == "OK"
    assert parsed["parsed_fields"]["dProtConsLote"] == "123"


def test_parse_consulta_lote_rejects_unexpected_root():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<env:Envelope xmlns:env="http://www.w3.org/2003/05/soap-envelope">
  <env:Body>
    <ns2:rRetEnviDe xmlns:ns2="http://ekuatia.set.gov.py/sifen/xsd">
      <ns2:dCodRes>0301</ns2:dCodRes>
      <ns2:dMsgRes>Operacion invalida</ns2:dMsgRes>
    </ns2:rRetEnviDe>
  </env:Body>
</env:Envelope>
"""
    root = etree.fromstring(xml.encode("utf-8"))
    with pytest.raises(SifenClientError, match="rResEnviConsLoteDe"):
        _client_without_init()._parse_consulta_lote_response_from_xml(root)
