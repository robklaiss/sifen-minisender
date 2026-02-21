from pathlib import Path
from types import SimpleNamespace
import sys
import json

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.sifen_client.exceptions import SifenClientError
from app.sifen_client.soap_client import SoapClient


class _MockResponse:
    def __init__(self, *, status_code: int, headers: dict, content: bytes):
        self.status_code = status_code
        self.headers = headers
        self.content = content


class _MockSession:
    def __init__(self, response: _MockResponse):
        self._response = response

    def post(self, *args, **kwargs):
        return self._response


def _client_without_init(session: _MockSession) -> SoapClient:
    client = SoapClient.__new__(SoapClient)
    client.transport = SimpleNamespace(session=session)
    client.config = SimpleNamespace(
        cert_pem_path="/tmp/cert.pem",
        key_pem_path="/tmp/key.pem",
        ca_bundle_path=True,
        get_soap_service_url=lambda service_key: "https://sifen-test.set.gov.py/de/ws/consultas/consulta-lote.wsdl",
    )
    client.connect_timeout = 1
    client.read_timeout = 1
    return client


def test_consulta_lote_raw_writes_last_request_even_if_response_is_invalid_xml(tmp_path: Path):
    artifacts_dir = tmp_path / "consulta_lote_artifacts"
    response = _MockResponse(
        status_code=200,
        headers={"Content-Type": "application/soap+xml; charset=utf-8"},
        content=b"<soap:Envelope><broken>",
    )
    client = _client_without_init(_MockSession(response))

    with pytest.raises(SifenClientError, match="consulta_lote_raw falló tras"):
        client.consulta_lote_raw(
            dprot_cons_lote="47353168698201554",
            did="202602170000001",
            artifacts_dir=artifacts_dir,
        )

    assert (artifacts_dir / "soap_last_request.xml").exists()
    assert (artifacts_dir / "soap_last_request.headers.json").exists()
    assert (artifacts_dir / "soap_last_response.xml").exists()
    assert (artifacts_dir / "soap_last_response.headers.json").exists()
    assert (artifacts_dir / "soap_last_response.meta.json").exists()
    assert (artifacts_dir / "soap_invalid_response.xml").exists()
    assert (artifacts_dir / "soap_invalid_response_preview.txt").exists()

    meta = json.loads((artifacts_dir / "soap_last_response.meta.json").read_text(encoding="utf-8"))
    assert meta["http_status"] == 200
    assert meta["did"] == "202602170000001"
    assert meta["dprot_cons_lote"] == "47353168698201554"
