from pathlib import Path
from types import SimpleNamespace
import sys

from requests.cookies import RequestsCookieJar

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.sifen_client.soap_client import SoapClient


class _MockResponse:
    def __init__(self, *, status_code: int, headers: dict, content: bytes):
        self.status_code = status_code
        self.headers = headers
        self.content = content


class _MockSession:
    def __init__(self):
        self.cookies = RequestsCookieJar()
        self.get_calls = 0
        self.post_cookies_empty = []

    def get(self, *args, **kwargs):
        self.get_calls += 1
        self.cookies.set("MRHSession", "cookie-value", domain="sifen-test.set.gov.py", path="/")
        return _MockResponse(
            status_code=200,
            headers={"Content-Type": "application/xml"},
            content=b"<definitions/>",
        )

    def post(self, *args, **kwargs):
        self.post_cookies_empty.append(len(self.cookies) == 0)
        return _MockResponse(
            status_code=200,
            headers={"Content-Type": "application/soap+xml; charset=utf-8"},
            content=(
                b'<?xml version="1.0" encoding="UTF-8"?>'
                b'<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">'
                b"<soap:Body>"
                b'<rResEnviConsLoteDe xmlns="http://ekuatia.set.gov.py/sifen/xsd">'
                b"<dCodResLot>0361</dCodResLot>"
                b"<dMsgResLot>OK</dMsgResLot>"
                b"</rResEnviConsLoteDe>"
                b"</soap:Body>"
                b"</soap:Envelope>"
            ),
        )


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


def test_consulta_lote_raw_clears_cookies_before_post(tmp_path: Path):
    session = _MockSession()
    client = _client_without_init(session)

    result = client.consulta_lote_raw(
        dprot_cons_lote="47353168698201554",
        did="202602170000001",
        artifacts_dir=tmp_path,
    )

    assert result["http_status"] == 200
    assert session.get_calls >= 1
    assert session.post_cookies_empty
    assert all(session.post_cookies_empty)
