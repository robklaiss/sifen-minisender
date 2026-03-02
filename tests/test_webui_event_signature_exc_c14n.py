from pathlib import Path
import sys
import types

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import webui.app as webapp
from app.sifen_client import xmlsec_signer


class _FakeXmlsecKey:
    def load_cert_from_file(self, *_args, **_kwargs) -> None:
        return None

    def load_cert_from_memory(self, *_args, **_kwargs) -> None:
        return None


class _FakeXmlsecKeyClass:
    @staticmethod
    def from_file(_path: str, _fmt: str) -> _FakeXmlsecKey:
        return _FakeXmlsecKey()


class _FakeXmlsecSignatureContext:
    def __init__(self) -> None:
        self.key = None

    def sign(self, _sig) -> None:
        return None


class _FakeXmlsecTree:
    @staticmethod
    def add_ids(_tree, _ids) -> None:
        return None


class _FakeXmlsecKeyFormat:
    PEM = "PEM"


class _FakePkcs12:
    @staticmethod
    def load_key_and_certificates(_p12_bytes, _password_bytes, backend=None):
        return (None, None, None)


def _fake_xmlsec_module():
    return types.SimpleNamespace(
        Key=_FakeXmlsecKeyClass,
        SignatureContext=_FakeXmlsecSignatureContext,
        tree=_FakeXmlsecTree,
        KeyFormat=_FakeXmlsecKeyFormat,
    )


def test_event_signature_uses_exc_c14n(tmp_path, monkeypatch):
    event_id = "123456"
    cdc = "0" * 44
    event_xml = webapp._build_cancel_event_xml(cdc, "Motivo valido", event_id)

    fake_p12 = tmp_path / "fake.p12"
    fake_p12.write_bytes(b"fake")

    fake_cert = tmp_path / "cert.pem"
    fake_key = tmp_path / "key.pem"
    fake_cert.write_text("fake-cert")
    fake_key.write_text("fake-key")

    monkeypatch.setattr(xmlsec_signer, "XMLSEC_AVAILABLE", True)
    monkeypatch.setattr(xmlsec_signer, "CRYPTOGRAPHY_AVAILABLE", True)
    monkeypatch.setattr(xmlsec_signer, "xmlsec", _fake_xmlsec_module())
    monkeypatch.setattr(xmlsec_signer, "pkcs12", _FakePkcs12)
    monkeypatch.setattr(xmlsec_signer, "default_backend", lambda: None)
    monkeypatch.setattr(
        xmlsec_signer,
        "p12_to_temp_pem_files",
        lambda _p12_path, _p12_password: (str(fake_cert), str(fake_key)),
    )
    monkeypatch.setattr(xmlsec_signer, "cleanup_pem_files", lambda *_args, **_kwargs: None)

    signed_event_xml = webapp.sign_event_with_p12(
        event_xml,
        str(fake_p12),
        "fake-password",
    ).decode("utf-8")

    assert "http://www.w3.org/2001/10/xml-exc-c14n#" in signed_event_xml
    assert "http://www.w3.org/TR/2001/REC-xml-c14n-20010315" not in signed_event_xml
