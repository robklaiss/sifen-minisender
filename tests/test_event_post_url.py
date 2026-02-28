from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from webui.app import _event_post_url  # noqa: E402


def test_event_post_url_strips_wsdl_suffix():
    wsdl_url = "https://example.test/de/ws/eventos/evento.wsdl"
    post_url = _event_post_url(wsdl_url)
    assert post_url == "https://example.test/de/ws/eventos/evento"
    assert not post_url.endswith(".wsdl")


def test_event_post_url_strips_wsdl_querystring():
    wsdl_url = "https://example.test/de/ws/eventos/evento.wsdl?wsdl"
    post_url = _event_post_url(wsdl_url)
    assert post_url == "https://example.test/de/ws/eventos/evento.wsdl"
    assert "?" not in post_url
