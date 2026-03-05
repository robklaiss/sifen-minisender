from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def test_base_html_has_mobile_navbar_collapse():
    html = webapp.BASE_HTML
    assert 'data-bs-target="#mainNavbar"' in html
    assert 'class="collapse navbar-collapse" id="mainNavbar"' in html

    new_doc_match = re.search(
        r"<button[^>]*data-bs-toggle=\"modal\"[^>]*data-bs-target=\"#newDocModal\"[^>]*>\s*Nuevo documento\s*</button>",
        html,
        re.IGNORECASE | re.DOTALL,
    )
    assert new_doc_match is not None
