from pathlib import Path
import json
import re
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


@pytest.fixture()
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", str(tmp_path / "webui_nre_geo.db"))
    with webapp.app.app_context():
        webapp.init_db()
        yield


def _find_asuncion_geo() -> tuple[str, str, str]:
    tree = json.loads(Path("data/georef_tree.json").read_text(encoding="utf-8"))
    city_by_dist = tree.get("city_by_dist", {})
    dist_to_dep = tree.get("dist_to_dep", {})

    def _pick(match) -> tuple[str, str, str]:
        for dist_code, cities in city_by_dist.items():
            if not isinstance(cities, dict):
                continue
            for city_code, name in cities.items():
                label = str(name or "")
                if match(label):
                    dep_code = dist_to_dep.get(str(dist_code), "")
                    return (
                        webapp._geo_display_code(dep_code),
                        webapp._geo_display_code(dist_code),
                        webapp._geo_display_code(city_code),
                    )
        return ("", "", "")

    exact = _pick(lambda label: label.strip().upper() == "ASUNCION (DISTRITO)")
    if any(exact):
        return exact
    contains = _pick(lambda label: "ASUNCION" in label.upper())
    if any(contains):
        return contains
    raise AssertionError("Asunción no encontrado en georef_tree.json")


def test_nre_geo_selects_include_asuncion(app_ctx):
    client = webapp.app.test_client()
    resp = client.get("/invoice/new?doc_type=7")
    assert resp.status_code == 200

    html = resp.get_data(as_text=True)
    for field in (
        "nre_sal_departamento",
        "nre_sal_distrito",
        "nre_sal_ciudad",
        "nre_ent_departamento",
        "nre_ent_distrito",
        "nre_ent_ciudad",
    ):
        assert re.search(rf'<select[^>]*name="{field}"[^>]*>', html) is not None

    _, _, city_code = _find_asuncion_geo()
    match = re.search(r'<select[^>]*name="nre_sal_ciudad"[^>]*>.*?</select>', html, re.S)
    assert match is not None
    select_html = match.group(0)
    assert "disabled" in select_html
    assert re.search(rf'value="{re.escape(city_code)}"[^>]*>[^<]*Asunc', select_html, re.I) is not None
