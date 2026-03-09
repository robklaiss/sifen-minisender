from datetime import datetime
from pathlib import Path
import json
import sys
import xml.etree.ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


NS = {"s": "http://ekuatia.set.gov.py/sifen/xsd"}
FE_CDC_REF = "01" + ("1" * 42)


@pytest.fixture()
def app_ctx(tmp_path, monkeypatch):
    monkeypatch.setattr(webapp, "DB_PATH", str(tmp_path / "webui_doc_types.db"))
    with webapp.app.app_context():
        webapp.init_db()
        yield


def _create_customer() -> int:
    con = webapp.get_db()
    con.execute(
        "INSERT INTO customers (name, ruc, created_at) VALUES (?,?,?)",
        ("Cliente Prueba", "80012345-6", webapp.now_iso()),
    )
    con.commit()
    row = con.execute("SELECT last_insert_rowid() AS id").fetchone()
    return int(row["id"])


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


@pytest.mark.parametrize("doc_type", ["5", "6"])
def test_nc_nd_new_invoice_builds_doc_asoc(app_ctx, doc_type):
    client = webapp.app.test_client()
    with webapp.app.app_context():
        customer_id = _create_customer()

    payload = {
        "doc_type": doc_type,
        "customer_id": str(customer_id),
        "establishment": "001",
        "point_exp": "001",
        "description": "Servicio",
        "qty": "1",
        "price_unit": "1000",
        "nc_doc_asoc_tipo": "1",
        "nc_cdc_asoc": FE_CDC_REF,
        "nc_motivo": "1",
    }

    resp = client.post("/invoice/new", data=payload, follow_redirects=False)
    assert resp.status_code in (302, 303)

    location = resp.headers.get("Location") or ""
    invoice_id = int(location.rsplit("/", 1)[-1])

    with webapp.app.app_context():
        con = webapp.get_db()
        inv = con.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        assert inv is not None
        assert inv["doc_type"] == doc_type

        extra = webapp._parse_extra_json(inv["doc_extra_json"], doc_type)
        errors = webapp._validate_doc_extra(doc_type, extra)
        assert not errors

        lines = con.execute(
            "SELECT * FROM invoice_lines WHERE invoice_id=? ORDER BY id ASC",
            (invoice_id,),
        ).fetchall()
        assert lines

        build = webapp._build_invoice_xml_from_template(
            template_path=webapp._template_for_doc_type(doc_type),
            invoice_id=invoice_id,
            customer={"name": "Cliente X", "ruc": "80012345-6"},
            lines=lines,
            doc_number="0000001",
            doc_type=doc_type,
            extra_json=extra,
            issue_dt=datetime(2026, 3, 4, 10, 0, 0),
            codseg="123456789",
            establishment="001",
            point_exp="001",
        )
        root = ET.fromstring(build["xml_bytes"])
        assert root.find(".//s:gCamDEAsoc", NS) is not None
        assert root.findtext(".//s:gDtipDE/s:gCamNCDE/s:iMotEmi", default="", namespaces=NS) == "1"
        assert root.findtext(".//s:gCamDEAsoc/s:dCdCDERef", default="", namespaces=NS) == FE_CDC_REF


def test_nd_builds_printed_factura_assoc(app_ctx):
    with webapp.app.app_context():
        webapp.set_setting("timbrado_num", "18578288")
        webapp.set_setting("timbrado_fe_ini", "2026-01-14")
        build = webapp._build_invoice_xml_from_template(
            template_path=webapp._template_for_doc_type("6"),
            invoice_id=66,
            customer={"name": "Cliente X", "ruc": "80012345-6"},
            lines=[{"description": "Servicio", "qty": 1, "price_unit": 1000, "line_total": 1000, "iva_rate": 10}],
            doc_number="0000001",
            doc_type="6",
            extra_json={
                "documentoAsociado": {
                    "tipoDocumentoAsoc": "2",
                    "timbradoAsoc": "12345678",
                    "establecimientoAsoc": "001",
                    "puntoAsoc": "002",
                    "numeroAsoc": "0000123",
                    "fechaDocIm": "2026-03-01",
                },
                "iMotEmi": "1",
            },
            issue_dt=datetime(2026, 3, 4, 10, 0, 0),
            codseg="123456789",
            establishment="001",
            point_exp="001",
        )

    root = ET.fromstring(build["xml_bytes"])
    assert root.findtext(".//s:gTimb/s:iTiDE", default="", namespaces=NS) == "6"
    assert root.findtext(".//s:gTimb/s:dDesTiDE", default="", namespaces=NS) == "Nota de débito electrónica"
    assert root.findtext(".//s:gCamDEAsoc/s:iTipDocAso", default="", namespaces=NS) == "2"
    assert root.findtext(".//s:gCamDEAsoc/s:iTipoDocAso", default="", namespaces=NS) == "1"
    assert root.findtext(".//s:gCamDEAsoc/s:dDTipoDocAso", default="", namespaces=NS) == "Factura"
    assert root.findtext(".//s:gCamDEAsoc/s:dFecEmiDI", default="", namespaces=NS) == "2026-03-01"
    assert root.find(".//s:gCamDEAsoc/s:dCdCDERef", NS) is None


@pytest.mark.parametrize(
    "assoc, expected",
    [
        (
            {
                "tipoDocumentoAsoc": "1",
                "cdcAsociado": FE_CDC_REF,
                "timbradoAsoc": "12345678",
            },
            "no mezclar referencia electrónica e impresa",
        ),
        (
            {
                "tipoDocumentoAsoc": "2",
                "timbradoAsoc": "12345678",
                "establecimientoAsoc": "001",
                "puntoAsoc": "002",
                "numeroAsoc": "0000123",
            },
            "fechaDocIm es obligatoria",
        ),
        (
            {
                "tipoDocumentoAsoc": "2",
                "timbradoAsoc": "12345678",
                "establecimientoAsoc": "001",
                "puntoAsoc": "002",
                "numeroAsoc": "0000123",
                "tipoDocumentoIm": "2",
                "fechaDocIm": "2026-03-01",
            },
            "tipoDocumentoIm debe ser 1",
        ),
        (
            {
                "tipoDocumentoAsoc": "1",
                "cdcAsociado": "06" + ("9" * 42),
            },
            "debe referenciar una Factura electrónica",
        ),
    ],
)
def test_nd_rejects_invalid_associated_document_payload(app_ctx, assoc, expected):
    errors = webapp._validate_doc_extra("6", {"documentoAsociado": assoc, "iMotEmi": "1"})
    assert any(expected in err for err in errors)


def test_nre_new_invoice_builds_transporte(app_ctx):
    client = webapp.app.test_client()
    with webapp.app.app_context():
        customer_id = _create_customer()

    dep_code, dist_code, city_code = _find_asuncion_geo()
    payload = {
        "doc_type": "7",
        "customer_id": str(customer_id),
        "establishment": "001",
        "point_exp": "001",
        "description": "Servicio",
        "qty": "1",
        "price_unit": "1000",
        "nre_motivo": "1",
        "nre_responsable": "1",
        "nre_trans_modalidad": "1",
        "nre_trans_resp_flete": "1",
        "nre_fecha_factura": "2026-03-01",
        "nre_sal_direccion": "Calle 1",
        "nre_sal_num_casa": "0",
        "nre_sal_departamento": dep_code,
        "nre_sal_distrito": dist_code,
        "nre_sal_ciudad": city_code,
        "nre_ent_direccion": "Calle 2",
        "nre_ent_num_casa": "0",
        "nre_ent_departamento": dep_code,
        "nre_ent_distrito": dist_code,
        "nre_ent_ciudad": city_code,
        "nre_veh_tipo": "1",
        "nre_veh_marca": "Toyota",
        "nre_veh_doc_tipo": "1",
        "nre_veh_numero": "AAET 366",
        "nre_transp_tipo": "1",
        "nre_transp_nombre": "Transportes SA",
        "nre_transp_numero": "80012345-6",
        "nre_transp_dir": "Av. Siempre Viva",
        "nre_transp_nacionalidad": "PARAGUAYA",
        "nre_chof_nombre": "Chofer Uno",
        "nre_chof_numero": "1234567",
        "nre_chof_dir": "Barrio Centro",
    }

    resp = client.post("/invoice/new", data=payload, follow_redirects=False)
    assert resp.status_code in (302, 303)

    location = resp.headers.get("Location") or ""
    invoice_id = int(location.rsplit("/", 1)[-1])

    with webapp.app.app_context():
        con = webapp.get_db()
        inv = con.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
        assert inv is not None
        assert inv["doc_type"] == "7"

        extra = webapp._parse_extra_json(inv["doc_extra_json"], "7")
        errors = webapp._validate_doc_extra("7", extra)
        assert not errors

        lines = con.execute(
            "SELECT * FROM invoice_lines WHERE invoice_id=? ORDER BY id ASC",
            (invoice_id,),
        ).fetchall()
        assert lines

        build = webapp._build_invoice_xml_from_template(
            template_path=webapp._template_for_doc_type("7"),
            invoice_id=invoice_id,
            customer={"name": "Cliente X", "ruc": "80012345-6"},
            lines=lines,
            doc_number="0000001",
            doc_type="7",
            extra_json=extra,
            issue_dt=datetime(2026, 3, 4, 10, 0, 0),
            codseg="123456789",
            establishment="001",
            point_exp="001",
        )
        root = ET.fromstring(build["xml_bytes"])
        gcam_nre = root.find(".//s:gDtipDE/s:gCamNRE", NS)
        assert gcam_nre is not None
        assert root.find(".//s:gDtipDE/s:gTransp", NS) is not None
        assert gcam_nre.findtext("s:dKmR", default="", namespaces=NS) == "1"
        assert gcam_nre.findtext("s:dFecEm", default="", namespaces=NS) == "2026-03-01"

        tags = [el.tag.split("}")[-1] for el in list(gcam_nre)]
        assert "dKmR" in tags
        assert "dFecEm" in tags
        assert tags.index("dKmR") < tags.index("dFecEm")

        gtransp = root.find(".//s:gDtipDE/s:gTransp", NS)
        assert gtransp is not None
        assert gtransp.findtext("s:gCamTrans/s:cNacTrans", default="", namespaces=NS) == "PRY"
        assert gtransp.findtext("s:gVehTras/s:dNroMatVeh", default="", namespaces=NS) == "AAET366"
