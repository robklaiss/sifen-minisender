#!/usr/bin/env python3
"""
Smoke test pre-sign XSD v150.

Runs:
- test_xsd_presign_all_doc_types_v150
- test_nre_presign_xsd_v150
- a small iTiDE sweep (1,4,5,6,7) validating with validate_rde_and_lote

Usage (inside container):
  PYTHONPATH=/app python3 tools/smoke_presign_v150.py
"""
from decimal import Decimal

import webui.app as webapp
from app.sifen_client.xsd_validator import validate_rde_and_lote

from tests.test_xsd_presign_all_doc_types import test_xsd_presign_all_doc_types_v150
from tests.test_nre_presign_xsd_v150 import test_nre_presign_xsd_v150


DOCS = [
    ("1", "rde_factura.xml"),
    ("4", "rde_factura.xml"),
    ("5", "rde_factura.xml"),
    ("6", "rde_factura.xml"),
    ("7", "rde_remision.xml"),
]

CODSEG = "123456789"


def main() -> int:
    print("== smoke: tests ==")
    print("RUN all_doc_types")
    test_xsd_presign_all_doc_types_v150()
    print("OK all_doc_types")

    print("RUN nre")
    test_nre_presign_xsd_v150()
    print("OK nre")

    print("\n== smoke: barrido itide (pre-sign XSD) ==")
    with webapp.app.app_context():
        webapp.init_db()
        webapp.set_setting("timbrado_num", "18578288")
        webapp.set_setting("timbrado_fe_ini", "2026-01-14")

        for doc_type, tpl in DOCS:
            template = webapp._repo_root() / "templates" / "xml" / tpl
            lines = [
                {
                    "description": "L1",
                    "qty": Decimal("1.0"),
                    "price_unit": Decimal("100"),
                    "line_total": Decimal("100"),
                    "iva_rate": 10,
                }
            ]
            extra = webapp._default_extra_json_for(doc_type) or {}

            if doc_type == "7":
                extra.setdefault("ope", {})
                extra["ope"]["codseg"] = CODSEG
                extra["ope"]["dCodSeg"] = CODSEG
                extra["codseg"] = CODSEG
                extra["dCodSeg"] = CODSEG

            build = webapp._build_invoice_xml_from_template(
                template_path=str(template),
                invoice_id=900000 + int(doc_type),
                customer={"name": "Cliente Test", "ruc": "7524653-8"},
                lines=lines,
                doc_number=f"{int(doc_type):07d}",
                doc_type=doc_type,
                extra_json=extra,
            )

            res = validate_rde_and_lote(build["xml_bytes"], None, webapp._repo_root() / "schemas_sifen")
            ok = res.get("rde_ok")
            schema = res.get("schema_path") or res.get("schema_used") or res.get("xsd")
            reason = res.get("schema_reason")
            print(f"iTiDE={doc_type} ok={ok} schema={schema} reason={reason}")
            if not ok:
                errs = res.get("schema_errors") or res.get("rde_errors") or []
                print("errors:", errs[:10])
                return 1

    print("\nOK: SMOKE TEST COMPLETO")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
