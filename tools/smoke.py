#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import webui.app as webapp
from tools import send_sirecepde as sender


DOCS = [
    ("factura", "1", "rde_factura.xml"),
    ("remision", "7", "rde_remision.xml"),
    ("credito", "5", "rde_nota_credito.xml"),
]


def _load_inputs(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    if not path.exists() or not path.is_file():
        raise RuntimeError(f"--inputs-json no existe o no es archivo: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _to_decimal(val: Any, default: str) -> Decimal:
    if val is None or str(val).strip() == "":
        return Decimal(default)
    return Decimal(str(val))


def _build_lines(raw_lines: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    rows = raw_lines or [
        {
            "description": "Producto demo",
            "qty": "1",
            "price_unit": "100",
            "line_total": "100",
            "iva_rate": 10,
        }
    ]
    out: list[dict[str, Any]] = []
    for idx, row in enumerate(rows, start=1):
        qty = _to_decimal(row.get("qty"), "1")
        price_unit = _to_decimal(row.get("price_unit"), "0")
        line_total = _to_decimal(row.get("line_total"), str(qty * price_unit))
        iva_rate = int(str(row.get("iva_rate", 10)))
        out.append(
            {
                "description": str(row.get("description") or f"Item {idx}"),
                "qty": qty,
                "price_unit": price_unit,
                "line_total": line_total,
                "iva_rate": iva_rate,
            }
        )
    return out


def _prepare_doc_extra(doc_key: str, doc_type: str, inputs: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    required_inputs: list[str] = []
    base = webapp._default_extra_json_for(doc_type) or {}
    overrides = (((inputs.get("docs") or {}).get(doc_key) or {}).get("extra_json") or {})
    if isinstance(overrides, dict):
        base.update(overrides)

    if doc_key == "credito":
        assoc = base.get("documentoAsociado") or {}
        base["documentoAsociado"] = assoc
        tip = str(assoc.get("tipoDocumentoAsoc") or assoc.get("iTipDocAso") or "1").strip()
        if tip not in ("1", "2"):
            tip = "1"
        assoc["tipoDocumentoAsoc"] = tip

        if tip == "1":
            cdc_ref = str(assoc.get("cdcAsociado") or assoc.get("dCdCDERef") or "").strip()
            if not (cdc_ref.isdigit() and len(cdc_ref) == 44):
                required_inputs.append(
                    "docs.credito.extra_json.documentoAsociado.cdcAsociado (CDC de FE original, 44 dígitos)"
                )
                assoc["cdcAsociado"] = "0" * 44
        if not str(base.get("iMotEmi") or "").strip():
            base["iMotEmi"] = "1"

    if doc_key == "remision":
        rem = base.get("remision") or {}
        if not rem:
            required_inputs.append("docs.remision.extra_json.remision")
            rem = {"iMotEmiNR": "1", "iRespEmiNR": "1"}
            base["remision"] = rem
        transporte = base.get("transporte")
        if not transporte:
            required_inputs.append("docs.remision.extra_json.transporte")

    return base, required_inputs


def _build_rde_xml(
    *,
    template_path: Path,
    doc_type: str,
    doc_number: str,
    customer: dict[str, Any],
    lines: list[dict[str, Any]],
    extra_json: dict[str, Any],
    codseg: str,
    est: str,
    pun: str,
) -> bytes:
    now = datetime.now()
    built = webapp._build_invoice_xml_from_template(
        template_path=str(template_path),
        invoice_id=int(datetime.now().strftime("%H%M%S")) + int(doc_type),
        customer=customer,
        lines=lines,
        doc_number=doc_number,
        doc_type=doc_type,
        extra_json=extra_json,
        issue_dt=now,
        codseg=codseg,
        establishment=est,
        point_exp=pun,
    )
    return built["xml_bytes"]


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Smoke test Factura/Remisión/Nota de Crédito (build + sign + send).")
    ap.add_argument("--env", choices=["test", "prod"], default="test")
    ap.add_argument("--artifacts-dir", default=None, help="Base de artifacts (default: env o artifacts/)")
    ap.add_argument("--inputs-json", default=None, help="JSON opcional con datos de cliente/docs.")
    ap.add_argument("--allow-send-failures", action="store_true", help="No fallar si SIFEN rechaza/no responde.")
    ap.add_argument("--no-dump-http", action="store_true", help="No guardar dump HTTP detallado.")
    args = ap.parse_args()

    inputs = _load_inputs(Path(args.inputs_json).expanduser() if args.inputs_json else None)
    dump_http = not args.no_dump_http

    codseg = str(inputs.get("codseg") or os.getenv("SIFEN_CODSEG") or "123456789").strip()
    if not (codseg.isdigit() and len(codseg) == 9):
        raise RuntimeError("codseg debe ser numérico de 9 dígitos (input codseg o SIFEN_CODSEG).")

    customer_cfg = inputs.get("customer") or {}
    customer = {
        "name": str(customer_cfg.get("name") or "Cliente Smoke"),
        "ruc": str(customer_cfg.get("ruc") or "80012345-0"),
    }
    lines = _build_lines(inputs.get("lines"))
    est = str(inputs.get("establishment") or "001").zfill(3)
    pun = str(inputs.get("point_exp") or "001").zfill(3)

    artifacts_base = Path(args.artifacts_dir).expanduser() if args.artifacts_dir else sender._resolve_artifacts_base_dir()
    run_ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = sender._resolve_artifacts_dir(artifacts_base / f"run_{run_ts}_smoke")

    print(f"Run dir: {run_dir}")
    overall_fail = False
    summary: dict[str, Any] = {
        "run_dir": str(run_dir),
        "env": args.env,
        "timestamp": datetime.now().isoformat(),
        "results": {},
        "required_inputs": [],
    }

    for index, (doc_key, doc_type, template_name) in enumerate(DOCS, start=1):
        doc_dir = sender._resolve_artifacts_dir(run_dir / doc_key)
        template_path = webapp._repo_root() / "templates" / "xml" / template_name
        doc_cfg = (inputs.get("docs") or {}).get(doc_key) or {}
        doc_number = str(doc_cfg.get("doc_number") or f"{index:07d}").zfill(7)
        extra_json, required_inputs = _prepare_doc_extra(doc_key, doc_type, inputs)
        summary["required_inputs"].extend(required_inputs)

        print(f"\n[{doc_key}] doc_type={doc_type} doc_number={doc_number}")
        record: dict[str, Any] = {
            "doc_type": doc_type,
            "doc_number": doc_number,
            "required_inputs": required_inputs,
            "success": False,
            "send_success": False,
            "error": None,
        }
        try:
            xml_bytes = _build_rde_xml(
                template_path=template_path,
                doc_type=doc_type,
                doc_number=doc_number,
                customer=customer,
                lines=lines,
                extra_json=extra_json,
                codseg=codseg,
                est=est,
                pun=pun,
            )
            xml_path = doc_dir / f"{doc_key}_input.xml"
            xml_path.write_bytes(xml_bytes)
            record["xml_path"] = str(xml_path)

            result = sender.send_sirecepde(
                xml_path=xml_path,
                env=args.env,
                artifacts_dir=doc_dir,
                dump_http=dump_http,
            )
            sender.ensure_core_artifacts(artifacts_dir=doc_dir, result=result)

            record["send_success"] = bool(result.get("success"))
            record["result"] = result
            record["success"] = bool(result.get("success"))
            if not record["send_success"] and not args.allow_send_failures:
                overall_fail = True

        except Exception as exc:
            record["error"] = f"{type(exc).__name__}: {exc}"
            overall_fail = True
            sender.ensure_core_artifacts(
                artifacts_dir=doc_dir,
                result={"success": False, "error": str(exc), "error_type": type(exc).__name__},
            )

        required_files = [
            doc_dir / "de.xml",
            doc_dir / "soap_last_request.xml",
            doc_dir / "soap_last_response.xml",
            doc_dir / "sifen_response.json",
        ]
        record["artifacts"] = {p.name: p.exists() for p in required_files}
        if not all(record["artifacts"].values()):
            overall_fail = True
        _write_json(doc_dir / "smoke_result.json", record)
        summary["results"][doc_key] = record
        print(f"[{doc_key}] send_success={record['send_success']} artifacts={record['artifacts']}")

    # Deduplicar inputs requeridos.
    summary["required_inputs"] = sorted(set(summary.get("required_inputs") or []))
    _write_json(run_dir / "smoke_summary.json", summary)
    print(f"\nSummary: {run_dir / 'smoke_summary.json'}")
    if summary["required_inputs"]:
        print("Inputs recomendados para operación real:")
        for item in summary["required_inputs"]:
            print(f"- {item}")

    return 1 if overall_fail else 0


if __name__ == "__main__":
    raise SystemExit(main())
