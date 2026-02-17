#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

# Asegurar import "app.*" aunque ejecutes desde tools/
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.pdf.invoice_renderer import render_invoice_pdf
from app.sifen_client.config import get_sifen_config


def _split_ruc(ruc_raw: Optional[str]) -> Tuple[str, str]:
    if not ruc_raw:
        return "", ""
    if "-" in ruc_raw:
        ruc, dv = ruc_raw.split("-", 1)
        return ruc.strip(), dv.strip()
    return ruc_raw.strip(), ""


def _first(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str):
            if value.strip():
                return value.strip()
        else:
            return str(value)
    return ""


def build_issuer(env: Optional[str]) -> Dict[str, Any]:
    cfg = None
    try:
        cfg = get_sifen_config(env=env)
    except Exception:
        cfg = None

    ruc_raw = _first(
        os.getenv("SIFEN_EMISOR_RUC"),
        getattr(cfg, "test_ruc", "") if cfg else "",
        os.getenv("SIFEN_TEST_RUC"),
    )
    ruc, dv = _split_ruc(ruc_raw)

    issuer = {
        "razon_social": _first(
            os.getenv("SIFEN_EMISOR_RAZON_SOCIAL"),
            os.getenv("SIFEN_RAZON_SOCIAL"),
            getattr(cfg, "test_razon_social", "") if cfg else "",
            os.getenv("SIFEN_TEST_RAZON_SOCIAL"),
        ),
        "ruc": ruc,
        "dv": dv,
        "direccion": _first(
            os.getenv("SIFEN_EMISOR_DIRECCION"),
            os.getenv("SIFEN_DIRECCION"),
        ),
        "telefono": _first(
            os.getenv("SIFEN_EMISOR_TELEFONO"),
            os.getenv("SIFEN_TELEFONO"),
        ),
        "email": _first(
            os.getenv("SIFEN_EMISOR_EMAIL"),
            os.getenv("SIFEN_EMISOR_MAIL"),
            os.getenv("SIFEN_EMAIL"),
        ),
        "timbrado": _first(
            os.getenv("SIFEN_TIMBRADO_OVERRIDE"),
            os.getenv("SIFEN_TIMBRADO"),
            getattr(cfg, "test_timbrado", "") if cfg else "",
            os.getenv("SIFEN_TEST_TIMBRADO"),
        ),
        "vigencia": _first(
            os.getenv("SIFEN_TIMBRADO_VIGENCIA"),
            os.getenv("SIFEN_VIGENCIA_TIMBRADO"),
        ),
    }

    return issuer


def main() -> int:
    ap = argparse.ArgumentParser(description="Genera PDF estilo factura desde JSON parseado/HTTP.")
    ap.add_argument("--in", dest="in_path", required=True, help="Ruta al JSON parseado/HTTP")
    ap.add_argument("--out", dest="out_path", default=None, help="Ruta PDF salida (opcional)")
    ap.add_argument("--env", choices=["test", "prod"], default=None, help="Ambiente para emisor")
    ap.add_argument("--artifacts-dir", default=None, help="Base dir de artifacts (opcional)")
    args = ap.parse_args()

    in_path = Path(args.in_path)
    if not in_path.exists():
        raise FileNotFoundError(f"JSON no encontrado: {in_path}")

    data = json.loads(in_path.read_text(encoding="utf-8"))
    issuer = build_issuer(args.env)

    if args.out_path:
        out_path = Path(args.out_path)
    else:
        base_dir = Path(args.artifacts_dir) if args.artifacts_dir else Path("artifacts")
        out_dir = base_dir / "pdf"
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"invoice_{stamp}.pdf"

    out_path.parent.mkdir(parents=True, exist_ok=True)
    render_invoice_pdf(data=data, issuer=issuer, out_path=out_path)

    print(f"✅ PDF generado: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
