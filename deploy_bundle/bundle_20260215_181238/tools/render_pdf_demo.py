#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas


def hr(c, y, left=40, right=555, thickness=0.6, color=colors.HexColor("#D9D9D9")):
    c.setStrokeColor(color)
    c.setLineWidth(thickness)
    c.line(left, y, right, y)


def money(x) -> str:
    try:
        return f"{float(x):,.0f}".replace(",", ".")
    except Exception:
        return str(x)


def safe_get(d: dict, *keys, default=None):
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def main() -> int:
    ap = argparse.ArgumentParser(description="Demo: render PDF de factura (placeholder) con ReportLab")
    ap.add_argument("--in", dest="in_path", required=True, help="Ruta a JSON (metadata/payload)")
    ap.add_argument("--out", dest="out_path", default=None, help="Ruta PDF salida (opcional)")
    ap.add_argument("--artifacts-dir", default="artifacts/pdf", help="Base dir para PDFs (default artifacts/pdf)")
    args = ap.parse_args()

    in_path = Path(args.in_path)
    data = json.loads(in_path.read_text(encoding="utf-8"))

    # Intentamos extraer cosas comunes (si no existen, no pasa nada)
    cdc = safe_get(data, "CDC") or safe_get(data, "cdc") or safe_get(data, "parsed_fields", "CDC") or "SIN_CDC"
    ruc = safe_get(data, "dRucEm") or safe_get(data, "ruc") or safe_get(data, "parsed_fields", "dRucEm") or ""
    razon = safe_get(data, "dNomEmi") or safe_get(data, "razon_social") or safe_get(data, "parsed_fields", "dNomEmi") or ""
    nro = safe_get(data, "dNumDoc") or safe_get(data, "nro") or safe_get(data, "parsed_fields", "dNumDoc") or ""
    total = safe_get(data, "dTotGralOpe") or safe_get(data, "total") or safe_get(data, "parsed_fields", "dTotGralOpe") or ""

    art_base = Path(args.artifacts_dir)
    art_base.mkdir(parents=True, exist_ok=True)

    if args.out_path:
        out_pdf = Path(args.out_path)
        out_pdf.parent.mkdir(parents=True, exist_ok=True)
    else:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_pdf = art_base / f"FACTURA_{cdc}_{stamp}.pdf"

    c = canvas.Canvas(str(out_pdf), pagesize=A4)
    w, h = A4
    y = h - 25 * mm

    # Header
    c.setFont("Helvetica-Bold", 16)
    c.drawString(20 * mm, y, "FACTURA ELECTRÓNICA (DEMO)")

    c.setFont("Helvetica", 10)
    y -= 7 * mm
    c.drawString(20 * mm, y, f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    y -= 6 * mm
    c.drawString(20 * mm, y, f"CDC: {cdc}")
    hr(c, y - 6)
    y -= 16

    # Emisor
    c.setFont("Helvetica-Bold", 12)
    c.drawString(20 * mm, y, "Emisor")
    c.setFont("Helvetica", 10)
    y -= 7 * mm
    c.drawString(20 * mm, y, f"RUC: {ruc}")
    y -= 6 * mm
    c.drawString(20 * mm, y, f"Razón social: {razon}")
    hr(c, y - 6)
    y -= 16

    # Documento
    c.setFont("Helvetica-Bold", 12)
    c.drawString(20 * mm, y, "Documento")
    c.setFont("Helvetica", 10)
    y -= 7 * mm
    c.drawString(20 * mm, y, f"Nro: {nro}")
    y -= 6 * mm
    c.drawString(20 * mm, y, f"Total: {money(total)}")
    hr(c, y - 6)
    y -= 16

    # Caja simple de items (placeholder)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(20 * mm, y, "Detalle (placeholder)")
    c.setFont("Helvetica", 9)
    y -= 8 * mm
    c.drawString(20 * mm, y, "• Este PDF es un demo. El siguiente paso es mapear los campos reales del DE.")
    y -= 6 * mm
    c.drawString(20 * mm, y, "• Luego agregamos QR (CDC), totales, impuestos y layout final.")
    hr(c, y - 6)

    c.showPage()
    c.save()

    print("✅ PDF generado:", out_pdf)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
