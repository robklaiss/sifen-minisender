#!/usr/bin/env python3
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

from reportlab import rl_config

# Asegurar import "app.*" aunque ejecutes desde tools/
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.pdf.doc_types import DOC_TYPE_CONFIG
from app.pdf.invoice_renderer import render_invoice_pdf
from webui.app import _load_geo_lookup


def _pick_geo_entry() -> Tuple[int, int, int, str, str, str]:
    lookup = _load_geo_lookup()
    for (dep, dis, ciu), (dep_desc, dis_desc, ciu_desc) in lookup.items():
        return dep, dis, ciu, dep_desc, dis_desc, ciu_desc
    raise RuntimeError("Geo lookup vacío; no hay entradas válidas.")


def _build_nre_source_xml(
    dep: int,
    dis: int,
    ciu: int,
    dep_desc: str,
    dis_desc: str,
    ciu_desc: str,
    issue_date: str,
) -> str:
    return f"""<rDE>
  <DE>
    <gDtipDE>
      <gCamNRE>
        <iMotEmiNR>1</iMotEmiNR>
        <dDesMotEmiNR>Traslado por ventas</dDesMotEmiNR>
        <iRespEmiNR>1</iRespEmiNR>
        <dDesRespEmiNR>Emisor de la factura</dDesRespEmiNR>
        <dKmR>12</dKmR>
        <dFecEm>{issue_date}</dFecEm>
      </gCamNRE>
      <gTransp>
        <iTipTrans>1</iTipTrans>
        <dDesTipTrans>Propio</dDesTipTrans>
        <iModTrans>1</iModTrans>
        <dDesModTrans>Terrestre</dDesModTrans>
        <iRespFlete>1</iRespFlete>
        <gCamSal>
          <dDirLocSal>Deposito demo</dDirLocSal>
          <dNumCasSal>123</dNumCasSal>
          <cDepSal>{dep}</cDepSal>
          <dDesDepSal>{dep_desc}</dDesDepSal>
          <cDisSal>{dis}</cDisSal>
          <dDesDisSal>{dis_desc}</dDesDisSal>
          <cCiuSal>{ciu}</cCiuSal>
          <dDesCiuSal>{ciu_desc}</dDesCiuSal>
          <dTelSal>021 000000</dTelSal>
        </gCamSal>
        <gCamEnt>
          <dDirLocEnt>Destino demo</dDirLocEnt>
          <dNumCasEnt>456</dNumCasEnt>
          <cDepEnt>{dep}</cDepEnt>
          <dDesDepEnt>{dep_desc}</dDesDepEnt>
          <cDisEnt>{dis}</cDisEnt>
          <dDesDisEnt>{dis_desc}</dDesDisEnt>
          <cCiuEnt>{ciu}</cCiuEnt>
          <dDesCiuEnt>{ciu_desc}</dDesCiuEnt>
          <dTelEnt>021 000000</dTelEnt>
        </gCamEnt>
      </gTransp>
    </gDtipDE>
  </DE>
</rDE>"""


def _demo_payload(doc_type: str, issue_date: str, nre_xml: str | None) -> Dict[str, Any]:
    total = "1000"
    iva10 = "90.91"
    items: List[Dict[str, Any]] = [
        {
            "descripcion": f"Item demo iTiDE={doc_type}",
            "cantidad": "1",
            "precio_unit": "1000",
            "iva": "10",
            "total": total,
        }
    ]
    parsed_fields = {
        "iTiDE": doc_type,
        "dNumDoc": f"{int(doc_type):07d}",
        "dSerDoc": "001-001",
        "dFecEmi": issue_date,
        "dTotGralOpe": total,
        "dTotOpe": total,
        "dIVA10": iva10,
        "dIVA5": "0",
        "dTotIVA": iva10,
        "dNomRec": "Cliente Demo",
        "dRucRec": "80012345",
        "dDVRec": "6",
        "dDirRec": "Asuncion",
        "dTelRec": "0991 000000",
        "dDCondOpe": "Contado",
        "dNumRem": "0000001",
    }
    return {
        "parsed_fields": parsed_fields,
        "items": items,
        "source_xml_text": nre_xml or "",
    }


def main() -> int:
    rl_config.pageCompression = 0

    now = datetime.now()
    stamp = now.strftime("%Y%m%d_%H%M%S")
    out_dir = Path("/data/artifacts") / f"pdf_demo_all_itide_{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    issue_date = now.strftime("%Y-%m-%d")
    dep, dis, ciu, dep_desc, dis_desc, ciu_desc = _pick_geo_entry()
    nre_xml = _build_nre_source_xml(dep, dis, ciu, dep_desc, dis_desc, ciu_desc, issue_date)

    issuer = {
        "razon_social": "Industria Feris (Demo)",
        "ruc": "80012345",
        "dv": "6",
        "direccion": "Av. Principal 123",
        "telefono": "0991 000000",
        "email": "demo@industriaferis.test",
        "timbrado": "12345678",
        "vigencia": "2026-12-31",
    }

    results: List[Tuple[str, Path]] = []
    errors: List[str] = []

    for doc_type, cfg in DOC_TYPE_CONFIG.items():
        xml_text = nre_xml if doc_type == "7" else ""
        payload = _demo_payload(doc_type, issue_date, xml_text)
        filename = f"{cfg['prefix']}_{doc_type}_{stamp}.pdf"
        out_path = out_dir / filename
        try:
            render_invoice_pdf(data=payload, issuer=issuer, out_path=out_path)
            pdf_bytes = out_path.read_bytes()
            if not pdf_bytes.startswith(b"%PDF"):
                raise RuntimeError("PDF inválido (no empieza con %PDF)")
            if doc_type == "1":
                if b"FACTURA" not in pdf_bytes:
                    raise RuntimeError("No se encontró 'FACTURA' en el PDF")
            elif doc_type == "4":
                if b"AUTOFACTURA" not in pdf_bytes:
                    raise RuntimeError("No se encontró 'AUTOFACTURA' en el PDF")
            else:
                if b"NOTA DE" not in pdf_bytes:
                    raise RuntimeError("No se encontró 'NOTA DE' en el PDF")
            results.append((doc_type, out_path))
        except Exception as exc:
            errors.append(f"iTiDE={doc_type}: {exc}")

    for doc_type, path in results:
        print(f"iTiDE={doc_type} -> {path}")

    if errors:
        print("\nErrores:")
        for err in errors:
            print(f"- {err}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
