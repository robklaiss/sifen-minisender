#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# Asegurar import "app.*" aunque ejecutes desde tools/
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.sifen_client.config import get_sifen_config
from app.sifen_client.soap_client import SoapClient


def _set_if_attr(obj, name: str, value) -> bool:
    if hasattr(obj, name):
        try:
            setattr(obj, name, value)
            return True
        except Exception:
            return False
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Consulta estado de lote en SIFEN (siConsLoteDE)")
    ap.add_argument("--env", choices=["test", "prod"], required=True)
    ap.add_argument("--prot", required=True, help="dProtConsLote")
    ap.add_argument("--did", type=int, default=1, help="dId para consulta (default 1)")
    ap.add_argument("--dump-http", action="store_true")
    ap.add_argument("--artifacts-dir", default=None)
    args = ap.parse_args()

    # Artifacts dir
    if args.artifacts_dir:
        artifacts_dir = Path(args.artifacts_dir)
    else:
        artifacts_dir = Path("artifacts") / f"consulta_lote_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    # Config + client
    config = get_sifen_config(env=args.env)
    client = SoapClient(config=config)  # sin kwargs: máxima compatibilidad

    # Intentar setear flags/paths según la versión de SoapClient
    _set_if_attr(client, "dump_http", bool(args.dump_http))
    _set_if_attr(client, "debug_soap", bool(args.dump_http))
    _set_if_attr(client, "artifacts_dir", artifacts_dir)
    _set_if_attr(client, "artifacts_base_dir", artifacts_dir)

    # Ejecutar consulta (la función ya existe en tu SoapClient)
    out = client.consulta_lote_raw(
        dprot_cons_lote=str(args.prot).strip(),
        did=int(args.did),
        dump_http=bool(args.dump_http),
    )

    # Guardar JSON parseado
    jpath = artifacts_dir / f"consulta_lote_{args.prot}.json"
    jpath.write_text(json.dumps(out, ensure_ascii=False, indent=2), encoding="utf-8")

    # Imprimir resumen
    dCodRes = out.get("dCodRes") or out.get("response_dCodRes") or out.get("response_dCodRes".lower())
    dMsgRes = out.get("dMsgRes") or out.get("response_dMsgRes") or out.get("response_dMsgRes".lower())
    parsed = out.get("parsed_fields") or {}

    print("============================================================")
    print("=== RESULT consulta_lote ===")
    print(f"env: {args.env}")
    print(f"dProtConsLote: {args.prot}")
    print(f"dCodRes: {dCodRes}")
    print(f"dMsgRes: {dMsgRes}")
    if "dTpoProces" in out:
        print(f"dTpoProces: {out.get('dTpoProces')}")
    for k in ["dEstLote", "dMsgEst", "dCodResLot", "dMsgResLot", "dFecProc"]:
        if k in parsed and parsed.get(k) is not None:
            print(f"{k}: {parsed.get(k)}")
    print("Artifacts dir:", str(artifacts_dir))
    print("JSON:", str(jpath))
    print("============================================================")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
