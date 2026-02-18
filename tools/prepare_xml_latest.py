#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _resolve_artifacts_dir(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit).expanduser()
    env_dir = (
        os.getenv("SIFEN_ARTIFACTS_DIR")
        or os.getenv("ARTIFACTS_DIR")
        or os.getenv("SIFEN_ARTIFACTS_PATH")
        or "artifacts"
    )
    return Path(env_dir).expanduser()


def _latest_sirecepde(artifacts_dir: Path) -> Path | None:
    if not artifacts_dir.exists():
        return None
    files = sorted(
        artifacts_dir.glob("sirecepde_*.xml"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    return files[0] if files else None


def _resolve_xml(xml_arg: str, artifacts_dir: Path) -> Path:
    xml_value = (xml_arg or "").strip()
    if xml_value.lower() == "latest":
        latest = _latest_sirecepde(artifacts_dir)
        if latest is None:
            raise FileNotFoundError(
                "No se encontró ningún sirecepde_*.xml para '--xml latest'.\n"
                f"Busqué en: {artifacts_dir}\n"
                "Soluciones:\n"
                "  1) Pasar ruta explícita: --xml /ruta/al/rde.xml\n"
                "  2) Generar un ejemplo base: make sample-xml\n"
                "  3) Reintentar con: make send-test XML=/ruta/al/rde.xml"
            )
        return latest

    candidate = Path(xml_value).expanduser()
    if candidate.exists() and candidate.is_file():
        return candidate

    candidate_in_artifacts = artifacts_dir / xml_value
    if candidate_in_artifacts.exists() and candidate_in_artifacts.is_file():
        return candidate_in_artifacts

    raise FileNotFoundError(f"No existe el XML indicado: {xml_value}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Resuelve un XML para envío: 'latest' o path explícito."
    )
    parser.add_argument("--xml", required=True, help="latest o ruta al XML")
    parser.add_argument(
        "--artifacts-dir",
        default=None,
        help="Directorio de búsqueda para latest (default: SIFEN_ARTIFACTS_DIR/ARTIFACTS_DIR/artifacts)",
    )
    args = parser.parse_args()

    artifacts_dir = _resolve_artifacts_dir(args.artifacts_dir)

    try:
        resolved = _resolve_xml(args.xml, artifacts_dir)
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(str(resolved.resolve()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
