from __future__ import annotations

from pathlib import Path
import os

def pick_latest_rde_signed_qr(repo_root: Path) -> Path:
    base = os.environ.get("SIFEN_ARTIFACTS_DIR", "").strip()
    artifacts_dir = Path(base) if base else Path("/data/artifacts")

    cands = sorted(
        artifacts_dir.glob("webui_dryrun_*/rde_signed_qr_*.xml"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    if not cands:
        raise AssertionError(f"No encontré rde_signed_qr_*.xml en {artifacts_dir} (corré un dry-run primero).")
    return cands[0]
