from __future__ import annotations

from pathlib import Path
import os
import pytest

def pick_latest_rde_signed_qr(repo_root: Path) -> Path:
    """
    These guardrail tests need a previously generated signed RDE artifact.
    On developer machines, this may not exist; in that case we SKIP.
    """

    # Prefer explicit override
    base = os.environ.get("SIFEN_ARTIFACTS_DIR", "").strip()
    if base:
        artifacts_dir = Path(base)
    else:
        # Default to repo-local artifacts
        artifacts_dir = repo_root / "data" / "artifacts"

    if not artifacts_dir.exists():
        pytest.skip(f"No artifacts dir found at {artifacts_dir} (set SIFEN_ARTIFACTS_DIR or run a dry-run)")

    cands = sorted(
        artifacts_dir.glob("webui_dryrun_*/rde_signed_qr_*.xml"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    if not cands:
        pytest.skip(f"No rde_signed_qr_*.xml found under {artifacts_dir} (run a dry-run first)")

    return cands[0]
