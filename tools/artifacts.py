#!/usr/bin/env python3
from __future__ import annotations

import os
import re
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

ArtifactsPathLike = Optional[Union[str, Path]]


def _safe_token(value: str, *, fallback: str) -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", (value or "").strip()).strip("-")
    return token or fallback


def resolve_artifacts_dir(artifacts_dir: ArtifactsPathLike = None) -> Path:
    """Resolve artifacts base dir using args/env defaults and ensure it exists.

    Resolution order:
    1) explicit argument
    2) SIFEN_ARTIFACTS_DIR
    3) ARTIFACTS_DIR
    4) /data/artifacts
    """
    raw: Optional[str]
    used_default_fallback = False
    if artifacts_dir is None:
        env_sifen_artifacts_dir = (os.getenv("SIFEN_ARTIFACTS_DIR") or "").strip()
        env_artifacts_dir = (os.getenv("ARTIFACTS_DIR") or "").strip()
        raw = env_sifen_artifacts_dir or env_artifacts_dir or "/data/artifacts"
        used_default_fallback = not env_sifen_artifacts_dir and not env_artifacts_dir
    else:
        raw = str(artifacts_dir).strip()
        if not raw:
            env_sifen_artifacts_dir = (os.getenv("SIFEN_ARTIFACTS_DIR") or "").strip()
            env_artifacts_dir = (os.getenv("ARTIFACTS_DIR") or "").strip()
            raw = env_sifen_artifacts_dir or env_artifacts_dir or "/data/artifacts"
            used_default_fallback = not env_sifen_artifacts_dir and not env_artifacts_dir

    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    else:
        path = path.resolve()

    try:
        path.mkdir(parents=True, exist_ok=True)
        return path
    except Exception:
        if not used_default_fallback:
            raise
        fallback = (Path.cwd() / "data" / "artifacts").resolve()
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


def make_run_dir(
    prefix: str,
    env: str,
    *,
    prot: Optional[str] = None,
    did: Optional[str] = None,
    artifacts_dir: ArtifactsPathLike = None,
) -> Path:
    """Create and return a per-run artifacts directory."""
    base_dir = resolve_artifacts_dir(artifacts_dir)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    parts = [
        "run",
        ts,
        _safe_token(prefix, fallback="consulta"),
        _safe_token(env, fallback="env"),
    ]
    if prot:
        parts.append(f"prot_{_safe_token(str(prot), fallback='prot')}")
    if did:
        parts.append(f"did_{_safe_token(str(did), fallback='did')}")

    run_dir = base_dir / "_".join(parts)
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir
