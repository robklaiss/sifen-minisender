#!/usr/bin/env python3
import os
import shutil
import sys
from pathlib import Path


def _resolve_base_dir() -> Path:
    return Path(__file__).resolve().parents[1]


def _resolve_uploads_dir(base_dir: Path) -> Path:
    raw = (os.getenv("WEBUI_UPLOADS_DIR") or "").strip()
    if raw:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = (base_dir / p).resolve()
        else:
            p = p.resolve()
        return p
    return (base_dir / "data" / "uploads").resolve()


def _target_name(source_path: Path) -> str:
    if source_path.suffix.lower() == ".png":
        return "issuer-logo.png"
    return "issuer-logo.jpg"


def main() -> int:
    if len(sys.argv) != 2:
        print("Usage: python3 tools/install_issuer_logo.py /path/to/logo.jpg")
        return 2

    source = Path(sys.argv[1]).expanduser()
    if not source.exists():
        print(f"Error: file not found: {source}")
        return 1
    if not source.is_file():
        print(f"Error: not a file: {source}")
        return 1

    base_dir = _resolve_base_dir()
    uploads_dir = _resolve_uploads_dir(base_dir)
    uploads_dir.mkdir(parents=True, exist_ok=True)
    target = uploads_dir / _target_name(source)

    shutil.copy2(source, target)
    os.chmod(target, 0o664)
    print(f"Issuer logo installed at {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
