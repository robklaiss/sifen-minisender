#!/usr/bin/env bash
set -euo pipefail

# ejemplo:
#   ./run.sh send --env test --xml artifacts/run_xxx/lote.xml
python3 -m sifen_minisender "$@"
