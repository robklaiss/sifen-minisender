#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${1:-.env}"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "ERROR: no existe $ENV_FILE" >&2
  exit 1
fi

if awk '
  BEGIN { bad = 0 }
  {
    raw = $0
    sub(/^[ \t]+/, "", raw)
    if (raw == "" || raw ~ /^#/) next

    sub(/^export[ \t]+/, "", raw)
    eq = index(raw, "=")
    if (eq == 0) next

    key = substr(raw, 1, eq - 1)
    val = substr(raw, eq + 1)
    sub(/^[ \t]+/, "", val)

    if (val == "") next

    first = substr(val, 1, 1)
    if (first == "\"" || first == "\047") next

    sub(/[ \t]+#.*/, "", val)
    if (val ~ /[ \t]+/) {
      printf("%d:%s\n", NR, $0)
      bad = 1
    }
  }
  END { exit bad }
' "$ENV_FILE" >/tmp/check_env_bad_lines.txt; then
  echo "OK: formato .env válido ($ENV_FILE)"
  exit 0
fi

echo "ERROR: hay variables con espacios sin comillas en $ENV_FILE" >&2
cat /tmp/check_env_bad_lines.txt >&2
echo "Ejemplo correcto: SMTP_PASS=\"rpfg shib ytjp lkka\"" >&2
exit 1
