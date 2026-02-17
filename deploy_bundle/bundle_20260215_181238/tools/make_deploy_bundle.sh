#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/deploy_bundle}"
STAMP="$(date +%Y%m%d_%H%M%S)"
DEST="$OUT/bundle_$STAMP"

mkdir -p "$DEST"

# Archivos base para correr en Docker/EC2
cp -v "$ROOT/Dockerfile" "$DEST/" 2>/dev/null || true
cp -v "$ROOT/docker-entrypoint.sh" "$DEST/" 2>/dev/null || true
cp -v "$ROOT/docker-compose.yml" "$DEST/" 2>/dev/null || true
cp -v "$ROOT/docker-compose.prod.yml" "$DEST/" 2>/dev/null || true
cp -v "$ROOT/requirements.txt" "$DEST/" 2>/dev/null || true
cp -v "$ROOT/.dockerignore" "$DEST/" 2>/dev/null || true
cp -v "$ROOT/README_DOCKER_EC2.md" "$DEST/" 2>/dev/null || true
cp -v "$ROOT/README.md" "$DEST/" 2>/dev/null || true

# Código
rsync -av --delete \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  --exclude '.pytest_cache' \
  --exclude '.venv' \
  --exclude 'artifacts/' \
  --exclude 'data/' \
  --exclude 'backups/' \
  --exclude 'secrets/' \
  "$ROOT/sifen_minisender/" "$DEST/sifen_minisender/"

rsync -av --delete \
  --exclude '__pycache__' \
  --exclude '*.pyc' \
  "$ROOT/tools/" "$DEST/tools/"

rsync -av --delete \
  "$ROOT/app/" "$DEST/app/" 2>/dev/null || true

# Schemas (solo lo que existe en el repo)
if [ -d "$ROOT/schemas_sifen" ]; then
  rsync -av --delete "$ROOT/schemas_sifen/" "$DEST/schemas_sifen/"
fi

# Secrets: creamos placeholder (no copiamos secretos reales)
mkdir -p "$DEST/secrets"
cat > "$DEST/secrets/README_SECRETS.txt" <<'TXT'
Poner aquí cert/key/etc (NO commitear).
En EC2 se montan como volumen o se copian manualmente.
TXT

# Wrapper de ejecución para evitar “qué comando era?”
cat > "$DEST/run.sh" <<'RUN'
#!/usr/bin/env bash
set -euo pipefail

# ejemplo:
#   ./run.sh send --env test --xml artifacts/run_xxx/lote.xml
python3 -m sifen_minisender "$@"
RUN
chmod +x "$DEST/run.sh"

# Comprimimos para scp
tar -C "$OUT" -czf "$OUT/bundle_$STAMP.tgz" "bundle_$STAMP"

echo
echo "OK:"
echo " - Bundle dir: $DEST"
echo " - Bundle tgz: $OUT/bundle_$STAMP.tgz"
