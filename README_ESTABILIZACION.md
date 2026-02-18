# Cómo Correr (Estabilización SIFEN)

## LOCAL (Mac)

```bash
cd "/Users/robinklaiss/Dev/sifen-minisender-2"
.venv/bin/python -m pytest -q tests/test_template_build_regressions.py tests/test_artifacts_paths.py
.venv/bin/python tools/smoke.py --env test
```

Si querés tolerar errores de red/SIFEN y solo validar generación + artifacts:

```bash
cd "/Users/robinklaiss/Dev/sifen-minisender-2"
.venv/bin/python tools/smoke.py --env test --allow-send-failures
```

Artifacts de la corrida:

```bash
ls -1dt artifacts/run_*_smoke | head -n 1
```

Cada tipo (`factura`, `remision`, `credito`) deja:
- `de.xml`
- `soap_last_request.xml`
- `soap_last_response.xml`
- `sifen_response.json`

## SERVIDOR (EC2)

```bash
cd "/home/ubuntu/sifen-minisender-2"
source .venv/bin/activate
python -m pytest -q tests/test_template_build_regressions.py tests/test_artifacts_paths.py
python tools/smoke.py --env test
```

## Inputs Requeridos (Nota de Crédito real)

Para operación real de Nota de Crédito, completar `cdcAsociado` en:

- `tools/smoke_inputs.example.json` -> `docs.credito.extra_json.documentoAsociado.cdcAsociado`

Ejecutar con inputs explícitos:

```bash
cd "/Users/robinklaiss/Dev/sifen-minisender-2"
.venv/bin/python tools/smoke.py --env test --inputs-json tools/smoke_inputs.example.json
```
