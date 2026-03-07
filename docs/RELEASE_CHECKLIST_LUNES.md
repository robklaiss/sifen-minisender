# Release checklist lunes

## Alcance congelado
- No agregar features nuevas
- No hacer refactors
- No tocar lógica común sin evidencia

## Tipos documentales
- iTiDE=1 FE: OK
- iTiDE=4 AFE: OK
- iTiDE=5 NC: OK
- iTiDE=7 Remisión: OK
- iTiDE=6 ND: NO habilitar hasta confirmar timbrado externo

## Guardrails obligatorios
- make predeploy-afe
- make predeploy-nc

## Validación manual previa
- Emitir FE y confirmar 0260
- Emitir AFE y confirmar 0260
- Emitir NC sobre FE válida y confirmar 0260

## Backups antes de deploy
- backup DB
- backup artifacts
- commit/tag identificable

## Regla de deploy
- Si falla un predeploy, no se deploya
- Si aparece error nuevo SIFEN, no improvisar; documentar primero
