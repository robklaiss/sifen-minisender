# TODO SIFEN Minisender (Backlog)

## Prioridad alta
- [ ] Cancelación (evento): dejar **smoketest reproducible** (script) que:
  - emita iTiDE=1 en TEST (si aplica), espere confirmación OK,
  - ejecute cancel con motivo válido,
  - guarde artifacts y reporte dCodRes/dMsgRes.
- [ ] Alinear “evento cancel” con WSDL real:
  - action/endpoint/binding correctos (SOAP 1.2),
  - headers correctos (Content-Type action si aplica),
  - validar que el request cumple esquema evento v150.
- [ ] Definir soporte por iTiDE:
  - Factura iTiDE=1: cancelación (evento) ✅/⏳
  - NDE/Nota de Remisión iTiDE=7: (confirmar) ¿tiene evento? (si no, documentar)
  - Nota de Crédito: **no cancelación** → se revierte con otra NC (documentar flujo).

## Prioridad media
- [ ] Consolidar “anti-regression guardrails”:
  - No volver a CDATA en dEvReg si no corresponde.
  - Canonicalization exc-c14n para eventos si aplica.
- [ ] Mejorar logs y debug:
  - imprimir en artifacts: endpoint final, HTTP status, headers enviados, first 300 chars de body response.
- [ ] Documentar “Recv failure: Connection reset by peer” post-recreate (esperar /health antes de smoke).

## Prioridad baja
- [ ] Refactor: separar módulo eventos (builder + signer + sender) fuera de webui/app.py
