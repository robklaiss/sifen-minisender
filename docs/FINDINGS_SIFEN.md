# FINDINGS SIFEN Minisender (Hechos comprobados)

> Regla: acá solo entra lo que **ya se probó** y tiene evidencia (artifact, log, commit, etc.).
> Si es hipótesis, va al TODO.

## 1) Evento cancel (Factura iTiDE=1) — Problema 0160 “XML Mal Formado”
**Síntoma:** SIFEN responde `dCodRes=0160` “XML Mal Formado” al enviar cancelación.

**Evidencia:**
- Respuesta típica:
  - `dCodRes=0160`
  - `dMsgRes=XML Mal Formado.`
  - `http=400`
- Se guardan artifacts en `data/artifacts/event_cancel_YYYYMMDD_HHMMSS/`

**Variables que ya tocamos/probamos en el camino:**
- `dEvReg` enviado como XML “hijo” vs CDATA:
  - CDATA no garantizó éxito.
  - XML hijo no garantizó éxito.
  - Conclusión: el 0160 no era solo por CDATA.
- Canonicalization en firma de evento:
  - Se cambió a `xml-exc-c14n` para eventos.
  - Commit relacionado: `fix(sifen): sign event XML with exc-c14n canonicalization (avoid 0160)`.

**Estado actual:** aún devuelve 0160 en TEST. Falta alinear request con WSDL/binding exactos.

## 2) Hecho operativo: “Recv failure: Connection reset by peer” tras `docker compose up --force-recreate`
**Causa probable:** el container reinicia y el socket se corta durante el curl inmediato.
**Mitigación comprobada:** siempre esperar `GET /health` con retry antes de cualquier smoke POST.

## 3) Reglas de negocio — Nota de Crédito
**Hecho:** Nota de Crédito no “tiene cancelación” como evento de anulación de factura.
**Acción correcta:** se corrige/revierte emitiendo otra Nota de Crédito (según normativa/escenario).

