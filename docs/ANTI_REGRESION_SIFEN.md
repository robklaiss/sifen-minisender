# Anti-regresión (SIFEN Minisender)

Este archivo registra “guardrails” (aprendizajes) para evitar romper cosas que ya funcionaban.

Reglas de oro:
- Cuando el XSD define `xs:sequence`, el **orden de los nodos importa**.
- Si se usa `_ensure_child_ns()` (que agrega al final), considerar **reordenar** explícitamente.
- Cada guardrail debe incluir: **síntoma**, **causa**, **fix**, **commit**, **smoke test**.

---

## Guardrail 2026-02-22 — Orden XSD en `gTotSub` (v150)

**Síntoma**
- Endpoint `POST /api/invoices/{id}/dry-run` fallaba XSD con:
  - `Element dBaseGrav5: This element is not expected. Expected is ( dTotalGs ).`

**Causa real**
- El template puede traer `dTBasGraIVA`, y luego el código crea `dBaseGrav5/dBaseGrav10` con `_ensure_child_ns()`.
- Eso deja `dBaseGrav*` **después** de `dTBasGraIVA`, violando el `xs:sequence` del `DE_v150.xsd` (tipo `tgTotSub`).
- En PYG además se elimina `dTotalGs`, pero el error real era el **orden**.

**Fix aplicado**
- Reordenar los hijos de `<gTotSub>` al final del armado para respetar el orden de `DE_v150.xsd tgTotSub`.
- Mantener nodos desconocidos “al final” si aparecen.
- Commit: `d0ad7b8` — Fix: enforce XSD order for gTotSub children (avoid dBaseGrav* after dTBasGraIVA)

**Smoke test**
- `POST /api/invoices/5/dry-run` → `HTTP 200`, `ok=true`, `xsd_ok=true`
- Artifacts: `/data/artifacts/webui_dryrun_5_20260222_201545`
