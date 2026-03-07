# 🚨 INVARIANTES CRÍTICOS (NO ROMPER)

Estas reglas son obligatorias. Si se toca algo relacionado, SIEMPRE correr smoke tests.

1. Orden XSD SIEMPRE se respeta.
   - Todo `xs:sequence` implica orden obligatorio.
   - Si se usa `_ensure_child_ns()`, luego evaluar reordenamiento manual.

2. Nunca modificar `gTotSub` sin validar contra `DE_v150.xsd (tgTotSub)`.

3. Siempre correr antes de commit:
   - POST /api/invoices/{id}/dry-run
   - Verificar: HTTP 200 + xsd_ok=true

4. Nunca tocar generación de CDC sin:
   - Comparar longitud exacta.
   - Validar DV.
   - Confirmar QR consistente.

5. Si algo rompe XSD:
   - Revisar ORDEN antes de revisar valores.

---

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

---

## Evento Cancelación (iTiDE=1)

### Guardrail 2026-03-01 — Cancelación de eventos (estructura + iTiDE=1)
- Síntoma: 0160 XML Mal Formado al cancelar
- Causa: firmar rEnviEventoDe completo / Signature mal ubicada / CDC incorrecto
- Reglas:
  1) Firmar gGroupGesEve
  2) Signature hermana de rEve
  3) CDC 44 chars
  4) Solo iTiDE=1
  5) Endpoint PROD usa .wsdl
- Señal de éxito: dCodRes=0600 + dEstRes=Aprobado + dProtAut presente

## Evento Cancelación

### Guardrail 2026-03-01 — Cancelación eventos (0160 → 0600 Aprobado)

**Síntoma**
- `dCodRes=0160` “XML Mal Formado” al enviar eventos de cancelación.

**Causa real**
- Se firmaba y enviaba el `rEnviEventoDe` completo dentro del SOAP.
- SIFEN exige **firmar** el `gGroupGesEve/rGesEve` y que la `Signature` sea **hermana** de `rEve`.

**Reglas obligatorias**
1. Firmar `gGroupGesEve` (no `rEnviEventoDe`).
2. `Signature` como hermano de `rEve` dentro de `rGesEve`.
3. CDC con **44 caracteres exactos**.
4. `rEve@Id` numérico y consistente con `Reference URI="#<Id>"` (Id derivado de `DID`).
5. Endpoint de eventos: PROD usa `.wsdl` (TEST usa `/evento`).

**Señal de éxito**
- `dEstRes=Aprobado`, `dCodRes=0600`, `dMsgRes=Evento registrado correctamente`, `dProtAut` presente.

- [ ] Regla: en eventos (cancelación/inutilización/etc) el XML **a firmar** debe ser `gGroupGesEve` y **no** `rEnviEventoDe`.
  - **Síntoma**: `0160 XML Mal Formado` en POST de eventos aunque XSD/firma parezcan correctos.
  - **Causa**: se firmó/envió como raíz el `rEnviEventoDe` dentro del SOAP.
  - **Fix**: firmar `gGroupGesEve` y dejar que el SOAP envuelva con `rEnviEventoDe` por fuera.
  - **Guardrail automático**: abortar si el XML firmado tiene raíz `rEnviEventoDe` o si `Signature` no es hermano de `rEve`.
  - **Ejemplo**:

    ```xml
    <gGroupGesEve xmlns="http://ekuatia.set.gov.py/sifen/xsd">
      <rGesEve>
        <rEve Id="1234567890">...</rEve>
        <ds:Signature>...</ds:Signature>
      </rGesEve>
    </gGroupGesEve>
    ```

- [ ] Regla: `rEve@Id` debe ser **numérico** y consistente con `Reference URI="#<Id>"`.
  - **Síntoma**: rechazo remoto o referencia inválida aun con firma local OK.
  - **Causa**: `Id` no numérico o desalineado con la referencia.
  - **Fix**: derivar `Id` numérico y asegurar el mismo valor en `Reference URI`.
  - **Guardrail automático**: validar `rEve@Id` con regex `^[0-9]+$` y coincidencia exacta con `Reference URI`.
  - **Ejemplo**:

    ```xml
    <rEve Id="1234567890">...</rEve>
    <Reference URI="#1234567890">...</Reference>
    ```

- [ ] Regla: `<rGeVeCan><Id>` debe ser el CDC completo de **exactamente 44 caracteres**.
  - **Síntoma**: SIFEN responde `dCodRes=0160` “XML Mal Formado” aunque XSD/firma parezcan correctos.
  - **Causa**: se envía un CDC truncado o incompleto en el `Id` de cancelación.
  - **Fix**: validar longitud 44 antes de construir/enviar el XML.
  - **Guardrail automático**: abortar el envío si `${#CDC} != 44` en el script de cancelación.
  - **Ejemplo**:

    ```xml
    <rGeVeCan>
      <Id>01234567890123456789012345678901234567890123</Id>
    </rGeVeCan>
    ```

- [ ] Regla: `dFecFirma` debe ir como `YYYY-MM-DDThh:mm:ss` **sin timezone/offset**.
  - **Síntoma**: falla validación XSD local o rechazo remoto.
  - **Causa**: timestamp con `-03:00` u otro offset.
  - **Fix**: generar la fecha de firma sin sufijo de zona horaria.
  - **Guardrail automático**: validar que `dFecFirma` no contenga `Z` ni `+/-HH:MM`.
  - **Ejemplo**:

    ```xml
    <dFecFirma>2026-03-01T10:20:30</dFecFirma>
    <!-- No usar: 2026-03-01T10:20:30-03:00 -->
    ```

- [ ] Regla: XMLDSig debe firmar sobre `rEve` (atributo `Id`) con `Reference URI="#<Id>"`.
  - **Síntoma**: firma “ok” localmente pero rechazo remoto o error de referencia.
  - **Causa**: referencia al nodo equivocado o uso de transform incorrecto.
  - **Fix**: `Reference URI` al `Id` de `rEve`, canonicalización `exc-c14n`, firma `RSA-SHA256`.
  - **Guardrail automático**: verificación local con `xmlsec1` antes de enviar.
  - **Ejemplo**:

    ```xml
    <rEve Id="ID123">
      ...
    </rEve>
    <Reference URI="#ID123">
      <Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
    </Reference>
    ```

    ```bash
    xmlsec1 --verify --id-attr:Id rEve \
      --trusted-pem certs/root.pem --untrusted-pem certs/issuer.pem \
      tmp/signed.xml
    ```

  - **Nota**: si `Signature` está **fuera** de `rEve` (detached), **no** usar transform `enveloped-signature`.

## Firma/Cert Chain

- [ ] Regla: la cadena de certificados debe incluir issuer y root (no solo leaf).
  - **Síntoma**: `xmlsec1` falla con “unable to get local issuer certificate”.
  - **Causa**: PEM con solo el certificado leaf.
  - **Fix**: obtener `issuer` y `root`, y verificar cadena.
  - **Guardrail automático**: si `xmlsec1` falla por issuer, reintentar agregando `--untrusted-pem` y `--trusted-pem`.
  - **Ejemplo**:

    ```bash
    openssl verify -CAfile certs/root.pem \
      -untrusted certs/issuer.pem certs/leaf.pem
    ```

## Transporte/Gateway

- [ ] Regla: `X-Backside-Transport: FAIL FAIL` indica problema de gateway/backside routing.
  - **Síntoma**: `HTTP 400` + `Content-Type: text/html` + `FAIL FAIL` aun con XML validado y firma verificada.
  - **Causa**: ruta/ACL/policy de gateway bloqueando el POST.
  - **Fix**: confirmar endpoint/ruta habilitada para POST antes de seguir “adivinando XML”.
  - **Guardrail automático**: si el header contiene `FAIL FAIL`, abortar y pedir verificación de ruta/policies.
  - **Ejemplo**:

    ```bash
    curl -i -X POST "$ENDPOINT" --data @tmp/signed.xml \
      -H "Content-Type: text/xml"
    ```

- [ ] Regla: WSDL accesible no implica POST habilitado.
  - **Síntoma**: `GET` WSDL responde `200` con `X-Backside-Transport: OK OK`, pero `POST` devuelve `FAIL FAIL`.
  - **Causa**: políticas del gateway permiten WSDL pero bloquean POST.
  - **Fix**: coordinar con infra/soporte para habilitar POST o usar endpoint alternativo.
  - **Guardrail automático**: preflight que compara `GET` WSDL y `POST` al endpoint; si divergen, detener.
  - **Ejemplo**:

    ```bash
    curl -I "$WSDL_URL" | rg "Backside-Transport"
    curl -i -X POST "$ENDPOINT" --data @tmp/signed.xml
    ```

## Debug/Operación

- [ ] Regla: no pegar bloques largos en la terminal.
  - **Síntoma**: fragmentos inyectados/rotos que dañan scripts/heredocs.
  - **Causa**: pegado masivo en terminal interactiva.

---

## Guardrail 2026-03-01 — UI requiere `/api/invoices` y `/api/customers`

**Síntoma**
- La UI muestra “no hay facturas / no hay clientes” aunque la DB SQLite tiene datos.
- `GET /api/invoices` o `GET /api/customers` devolvía `404`.

**Causa real**
- Faltaban los endpoints REST de listado que el frontend consume.

**Fix aplicado**
- Agregar `GET /api/invoices` y `GET /api/customers` en `webui/app.py`.
- Respuesta JSON con campos mínimos y tolerancia a columnas faltantes.

**Smoke test**
- `curl -fsS http://127.0.0.1:8000/api/invoices | head`
- `curl -fsS http://127.0.0.1:8000/api/customers | head`
- Abrir `/invoices` y confirmar que aparecen registros.

---

## Guardrail 2026-03-01 — SQLite WAL/PRAGMA no debe crashar WebUI

**Síntoma**
- `sqlite3.OperationalError: database is locked`
- `AttributeError: db`

**Causa real**
- PRAGMA `journal_mode=WAL` se ejecuta durante arranque con DB bloqueada y `g.db` no quedó seteado.

**Fix aplicado**
- `PRAGMA busy_timeout = 10000` antes de WAL.
- `PRAGMA journal_mode = WAL` tolerante (try/except).
- `g.db` seteado inmediatamente tras abrir conexión.

**Señal de éxito**
- `curl -fsS http://127.0.0.1:8000/invoices | head`
- `curl -fsS http://127.0.0.1:8000/api/invoices | head`
- Logs sin “database is locked” ni “AttributeError: db”.
  - **Fix**: crear scripts en `scripts/` y ejecutarlos.
  - **Guardrail automático**: usar creación de script con heredoc corto y ejecutar con `bash`.
  - **Ejemplo**:

    ```bash
    cat > scripts/cancel_send.sh <<'SH'
    set -euo pipefail
    bash scripts/build_cancel_xml.sh
    bash scripts/post_cancel.sh
    SH
    bash scripts/cancel_send.sh
    ```

- [ ] Regla: trazas HTTP deterministas con `curl`.
  - **Síntoma**: difícil reproducir errores o comparar requests.
  - **Causa**: falta de headers y trace guardados.
  - **Fix**: usar `--dump-header` y `--trace-ascii` en `tmp/` (relativo al repo).
  - **Guardrail automático**: en scripts de envío, siempre registrar headers/trace cuando `DEBUG=1`.
  - **Ejemplo**:

    ```bash
    mkdir -p tmp
    curl -sS -X POST "$ENDPOINT" --data @tmp/signed.xml \
      --dump-header tmp/headers.txt --trace-ascii tmp/trace.txt
    ```

- [ ] Regla: primero DEV/TEST, luego PROD.
  - **Síntoma**: pruebas repetidas en PROD y ruido operativo.
  - **Causa**: falta de separación clara de entornos.
  - **Fix**: validar cambios en DEV/TEST antes de tocar PROD.
  - **Guardrail automático**: requerir flag explícito `--prod` y mostrar warning si no está.
  - **Ejemplo**:

    ```bash
    if [ "${ENV}" = "prod" ] && [ "${ALLOW_PROD:-}" != "1" ]; then
      echo "Refuse: set ALLOW_PROD=1"; exit 1
    fi
    ```

### Checklist antes de enviar cancelación (máx 10)

- [ ] XML firmado tiene raíz `gGroupGesEve` (no `rEnviEventoDe`).
- [ ] `Signature` es hermano de `rEve` dentro de `rGesEve`.
- [ ] `rEve@Id` numérico y coincide con `Reference URI`.
- [ ] `CDC` tiene 44 caracteres exactos.
- [ ] `dFecFirma` sin timezone/offset.
- [ ] `Reference URI` apunta al `Id` de `rEve`.
- [ ] Canonicalización `exc-c14n` y firma `RSA-SHA256`.
- [ ] Verificación `xmlsec1` OK con `root/issuer`.
- [ ] Cadena de certs verificada con `openssl verify`.
- [ ] `X-Backside-Transport` no indica `FAIL FAIL`.
- [ ] Endpoint POST validado (WSDL OK no basta).
- [ ] Envío con `curl` guardando headers/trace en `tmp/`.
- [ ] Pruebas en DEV/TEST completadas antes de PROD.

## AFE / Autofactura - cadena de fixes que no debe romperse

### Caso real validado
- Documento AFE aprobado en SIFEN:
  - invoice id: `39`
  - doc_number: `0000010`
  - código SIFEN: `0260`
  - resultado: `Aprobado`

### Reglas anti-regresion confirmadas para `iTiDE=4`
1. En `gDtipDE`, el orden correcto es:
   - `gCamAE`
   - `gCamCond`
   - `gCamItem`

2. En AFE, `gDatRec` debe quedar sincronizado con emisor asi:
   - `dRucRec = dRucEm`
   - `dDVRec = dDVEmi`
   - `iNatRec = 1`
   - `iTiOpe = 2`
   - `iTiContRec = iTipCont` del emisor

3. En AFE, `gCamItem`:
   - debe conservar `gValorItem`
   - no debe incluir `gCamIVA`

4. En AFE, `gCamDEAsoc`:
   - `iTipDocAso = 3`
   - `dDesTipDocAso = Constancia Electronica`
   - `iTipCons` obligatorio
   - `dDesTipCons` obligatorio
   - default actual valido:
     - `iTipCons = 1`
     - `dDesTipCons = Constancia de no ser contribuyente`

### Errores historicos y causa raiz
- `0160`: orden XSD incorrecto de `gCamAE`
- `1316`: `gDatRec/iTiOpe` incompatible para AFE
- `1901`: `gCamIVA` informado en AFE
- `2426`: faltaba `iTipCons/dDesTipCons`

### Tests que deben seguir pasando
- `tests/test_autofactura_master_smoke.py`
- `tests/test_autofactura_flow.py`
- `tests/test_template_build_regressions.py::test_autofactura_orders_gcamae_before_cond_and_items_and_keeps_geo_codes`
- `tests/test_dry_run_xsd_gate.py::test_validate_de_xml_against_xsd_accepts_autofactura_signed_qr`
- `tests/test_dry_run_xsd_gate.py::test_smoke_dry_run_afe_includes_distrito`

### Smoke maestro local
- Test maestro: `tests/test_autofactura_master_smoke.py::test_afe_master_smoke_covers_historical_regressions`
- Cubre en un solo XML AFE:
- orden `gCamAE < gCamCond < gCamItem` (`0160`)
- `gDatRec/iNatRec = 1`
- `gDatRec/iTiOpe = 2` (`1316`)
- `gDatRec/iTiContRec = gEmis/iTipCont`
- `gCamItem` conserva `gValorItem`
- `gCamItem` no incluye `gCamIVA` (`1901`)
- `gCamDEAsoc/iTipDocAso = 3`
- `gCamDEAsoc/iTipCons` presente
- `gCamDEAsoc/dDesTipCons` presente (`2426`)
- XSD OK sobre XML firmado + QR

### Comando único de predeploy
```bash
make predeploy-afe
```

Comando exacto que ejecuta ese target:
```bash
./.venv/bin/pytest -q \
  tests/test_autofactura_master_smoke.py \
  tests/test_autofactura_flow.py \
  tests/test_template_build_regressions.py::test_autofactura_orders_gcamae_before_cond_and_items_and_keeps_geo_codes \
  tests/test_dry_run_xsd_gate.py::test_validate_de_xml_against_xsd_accepts_autofactura_signed_qr \
  tests/test_dry_run_xsd_gate.py::test_smoke_dry_run_afe_includes_distrito
```

## NC / Nota de crédito - validación de cierre

### Caso real validado
- Documento NC aprobado en SIFEN:
  - invoice id: `43`
  - doc_number: `0000003`
  - código SIFEN: `0260`
  - resultado: `Aprobado`

### Reglas anti-regresion confirmadas para `iTiDE=5/6`
1. En `gDatGralOpe/gOpeCom`:
   - no informar `iTipTra`
   - no informar `dDesTipTra`

2. Mantener en `gDatGralOpe/gOpeCom`:
   - `iTImp`
   - moneda
   - resto del bloque aplicable

### Observación operativa
- Si aparece `1309` (`DV del RUC incorrecto`), revisar primero el cliente cargado.
- No confundir error de datos del receptor con error del builder XML.

### Caso real de datos
- `Cliente Demo S.A. — 80012345-6` produjo rechazo `1309`
- `Robin Klaiss — 7524653-8` produjo aprobación `0260`

### Tests que deben seguir pasando
- `tests/test_template_build_regressions.py::test_nc_nd_remove_tiptra_from_gopecom`
- `tests/test_xml_generator_v150_regressions.py::test_create_rde_xml_v150_omits_tiptra_for_nc_nd`

### Smoke maestro local
- Test maestro: `tests/test_nota_credito_master_smoke.py::test_nc_master_smoke_covers_historical_regressions`
- Cubre en un solo XML NC:
- `gDatGralOpe/gOpeCom` sin `iTipTra`
- `gDatGralOpe/gOpeCom` sin `dDesTipTra`
- `gDtipDE/gCamNCDE/iMotEmi` presente
- `gCamDEAsoc/iTipDocAso = 1`
- `gCamDEAsoc/dCdCDERef` presente
- `gDtipDE/gCamCond` ausente
- `gDtipDE/gTransp` ausente
- XSD OK sobre XML firmado + QR

### Comando único de predeploy
```bash
make predeploy-nc
```

Comando exacto que ejecuta ese target:
```bash
./.venv/bin/pytest -q \
  tests/test_nota_credito_master_smoke.py \
  tests/test_xml_generator_v150_regressions.py \
  tests/test_template_build_regressions.py::test_baseline_doc_types_keep_tiptra_in_gopecom
```

## Plantilla (copiar/pegar para un nuevo guardrail)

## Guardrail YYYY-MM-DD — Título corto (componente / norma / endpoint)

**ID**
- GR-YYYYMMDD-XX

**Síntoma**
- Qué falló (endpoint/comando) + mensaje exacto (1–3 líneas).

**Impacto**
- Ambiente: DEV | TEST | PROD
- Severidad: Baja | Media | Alta | Bloqueante

**Causa real**
- Qué lo provocó (archivo/función/orden XSD/etc.) y por qué.

**Fix aplicado**
- Qué se cambió (archivo/s) y enfoque.
- Commit: _____ — mensaje

**Smoke test (copy/paste)**

COMANDO:
    # comando exacto que valida que volvió a funcionar

**Evidencia / artifacts**
- Ruta(s): _____
- Logs clave: _____

**Anti-regresión**
- Qué NO tocar / invariantes.
- Si se vuelve a tocar: qué test correr SIEMPRE.


---

## Operativa

6. Antes de cualquier deploy:
   - Ejecutar: `./scripts/full_check.sh 5`
   - No desplegar si falla.
