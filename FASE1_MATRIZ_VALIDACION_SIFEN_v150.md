# FASE 1 - Matriz de validacion estructural SIFEN v150

## Alcance y fuentes

Este documento consolida reglas estructurales para:

- Factura Electronica (`C002/iTiDE=1`)
- Nota de Remision Electronica (`C002/iTiDE=7`)
- Nota de Credito Electronica (`C002/iTiDE=5`) y nota de debito (`C002=6`) cuando aplique
- Autofactura Electronica (`C002/iTiDE=4`)

Fuentes usadas:

- XSD local de referencia:
  - `/Users/robinklaiss/Desktop/sifen-ec2-backup/sifen-minisender/schemas_sifen/DE_v150.xsd`
  - `/Users/robinklaiss/Desktop/sifen-ec2-backup/sifen-minisender/schemas_sifen/DE_Types_v150.xsd`
- Manual Tecnico oficial v150 (DNIT):
  - https://ekuatia.set.gov.py/documents/20123/420592/Manual%2BT%C3%A9cnico%2BVersi%C3%B3n%2B150.pdf/e706f7c7-6d93-21d4-b45b-5d22d07b2d22?t=1687351495907.pdf

## Reglas de trabajo / Gate de merges

• “Todo cambio debe pasar: docker compose build && docker compose up -d + smoke test de /invoices y un dry_run de emisión (sin enviar). Si falla localmente, no se puede mergear.”

- Para `iTiDE=7` (NRE), `gTransp` es obligatorio y no puede quedar vacio: debe contener como minimo `iModTrans` y los subgrupos/campos requeridos por XSD/manual segun la matriz (locales de salida/entrega, vehiculo y transportista cuando corresponda).
- Para `iTiDE=7` (NRE), `gTotSub` esta prohibido y no debe informarse.

## Hallazgo critico previo

Hay una divergencia de codificacion de tipo de DE:

- Manual v150: `C002` incluye `1..8` (con 2,3,8 marcados futuro).
- XSD local `DE_Types_v150.xsd` (`tiTiDE`) permite `1,4,5,6,7,9,10` y no incluye `2,3,8`.

Esto es un riesgo normativo/operativo y debe tratarse como bloqueo de definicion antes de endurecer validadores.

## Orden XML obligatorio (base comun)

Orden raiz `rDE` (manual + XSD):

1. `dVerFor`
2. `DE`
3. `ds:Signature`
4. `gCamFuFD`

Orden dentro de `DE` (`tDE`):

1. `dDVId`
2. `dFecFirma`
3. `dSisFact`
4. `gOpeDE`
5. `gTimb`
6. `gDatGralOpe`
7. `gDtipDE`
8. `gTotSub` (condicional por tipo)
9. `gCamGen` (opcional)
10. `gCamDEAsoc` (condicional por tipo)

Orden dentro de `gDtipDE`:

1. `gCamFE`
2. `gCamAE`
3. `gCamNCDE`
4. `gCamNRE`
5. `gCamCond`
6. `gCamItem`
7. `gCamEsp`
8. `gTransp`
9. `gCamRDE`

## Reglas numericas y matematicas transversales (base)

- `tdCantProSer`: hasta 10 enteros y 8 decimales.
- `tMontoBase`: hasta 15 enteros y 8 decimales.
- `tMontoBase4`: hasta 15 enteros y 4 decimales.
- `tPorcDesc8`: hasta 3 enteros y 8 decimales (max 100).
- `tdCRed` (`dRedon`): 4 decimales.
- Reglas de redondeo manual: multiples de 50 guaranies (o 50 centimos para calculos con decimales).
- Formula `E727`: `dTotBruOpeItem = E721 * E711`.
- Formula `EA008`:
  - General: `(E721 - EA002 - EA004 - EA006 - EA007) * E711`.
  - Autofactura: `E721 * E711`.
- Formula `E736`: `dLiqIVAItem = E735 * (E734/100)`.
- Formula `F014`: `dTotGralOpe = F008 - F013 + F025`.
- Formula `F017`: `dTotIVA = F015 + F016 - F036 - F037 + F026`.
- Formula `F020`: `dTBasGraIVA = F018 + F019`.
- Formula `F023`:
  - Si `D015 != PYG` y `D017=1`: `F014 * D018`.
  - Si `D015 != PYG` y `D017=2`: suma de `EA009`.

## Matriz por tipo - Factura Electronica (C002=1)

| Nodo | Obligatorio | Condicional | Orden requerido | Regla asociada | Validacion backend necesaria |
|---|---|---|---|---|---|
| `gCamFE (E010)` | Si | `C002=1` | En `gDtipDE` posicion 1 | Manual: obligatorio si `C002=1`; no informar si `!=1` | Rechazar FE sin `gCamFE` o con `gCamFE` fuera de orden |
| `gCamCond (E600)` | Si | Manual: solo `C002=1 o 4` | En `gDtipDE` antes de `gCamItem` | `E600` obligatorio para FE | Exigir `E601/E602`; validar consistencia contado/credito |
| `gPaConEIni (E605)` | Segun `E601` | Si `E601=1` | Dentro de `gCamCond` | Obligatorio contado | Si contado, exigir >=1 forma de pago |
| `gPagCred (E640)` | Segun `E601` | Si `E601=2` | Dentro de `gCamCond` | Obligatorio credito | Si credito, exigir bloque y validar `E641` plazo/cuota |
| `gCamItem (E700)` | Si | Siempre | En `gDtipDE` despues de `gCamCond` | `1..999` ocurrencias | Exigir al menos 1 item |
| `gValorItem (E720)` | Si | `C002!=7` | Dentro de item, antes de `gCamIVA` | Obligatorio FE | Validar formulas `E727`, `EA008`, `EA009` |
| `gCamIVA (E730)` | Si/No | Si `D013 in (1,3,4,5)` y `C002!=4,7` | Dentro de item | Regla IVA por afectacion | Validar formulas `E735/E736` y dominio de tasa |
| `gTransp (E900)` | No | Opcional si `C002=1` | En `gDtipDE` despues de `gCamEsp` | Manual transporte | Si existe, `E903/iModTrans` obligatorio |
| `gCamSal (E920)` | No | Opcional si `C002=1` | Dentro de `gTransp` | Local salida | Validar subcampos obligatorios del grupo cuando exista |
| `gTotSub (F001)` | Si | `C002!=7` | Despues de `gDtipDE` | Totales obligatorios FE | Validar formulas F y no permitir incoherencias |
| `dCarQR (J002)` | Si | Siempre | En `gCamFuFD` | Longitud 100..600 y algoritmo QR | Validar URL QR + hash + `&amp;` |

## Matriz por tipo - Nota de Remision Electronica (C002=7)

| Nodo | Obligatorio | Condicional | Orden requerido | Regla asociada | Validacion backend necesaria |
|---|---|---|---|---|---|
| `gCamNRE (E500)` | Si | `C002=7` | En `gDtipDE` posicion 4 | Obligatorio NRE | Rechazar NRE sin `gCamNRE` |
| `gCamCond (E600)` | No (prohibido) | Manual: solo `C002=1 o 4` | No debe aparecer | Regla tipo especifica | Bloquear NRE que incluya `gCamCond` |
| `gCamItem (E700)` | Si | Siempre | En `gDtipDE` | `1..999` | Exigir al menos 1 item |
| `gValorItem (E720)` | No (prohibido) | No informar si `C002=7` | No debe aparecer en item | Regla E720 | Bloquear `gValorItem` en NRE |
| `gCamIVA (E730)` | No (prohibido) | No informar si `C002=7` | No debe aparecer en item | Regla E730 | Bloquear IVA por item en NRE |
| `gTransp (E900)` | Si | `C002=7` | En `gDtipDE` despues de `gCamEsp` | Transporte obligatorio | Rechazar NRE sin `gTransp` |
| `iModTrans (E903)` | Si | Dentro de `gTransp` | Secuencia interna de `gTransp` | `1..4` modalidad | Rechazar `gTransp` sin `iModTrans` |
| `gCamSal (E920)` | Si | `C002=7` | Dentro de `gTransp` | Local salida obligatorio | Rechazar NRE sin local de salida |
| `gCamEnt (E940)` | Si | `C002=7` | Dentro de `gTransp` | Local entrega obligatorio | Exigir al menos una ocurrencia |
| `gVehTras (E960)` | Si | `C002=7` | Dentro de `gTransp` | Vehiculo obligatorio | Exigir al menos una ocurrencia |
| `gCamTrans (E980)` | Si (con excepcion puntual) | Obligatorio en 7; opcional si `E903=1` y `E967=1` | Dentro de `gTransp` | Transportista | Validar regla de excepcion |
| `gTotSub (F001)` | No (prohibido) | No informar si `C002=7` | No debe aparecer | Regla F001 | Bloquear NRE con `gTotSub` |
| `dInfoFisc (B006)` | Si | Cuando `C002=7` | Dentro de `gOpeDE` | Mensaje obligatorio segun RG 41/2014 | Validar presencia y no vacio |
| `dCarQR (J002)` | Si | Siempre | `gCamFuFD` | QR obligatorio | Validar URL/hash y coherencia campos |

## Matriz por tipo - Nota de Credito Electronica (C002=5)

| Nodo | Obligatorio | Condicional | Orden requerido | Regla asociada | Validacion backend necesaria |
|---|---|---|---|---|---|
| `gCamNCDE (E400)` | Si | `C002=5 o 6` | En `gDtipDE` posicion 3 | Bloque NC/ND | Rechazar NC sin `gCamNCDE` |
| `gCamCond (E600)` | No (prohibido) | Manual: solo `C002=1 o 4` | No debe aparecer | Regla E600 | Bloquear NC/ND con `gCamCond` |
| `gCamItem (E700)` | Si | Siempre | En `gDtipDE` | `1..999` | Exigir al menos 1 item |
| `gValorItem (E720)` | Si | `C002!=7` | Dentro de item | E720 obligatorio para NC | Validar formulas E7/E8 |
| `gCamIVA (E730)` | Si/No | Segun `D013` y `C002!=4,7` | Dentro de item | Reglas IVA | Validar E735/E736 y consistencia por tasa |
| `gTransp (E900)` | No (prohibido) | No informar si `C002=4,5,6` | No debe aparecer | Regla transporte | Bloquear transporte en NC |
| `gCamSal/gCamEnt` | No (prohibido) | No informar si `C002=4,5,6` | No deben aparecer | Regla locales | Bloquear si aparecen |
| `gTotSub (F001)` | Si | `C002!=7` | Despues de `gDtipDE` | Totales obligatorios | Validar formulas F |
| `gCamDEAsoc (H001)` | Si | Obligatorio si `C002=4,5,6` | Despues de `gCamGen` | Documento asociado obligatorio | Exigir al menos un documento asociado valido |
| `dCarQR (J002)` | Si | Siempre | `gCamFuFD` | QR obligatorio | Validar URL/hash/campos |

## Matriz por tipo - Autofactura Electronica (C002=4)

| Nodo | Obligatorio | Condicional | Orden requerido | Regla asociada | Validacion backend necesaria |
|---|---|---|---|---|---|
| `gCamAE (E300)` | Si | `C002=4` | En `gDtipDE` posicion 2 | Obligatorio AFE | Rechazar AFE sin `gCamAE` |
| `gCamCond (E600)` | Si | Manual: `C002=1 o 4` | En `gDtipDE` antes de `gCamItem` | Condicion operacion | Exigir bloque y reglas contado/credito |
| `gPagCred (E640)` | Segun `E601` | Si `E601=2` | Dentro de `gCamCond` | Operacion credito | Exigir subestructura credito |
| `gCamItem (E700)` | Si | Siempre | En `gDtipDE` | `1..999` | Exigir al menos 1 item |
| `gValorItem (E720)` | Si | `C002!=7` | Dentro de item | Obligatorio AFE | Validar formula especial EA008 para C002=4 |
| `gCamIVA (E730)` | No (prohibido) | No informar si `C002=4` | No debe aparecer | Regla E730 | Bloquear IVA por item en AFE |
| `gTransp (E900)` | No (prohibido) | No informar si `C002=4,5,6` | No debe aparecer | Regla transporte | Bloquear transporte en AFE |
| `gTotSub (F001)` | Si | `C002!=7` | Despues de `gDtipDE` | Totales con exclusiones para C002=4 | Bloquear campos F no permitidos para AFE (`F002,F003,F004,F005,F015,F016,F017,F018,F019,F020,F023,F025,F026`) |
| `gCamDEAsoc (H001)` | Si | Obligatorio si `C002=4,5,6` | Despues de `gCamGen` | Documento asociado obligatorio | Exigir al menos una referencia valida |
| `dCarQR (J002)` | Si | Siempre | `gCamFuFD` | QR obligatorio | Validar URL/hash/campos |

## Aclaracion critica sobre "Factura Credito (iTiDE=2)"

Con evidencia del MT v150:

- `C002=2` es "Factura electronica de exportacion (Futuro)", no "Factura a credito".
- La "Factura a credito" se modela con:
  - `C002=1` (Factura Electronica)
  - `E601/iCondOpe=2` (Credito) dentro de `gCamCond`.

En el XSD local actual, `tiTiDE` ni siquiera admite `2`. Por seguridad operativa, cualquier intento de emitir "iTiDE=2" debe bloquearse hasta definir politica normativa/tecnica.

## Checklist de validaciones backend que deben existir (resultado Fase 1)

- Validar orden exacto de nodos para `rDE`, `DE` y `gDtipDE`.
- Validar presencia/ausencia por tipo (`C002`) segun matriz.
- Validar cardinalidades reales (incluyendo minimas manuales aunque XSD tenga `minOccurs=0`).
- Validar dependencias condicionales:
  - `E601 -> E605/E640`
  - `E903 -> bloques de transporte`
  - `E711/E721/E727/EA008/E735/E736/F*`
- Validar coherencia matematica de totales/IVA/redondeo.
- Validar `dCarQR`:
  - formato URL y escape `&amp;`
  - consistencia con campos del XML
  - hash SHA-256 segun metodologia del MT
- Bloquear emision local si falla cualquier validacion estructural.
