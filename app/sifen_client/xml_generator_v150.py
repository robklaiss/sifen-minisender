"""
Generador de XML para documentos electrónicos SIFEN v150

Estructura correcta según XSD v150
"""
from typing import Optional
from datetime import datetime
import hashlib
import base64


def generate_cdc(ruc: str, timbrado: str, establecimiento: str, punto_expedicion: str,
                 numero_documento: str, tipo_documento: str, fecha: str, monto: str, codseg: Optional[str] = None) -> str:
    """
    CDC numérico de 44 dígitos (43 + DV módulo 11).
    Conformación base (43):
      2  TipoDocumento
      8  RUC (sin DV, zero-left)
      1  DV RUC
      3  Establecimiento
      3  Punto expedición
      7  Número documento
      1  Tipo contribuyente
      8  Fecha (YYYYMMDD)
      1  Tipo emis   9  Código seguridad (dCodSeg)
    +  1  DV final (módulo 11 sobre los 43)
    """
    import os
    import re

    # 1) Tipo documento (2)
    tipo = str(tipo_documento or "").zfill(2)[:2]
    if not tipo.isdigit():
        raise ValueError(f"tipo_documento inválido: {tipo_documento!r}")

    # 2) RUC base (8) + DV (1)
    ruc_raw = str(ruc or "").strip()
    dv_ruc = None

    m = re.match(r"^\s*(\d+)-(\d)\s*$", ruc_raw)
    if m:
        ruc_num = m.group(1)
        dv_ruc = m.group(2)
    else:
        ruc_num = re.sub(r"\D", "", ruc_raw)

    if not dv_ruc:
        env = os.getenv("SIFEN_EMISOR_RUC", "").strip()
        m2 = re.match(r"^\s*(\d+)-(\d)\s*$", env)
        if m2:
            if not ruc_num:
                ruc_num = m2.group(1)
            dv_ruc = m2.group(2)

    if not ruc_num:
     raise ValueError("RUC vacío para generar CDC.")
    if not dv_ruc:
        raise ValueError("Falta DV del RUC. Seteá SIFEN_EMISOR_RUC='RUC-DV' (ej: 4554737-8).")

    ruc8 = str(ruc_num).zfill(8)[-8:]
    dv_ruc = str(dv_ruc).strip()[:1]
    if not (ruc8.isdigit() and dv_ruc.isdigit()):
        raise ValueError(f"RUC/DV inválidos: ruc8={ruc8!r} dv={dv_ruc!r}")

    # 3) Est / Punto / Número
    est = str(establecimiento or "").zfill(3)[-3:]
    pun = str(punto_expedicion or "").zfill(3)[-3:]
    num = str(numero_documento or "").zfill(7)[-7:]
    if not (est.isdigit() and pun.isdigit() and num.isdigit()):
        raise ValueError(f"est/pun/num inválidos: {est}-{pun}-{num}")

    # 4) Tipo contribuyente (1)
    tip_cont = os.getenv("SIFEN_TIP_CONT", "1").strip()[:1]
    if not tip_cont.isdigit():
        tip_cont = "1"

    # 5) Fecha YYYYMMDD (del ISO)
    fecha8 = re.sub(r"\D", "", str(fecha or ""))[:8]
    if len(fecha8) != 8 or (not fecha8.isdigit()):
        raise ValueError(f"Fecha inválida para CDC: {fecha!r} -> {fecha8!r}")

    # 6) Tipo emisión (1)
    tip_emi = os.getenv("SI_TIP_EMI", "1").strip()[:1]
    if not tip_emi.isdigit():
        tip_emi = "1"

    # 7) Código seguridad (9)
    codseg = (codseg or os.getenv("SIFEN_CODSEG", "123456789")).strip()
    if not re.fullmatch(r"\d{9}", codseg):
        raise ValueError("SIFEN_CODSEG debe ser 9 dígitos (ej: 123456789).")

    base43 = f"{tipo}{ruc8}{dv_ruc}{est}{pun}{num}{tip_cont}{fecha8}{tip_emi}{codseg}"
    if len(base43) != 43 or (not base43.isdigit()):
        raise ValueError(f"Base CDC inválida ({len(base43)}): {base43}")

    dv_id = str(calculate_digit_verifier(base43)).strip()[-1:]
    if not dv_id.isdigit():
        raise ValueError(f"DV inválido: {dv_id!r}")

    return base43 + dv_id


def calculate_digit_verifier(base43: str) -> str:
    """
    DV del CDC (módulo 11) sobre los 43 dígitos.

    Regla SIFEN:
      - pesos cíclicos 2..9 desde derecha a izquierda
      - dv = 11 - (suma % 11)
      - si dv == 11 => 0
      - si dv == 10 => 1
    """
    # Importar función reutilizable
    from app.sifen_client.cdc_utils import calc_dv_mod11
    
    s = "".join(c for c in str(base43) if c.isdigit())
    if len(s) != 43:
        raise ValueError(f"Base CDC inválida para DV (len={len(s)}): {s}")

    dv = calc_dv_mod11(s)
    return str(dv)


def create_rde_xml_v150(
    ruc: str = "80012345",
    timbrado: str = "12345678",
    establecimiento: str = "001",
    punto_expedicion: str = "001",
    numero_documento: str = "0000001",
    tipo_documento: str = "1",
    fecha: Optional[str] = None,
    hora: Optional[str] = None,
    csc: Optional[str] = None,
) -> str:
    """
    Crea un XML rDE según estructura XSD v150
    
    Args:
        ruc: RUC del contribuyente emisor
        timbrado: Número de timbrado
        establecimiento: Código de establecimiento
        punto_expedicion: Código de punto de expedición
        numero_documento: Número de documento
        tipo_documento: Tipo de documento (1=Factura)
        fecha: Fecha de emisión (YYYY-MM-DD)
        hora: Hora de emisión (HH:MM:SS)
        csc: Código de Seguridad del Contribuyente
        
    Returns:
        XML como string
    """
    if fecha is None:
        fecha = datetime.now().strftime("%Y-%m-%d")
    if hora is None:
        hora = datetime.now().strftime("%H:%M:%S")
    
    # Fecha formato SIFEN: YYYY-MM-DDTHH:MM:SS
    fecha_firma = f"{fecha}T{hora}"
    fecha_emision = fecha_firma
    
    # Monto para CDC (simplificado)
    monto = "100000"
    
    # Generar CDC (simplificado para pruebas)
    cdc = generate_cdc(ruc, timbrado, establecimiento, punto_expedicion, 
                      numero_documento, tipo_documento, fecha.replace("-", ""), monto)
    
    # Validación defensiva: asegurar que el CDC sea válido antes de usarlo
    from app.sifen_client.cdc_utils import validate_cdc, fix_cdc
    
    # Convertir a string si no lo es
    cdc = str(cdc).strip()
    
    # Validar longitud y formato
    if len(cdc) != 44:
        raise ValueError(
            f"CDC generado tiene longitud inválida: {len(cdc)} (esperado: 44). "
            f"CDC recibido: {cdc!r}"
        )
    
    # Validar que sea solo dígitos
    if not cdc.isdigit():
        raise ValueError(
            f"CDC generado contiene caracteres no numéricos: {cdc!r}. "
            f"El CDC debe ser exactamente 44 dígitos (0-9)."
        )
    
    # Validar DV
    es_valido, dv_orig, dv_calc = validate_cdc(cdc)
    if not es_valido:
        # Corregir automáticamente si el DV es incorrecto
        cdc = fix_cdc(cdc)
        # Re-validar después de corregir
        es_valido, _, _ = validate_cdc(cdc)
        if not es_valido:
            raise ValueError(
                f"CDC generado tiene DV inválido y no pudo corregirse. "
                f"CDC: {cdc!r}"
            )
    
    # Calcular dígito verificador (dv del CDC)
    # El dDVId es el último dígito del CDC (que ya está validado)
    dv_id = cdc[-1]
    
    # Código de seguridad (CSC) - debe ser entero de 9 dígitos según tiCodSe
    # Para pruebas: generar número de 9 dígitos
    if csc:
        # Asegurar que sea numérico de 9 dígitos
        cod_seg_digits = ''.join(c for c in str(csc) if c.isdigit())
        cod_seg = cod_seg_digits[:9].zfill(9) if cod_seg_digits else "123456789"
    else:
        cod_seg = "123456789"
    
    # RUC debe ser máximo 8 dígitos
    ruc_str = str(ruc or "")
    if not ruc_str or not ruc_str.strip():
        ruc_str = "80012345"
    ruc_clean = ruc_str[:8].zfill(8) if len(ruc_str) < 8 else ruc_str[:8]
    
    # Calcular DV del RUC (simplificado)
    # Asegurar que sea un dígito válido
    dv_ruc = "0"
    try:
        ruc_digits = ''.join(c for c in ruc_clean if c.isdigit())
        if ruc_digits:
            # Algoritmo simplificado para DV
            dv_ruc = str(sum(int(d) for d in ruc_digits) % 10)
    except:
        dv_ruc = "0"
    
    # Normalizar tipo de documento para evitar valores con cero a la izquierda (ej: "01")
    try:
        tipo_documento_norm = str(int(str(tipo_documento)))
    except Exception:
        tipo_documento_norm = str(tipo_documento)

    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<rDE xmlns="http://ekuatia.set.gov.py/sifen/xsd" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <dVerFor>150</dVerFor>
    <DE Id="{cdc}">
        <dDVId>{dv_id}</dDVId>
        <dFecFirma>{fecha_firma}</dFecFirma>
        <dSisFact>1</dSisFact>
        <gOpeDE>
            <iTipEmi>1</iTipEmi>
            <dDesTipEmi>Normal</dDesTipEmi>
            <dCodSeg>{cod_seg}</dCodSeg>
        </gOpeDE>
        <gTimb>
            <iTiDE>{tipo_documento_norm}</iTiDE>
            <dDesTiDE>Factura electrónica</dDesTiDE>
            <dNumTim>{timbrado}</dNumTim>
            <dEst>{establecimiento}</dEst>
            <dPunExp>{punto_expedicion}</dPunExp>
            <dNumDoc>{numero_documento}</dNumDoc>
            <dFeIniT>{fecha}</dFeIniT>
        </gTimb>
        <gDatGralOpe>
            <dFeEmiDE>{fecha_emision}</dFeEmiDE>
            <gOpeCom>
                <iTipTra>1</iTipTra>
                <dDesTipTra>Venta de mercadería</dDesTipTra>
                <iTImp>1</iTImp>
                <dDesTImp>IVA</dDesTImp>
                <cMoneOpe>PYG</cMoneOpe>
                <dDesMoneOpe>Guarani</dDesMoneOpe>
            </gOpeCom>
            <gEmis>
                <dRucEm>{ruc_clean}</dRucEm>
                <dDVEmi>{dv_ruc}</dDVEmi>
                <iTipCont>1</iTipCont>
                <dNomEmi>Contribuyente de Prueba S.A.</dNomEmi>
                <dDirEmi>Asunción</dDirEmi>
                <dNumCas>1234</dNumCas>
                <cDepEmi>1</cDepEmi>
                <dDesDepEmi>CAPITAL</dDesDepEmi>
                <cCiuEmi>1</cCiuEmi>
                <dDesCiuEmi>ASUNCION (DISTRITO)</dDesCiuEmi>
                <dTelEmi>021123456</dTelEmi>
                <dEmailE>test@example.com</dEmailE>
                <gActEco>
                    <cActEco>471100</cActEco>
                    <dDesActEco>Venta al por menor en comercios no especializados</dDesActEco>
                </gActEco>
            </gEmis>
            <gDatRec>
                <iNatRec>1</iNatRec>
                <iTiOpe>1</iTiOpe>
                <cPaisRec>PRY</cPaisRec>
                <dDesPaisRe>Paraguay</dDesPaisRe>
                <dRucRec>80012345</dRucRec>
                <dDVRec>7</dDVRec>
                <dNomRec>Cliente de Prueba</dNomRec>
                <dDirRec>Asunción</dDirRec>
                <dNumCasRec>5678</dNumCasRec>
                <cDepRec>1</cDepRec>
                <dDesDepRec>CAPITAL</dDesDepRec>
                <cCiuRec>1</cCiuRec>
                <dDesCiuRec>ASUNCION (DISTRITO)</dDesCiuRec>
            </gDatRec>
        </gDatGralOpe>
        <gDtipDE>
            <gCamItem>
                <dCodInt>001</dCodInt>
                <dDesProSer>Producto de Prueba</dDesProSer>
                <cUniMed>99</cUniMed>
                <dDesUniMed>UNI</dDesUniMed>
                <dCantProSer>1.00</dCantProSer>
                <gValorItem>
                    <dPUniProSer>100000</dPUniProSer>
                    <dTotBruOpeItem>100000</dTotBruOpeItem>
                    <gValorRestaItem>
                        <dTotOpeItem>100000</dTotOpeItem>
                    </gValorRestaItem>
                </gValorItem>
            </gCamItem>
        </gDtipDE>
        <gTotSub>
            <dSubExe>0</dSubExe>
            <dSubExo>0</dSubExo>
            <dSub5>0</dSub5>
            <dSub10>0</dSub10>
            <dTotOpe>100000</dTotOpe>
            <dTotDesc>0</dTotDesc>
            <dTotDescGlotem>0</dTotDescGlotem>
            <dTotAntItem>0</dTotAntItem>
            <dTotAnt>0</dTotAnt>
            <dPorcDescTotal>0</dPorcDescTotal>
            <dDescTotal>0</dDescTotal>
            <dAnticipo>0</dAnticipo>
            <dRedon>0</dRedon>
            <dTotGralOpe>100000</dTotGralOpe>
            <dIVA5>0</dIVA5>
            <dIVA10>0</dIVA10>
            <dLiqTotIVA5>0</dLiqTotIVA5>
            <dLiqTotIVA10>0</dLiqTotIVA10>
            <dTotalGs>100000</dTotalGs>
        </gTotSub>
    </DE>
    <gCamFuFD>
        <dCarQR>TESTQRCODE12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890</dCarQR>
    </gCamFuFD>
</rDE>"""
    
    return xml
