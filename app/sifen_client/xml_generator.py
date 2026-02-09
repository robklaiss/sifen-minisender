"""
Generador de XML para documentos electrónicos SIFEN

Este módulo genera XML válido según el esquema SIFEN.
TODO: Actualizar cuando se tenga el esquema XSD oficial completo.
"""
from lxml import etree
from typing import Dict, Any, Optional
from datetime import datetime
import xml.etree.ElementTree as ET
from xml.dom import minidom

# Importar generador v150
try:
    from .xml_generator_v150 import create_rde_xml_v150
except ImportError:
    create_rde_xml_v150 = None


def create_test_de_xml(
    ruc: str = "12345678901",
    timbrado: str = "12345678",
    csc: Optional[str] = None,
    razon_social: str = "Contribuyente de Prueba S.A.",
    tipo_documento: str = "1"  # 1 = Factura
) -> str:
    """
    Crea un XML de prueba básico para Documento Electrónico (DE) según estructura SIFEN
    
    Args:
        ruc: RUC del contribuyente
        timbrado: Número de timbrado
        csc: Código de Seguridad del Contribuyente (opcional)
        razon_social: Razón social del contribuyente
        tipo_documento: Tipo de documento (1=Factura, 2=Nota de Crédito, etc.)
        
    Returns:
        XML como string
    """
    # Namespace SIFEN (basado en estructura típica)
    # TODO: Confirmar namespace exacto desde documentación oficial
    ns = "http://ekuatia.set.gov.py/xsd"
    ns_map = {"": ns}
    
    # Crear raíz
    root = ET.Element("DE", xmlns=ns)
    
    # Datos Generales
    dg = ET.SubElement(root, "dg")
    ET.SubElement(dg, "dVer").text = "130"
    ET.SubElement(dg, "dFecEmi").text = datetime.now().strftime("%Y-%m-%d")
    ET.SubElement(dg, "dHorEmi").text = datetime.now().strftime("%H:%M:%S")
    ET.SubElement(dg, "dEst").text = "001"
    ET.SubElement(dg, "dPunExp").text = "001"
    ET.SubElement(dg, "dNumDoc").text = "0000001"
    ET.SubElement(dg, "dTipoDoc").text = tipo_documento
    ET.SubElement(dg, "dRucEm").text = ruc
    ET.SubElement(dg, "dDVEmi").text = "0"
    ET.SubElement(dg, "dRucRec").text = "80012345"
    ET.SubElement(dg, "dDVRec").text = "7"
    ET.SubElement(dg, "dRazSocRec").text = "Cliente de Prueba S.A."
    ET.SubElement(dg, "dDirRec").text = "Av. Principal 123, Asunción"
    ET.SubElement(dg, "dTipoEmi").text = "1"  # Normal
    ET.SubElement(dg, "dTipoTra").text = "1"  # Venta
    ET.SubElement(dg, "dTipoCon").text = "1"  # Contado
    ET.SubElement(dg, "dCondTi").text = "0"  # Sin condición
    
    # Datos del Emisor
    gOpeDE = ET.SubElement(root, "gOpeDE")
    ET.SubElement(gOpeDE, "iTipEmi").text = "1"
    ET.SubElement(gOpeDE, "dDesTipEmi").text = "Normal"
    
    # Timbrado
    gTimb = ET.SubElement(root, "gTimb")
    ET.SubElement(gTimb, "dNumTim").text = timbrado
    ET.SubElement(gTimb, "dEst").text = "001"
    ET.SubElement(gTimb, "dPunExp").text = "001"
    ET.SubElement(gTimb, "dNumDoc").text = "0000001"
    ET.SubElement(gTimb, "dSitRec").text = "1"
    
    if csc:
        ET.SubElement(gTimb, "dCodSeg").text = csc
    
    # Items del documento
    gCamGen = ET.SubElement(root, "gCamGen")
    gCamItem = ET.SubElement(gCamGen, "gCamItem")
    
    item1 = ET.SubElement(gCamItem, "dCodInt")
    item1.text = "001"
    ET.SubElement(gCamItem, "dParProd").text = "1"
    ET.SubElement(gCamItem, "dDesProSer").text = "Producto de Prueba"
    ET.SubElement(gCamItem, "dCantProSer").text = "1.00"
    ET.SubElement(gCamItem, "dUniMedProSer").text = "99"
    ET.SubElement(gCamItem, "dPreUniProSer").text = "100000"
    ET.SubElement(gCamItem, "dTotBruOpeItem").text = "100000"
    ET.SubElement(gCamItem, "dPreTotItem").text = "100000"
    ET.SubElement(gCamItem, "dDescItem").text = "0"
    ET.SubElement(gCamItem, "dTotOpeItem").text = "100000"
    ET.SubElement(gCamItem, "gValorItem").text = "1"
    ET.SubElement(gCamItem, "dPDesProSer").text = "0"
    
    # Totales
    gTotSub = ET.SubElement(root, "gTotSub")
    ET.SubElement(gTotSub, "dSubExe").text = "0"
    ET.SubElement(gTotSub, "dSubGra5").text = "0"
    ET.SubElement(gTotSub, "dSubGra10").text = "0"
    ET.SubElement(gTotSub, "dSubGraIVA5").text = "0"
    ET.SubElement(gTotSub, "dSubGraIVA10").text = "0"
    ET.SubElement(gTotSub, "dSubNoGra").text = "100000"
    ET.SubElement(gTotSub, "dSubExo").text = "0"
    ET.SubElement(gTotSub, "dTotOpe").text = "100000"
    ET.SubElement(gTotSub, "dTotDesc").text = "0"
    ET.SubElement(gTotSub, "dTotDescGlotem").text = "0"
    ET.SubElement(gTotSub, "dTotAntItem").text = "0"
    ET.SubElement(gTotSub, "dTotAnt").text = "0"
    ET.SubElement(gTotSub, "dTotGralOpe").text = "100000"
    ET.SubElement(gTotSub, "dIVA5").text = "0"
    ET.SubElement(gTotSub, "dIVA10").text = "0"
    ET.SubElement(gTotSub, "dIVA").text = "0"
    ET.SubElement(gTotSub, "dTotIVA").text = "0"
    ET.SubElement(gTotSub, "dBasGraIVA").text = "0"
    ET.SubElement(gTotSub, "dLiqTotOpe").text = "100000"
    
    # Convertir a string XML bien formateado
    xml_str = ET.tostring(root, encoding='utf-8', method='xml').decode('utf-8')
    
    # Asegurar encoding correcto
    xml_final = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str
    
    return xml_final


def create_minimal_test_xml(
    ruc: str = "12345678901",
    timbrado: str = "12345678",
    fecha: Optional[str] = None
) -> str:
    """
    Crea un XML mínimo de prueba (estructura básica)
    Útil para testing cuando no se tiene el esquema completo
    
    NOTA: Esta estructura es tentativa basada en patrones comunes de SIFEN.
    Requiere validación contra el esquema XSD oficial para asegurar validez completa.
    
    Args:
        ruc: RUC del contribuyente emisor
        timbrado: Número de timbrado
        fecha: Fecha de emisión (YYYY-MM-DD). Si es None, usa fecha actual
    """
    from datetime import datetime
    
    if fecha is None:
        fecha = datetime.now().strftime("%Y-%m-%d")
        hora = datetime.now().strftime("%H:%M:%S")
    else:
        hora = "10:00:00"
    
    # Namespace correcto según XSD oficial: http://ekuatia.set.gov.py/sifen/xsd
    # Estructura según XSD: rDE es el elemento raíz, que contiene DE
    # IMPORTANTE: Según el XSD, el elemento raíz debe ser rDE, no DE
    xml_minimal = f"""<?xml version="1.0" encoding="UTF-8"?>
<rDE xmlns="http://ekuatia.set.gov.py/sifen/xsd" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <dVerFor>150</dVerFor>
    <DE>
    <dg>
        <dVer>130</dVer>
        <dFecEmi>{fecha}</dFecEmi>
        <dHorEmi>{hora}</dHorEmi>
        <dEst>001</dEst>
        <dPunExp>001</dPunExp>
        <dNumDoc>0000001</dNumDoc>
        <dTipoDoc>1</dTipoDoc>
        <dRucEm>{ruc}</dRucEm>
        <dDVEmi>0</dDVEmi>
        <dRucRec>80012345</dRucRec>
        <dDVRec>7</dDVRec>
        <dRazSocRec>Cliente de Prueba</dRazSocRec>
        <dDirRec>Asunción</dDirRec>
        <dTipoEmi>1</dTipoEmi>
        <dTipoTra>1</dTipoTra>
        <dTipoCon>1</dTipoCon>
        <dCondTi>0</dCondTi>
    </dg>
    <gOpeDE>
        <iTipEmi>1</iTipEmi>
        <dDesTipEmi>Normal</dDesTipEmi>
    </gOpeDE>
    <gTimb>
        <dNumTim>{timbrado}</dNumTim>
        <dEst>001</dEst>
        <dPunExp>001</dPunExp>
        <dNumDoc>0000001</dNumDoc>
        <dSitRec>1</dSitRec>
    </gTimb>
    <gCamGen>
        <gCamItem>
            <dCodInt>001</dCodInt>
            <dParProd>1</dParProd>
            <dDesProSer>Producto de Prueba</dDesProSer>
            <dCantProSer>1.00</dCantProSer>
            <dUniMedProSer>99</dUniMedProSer>
            <dPreUniProSer>100000</dPreUniProSer>
            <dTotBruOpeItem>100000</dTotBruOpeItem>
            <dPreTotItem>100000</dPreTotItem>
            <dDescItem>0</dDescItem>
            <dTotOpeItem>100000</dTotOpeItem>
            <gValorItem>1</gValorItem>
            <dPDesProSer>0</dPDesProSer>
        </gCamItem>
    </gCamGen>
    <gTotSub>
        <dSubExe>0</dSubExe>
        <dSubGra5>0</dSubGra5>
        <dSubGra10>0</dSubGra10>
        <dSubGraIVA5>0</dSubGraIVA5>
        <dSubGraIVA10>0</dSubGraIVA10>
        <dSubNoGra>100000</dSubNoGra>
        <dSubExo>0</dSubExo>
        <dTotOpe>100000</dTotOpe>
        <dTotDesc>0</dTotDesc>
        <dTotDescGlotem>0</dTotDescGlotem>
        <dTotAntItem>0</dTotAntItem>
        <dTotAnt>0</dTotAnt>
        <dTotGralOpe>100000</dTotGralOpe>
        <dIVA5>0</dIVA5>
        <dIVA10>0</dIVA10>
        <dIVA>0</dIVA>
        <dTotIVA>0</dTotIVA>
        <dBasGraIVA>0</dBasGraIVA>
        <dLiqTotOpe>100000</dLiqTotOpe>
    </gTotSub>
    </DE>
    <!-- Firma digital opcional - omitida para pruebas -->
    <!-- <ds:Signature>...</ds:Signature> -->
    <gCamFuFD>
        <dCarQR>{{"cod": "12345678", "est": "001", "pnt": "001", "num": "0000001", "tipo": "1", "ruc": "12345678901", "dv": "0", "fecha": "20241226", "monto": "100000", "moneda": "PYG", "tasa": "0", "imp": "0", "test": "TESTQRCODE123456789012345678901234567890123456789012345678901234567890"}}</dCarQR>
    </gCamFuFD>
</rDE>"""
    
    return xml_minimal

