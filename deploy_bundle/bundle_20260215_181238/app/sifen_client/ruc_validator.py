"""
Validador de RUC del emisor para evitar envíos con datos dummy

Doc SIFEN: El RUC del emisor debe ser el del contribuyente real habilitado.
No se permiten RUCs de prueba o dummy en producción.
"""
import os
import re
from typing import Optional, Tuple
from lxml import etree
from pathlib import Path

# RUCs dummy conocidos que deben ser rechazados
DUMMY_RUC_PATTERNS = [
    r"^80012345",  # RUC de prueba común
    r"^12345678",  # RUC de prueba común
    r"^123456789",  # RUC de prueba común
    r"^00000000",  # RUC vacío/cero
]

# RUC real del contribuyente (desde env o config)
EXPECTED_RUC = os.getenv("SIFEN_EMISOR_RUC") or os.getenv("SIFEN_TEST_RUC") or "4554737-8"


def extract_emisor_ruc_from_xml(xml_content: str) -> str:
    """
    Extrae el RUC del emisor con formato "RUC-DV" del XML.
    
    Busca en:
    - <dRucEm> dentro de <gEmis>
    - <dDVEmi> dentro de <gEmis>
    
    Args:
        xml_content: Contenido XML como string o bytes
        
    Returns:
        RUC con formato "RUC-DV" (ej: "4554737-8")
        
    Raises:
        ValueError: Si no se encuentra dRucEm o dDVEmi en el XML
    """
    try:
        # Aceptar string o bytes
        if isinstance(xml_content, bytes):
            xml_bytes = xml_content
        else:
            xml_bytes = xml_content.encode('utf-8')
        
        # Parsear XML
        root = etree.fromstring(xml_bytes)
        
        # Namespace SIFEN
        ns = {"sifen": "http://ekuatia.set.gov.py/sifen/xsd"}
        
        # Buscar dRucEm y dDVEmi
        # Puede estar en rEnviDe/xDE/DE/gDatGralOpe/gEmis o directamente en rDE/DE/gDatGralOpe/gEmis
        ruc_elem = None
        dv_elem = None
        
        # Intentar con namespace
        ruc_candidates = root.xpath(".//sifen:dRucEm", namespaces=ns)
        if not ruc_candidates:
            # Intentar sin namespace
            ruc_candidates = root.xpath(".//dRucEm")
        
        if ruc_candidates:
            ruc_elem = ruc_candidates[0]
        
        # Buscar dDVEmi
        dv_candidates = root.xpath(".//sifen:dDVEmi", namespaces=ns)
        if not dv_candidates:
            dv_candidates = root.xpath(".//dDVEmi")
        
        if dv_candidates:
            dv_elem = dv_candidates[0]
        
        if ruc_elem is None:
            raise ValueError("No se encontró <dRucEm> en el XML. El XML debe contener el RUC del emisor dentro de <gEmis>.")
        
        ruc = (ruc_elem.text or "").strip()
        if not ruc:
            raise ValueError("El elemento <dRucEm> está vacío en el XML.")
        
        dv = (dv_elem.text or "").strip() if dv_elem is not None else ""
        if not dv:
            raise ValueError("No se encontró <dDVEmi> o está vacío en el XML. El XML debe contener el dígito verificador del RUC del emisor.")
        
        # Retornar formato "RUC-DV"
        return f"{ruc}-{dv}"
        
    except ValueError:
        # Re-lanzar ValueError tal cual
        raise
    except Exception as e:
        # Otros errores de parseo
        raise ValueError(f"Error al parsear XML para extraer RUC del emisor: {e}")


def is_dummy_ruc(ruc: str) -> bool:
    """
    Verifica si un RUC es dummy/de prueba.
    
    Args:
        ruc: RUC a verificar (sin DV, solo números)
        
    Returns:
        True si es dummy, False si es válido
    """
    if not ruc or not ruc.strip():
        return True
    
    ruc_clean = ruc.strip()
    
    # Verificar contra patrones dummy
    for pattern in DUMMY_RUC_PATTERNS:
        if re.match(pattern, ruc_clean):
            return True
    
    return False


def validate_emisor_ruc(xml_content: str, expected_ruc: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Valida que el RUC del emisor en el XML no sea dummy y coincida con el esperado.
    
    Args:
        xml_content: Contenido XML como string o bytes
        expected_ruc: RUC esperado (formato: "4554737-8"). Si None, usa EXPECTED_RUC
        
    Returns:
        Tupla (is_valid, error_message)
        - is_valid: True si el RUC es válido, False si es dummy o no coincide
        - error_message: Mensaje de error si is_valid es False, None si es válido
    """
    if expected_ruc is None:
        expected_ruc = EXPECTED_RUC
    
    # Extraer RUC del XML (formato "RUC-DV")
    try:
        ruc_dv = extract_emisor_ruc_from_xml(xml_content)
    except ValueError as e:
        return (False, str(e))
    
    # Separar RUC y DV
    if '-' in ruc_dv:
        ruc_clean, dv = ruc_dv.split('-', 1)
        ruc_clean = ruc_clean.strip()
        dv = dv.strip()
    else:
        ruc_clean = ruc_dv.strip()
        dv = ""
    
    # Validar que no esté vacío
    if not ruc_clean:
        return (False, "El RUC del emisor está vacío en el XML. No se puede enviar con RUC vacío.")
    
    # Validar que no sea dummy
    if is_dummy_ruc(ruc_clean):
        return (False, f"El RUC del emisor '{ruc_clean}' es un RUC de prueba/dummy. SIFEN rechazará el documento con código 1264. Configure SIFEN_EMISOR_RUC con el RUC real del contribuyente habilitado (formato: RUC-DV, ej: 4554737-8).")
    
    # Si hay RUC esperado, comparar (formato "RUC-DV")
    if expected_ruc:
        # Normalizar expected_ruc: separar RUC y DV
        if '-' in expected_ruc:
            expected_ruc_clean, expected_dv = expected_ruc.split('-', 1)
            expected_ruc_clean = expected_ruc_clean.strip()
            expected_dv = expected_dv.strip()
        else:
            expected_ruc_clean = expected_ruc.strip()
            expected_dv = ""
        
        # Comparar RUC (sin DV)
        if expected_ruc_clean != ruc_clean:
            return (False, f"El RUC del emisor en el XML ('{ruc_clean}') no coincide con el RUC esperado ('{expected_ruc_clean}'). Verifique SIFEN_EMISOR_RUC (formato: RUC-DV, ej: 4554737-8).")
        
        # Si ambos tienen DV, comparar también el DV
        if expected_dv and dv and expected_dv != dv:
            return (False, f"El dígito verificador del RUC en el XML ('{dv}') no coincide con el esperado ('{expected_dv}'). Verifique SIFEN_EMISOR_RUC (formato: RUC-DV, ej: 4554737-8).")
    
    return (True, None)

