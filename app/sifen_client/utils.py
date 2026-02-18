"""
Utilidades para SIFEN
"""
from typing import Optional
from pathlib import Path


def validate_certificate_path(cert_path: Path) -> bool:
    """
    Valida que el certificado existe y es accesible
    
    Args:
        cert_path: Ruta al certificado
        
    Returns:
        True si es válido
    """
    if not cert_path.exists():
        return False
    
    # Verificar que sea un archivo (no directorio)
    if not cert_path.is_file():
        return False
    
    # Verificar extensión común de certificados
    valid_extensions = ['.p12', '.pfx', '.pem', '.crt', '.cer']
    if cert_path.suffix.lower() not in valid_extensions:
        # No es un error crítico, pero puede ser una advertencia
        pass
    
    return True


def format_xml_prettily(xml_content: str) -> str:
    """
    Formatea XML de manera legible (indentado)
    
    Args:
        xml_content: XML sin formato
        
    Returns:
        XML formateado
    """
    try:
        import xml.dom.minidom
        dom = xml.dom.minidom.parseString(xml_content)
        return dom.toprettyxml(indent="  ")
    except:
        return xml_content

