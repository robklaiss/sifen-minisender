#!/usr/bin/env python3
"""
Sanitización final del XML antes de enviar a SIFEN.
Modo GUERRA 0160 - eliminar atributos prohibidos.
"""
import re
from pathlib import Path

def sanitize_lote_payload(xml_bytes: bytes) -> bytes:
    """
    Elimina atributos prohibidos del XML antes de enviar.
    - rDE no debe tener atributo Id
    - Elimina microsegundos de datetime
    """
    xml_str = xml_bytes.decode('utf-8')
    
    # 1. Eliminar atributo Id de rDE (namespace-agnostic)
    # <rDE Id="rDE_..."> -> <rDE>
    xml_str = re.sub(r'<rDE([^>]*)\bId="[^"]*"([^>]*)>', r'<rDE\1\2>', xml_str)
    
    # 2. Eliminar microsegundos de datetime
    # T..:..:..XXXXXX -> T..:..:..
    xml_str = re.sub(r'T(\d{2}:\d{2}:\d{2})\.\d+', r'T\1', xml_str)
    
    # 3. Verificar que no quede rDE con Id
    if re.search(r'<rDE[^>]*\bId=', xml_str):
        raise ValueError("No se pudo eliminar Id de rDE")
    
    # 4. Verificar que no queden microsegundos
    if re.search(r'T\d{2}:\d{2}:\d{2}\.\d+', xml_str):
        raise ValueError("No se pudieron eliminar microsegundos")
    
    return xml_str.encode('utf-8')

if __name__ == "__main__":
    # Test
    import sys
    if len(sys.argv) == 3:
        xml_file = sys.argv[1]
        out_file = sys.argv[2]
        
        with open(xml_file, 'rb') as f:
            xml_bytes = f.read()
        
        sanitized = sanitize_lote_payload(xml_bytes)
        
        with open(out_file, 'wb') as f:
            f.write(sanitized)
        
        print(f"Sanitizado: {xml_file} -> {out_file}")
        print(f"Size: {len(xml_bytes)} -> {len(sanitized)}")
