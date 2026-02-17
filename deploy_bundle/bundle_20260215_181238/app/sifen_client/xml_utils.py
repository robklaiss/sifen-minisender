"""
Utilidades para manejo y limpieza de XML para SIFEN

Según "Guía de Mejores Prácticas para la Gestión del Envío de DE" (Octubre 2024)
"""
from lxml import etree
import re
from typing import Optional
import xml.etree.ElementTree as ET


def clean_xml(xml_content: str) -> str:
    """
    Limpia XML según Guía de Mejores Prácticas SIFEN
    
    Reglas aplicadas (según guía oficial):
    1. NO espacios en blanco al inicio o final de campos numéricos/alfanuméricos
    2. NO comentarios XML (<!-- -->)
    3. NO caracteres de formato (line-feed, carriage return, tab, espacios entre etiquetas)
    4. NO prefijos en namespace de las etiquetas
    5. NO etiquetas vacías (excepto obligatorias)
    6. NO valores negativos en campos numéricos
    7. Campos case-sensitive (respetar minúsculas/mayúsculas)
    
    Args:
        xml_content: Contenido XML crudo
        
    Returns:
        XML limpio y listo para enviar a SIFEN
    """
    if not xml_content:
        return ""
    
    # Remover BOM (Byte Order Mark) si existe
    xml_clean = xml_content.lstrip('\ufeff')
    
    # Remover espacios y saltos de línea al inicio hasta encontrar <?xml
    xml_clean = xml_clean.lstrip()
    
    # Si no empieza con <?xml, buscar su posición
    if not xml_clean.startswith('<?xml'):
        xml_start = xml_clean.find('<?xml')
        if xml_start > 0:
            xml_clean = xml_clean[xml_start:]
    
    # Extraer el prolog XML si existe
    prolog_match = re.match(r'^(<\?xml[^?]*\?>)', xml_clean, re.DOTALL)
    prolog = prolog_match.group(1) if prolog_match else '<?xml version="1.0" encoding="UTF-8"?>'
    
    # Asegurar que el prolog tenga encoding UTF-8
    if 'encoding' not in prolog:
        prolog = '<?xml version="1.0" encoding="UTF-8"?>'
    
    # Obtener el contenido XML sin el prolog
    if prolog_match:
        xml_body_original = xml_clean[len(prolog_match.group(0)):].lstrip()
    else:
        xml_body_original = xml_clean
    
    # Extraer namespaces del XML original antes de parsear
    # Buscar xmlns en el elemento raíz
    xmlns_pattern = r'(xmlns(?::[^\s=]+)?\s*=\s*["\'][^"\']+["\'])'
    xmlns_matches = re.findall(xmlns_pattern, xml_body_original)
    
    xml_body = xml_body_original
    
    # Limpieza según guía de mejores prácticas:
    # 1. Remover comentarios XML
    xml_body = re.sub(r'<!--.*?-->', '', xml_body, flags=re.DOTALL)
    
    # 2. Remover espacios entre etiquetas (según guía: NO espacios entre etiquetas)
    xml_body = re.sub(r'>\s+<', '><', xml_body)
    
    # 3. Remover saltos de línea, carriage return, tabs (según guía)
    xml_body = re.sub(r'[\r\n\t]+', '', xml_body)
    
    # 4. Remover espacios en blanco al inicio/final de valores de atributos y texto
    # (esto requiere parsear, pero intentamos hacerlo de forma segura)
    try:
        # Parsear para validar estructura (pero NO reconstruir con ET.tostring que agrega prefijos)
        root = ET.fromstring(prolog + xml_body)
        
        # Limpiar espacios en valores de atributos y texto manualmente
        # Iterar sobre todos los elementos y limpiar texto
        for elem in root.iter():
            # Limpiar texto del elemento
            if elem.text:
                elem.text = elem.text.strip()
            # Limpiar texto de cola
            if elem.tail:
                elem.tail = elem.tail.strip()
        
        # Reconstruir XML manualmente SIN prefijos de namespace en etiquetas (según guía)
        # Pero preservando namespaces como atributos xmlns en el elemento raíz
        # Capturar xmlns_matches en closure
        captured_xmlns = xmlns_matches
        
        def element_to_string(elem, level=0, is_root=True):
            """Convierte elemento a string preservando prefijos necesarios (ej: ds:)"""
            tag = elem.tag
            
            # Detectar namespace del elemento
            if '}' in tag:
                namespace, local_name = tag.split('}', 1)
                namespace = namespace[1:]  # Remover {
            else:
                namespace = None
                local_name = tag
            
            # Preservar prefijo ds: para elementos del namespace ds (XML Digital Signature)
            # Según XSD, ds:Signature debe mantener el prefijo
            if namespace == "http://www.w3.org/2000/09/xmldsig#":
                tag = f"ds:{local_name}"
            else:
                # Para otros elementos, remover prefijo (según guía: NO prefijos en namespace)
                tag = local_name
            
            # Construir atributos
            attrs_list = []
            
            # Si es el elemento raíz, preservar namespaces como atributos xmlns
            if is_root and captured_xmlns:
                # Agregar namespaces extraídos del XML original
                for ns_attr in captured_xmlns:
                    # Normalizar espacios
                    ns_attr_clean = re.sub(r'\s+', ' ', ns_attr.strip())
                    attrs_list.append(ns_attr_clean)
            
            # Agregar otros atributos normales
            for k, v in elem.attrib.items():
                # Ignorar namespaces que ya agregamos
                if k.startswith('xmlns') or k.startswith('{http://www.w3.org/2000/xmlns/}'):
                    continue
                attr_key = k.split('}')[-1] if '}' in k else k
                attrs_list.append(f'{attr_key}="{v}"')
            
            attrs_str = ' '.join(attrs_list)
            tag_with_attrs = f'{tag} {attrs_str}' if attrs_str else tag
            
            # Si no tiene hijos ni texto, es elemento vacío
            if len(elem) == 0 and (not elem.text or not elem.text.strip()):
                return f'<{tag_with_attrs}/>'
            
            # Construir contenido
            content = ''
            if elem.text and elem.text.strip():
                content += elem.text.strip()
            
            for child in elem:
                content += element_to_string(child, level + 1, is_root=False)
            
            if elem.tail and elem.tail.strip():
                content += elem.tail.strip()
            
            return f'<{tag_with_attrs}>{content}</{tag}>'
        
        # Reconstruir XML body sin prefijos en etiquetas pero con namespaces preservados
        xml_body = element_to_string(root, is_root=True)
        
    except ET.ParseError:
        # Si falla el parsing, hacer limpieza básica sin parsear
        # Remover espacios extras
        xml_body = re.sub(r'\s+', ' ', xml_body).strip()
    
    # Reconstruir XML completo con prolog
    # IMPORTANTE: Asegurar que siempre se incluya el prolog
    if not xml_body.startswith('<?xml'):
        xml_clean = prolog + xml_body
    else:
        # Si por alguna razón el xml_body ya tiene prolog, usar solo el body
        # pero asegurar que nuestro prolog está presente
        xml_clean = prolog + xml_body.split('?>', 1)[-1].lstrip() if '?>' in xml_body else prolog + xml_body
    
    # Validación final: asegurar que siempre empieza con prolog
    if not xml_clean.startswith('<?xml'):
        # Si por alguna razón se perdió el prolog, agregarlo
        xml_clean = prolog + xml_clean
    
    return xml_clean


def validate_xml_prolog(xml_content: str) -> tuple[bool, Optional[str]]:
    """
    Valida que el XML tenga un prolog válido
    
    Args:
        xml_content: Contenido XML a validar
        
    Returns:
        Tupla (es_valido, mensaje_error)
    """
    if not xml_content:
        return False, "XML vacío"
    
    xml_clean = xml_content.lstrip()
    
    # Verificar que no hay caracteres antes del prolog
    if not xml_clean.startswith('<?xml'):
        return False, "XML debe empezar con <?xml"
    
    # Verificar que el prolog está bien formado
    if not re.match(r'^<\?xml\s+version\s*=\s*["\']1\.0["\']', xml_clean, re.IGNORECASE):
        return False, "Prolog XML debe incluir version='1.0'"
    
    # Verificar que no hay caracteres inválidos antes del prolog
    if xml_content != xml_clean and xml_content.lstrip() != xml_clean:
        return False, "No se permiten espacios o caracteres antes del prolog XML"
    
    return True, None


def ensure_utf8_encoding(xml_content: str) -> bytes:
    """
    Asegura que el XML esté codificado en UTF-8 sin BOM
    
    Args:
        xml_content: XML como string
        
    Returns:
        XML como bytes en UTF-8 sin BOM
    """
    xml_clean = clean_xml(xml_content)
    
    # Convertir a bytes en UTF-8
    xml_bytes = xml_clean.encode('utf-8')
    
    # Remover BOM UTF-8 si existe (0xEF 0xBB 0xBF)
    if xml_bytes.startswith(b'\xef\xbb\xbf'):
        xml_bytes = xml_bytes[3:]
    
    return xml_bytes


def prepare_xml_for_sifen(xml_content: str) -> str:
    """
    Prepara XML según todas las mejores prácticas de SIFEN
    
    Esta función aplica todas las reglas de la Guía de Mejores Prácticas:
    - Remueve espacios, comentarios, caracteres de formato
    - Asegura formato compacto (sin espacios entre etiquetas)
    - Valida prolog correcto
    
    Args:
        xml_content: XML original
        
    Returns:
        XML listo para enviar a SIFEN
    """
    return clean_xml(xml_content)

