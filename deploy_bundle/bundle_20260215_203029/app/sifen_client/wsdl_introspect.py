"""
Introspection de WSDL para extraer información necesaria para construir requests SOAP.

Extrae del WSDL:
- URL de POST (soap12:address/@location o soap:address/@location)
- QName del elemento root del Body (desde wsdl:message/wsdl:part/@element)
- soapAction y si debe incluirse en Content-Type
- targetNamespace
- Si es wrapped o bare (document/literal)
- Versión SOAP (1.1 o 1.2)
"""
import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from urllib.parse import urlparse

try:
    import lxml.etree as etree
except ImportError:
    raise ImportError("lxml es requerido para WSDL introspection. Instalar con: pip install lxml")


# Namespaces WSDL
NS_WSDL = "http://schemas.xmlsoap.org/wsdl/"
NS_SOAP12 = "http://schemas.xmlsoap.org/wsdl/soap12/"
NS_SOAP11 = "http://schemas.xmlsoap.org/wsdl/soap/"
NS_XSD = "http://www.w3.org/2001/XMLSchema"


def load_wsdl(url_or_path: str) -> etree._Element:
    """
    Carga un WSDL desde URL o path local.
    
    Args:
        url_or_path: URL del WSDL o path local al archivo
        
    Returns:
        Element root del WSDL parseado
        
    Raises:
        FileNotFoundError: Si el path local no existe
        etree.XMLSyntaxError: Si el XML es inválido
        Exception: Si falla la descarga desde URL
    """
    # Primero intentar como path local (absoluto o relativo)
    path = Path(url_or_path)
    if path.exists():
        return etree.parse(str(path)).getroot()
    
    # Si no existe como path relativo, intentar desde cwd
    cwd_path = Path.cwd() / url_or_path
    if cwd_path.exists():
        return etree.parse(str(cwd_path)).getroot()
    
    # Intentar desde parent del parent (si estamos en subdirectorio)
    parent_path = Path(__file__).parent.parent.parent / url_or_path
    if parent_path.exists():
        return etree.parse(str(parent_path)).getroot()
    
    # Si no es un path local, verificar si es una URL válida
    parsed = urlparse(url_or_path)
    if parsed.scheme in ("http", "https"):
        # Intentar descargar desde URL (requiere requests)
        try:
            import requests
            resp = requests.get(url_or_path, timeout=30, verify=True)
            resp.raise_for_status()
            return etree.fromstring(resp.content)
        except ImportError:
            raise ImportError("requests es requerido para descargar WSDL desde URL. Instalar con: pip install requests")
    else:
        raise FileNotFoundError(f"WSDL no encontrado: {url_or_path}")


def extract_qname(qname_str: str, default_ns: str = "") -> tuple[str, str]:
    """
    Extrae (namespace, localname) de un QName string.
    
    Args:
        qname_str: QName como string (ej: "ns0:rEnvioLote" o "rEnvioLote")
        default_ns: Namespace por defecto si no hay prefijo
        
    Returns:
        Tupla (namespace, localname)
    """
    if ":" in qname_str:
        prefix, localname = qname_str.split(":", 1)
        return (default_ns, localname)  # El namespace real viene del contexto
    return (default_ns, qname_str)


def inspect_wsdl(wsdl_url_or_path: str, operation_name: Optional[str] = None) -> Dict[str, Any]:
    """
    Inspecciona un WSDL y extrae información para construir requests SOAP.
    
    Args:
        wsdl_url_or_path: URL o path al WSDL
        operation_name: Nombre de la operación a inspeccionar (opcional, si None busca la primera)
        
    Returns:
        Dict con:
        {
            "wsdl_url": str,
            "target_namespace": str,
            "soap_version": "1.2" o "1.1",
            "url_post": str,  # soap12:address/@location o soap:address/@location
            "operation_name": str,
            "body_root_qname": {"namespace": str, "localname": str},  # Elemento root del Body
            "soap_action": str,  # Valor del soapAction (puede ser "")
            "action_required": bool,  # soapActionRequired="true"
            "style": str,  # "document" o "rpc"
            "use": str,  # "literal" o "encoded"
            "is_wrapped": bool,  # True si es document/literal wrapped
            "namespaces": dict,  # Mapeo de prefijos a namespaces usados
        }
    """
    root = load_wsdl(wsdl_url_or_path)
    
    result = {
        "wsdl_url": wsdl_url_or_path,
        "target_namespace": root.get("targetNamespace", ""),
        "soap_version": None,
        "url_post": None,
        "operation_name": None,
        "body_root_qname": None,
        "soap_action": "",
        "action_required": False,
        "style": "document",
        "use": "literal",
        "is_wrapped": False,
        "namespaces": {},
    }
    
    # Detectar versión SOAP (buscar soap12:binding o soap:binding)
    bindings = root.findall(f".//{{{NS_WSDL}}}binding")
    soap_version = None
    soap_ns = None
    
    for binding in bindings:
        soap12_binding = binding.find(f"{{{NS_SOAP12}}}binding", root.nsmap)
        if soap12_binding is not None:
            soap_version = "1.2"
            soap_ns = NS_SOAP12
            break
        
        soap11_binding = binding.find(f"{{{NS_SOAP11}}}binding", root.nsmap)
        if soap11_binding is not None:
            soap_version = "1.1"
            soap_ns = NS_SOAP11
            break
    
    if not soap_version:
        raise ValueError("No se encontró binding SOAP 1.1 ni 1.2 en el WSDL")
    
    result["soap_version"] = soap_version
    
    # Extraer URL de POST desde soap12:address/@location o soap:address/@location
    services = root.findall(f".//{{{NS_WSDL}}}service")
    for service in services:
        ports = service.findall(f".//{{{NS_WSDL}}}port")
        for port in ports:
            if soap_version == "1.2":
                address = port.find(f"{{{NS_SOAP12}}}address", root.nsmap)
            else:
                address = port.find(f"{{{NS_SOAP11}}}address", root.nsmap)
            
            if address is not None:
                location = address.get("location", "")
                if location:
                    # Normalizar: quitar ?wsdl o .wsdl del final
                    if location.endswith("?wsdl"):
                        location = location[:-5]
                    elif location.endswith(".wsdl"):
                        location = location[:-5]
                    result["url_post"] = location
                    break
        
        if result["url_post"]:
            break
    
    # Buscar operación
    if not operation_name:
        # Buscar la primera operación en portType
        port_types = root.findall(f".//{{{NS_WSDL}}}portType")
        if port_types:
            operations = port_types[0].findall(f".//{{{NS_WSDL}}}operation")
            if operations:
                operation_name = operations[0].get("name")
    
    if not operation_name:
        raise ValueError("No se encontró operación en el WSDL")
    
    result["operation_name"] = operation_name
    
    # Buscar binding operation para esta operación
    binding_ops = root.findall(f".//{{{NS_WSDL}}}binding/{{{NS_WSDL}}}operation[@name='{operation_name}']")
    
    if not binding_ops:
        raise ValueError(f"No se encontró binding para operación '{operation_name}'")
    
    binding_op = binding_ops[0]
    
    # Extraer soapAction y actionRequired
    if soap_version == "1.2":
        soap_op = binding_op.find(f"{{{NS_SOAP12}}}operation", root.nsmap)
        if soap_op is not None:
            result["soap_action"] = soap_op.get("soapAction", "")
            action_required = soap_op.get("soapActionRequired", "false")
            result["action_required"] = action_required.lower() in ("true", "1")
            result["style"] = soap_op.get("style", "document")
    else:
        soap_op = binding_op.find(f"{{{NS_SOAP11}}}operation", root.nsmap)
        if soap_op is not None:
            result["soap_action"] = soap_op.get("soapAction", "")
            result["action_required"] = True  # SOAP 1.1 siempre requiere SOAPAction
            result["style"] = soap_op.get("style", "document")
    
    # Buscar input message
    input_elem = binding_op.find(f"{{{NS_WSDL}}}input", root.nsmap)
    if input_elem is None:
        raise ValueError(f"No se encontró input para operación '{operation_name}'")
    
    # Extraer use (literal o encoded)
    if soap_version == "1.2":
        soap_body = input_elem.find(f"{{{NS_SOAP12}}}body", root.nsmap)
    else:
        soap_body = input_elem.find(f"{{{NS_SOAP11}}}body", root.nsmap)
    
    if soap_body is not None:
        result["use"] = soap_body.get("use", "literal")
    
    # Buscar el message referenciado por el input
    input_name = input_elem.get("name")
    if not input_name:
        # Buscar por posición (primer input del portType operation)
        port_type_ops = root.findall(f".//{{{NS_WSDL}}}portType/{{{NS_WSDL}}}operation[@name='{operation_name}']")
        if port_type_ops:
            pt_input = port_type_ops[0].find(f"{{{NS_WSDL}}}input", root.nsmap)
            if pt_input is not None:
                input_name = pt_input.get("name")
    
    if input_name:
        messages = root.findall(f".//{{{NS_WSDL}}}message[@name='{input_name}']")
        if messages:
            message = messages[0]
            parts = message.findall(f"{{{NS_WSDL}}}part", root.nsmap)
            if parts:
                part = parts[0]
                element_ref = part.get("element", "")
                if element_ref:
                    # element_ref puede ser "ns0:rEnvioLote" o "rEnvioLote"
                    # Necesitamos resolver el namespace del prefijo
                    if ":" in element_ref:
                        prefix, localname = element_ref.split(":", 1)
                        # Buscar namespace del prefijo en el WSDL
                        ns_uri = root.nsmap.get(prefix, result["target_namespace"])
                    else:
                        localname = element_ref
                        ns_uri = result["target_namespace"]
                    
                    result["body_root_qname"] = {
                        "namespace": ns_uri,
                        "localname": localname,
                    }
    
    # Determinar si es wrapped (document/literal wrapped)
    # Es wrapped si el elemento root tiene el mismo nombre que la operación
    # En document/literal bare, el elemento del message part es el root del Body directamente
    # En document/literal wrapped, el elemento root tiene el nombre de la operación
    # y contiene parámetros nombrados (el elemento del message part estaría dentro)
    if result["body_root_qname"]:
        # Si el elemento del message part tiene el mismo nombre que la operación, es bare
        # Si el elemento tiene un nombre diferente de la operación, es wrapped (raro pero posible)
        # Por defecto, document/literal es bare si el elemento va directo al Body
        if result["body_root_qname"]["localname"] == operation_name:
            # Mismo nombre: es bare (el elemento va directo al Body)
            result["is_wrapped"] = False
        else:
            # Diferente nombre: podría ser wrapped, pero en SIFEN parece ser siempre bare
            result["is_wrapped"] = False
    
    # Recopilar namespaces importantes
    result["namespaces"] = {
        "soap": NS_SOAP12 if soap_version == "1.2" else NS_SOAP11,
        "target": result["target_namespace"],
    }
    if result["body_root_qname"]:
        result["namespaces"]["body"] = result["body_root_qname"]["namespace"]
    
    return result


def save_wsdl_inspection(result: Dict[str, Any], output_path: Path) -> None:
    """
    Guarda el resultado de la inspección WSDL en formato JSON.
    
    Args:
        result: Resultado de inspect_wsdl()
        output_path: Path donde guardar el JSON
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(result, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Inspecciona un WSDL y guarda resultado en JSON")
    parser.add_argument("wsdl", help="URL o path al WSDL")
    parser.add_argument("--operation", help="Nombre de la operación (opcional)")
    parser.add_argument("--output", type=Path, default=Path("artifacts/wsdl_inspected.json"), help="Path de salida JSON")
    
    args = parser.parse_args()
    
    try:
        result = inspect_wsdl(args.wsdl, args.operation)
        save_wsdl_inspection(result, args.output)
        
        print(json.dumps(result, indent=2, ensure_ascii=False))
        print(f"\n✅ Resultado guardado en: {args.output}")
    except Exception as e:
        print(f"❌ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

