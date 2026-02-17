"""
Validación de XML para SIFEN
"""
import xml.etree.ElementTree as ET
from lxml import etree
from typing import Dict, Any, List, Optional
from pathlib import Path
import httpx

try:
    from .angular_bridge import AngularBridge
    from .xml_utils import clean_xml, validate_xml_prolog, ensure_utf8_encoding
except ImportError:
    AngularBridge = None
    clean_xml = lambda x: x.strip()
    validate_xml_prolog = lambda x: (True, None)
    ensure_utf8_encoding = lambda x: x.encode('utf-8')


class SifenValidator:
    """
    Validador de XML para Documentos Electrónicos SIFEN
    """
    
    def __init__(self):
        """Inicializa el validador"""
        # TODO: Cargar esquema XSD cuando esté disponible
        # self.xsd_schema = self._load_xsd_schema()
        self.prevalidador_url = "https://ekuatia.set.gov.py/prevalidador/validacion"
        # Posibles endpoints API del Prevalidador Angular (comúnmente tienen API REST detrás)
        self.prevalidador_api_urls = [
            "https://ekuatia.set.gov.py/prevalidador/api/validar",  # Tentativo
            "https://ekuatia.set.gov.py/api/prevalidador/validar",  # Tentativo
            "https://ekuatia.set.gov.py/prevalidador/validar",  # Tentativo
        ]
        # Bridge para descubrir APIs de aplicación Angular
        if AngularBridge:
            self.angular_bridge = AngularBridge("https://ekuatia.set.gov.py/prevalidador")
        else:
            self.angular_bridge = None
    
    def _load_xsd_schema(self) -> Optional[Any]:
        """
        Carga el esquema XSD de SIFEN
        
        TODO: Implementar cuando se tenga el XSD oficial
        - Descargar desde documentación oficial
        - Guardar en schemas/sifen/
        - Usar lxml o xmlschema para validar
        """
        xsd_path = Path(__file__).parent.parent.parent / "schemas" / "sifen" / "de.xsd"
        
        if xsd_path.exists():
            # TODO: Implementar carga de XSD
            # from xmlschema import XMLSchema
            # return XMLSchema(str(xsd_path))
            pass
        
        return None
    
    def validate_xml_structure(self, xml_content: str) -> Dict[str, Any]:
        """
        Valida la estructura básica del XML (well-formed)
        
        Args:
            xml_content: Contenido XML
            
        Returns:
            Resultado de validación
        """
        errors = []
        
        try:
            ET.fromstring(xml_content)
            return {
                "valid": True,
                "errors": []
            }
        except ET.ParseError as e:
            errors.append(f"XML mal formado: {str(e)}")
            return {
                "valid": False,
                "errors": errors
            }
    
    def validate_against_xsd(self, xml_content: str) -> Dict[str, Any]:
        """
        Valida el XML contra el esquema XSD de SIFEN
        
        Args:
            xml_content: Contenido XML
            
        Returns:
            Resultado de validación
        """
        # Validar estructura básica primero
        structure_check = self.validate_xml_structure(xml_content)
        if not structure_check["valid"]:
            return structure_check
        
        # Intentar validar contra XSD si está disponible
        from pathlib import Path
        try:
            from lxml import etree
            from .xml_utils import clean_xml
            
            xml_clean = clean_xml(xml_content)
            errors = []
            
            # Buscar XSD en directorio xsd/
            xsd_dir = Path(__file__).parent.parent.parent / "xsd"
            xsd_path = None
            
            # Detectar elemento raíz del XML para usar el XSD correcto
            try:
                xml_doc_test = etree.fromstring(xml_clean.encode('utf-8'))
                root_tag = xml_doc_test.tag
                
                # Si el elemento raíz es rDE, usar siRecepDE_v150.xsd
                if 'rDE' in root_tag or root_tag.endswith('}rDE'):
                    for pattern in ["siRecepDE_v150.xsd", "siRecepDE_v141.xsd", "siRecepDE_v130.xsd"]:
                        candidate = xsd_dir / pattern
                        if candidate.exists():
                            xsd_path = candidate
                            break
            except:
                pass
            
            # Si no se encontró o el raíz es DE, usar DE_v150.xsd
            if xsd_path is None:
                for pattern in ["DE_v150.xsd", "DE_v1.5.0.xsd", "DE_v130.xsd", "DE_v1.3.0.xsd", "DE.xsd"]:
                    candidate = xsd_dir / pattern
                    if candidate.exists():
                        xsd_path = candidate
                        break
            
            if xsd_path is None:
                # Buscar cualquier siRecepDE*.xsd primero, luego DE*.xsd
                recep_xsd_files = list(xsd_dir.glob("siRecepDE*.xsd"))
                if recep_xsd_files:
                    xsd_path = recep_xsd_files[0]
                else:
                    de_xsd_files = list(xsd_dir.glob("DE*.xsd"))
                    if de_xsd_files:
                        xsd_path = de_xsd_files[0]
            
            if xsd_path is None or not xsd_path.exists():
                return {
                    "valid": None,
                    "errors": [],
                    "note": "Esquema XSD no encontrado. Ejecuta: python -m tools.download_xsd"
                }
            
            try:
                # Usar resolutor de dependencias local
                import sys
                sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools"))
                try:
                    from xsd_resolver import resolve_xsd_dependencies
                    
                    # Parsear XML
                    xml_doc = etree.fromstring(xml_clean.encode('utf-8'))
                    
                    # Resolver XSD con dependencias
                    schema = resolve_xsd_dependencies(xsd_path, xsd_dir)
                    
                    # Validar
                    if schema.validate(xml_doc):
                        return {
                            "valid": True,
                            "errors": [],
                            "xsd_used": str(xsd_path.name)
                        }
                    else:
                        for error in schema.error_log:
                            errors.append(
                                f"Línea {error.line}, columna {error.column}: {error.message}"
                            )
                        return {
                            "valid": False,
                            "errors": errors,
                            "xsd_used": str(xsd_path.name)
                        }
                except ImportError:
                    # Fallback si no se puede importar el resolutor
                    # Parsear XML
                    xml_doc = etree.fromstring(xml_clean.encode('utf-8'))
                    
                    # Parsear y validar XSD (puede fallar si hay dependencias)
                    xsd_doc = etree.parse(str(xsd_path))
                    schema = etree.XMLSchema(xsd_doc)
                    
                    # Validar
                    if schema.validate(xml_doc):
                        return {
                            "valid": True,
                            "errors": [],
                            "xsd_used": str(xsd_path.name)
                        }
                    else:
                        for error in schema.error_log:
                            errors.append(
                                f"Línea {error.line}, columna {error.column}: {error.message}"
                            )
                        return {
                            "valid": False,
                            "errors": errors,
                            "xsd_used": str(xsd_path.name)
                        }
                    
            except etree.XMLSyntaxError as e:
                return {
                    "valid": False,
                    "errors": [f"Error de sintaxis XML: {str(e)}"],
                    "xsd_used": None
                }
            except etree.XMLSchemaParseError as e:
                return {
                    "valid": None,
                    "errors": [f"Error al parsear XSD: {str(e)}"],
                    "xsd_used": str(xsd_path.name) if xsd_path else None,
                    "note": "Verifica que el XSD y sus dependencias estén correctamente descargados"
                }
            except Exception as e:
                return {
                    "valid": None,
                    "errors": [f"Error inesperado: {str(e)}"],
                    "xsd_used": str(xsd_path.name) if xsd_path else None
                }
        except ImportError:
            return {
                "valid": None,
                "errors": [],
                "note": "lxml no está instalado. Instala con: pip install lxml"
            }
    
    def prevalidate_with_service(self, xml_content: str) -> Dict[str, Any]:
        """
        Prevalida usando el servicio Prevalidador SIFEN
        
        Este método intenta múltiples estrategias para comunicarse con el Prevalidador:
        1. Descubrir endpoints API REST usando AngularBridge (si disponible)
        2. Intentar endpoints API REST comunes (detrás de la aplicación Angular)
        3. Intentar POST directo al endpoint web
        4. Intentar multipart/form-data (simular formulario)
        
        Args:
            xml_content: Contenido XML del DE
            
        Returns:
            Resultado de prevalidación
        """
        # Limpiar XML antes de enviarlo (remover BOM, espacios iniciales)
        xml_content_clean = clean_xml(xml_content)
        
        # Validar prolog antes de enviar
        prolog_valid, prolog_error = validate_xml_prolog(xml_content_clean)
        if not prolog_valid:
            return {
                "valid": False,
                "error": f"Error en prolog XML: {prolog_error}",
                "suggestion": "Asegúrese de que el XML empiece exactamente con <?xml version=\"1.0\" encoding=\"UTF-8\"?> sin espacios antes"
            }
        
        # Convertir a bytes UTF-8 sin BOM
        xml_bytes = ensure_utf8_encoding(xml_content_clean)
        
        # Estrategia 0: Intentar comunicarse directamente con app Angular del Prevalidador
        try:
            from .angular_prevalidador import AngularPrevalidadorClient
            
            angular_client = AngularPrevalidadorClient()
            result = angular_client.prevalidate_xml(xml_content_clean)
            angular_client.close()
            
            if result.get("valid") is not None or result.get("response"):
                return result
        except ImportError:
            pass
        except Exception as e:
            # Continuar con otros métodos si falla
            pass
        
        # Estrategia 0.5: Intentar descubrir API usando AngularBridge
        if self.angular_bridge:
            try:
                discovered_endpoint = self.angular_bridge.discover_api_endpoint(xml_content_clean)
                if discovered_endpoint:
                    try:
                        response = httpx.post(
                            discovered_endpoint,
                            content=xml_bytes,
                            headers={"Content-Type": "application/xml; charset=UTF-8", "Accept": "application/json"},
                            timeout=15
                        )
                        if response.status_code in [200, 201, 400] and not response.text.strip().startswith("<!DOCTYPE"):
                            try:
                                return {
                                    "valid": response.json().get("valido", response.json().get("valid", None)),
                                    "response": response.json(),
                                    "status_code": response.status_code,
                                    "api_endpoint": discovered_endpoint,
                                    "format": "json",
                                    "discovered": True
                                }
                            except:
                                return {
                                    "valid": None,
                                    "response": response.text[:1000],
                                    "status_code": response.status_code,
                                    "api_endpoint": discovered_endpoint,
                                    "format": "text",
                                    "discovered": True
                                }
                    except:
                        pass
                
                # Intentar servicio Angular típico
                angular_result = self.angular_bridge.try_angular_service_call(xml_content, "validacion")
                if angular_result:
                    return {
                        "valid": angular_result.get("valido", angular_result.get("valid", None)),
                        "response": angular_result,
                        "format": "json",
                        "method": "angular_service"
                    }
            except:
                pass
        
        # Estrategia 1: Intentar endpoints API REST (comúnmente las apps Angular tienen APIs)
        for api_url in self.prevalidador_api_urls:
            try:
                response = httpx.post(
                    api_url,
                    content=xml_bytes,
                    headers={
                        "Content-Type": "application/xml; charset=UTF-8",
                        "Accept": "application/json"
                    },
                    timeout=15,
                    follow_redirects=False
                )
                
                # Si encontramos un endpoint que no es HTML, usarlo
                if response.status_code in [200, 201, 400] and not response.text.strip().startswith("<!DOCTYPE"):
                    try:
                        # Intentar parsear como JSON
                        json_response = response.json()
                        return {
                            "valid": json_response.get("valido", json_response.get("valid", None)),
                            "response": json_response,
                            "status_code": response.status_code,
                            "api_endpoint": api_url,
                            "format": "json"
                        }
                    except:
                        # Si no es JSON, retornar texto
                        return {
                            "valid": None,
                            "response": response.text[:1000],
                            "status_code": response.status_code,
                            "api_endpoint": api_url,
                            "format": "text",
                            "note": "Respuesta recibida (formato a verificar)"
                        }
            except (httpx.TimeoutException, httpx.RequestError, httpx.HTTPStatusError):
                continue  # Intentar siguiente URL
        
        # Estrategia 2: POST directo al endpoint web
        try:
            response = httpx.post(
                self.prevalidador_url,
                content=xml_bytes,
                headers={"Content-Type": "application/xml; charset=UTF-8"},
                timeout=30
            )
            
            if response.status_code == 200:
                response_text = response.text
                
                # Si la respuesta es HTML (aplicación web Angular)
                if response_text.strip().startswith("<!DOCTYPE html>") or "<html" in response_text[:200].lower():
                    # Estrategia 3: Intentar con multipart/form-data (simular formulario Angular)
                    try:
                        files = {'file': ('documento.xml', xml_bytes, 'application/xml; charset=UTF-8')}
                        response2 = httpx.post(
                            self.prevalidador_url,
                            files=files,
                            headers={"Accept": "application/json"},
                            timeout=30
                        )
                        if response2.status_code == 200 and not response2.text.strip().startswith("<!DOCTYPE"):
                            try:
                                json_resp = response2.json()
                                return {
                                    "valid": json_resp.get("valido", json_resp.get("valid", None)),
                                    "response": json_resp,
                                    "status_code": response2.status_code,
                                    "method": "multipart/form-data",
                                    "format": "json"
                                }
                            except:
                                return {
                                    "valid": None,
                                    "response": response2.text[:500],
                                    "status_code": response2.status_code,
                                    "method": "multipart/form-data",
                                    "format": "text",
                                    "note": "Respuesta recibida (formato a verificar)"
                                }
                    except:
                        pass
                    
                    # Si sigue siendo HTML después de todos los intentos
                    return {
                        "valid": None,
                        "error": "El Prevalidador devuelve HTML (aplicación web Angular). No se encontró API REST programática.",
                        "response_type": "html",
                        "response_preview": response_text[:500],
                        "status_code": response.status_code,
                        "note": "Usar https://ekuatia.set.gov.py/prevalidador/validacion manualmente o verificar documentación para API programática",
                        "suggestions": [
                            "Revisar documentación técnica para encontrar endpoint API",
                            "Inspeccionar requests de la aplicación Angular (DevTools Network)",
                            "Contactar soporte DNIT/SET para API programática"
                        ]
                    }
                
                # Si no es HTML, intentar parsear
                try:
                    json_resp = response.json()
                    return {
                        "valid": json_resp.get("valido", json_resp.get("valid", None)),
                        "response": json_resp,
                        "status_code": response.status_code,
                        "format": "json"
                    }
                except:
                    # Parsear texto
                    is_valid = None
                    if "error" in response_text.lower() or "invalido" in response_text.lower() or "rechazado" in response_text.lower():
                        is_valid = False
                    elif "valido" in response_text.lower() or "exitoso" in response_text.lower() or "aceptado" in response_text.lower():
                        is_valid = True
                    
                    return {
                        "valid": is_valid,
                        "response": response_text[:1000],
                        "status_code": response.status_code,
                        "format": "text"
                    }
            else:
                return {
                    "valid": False,
                    "error": f"Error HTTP {response.status_code}: {response.text[:200]}",
                    "status_code": response.status_code,
                }
                
        except httpx.TimeoutException:
            return {
                "valid": False,
                "error": "Timeout al contactar Prevalidador",
            }
        except httpx.RequestError as e:
            return {
                "valid": False,
                "error": f"Error de conexión: {str(e)}",
            }
    
    def validate(self, xml_content: str, use_prevalidador: bool = True) -> Dict[str, Any]:
        """
        Valida un XML de Documento Electrónico
        
        Args:
            xml_content: Contenido XML
            use_prevalidador: Si usar el Prevalidador SIFEN además de validación local
            
        Returns:
            Resultado completo de validación
        """
        results = {
            "valid": False,
            "errors": [],
            "warnings": [],
        }
        
        # 1. Validar estructura básica
        structure_result = self.validate_xml_structure(xml_content)
        if not structure_result["valid"]:
            results["errors"].extend(structure_result["errors"])
            return results
        
        # 2. Validar contra XSD (si disponible)
        xsd_result = self.validate_against_xsd(xml_content)
        if not xsd_result["valid"]:
            results["errors"].extend(xsd_result.get("errors", []))
        if xsd_result.get("note"):
            results["warnings"].append(xsd_result["note"])
        
        # 3. Prevalidar con servicio (opcional)
        if use_prevalidador:
            prevalidation = self.prevalidate_with_service(xml_content)
            if not prevalidation.get("valid"):
                results["errors"].append(
                    f"Prevalidador: {prevalidation.get('error', 'Errores no especificados')}"
                )
            results["prevalidation"] = prevalidation
        
        # Determinar validez final
        results["valid"] = len(results["errors"]) == 0
        
        return results

