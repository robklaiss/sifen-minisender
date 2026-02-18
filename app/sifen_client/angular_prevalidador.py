"""
Cliente para interactuar directamente con la aplicación Angular del Prevalidador SIFEN

Este módulo permite comunicarse con los endpoints REST que usa la aplicación Angular
del Prevalidador, evitando la necesidad de usar el formulario web manualmente.
"""
import httpx
import json
from typing import Dict, Any, Optional, List
from pathlib import Path
import re


class AngularPrevalidadorClient:
    """
    Cliente para interactuar con la aplicación Angular del Prevalidador SIFEN
    
    Detecta y usa los endpoints API REST que la aplicación Angular utiliza internamente
    """
    
    BASE_URL = "https://ekuatia.set.gov.py/prevalidador"
    
    def __init__(self, timeout: int = 30):
        """
        Inicializa el cliente
        
        Args:
            timeout: Timeout para peticiones HTTP
        """
        self.timeout = timeout
        self.client = httpx.Client(
            timeout=timeout,
            verify=True,
            follow_redirects=True
        )
        self._api_endpoints = None
        self._session_token = None
    
    def discover_api_endpoints(self) -> Dict[str, str]:
        """
        Descubre los endpoints API que usa la aplicación Angular
        
        Intenta obtener la página principal y extraer URLs de endpoints API
        desde el código JavaScript de Angular
        
        Returns:
            Diccionario con endpoints descubiertos
        """
        if self._api_endpoints:
            return self._api_endpoints
        
        endpoints = {}
        
        try:
            # Obtener página principal
            response = self.client.get(f"{self.BASE_URL}/validacion")
            html_content = response.text
            
            # Buscar referencias a APIs en el código JavaScript
            # Angular típicamente usa servicios HTTP con URLs como:
            # - /api/validar
            # - /api/prevalidate
            # - /prevalidador/api/...
            
            api_patterns = [
                r'["\']([^"\']*\/api\/[^"\']+)["\']',
                r'url:\s*["\']([^"\']+)["\']',
                r'endpoint["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'prevalidar["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                r'validar["\']?\s*[:=]\s*["\']([^"\']+)["\']',
            ]
            
            for pattern in api_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if 'api' in match.lower() or 'valid' in match.lower():
                        # Normalizar URL
                        if match.startswith('/'):
                            url = f"{self.BASE_URL}{match}"
                        elif match.startswith('http'):
                            url = match
                        else:
                            url = f"{self.BASE_URL}/{match}"
                        
                        endpoint_name = match.split('/')[-1] or match.split('/')[-2]
                        if endpoint_name:
                            endpoints[endpoint_name] = url
            
            # También buscar en archivos JavaScript separados
            # Angular apps suelen cargar main.js, vendor.js, etc.
            js_patterns = [
                r'<script[^>]*src=["\']([^"\']*\.js)["\']',
            ]
            
            for pattern in js_patterns:
                matches = re.findall(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    if not match.startswith('http'):
                        match = f"{self.BASE_URL}/{match.lstrip('/')}"
                    
                    try:
                        js_response = self.client.get(match, timeout=5)
                        if js_response.status_code == 200:
                            # Buscar endpoints en el JavaScript
                            for api_pattern in api_patterns:
                                js_matches = re.findall(api_pattern, js_response.text, re.IGNORECASE)
                                for js_match in js_matches:
                                    if 'api' in js_match.lower():
                                        if js_match.startswith('/'):
                                            url = f"{self.BASE_URL}{js_match}"
                                        elif not js_match.startswith('http'):
                                            url = f"{self.BASE_URL}/{js_match}"
                                        else:
                                            url = js_match
                                        
                                        endpoint_name = js_match.split('/')[-1] or js_match.split('/')[-2]
                                        if endpoint_name:
                                            endpoints[endpoint_name] = url
                    except:
                        continue
            
            # Endpoints comunes a probar directamente
            common_endpoints = {
                'validar': f"{self.BASE_URL}/api/validar",
                'prevalidate': f"{self.BASE_URL}/api/prevalidate",
                'prevalidar': f"{self.BASE_URL}/api/prevalidar",
                'validate': f"{self.BASE_URL}/api/validate",
                'validacion': f"{self.BASE_URL}/api/validacion",
            }
            
            # Probar endpoints comunes
            for name, url in common_endpoints.items():
                if name not in endpoints:
                    endpoints[name] = url
            
            self._api_endpoints = endpoints
            
        except Exception as e:
            print(f"⚠️  Error descubriendo endpoints: {e}")
            # Usar endpoints por defecto
            self._api_endpoints = {
                'validar': f"{self.BASE_URL}/api/validar",
                'prevalidate': f"{self.BASE_URL}/api/prevalidate",
            }
        
        return self._api_endpoints
    
    def prevalidate_xml(self, xml_content: str) -> Dict[str, Any]:
        """
        Prevalida XML usando los endpoints API de la aplicación Angular
        
        Intenta múltiples métodos:
        1. POST directo a endpoints API descubiertos
        2. Multipart/form-data (simular formulario Angular)
        3. JSON con XML (si la API lo acepta)
        
        Args:
            xml_content: Contenido XML a prevalidar
            
        Returns:
            Resultado de prevalidación
        """
        endpoints = self.discover_api_endpoints()
        
        # Método 1: Intentar endpoints API descubiertos
        for endpoint_name, url in endpoints.items():
            # Intentar como JSON
            try:
                response = self.client.post(
                    url,
                    json={"xml": xml_content},
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json"
                    },
                    timeout=15
                )
                
                if response.status_code in [200, 201, 400] and not response.text.strip().startswith("<!DOCTYPE"):
                    try:
                        return {
                            "valid": True,
                            "response": response.json(),
                            "method": f"API JSON ({endpoint_name})",
                            "endpoint": url,
                            "status_code": response.status_code
                        }
                    except:
                        return {
                            "valid": None,
                            "response": response.text[:1000],
                            "method": f"API Text ({endpoint_name})",
                            "endpoint": url,
                            "status_code": response.status_code
                        }
            except:
                continue
            
            # Intentar como XML directo
            try:
                response = self.client.post(
                    url,
                    content=xml_content,
                    headers={
                        "Content-Type": "application/xml; charset=UTF-8",
                        "Accept": "application/json"
                    },
                    timeout=15
                )
                
                if response.status_code in [200, 201, 400] and not response.text.strip().startswith("<!DOCTYPE"):
                    try:
                        return {
                            "valid": True,
                            "response": response.json(),
                            "method": f"API XML ({endpoint_name})",
                            "endpoint": url,
                            "status_code": response.status_code
                        }
                    except:
                        return {
                            "valid": None,
                            "response": response.text[:1000],
                            "method": f"API XML Text ({endpoint_name})",
                            "endpoint": url,
                            "status_code": response.status_code
                        }
            except:
                continue
        
        # Método 2: Simular formulario Angular (multipart/form-data)
        try:
            files = {
                'file': ('documento.xml', xml_content.encode('utf-8'), 'application/xml')
            }
            # También intentar con nombres de campo comunes
            data_variants = [
                {},  # Sin datos adicionales
                {'xml': xml_content},  # Campo xml
                {'documento': xml_content},  # Campo documento
            ]
            
            for data in data_variants:
                try:
                    response = self.client.post(
                        f"{self.BASE_URL}/validacion",
                        files=files,
                        data=data,
                        headers={"Accept": "application/json"},
                        timeout=15
                    )
                    
                    if response.status_code in [200, 201, 400] and not response.text.strip().startswith("<!DOCTYPE"):
                        try:
                            return {
                                "valid": True,
                                "response": response.json(),
                                "method": "Multipart Form (Angular)",
                                "endpoint": f"{self.BASE_URL}/validacion",
                                "status_code": response.status_code
                            }
                        except:
                            return {
                                "valid": None,
                                "response": response.text[:1000],
                                "method": "Multipart Form (Angular)",
                                "endpoint": f"{self.BASE_URL}/validacion",
                                "status_code": response.status_code
                            }
                except:
                    continue
        except:
            pass
        
        # Método 3: Intentar como formulario URL-encoded (común en Angular)
        try:
            response = self.client.post(
                f"{self.BASE_URL}/api/validar",
                data={"xml": xml_content},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json"
                },
                timeout=15
            )
            
            if response.status_code in [200, 201, 400] and not response.text.strip().startswith("<!DOCTYPE"):
                try:
                    return {
                        "valid": True,
                        "response": response.json(),
                        "method": "Form URL-Encoded",
                        "endpoint": f"{self.BASE_URL}/api/validar",
                        "status_code": response.status_code
                    }
                except:
                    return {
                        "valid": None,
                        "response": response.text[:1000],
                        "method": "Form URL-Encoded",
                        "endpoint": f"{self.BASE_URL}/api/validar",
                        "status_code": response.status_code
                    }
        except:
            pass
        
        # Si nada funciona, retornar que requiere uso manual
        return {
            "valid": None,
            "error": "No se pudo encontrar endpoint API funcional de la aplicación Angular",
            "endpoints_tried": list(endpoints.keys()),
            "note": "Usar el formulario web manualmente o verificar documentación técnica para API programática"
        }
    
    def test_connection(self) -> Dict[str, Any]:
        """
        Prueba la conexión con la aplicación Angular
        
        Returns:
            Información sobre la conexión y endpoints disponibles
        """
        try:
            response = self.client.get(f"{self.BASE_URL}/validacion", timeout=10)
            
            endpoints = self.discover_api_endpoints()
            
            return {
                "connected": response.status_code == 200,
                "status_code": response.status_code,
                "endpoints_discovered": endpoints,
                "is_angular_app": "angular" in response.text.lower() or "ng-" in response.text.lower(),
                "has_api_endpoints": len(endpoints) > 0
            }
        except Exception as e:
            return {
                "connected": False,
                "error": str(e)
            }
    
    def close(self):
        """Cierra el cliente HTTP"""
        self.client.close()


def prevalidate_with_angular_app(xml_content: str) -> Dict[str, Any]:
    """
    Función helper para prevalidar XML usando la aplicación Angular
    
    Args:
        xml_content: Contenido XML a prevalidar
        
    Returns:
        Resultado de prevalidación
    """
    client = AngularPrevalidadorClient()
    try:
        return client.prevalidate_xml(xml_content)
    finally:
        client.close()

