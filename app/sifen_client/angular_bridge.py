"""
Bridge para comunicarse con aplicación Angular del Prevalidador SIFEN

Este módulo intenta descubrir y comunicarse con la API REST que hay detrás
de la aplicación Angular del Prevalidador.
"""
import httpx
import json
from typing import Dict, Any, Optional, List
import re


class AngularBridge:
    """
    Bridge para descubrir y comunicarse con APIs REST de aplicaciones Angular
    
    Las aplicaciones Angular típicamente tienen:
    - Servicios HTTP que consumen APIs REST
    - Endpoints comunes como /api/*, /services/*, etc.
    """
    
    def __init__(self, base_url: str = "https://ekuatia.set.gov.py/prevalidador"):
        self.base_url = base_url.rstrip('/')
        self.api_candidates = [
            f"{self.base_url}/api/validar",
            f"{self.base_url}/api/validate",
            f"{self.base_url}/api/validacion",
            f"{self.base_url}/services/validar",
            f"{self.base_url}/validate",
            f"{self.base_url}/validar",
        ]
    
    def discover_api_endpoint(self, xml_content: str) -> Optional[str]:
        """
        Intenta descubrir el endpoint API real del Prevalidador
        
        Args:
            xml_content: XML de prueba
            
        Returns:
            URL del endpoint API si se encuentra, None si no
        """
        for api_url in self.api_candidates:
            try:
                response = httpx.post(
                    api_url,
                    content=xml_content,
                    headers={
                        "Content-Type": "application/xml",
                        "Accept": "application/json"
                    },
                    timeout=10,
                    follow_redirects=False
                )
                
                # Si no es HTML y parece una respuesta API
                if not response.text.strip().startswith("<!DOCTYPE") and \
                   not response.text.strip().startswith("<html"):
                    # Verificar si es JSON o XML válido
                    try:
                        json.loads(response.text)
                        return api_url
                    except:
                        # Podría ser XML
                        if response.text.strip().startswith("<?xml") or "<" in response.text[:100]:
                            return api_url
            except:
                continue
        
        return None
    
    def try_angular_service_call(self, xml_content: str, service_name: str = "validacion") -> Optional[Dict[str, Any]]:
        """
        Intenta llamar a un servicio Angular típico
        
        Las apps Angular comúnmente usan patrones como:
        - POST /api/{service}
        - POST /services/{service}
        - POST /{service}/api
        
        Args:
            xml_content: XML a validar
            service_name: Nombre del servicio
            
        Returns:
            Respuesta si se encuentra, None si no
        """
        patterns = [
            f"{self.base_url}/api/{service_name}",
            f"{self.base_url}/services/{service_name}",
            f"{self.base_url}/{service_name}/api",
            f"{self.base_url}/api/v1/{service_name}",
        ]
        
        for url in patterns:
            try:
                # Intentar como JSON
                response = httpx.post(
                    url,
                    json={"xml": xml_content},
                    headers={"Content-Type": "application/json", "Accept": "application/json"},
                    timeout=10
                )
                
                if response.status_code in [200, 201, 400] and not response.text.strip().startswith("<!DOCTYPE"):
                    try:
                        return response.json()
                    except:
                        if not response.text.strip().startswith("<html"):
                            return {"response": response.text, "endpoint": url}
            except:
                continue
        
        return None
    
    def extract_api_from_angular(self) -> Optional[List[str]]:
        """
        Intenta extraer endpoints API de la aplicación Angular
        
        Las apps Angular a veces exponen endpoints en:
        - environment.ts/prod.ts (archivos de configuración)
        - main.js bundle (si no está minificado)
        
        Returns:
            Lista de posibles endpoints API
        """
        try:
            # Obtener la página principal
            response = httpx.get(self.base_url, timeout=10)
            html = response.text
            
            # Buscar referencias a APIs comunes en el código
            api_patterns = [
                r'/api/[^"\')\s]+',
                r'/services/[^"\')\s]+',
                r'https?://[^"\')\s]+/api/[^"\')\s]+',
            ]
            
            found_endpoints = []
            for pattern in api_patterns:
                matches = re.findall(pattern, html)
                found_endpoints.extend([m.strip("'\"") for m in matches if 'api' in m.lower() or 'service' in m.lower()])
            
            # Limpiar y normalizar
            unique_endpoints = list(set([e for e in found_endpoints if e]))
            return unique_endpoints[:10]  # Limitar a 10
            
        except:
            return None

