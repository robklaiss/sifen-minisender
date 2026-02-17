"""
Cliente para comunicación con servicios SIFEN
"""
import json
import httpx
from typing import Dict, Any, Optional
from pathlib import Path

from .config import SifenConfig
from .validator import SifenValidator


class SifenClientError(Exception):
    """Excepción base para errores del cliente SIFEN"""
    pass


class SifenClient:
    """
    Cliente para comunicación con servicios SIFEN
    
    Soporta ambiente de pruebas (test) y producción (prod)
    """
    
    def __init__(self, config: SifenConfig):
        """
        Inicializa el cliente SIFEN
        
        Args:
            config: Configuración SIFEN
        """
        self.config = config
        self.validator = SifenValidator()
        
        # Configurar cliente HTTP según tipo de servicio
        if config.SERVICE_TYPE == "SOAP":
            self._init_soap_client()
        else:
            self._init_rest_client()
    
    def _init_rest_client(self):
        """Inicializa cliente HTTP REST"""
        client_kwargs = {
            "timeout": self.config.request_timeout,
            "verify": True,  # Verificar certificados SSL
        }
        
        # Configurar mTLS si aplica
        if self.config.use_mtls:
            client_kwargs["cert"] = (
                str(self.config.cert_path),
                self.config.cert_password
            )
            if self.config.ca_bundle_path:
                client_kwargs["verify"] = str(self.config.ca_bundle_path)
        
        self.client = httpx.Client(**client_kwargs)
        
        # Headers base
        self.headers = {
            "Content-Type": "application/xml",  # VERIFICAR formato exacto
            "Accept": "application/xml",  # VERIFICAR formato exacto
        }
        
        # Agregar autenticación si no es mTLS
        if not self.config.use_mtls and hasattr(self.config, 'api_key') and self.config.api_key:
            self.headers["X-API-Key"] = self.config.api_key  # VERIFICAR header exacto
    
    def _init_soap_client(self):
        """
        Inicializa cliente SOAP
        
        TODO: Implementar usando zeep o similar cuando se confirme que es SOAP
        """
        raise NotImplementedError(
            "Cliente SOAP no implementado aún. "
            "Requiere confirmar WSDL desde documentación oficial"
        )
    
    def prevalidar_xml(self, xml_content: str) -> Dict[str, Any]:
        """
        Prevalida un XML de Documento Electrónico usando el Prevalidador SIFEN
        
        Args:
            xml_content: Contenido XML del DE
            
        Returns:
            Resultado de la prevalidación
        """
        try:
            # El Prevalidador es un servicio público
            response = httpx.post(
                self.config.PREVALIDADOR_URL,
                content=xml_content,
                headers={"Content-Type": "application/xml"},
                timeout=self.config.request_timeout
            )
            
            if response.status_code == 200:
                # TODO: Verificar formato exacto de respuesta del Prevalidador
                try:
                    return {
                        "ok": True,
                        "response": response.text,
                        "valid": True,  # VERIFICAR cómo se indica validez
                    }
                except:
                    return {
                        "ok": True,
                        "response": response.text,
                        "valid": None,  # No se pudo parsear
                    }
            else:
                return {
                    "ok": False,
                    "error": f"Error HTTP {response.status_code}: {response.text}",
                    "valid": False,
                }
        except httpx.TimeoutException:
            raise SifenClientError(f"Timeout al contactar Prevalidador ({self.config.request_timeout}s)")
        except httpx.RequestError as e:
            raise SifenClientError(f"Error de conexión al Prevalidador: {str(e)}")
    
    def enviar_documento_electronico(self, xml_content: str) -> Dict[str, Any]:
        """
        Envía un Documento Electrónico al ambiente SIFEN
        
        Args:
            xml_content: Contenido XML del DE
            
        Returns:
            Respuesta del servidor SIFEN
            
        Raises:
            SifenClientError: Si hay algún error en la petición
        """
        # Prevalidar primero
        prevalidation = self.prevalidar_xml(xml_content)
        if not prevalidation.get("valid"):
            raise SifenClientError(
                f"XML no pasa prevalidación: {prevalidation.get('error', 'Errores no especificados')}"
            )
        
        # Obtener endpoint
        endpoint_url = self.config.get_endpoint_url("envio_de")
        
        try:
            response = self.client.post(
                endpoint_url,
                content=xml_content,
                headers=self.headers
            )
            
            if response.status_code == 200:
                try:
                    return {
                        "ok": True,
                        "response": response.text,  # O response.json() si es JSON
                        "status_code": response.status_code,
                    }
                except:
                    return {
                        "ok": True,
                        "response": response.text,
                        "status_code": response.status_code,
                    }
            elif response.status_code == 401:
                raise SifenClientError("Error de autenticación (401): Credenciales incorrectas o certificado inválido")
            elif response.status_code == 400:
                error_msg = "Error de validación (400)"
                try:
                    # Intentar parsear error si es XML/JSON
                    error_data = response.text
                    error_msg += f": {error_data[:200]}"
                except:
                    error_msg += f": {response.text[:200]}"
                raise SifenClientError(error_msg)
            elif response.status_code >= 500:
                raise SifenClientError(f"Error del servidor SIFEN ({response.status_code}): {response.text[:200]}")
            else:
                raise SifenClientError(f"Error HTTP {response.status_code}: {response.text[:200]}")
                
        except httpx.TimeoutException:
            raise SifenClientError(f"Timeout: La petición excedió {self.config.request_timeout} segundos")
        except httpx.RequestError as e:
            raise SifenClientError(f"Error de conexión: {str(e)}")
        except SifenClientError:
            raise
        except Exception as e:
            raise SifenClientError(f"Error inesperado: {str(e)}")
    
    def consultar_documento(self, identificador: str) -> Dict[str, Any]:
        """
        Consulta el estado de un Documento Electrónico
        
        Args:
            identificador: Identificador único del DE (cdc, etc.)
            
        Returns:
            Estado y detalles del documento
        """
        endpoint_url = self.config.get_endpoint_url("consulta")
        
        # TODO: Verificar formato exacto del request (query param, body, etc.)
        try:
            response = self.client.get(
                f"{endpoint_url}?id={identificador}",  # VERIFICAR formato
                headers=self.headers,
                timeout=self.config.request_timeout
            )
            
            if response.status_code == 200:
                return {
                    "ok": True,
                    "response": response.text,
                }
            else:
                raise SifenClientError(f"Error HTTP {response.status_code}: {response.text[:200]}")
                
        except httpx.TimeoutException:
            raise SifenClientError(f"Timeout al consultar documento")
        except httpx.RequestError as e:
            raise SifenClientError(f"Error de conexión: {str(e)}")
    
    def close(self):
        """Cierra el cliente HTTP"""
        if hasattr(self, 'client'):
            self.client.close()
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

