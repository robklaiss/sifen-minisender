from app.sifen_client.config import (
    get_mtls_cert_path_and_password,
    get_mtls_cert_and_key_paths,
    get_mtls_config,
)
"""
Cliente SOAP 1.2 Document/Literal para SIFEN

Requisitos:
- SOAP 1.2
- Estilo Document/Literal
- mTLS (TLS 1.2) con certificados
- Validación de tamaño antes de enviar
- Manejo de códigos de error SIFEN

Notas importantes:
- El WSDL .../recibe.wsdl en test puede devolver body vacío; se debe usar ?wsdl.
- NO usar elem1 or elem2 con lxml Elements (pueden ser "falsy" si no tienen hijos).
"""

import os
import json
import logging
import re
import time
import random
from datetime import datetime
from typing import Dict, Any, Optional, List, TYPE_CHECKING
from pathlib import Path
from urllib.parse import urlparse, urlunparse

try:
    # Import lxml.etree - el linter puede no reconocerlo, pero funciona correctamente
    import lxml.etree as etree  # noqa: F401
except ImportError:
    etree = None  # type: ignore

if TYPE_CHECKING:
    from lxml.etree import _Element as etree_type  # noqa: F401

try:
    from zeep import Client, Settings
    from zeep.transports import Transport
    from zeep.exceptions import Fault, TransportError
    from zeep.helpers import serialize_object

    ZEEP_AVAILABLE = True
except ImportError:
    ZEEP_AVAILABLE = False
    serialize_object = None
    Client = None
    Settings = None
    Transport = None
    Fault = Exception
    TransportError = Exception

from requests import Session
from requests.adapters import HTTPAdapter
import requests

from .config import SifenConfig, get_mtls_cert_path_and_password
from .exceptions import (
    SifenClientError,
    SifenSizeLimitError,
)
from .pkcs12_utils import p12_to_temp_pem_files, cleanup_pem_files, PKCS12Error

try:
    from .wsdl_introspect import inspect_wsdl, save_wsdl_inspection
except ImportError:
    inspect_wsdl = None  # type: ignore
    save_wsdl_inspection = None  # type: ignore

# Importar cert_resolver para validación de certificados
try:
    from tools.cert_resolver import validate_no_self_signed, save_resolved_certs_artifact
except ImportError:
    # Fallback si no está en PATH (ej: importado desde otro módulo)
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools"))
    from cert_resolver import validate_no_self_signed, save_resolved_certs_artifact

try:
    from tools.artifacts import resolve_artifacts_dir
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "tools"))
    from artifacts import resolve_artifacts_dir

logger = logging.getLogger(__name__)

# Constantes de namespace SIFEN
SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
SIFEN_SCHEMA_LOCATION = "http://ekuatia.set.gov.py/sifen/xsd/siRecepDE_v150.xsd"

# Límites de tamaño según requisitos SIFEN (en bytes)
SIZE_LIMITS = {
    "siRecepDE": 1000 * 1024,  # 1000 KB
    "siRecepLoteDE": 10000 * 1024,  # 10.000 KB
    "rEnvioLote": 10000 * 1024,  # 10.000 KB
    "siConsRUC": 1000 * 1024,  # 1000 KB
    "siConsDE": 1000 * 1024,  # 1000 KB (asumido)
    "siConsLoteDE": 10000 * 1024,  # 10.000 KB (asumido)
}


def build_consulta_lote_raw_envelope(d_id: str, d_prot_cons_lote: str) -> bytes:
    """Construye el envelope SOAP 1.2 requerido por siConsLoteDE."""
    if not d_id or not str(d_id).strip():
        raise ValueError("dId no puede estar vacío para consulta_lote_raw")
    if not d_prot_cons_lote or not str(d_prot_cons_lote).strip():
        raise ValueError("dProtConsLote no puede estar vacío para consulta_lote_raw")

    if etree is None:
        raise SifenClientError("lxml no está disponible para construir SOAP consulta_lote_raw")

    soap_ns = "http://www.w3.org/2003/05/soap-envelope"

    envelope = etree.Element(f"{{{soap_ns}}}Envelope", nsmap={"soap": soap_ns})
    etree.SubElement(envelope, f"{{{soap_ns}}}Header")
    body = etree.SubElement(envelope, f"{{{soap_ns}}}Body")
    r_envi = etree.SubElement(body, "rEnviConsLoteDe", nsmap={None: SIFEN_NS})

    d_id_elem = etree.SubElement(r_envi, "dId")
    d_id_elem.text = str(d_id)

    d_prot_elem = etree.SubElement(r_envi, "dProtConsLote")
    d_prot_elem.text = str(d_prot_cons_lote)

    return etree.tostring(
        envelope,
        xml_declaration=True,
        encoding="UTF-8",
        pretty_print=False,
    )


def validate_xml_bytes_or_raise(xml_bytes: bytes, context: str) -> None:
    """Valida que XML bytes sean parseables por lxml."""
    if etree is None:
        raise SifenClientError(f"lxml no está disponible para validar XML ({context})")
    try:
        etree.fromstring(xml_bytes)
    except Exception as exc:
        raise SifenClientError(f"XML inválido en {context}: {exc}") from exc

# Códigos de error SIFEN (parciales)
ERROR_CODES = {
    "0200": "Mensaje excede tamaño máximo (siRecepDE)",
    "0270": "Lote excede tamaño máximo (rEnvioLote)",
    "0460": "Mensaje excede tamaño máximo (siConsRUC)",
    "0500": "RUC inexistente",
    "0501": "Sin permiso para consultar",
    "0502": "Éxito (RUC encontrado)",
    "0183": "RUC del certificado no activo/válido",
}


class SoapClient:
    """Cliente SOAP 1.2 (document/literal) para SIFEN, con mTLS."""

    def __init__(self, config: SifenConfig):
        self.config = config

        if not ZEEP_AVAILABLE:
            raise SifenClientError(
                "zeep no está instalado. Instale con: pip install zeep"
            )

        # Timeouts / retries
        self.connect_timeout = int(os.getenv("SIFEN_SOAP_TIMEOUT_CONNECT", "15"))
        self.read_timeout = int(os.getenv("SIFEN_SOAP_TIMEOUT_READ", "45"))
        self.max_retries = int(os.getenv("SIFEN_SOAP_MAX_RETRIES", "3"))

        # Modo compatibilidad Roshka
        self.roshka_compat = os.getenv("SIFEN_SOAP_COMPAT", "").lower() == "roshka"
        if self.roshka_compat:
            logger.info("Modo compatibilidad Roshka activado")

        # Transporte con mTLS
        self.transport = self._create_transport()

        # Cache
        self.clients: Dict[str, Any] = {}  # Client de Zeep
        self._soap_address: Dict[str, str] = {}

        # PEM temporales (si se convierten desde P12)
        self._temp_pem_files: Optional[tuple[str, str]] = None

    # ---------------------------------------------------------------------
    # Helpers WSDL
    # ---------------------------------------------------------------------
    def _normalize_wsdl_url(self, wsdl_url: str) -> str:
        """Normaliza URLs de WSDL.

        En SIFEN-test se observó:
        - .../recibe.wsdl -> HTTP 200 pero body vacío (len=0)
        - .../recibe.wsdl?wsdl -> WSDL real
        Por eso forzamos ?wsdl si no está.
        
        Para consulta_ruc, es CRÍTICO usar WSDL para evitar error 0160.
        """
        u = (wsdl_url or "").strip()
        if not u:
            return u

        # Si ya trae query, no tocamos (ej: ?wsdl)
        if "?" in u:
            return u

        # Si termina en .wsdl, forzar ?wsdl
        if u.endswith(".wsdl"):
            return f"{u}?wsdl"

        return u

    @staticmethod
    def _normalize_soap_endpoint(url: str) -> str:
        """Normaliza un endpoint SOAP quitando .wsdl y query strings.

        NOTA: Para recibe-lote y consulta-ruc, NO quitamos .wsdl porque el endpoint POST
        real debe incluir .wsdl (ej: /recibe-lote.wsdl, /consulta-ruc.wsdl)

        Ejemplos:
        - https://.../recibe.wsdl?wsdl -> https://.../recibe
        - https://.../recibe.wsdl      -> https://.../recibe
        - https://.../recibe            -> https://.../recibe
        - https://.../recibe-lote.wsdl -> https://.../recibe-lote.wsdl (NO cambiar)
        - https://.../consulta-ruc.wsdl -> https://.../consulta-ruc.wsdl (NO cambiar)
        """
        if not url:
            return url

        # Para recibe-lote, consulta-ruc y consulta-lote, conservar el .wsdl
        if (
            "/recibe-lote.wsdl" in url
            or "/consulta-ruc.wsdl" in url
            or "/consulta-lote.wsdl" in url
        ):
            # Solo quitar query string si existe
            if "?" in url:
                url = url.split("?")[0]
            return url

        # Quitar query string
        if "?" in url:
            url = url.split("?")[0]

        if "/consulta-lote" in url and not url.endswith(".wsdl"):
            url = url + ".wsdl"

        # Quitar .wsdl si termina en eso (excepto para recibe-lote y consulta-ruc)
        # Quitar .wsdl si termina en eso (excepto para recibe-lote, consulta-ruc y consulta-lote)
        if url.endswith(".wsdl") and (
            "/recibe-lote.wsdl" not in url
            and "/consulta-ruc.wsdl" not in url
            and "/consulta-lote.wsdl" not in url
        ):
            url = url[:-5]  # quitar ".wsdl"

        return url

    def _get_artifacts_dir(self) -> Path:
        """Resolve artifacts directory (env override) and ensure it exists."""
        raw_dir = (
            os.getenv("SIFEN_ARTIFACTS_DIR")
            or os.getenv("ARTIFACTS_DIR")
            or os.getenv("SIFEN_ARTIFACTS_PATH")
        )
        return resolve_artifacts_dir(raw_dir)

    def _prepare_request_artifacts(
        self,
        *,
        artifacts_dir: Path,
        label: str,
        post_url: str,
        headers: Dict[str, str],
        soap_bytes: bytes,
    ) -> Path:
        """Persist request payload and curl helper for a specific attempt."""
        request_path = artifacts_dir / f"{label}_request.xml"
        try:
            request_path.write_bytes(soap_bytes)
        except Exception as exc:
            logger.warning(f"No se pudo guardar request SOAP ({label}): {exc}")

        curl_path = artifacts_dir / f"{label}_curl.sh"
        try:
            self._write_curl_script(curl_path, post_url, headers, request_path)
        except Exception as exc:
            logger.warning(f"No se pudo generar curl helper ({label}): {exc}")

        return request_path

    @staticmethod
    def _write_curl_script(
        curl_path: Path,
        post_url: str,
        headers: Dict[str, str],
        request_path: Path,
    ) -> None:
        lines: List[str] = [
            "#!/bin/bash",
            "set -euo pipefail",
            "",
            "# Reemplaza estos paths antes de usar el curl equivalente",
            'CERT_PATH="${CERT_PATH:-/path/to/your_cert.pem}"',
            'KEY_PATH="${KEY_PATH:-/path/to/your_key.pem}"',
            "",
            "curl -v -X POST \\",
            f"  '{post_url}' \\",
        ]

        for key, value in headers.items():
            if value is None:
                continue
            lines.append(f"  -H '{key}: {value}' \\")

        lines.extend(
            [
                f"  --data-binary '@{request_path}' \\",
                "  --cert \"$CERT_PATH\" \\",
                "  --key \"$KEY_PATH\"",
            ]
        )

        curl_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            curl_path.chmod(0o700)
        except Exception:
            pass

    def _persist_http_attempt(
        self,
        *,
        artifacts_dir: Path,
        label: str,
        service_key: str,
        post_url: str,
        soap_version: str,
        headers: Dict[str, str],
        request_path: Path,
        response_status: Optional[int],
        response_headers: Optional[Dict[str, Any]],
        response_body: Optional[bytes],
        error_message: Optional[str],
    ) -> None:
        meta_path = artifacts_dir / f"{label}_http.json"
        response_path = artifacts_dir / f"{label}_response.xml"

        if response_body is not None:
            try:
                response_path.write_bytes(response_body)
            except Exception as exc:
                logger.warning(f"No se pudo guardar response SOAP ({label}): {exc}")
        elif not response_path.exists():
            try:
                if error_message:
                    response_path.write_text(f"NO_RESPONSE\nERROR: {error_message}\n", encoding="utf-8")
                else:
                    response_path.write_text("", encoding="utf-8")
            except Exception:
                pass

        metadata: Dict[str, Any] = {
            "timestamp": datetime.now().isoformat(),
            "service": service_key,
            "post_url": post_url,
            "soap_version": soap_version,
            "content_type": headers.get("Content-Type"),
            "soapaction_header": headers.get("SOAPAction"),
            "request_path": str(request_path),
            "response_path": str(response_path),
            "headers": headers,
        }

        if response_status is not None:
            metadata["http_status"] = response_status
        if response_headers is not None:
            metadata["response_headers"] = response_headers
        if error_message:
            metadata["error"] = error_message

        try:
            meta_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as exc:
            logger.warning(f"No se pudo guardar metadata HTTP ({label}): {exc}")

    def _extract_soap_address_from_wsdl(self, wsdl_url: str) -> Optional[str]:
        """Parsea el SOAP address (location) desde el XML del WSDL usando mTLS.

        Busca soap12:address/@location primero, luego soap:address/@location como fallback.
        Normaliza el WSDL URL y el endpoint resultante.
        """
        import lxml.etree as etree  # noqa: F401
        
        # Normalizar WSDL URL antes del GET
        wsdl_url_final = self._normalize_wsdl_url(wsdl_url)
        logger.debug(f"WSDL URL normalizada: {wsdl_url} -> {wsdl_url_final}")

        session = (
            self.transport.session if hasattr(self, "transport") else Session()
        )
        
        # Implementar retries para WSDL GET con parámetros configurables
        max_attempts = int(os.getenv("SIFEN_SOAP_MAX_RETRIES", "3")) + 1  # +1 para el intento inicial
        base_delay = float(os.getenv("SIFEN_SOAP_BACKOFF_BASE", "0.6"))
        max_delay = float(os.getenv("SIFEN_SOAP_BACKOFF_MAX", "8.0"))
        
        last_exception = None
        resp = None
        
        for attempt in range(1, max_attempts + 1):
            try:
                logger.debug(f"Descargando WSDL (intento {attempt}/{max_attempts}): {wsdl_url_final}")
                resp = session.get(
                    wsdl_url_final, timeout=(self.connect_timeout, self.read_timeout)
                )
                # Si llegamos aquí, el GET fue exitoso
                break
                
            except (requests.exceptions.ConnectionError, 
                    requests.exceptions.Timeout,
                    requests.exceptions.HTTPError,
                    ConnectionResetError) as e:
                last_exception = e
                
                if attempt < max_attempts:
                    # Calcular delay con backoff exponencial y jitter
                    delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
                    jitter = delay * 0.25 * (random.random() * 2 - 1)
                    final_delay = delay + jitter
                    
                    logger.warning(
                        f"Error descargando WSDL (intento {attempt}/{max_attempts}): {e}. "
                        f"Reintentando en {final_delay:.2f}s..."
                    )
                    time.sleep(final_delay)
                else:
                    logger.error(f"No se pudo descargar WSDL después de {max_attempts} intentos: {e}")
                    
        # Si todos los intentos fallaron
        if resp is None:
            logger.warning(
                f"No se pudo extraer SOAP address desde WSDL después de {max_attempts} intentos: {last_exception}"
            )
            return None

        logger.debug(
            f"WSDL GET: status={resp.status_code}, len={len(resp.content or b'')}"
        )

        if resp.status_code != 200 or not resp.content:
            logger.warning(
                f"WSDL vacío o error HTTP al obtener WSDL: {wsdl_url_final} "
                f"(status={resp.status_code}, len={len(resp.content or b'')})"
            )
            return None

        wsdl_xml = etree.fromstring(resp.content)

        ns = {
            "wsdl": "http://schemas.xmlsoap.org/wsdl/",
            "soap12": "http://schemas.xmlsoap.org/wsdl/soap12/",
            "soap": "http://schemas.xmlsoap.org/wsdl/soap/",
        }

        location_raw = None
        # Preferir soap12:address
        addr = wsdl_xml.find(".//soap12:address", namespaces=ns)
        if addr is not None:
            location_raw = addr.get("location")
        else:
            # Fallback a soap:address
            addr = wsdl_xml.find(".//soap:address", namespaces=ns)
            if addr is not None:
                location_raw = addr.get("location")

        if location_raw:
            # En modo Roshka, NO normalizar el endpoint (usar exacto del WSDL)
            if self.roshka_compat:
                logger.debug(
                    f"SOAP endpoint extraído (Roshka compat, sin normalizar): "
                    f"{location_raw}"
                )
                return location_raw
            else:
                endpoint_normalized = self._normalize_soap_endpoint(location_raw)
                logger.debug(
                    f"SOAP endpoint extraído: location_raw={location_raw}, "
                    f"endpoint_normalized={endpoint_normalized}"
                )
                return endpoint_normalized

        return None

    # ---------------------------------------------------------------------
    # Transport (mTLS)
    # ---------------------------------------------------------------------
    def _create_transport(self) -> Any:  # Transport de Zeep
        """Crea el transporte Zeep con requests.Session configurada para mTLS."""
        session = Session()
        
        # Usar helper unificado get_mtls_config()
        cert_path, key_or_password, is_pem_mode = get_mtls_config()
        
        # Validar que no sea self-signed
        validate_no_self_signed(cert_path, "mTLS")
        if is_pem_mode and key_or_password:
            validate_no_self_signed(key_or_password, "mTLS")
        
        if is_pem_mode:
            # Modo PEM: requests necesita (cert_path, key_path)
            session.cert = (cert_path, key_or_password)  # key_or_password es la key PEM
            self._temp_pem_files = None
            # Guardar artifact con certificados resueltos
            try:
                artifacts_dir = os.getenv("SIFEN_ARTIFACTS_DIR") or os.getenv("SIFEN_ARTIFACTS_PATH") or "artifacts"
                save_resolved_certs_artifact(
                    artifacts_dir=artifacts_dir,
                    cert_path=cert_path,
                    key_path=key_or_password,
                    note="mTLS PEM"
                )
            except Exception as e:
                logger.warning(f"No se pudo guardar artifact de certificados: {e}")
            
            logger.info(
                f"Usando mTLS modo PEM: cert={Path(cert_path).name}, key={Path(key_or_password).name}"
            )
        else:
            # Modo P12: convertir a PEM temporales para requests/urllib3
            try:
                cert_pem_path, key_pem_path = p12_to_temp_pem_files(
                    cert_path, key_or_password  # key_or_password es el password del P12
                )
                self._temp_pem_files = (cert_pem_path, key_pem_path)
                session.cert = (cert_pem_path, key_pem_path)
                
                # Guardar artifact con certificados resueltos
                try:
                    artifacts_dir = os.getenv("SIFEN_ARTIFACTS_DIR") or os.getenv("SIFEN_ARTIFACTS_PATH") or "artifacts"
                    save_resolved_certs_artifact(
                        artifacts_dir=artifacts_dir,
                        cert_path=cert_path,
                        key_path=key_pem_path,
                        note="mTLS P12->PEM"
                    )
                except Exception as e:
                    logger.warning(f"No se pudo guardar artifact de certificados: {e}")
                
                # Debug: guardar paths si está habilitado
                debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
                if debug_enabled:
                    logger.info(
                        f"mTLS: Certificado P12 convertido a PEM temporales: "
                        f"cert={cert_pem_path}, key={key_pem_path}"
                    )
                else:
                    logger.info(
                        f"Certificado P12 convertido a PEM temporales para mTLS: "
                        f"{Path(cert_pem_path).name}, {Path(key_pem_path).name}"
                    )
            except PKCS12Error as e:
                raise SifenClientError(
                    f"Error al convertir certificado P12 a PEM: {e}"
                ) from e
            except Exception as e:
                raise SifenClientError(
                    f"Error inesperado al procesar certificado: {e}"
                ) from e

        # SSL verify
        session.verify = True
        ca_bundle_path = getattr(self.config, "ca_bundle_path", None)
        if ca_bundle_path:
            session.verify = ca_bundle_path

        session.mount("https://", HTTPAdapter())

        # Transport está disponible porque ZEEP_AVAILABLE es True (verificado en __init__)
        # timeout puede ser int o tuple (connect, read) según requests/zeep
        return Transport(  # type: ignore[arg-type]
            session=session,
            timeout=(self.connect_timeout, self.read_timeout),  # type: ignore[arg-type]
            operation_timeout=self.read_timeout,
        )

    # ---------------------------------------------------------------------
    # Zeep client (solo para WSDL/address)
    # ---------------------------------------------------------------------
    def _validate_wsdl_access(self, wsdl_url: str) -> None:
        """
        Valida que el WSDL sea accesible con mTLS antes de intentar usarlo.
        
        Detecta errores comunes:
        - Redirects a /vdesk/hangup.php3 (indica falta/fracaso de certificado mTLS)
        - Body vacío
        - Respuestas que no son XML
        
        Args:
            wsdl_url: URL del WSDL a validar
            
        Raises:
            RuntimeError: Si el WSDL no es accesible o hay problemas con mTLS
        """
        debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
        
        try:
            session = self.transport.session if hasattr(self, "transport") else Session()
            resp = session.get(
                wsdl_url,
                timeout=(self.connect_timeout, self.read_timeout),
                allow_redirects=False  # No seguir redirects automáticamente para detectarlos
            )
            
            # Verificar redirects
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location", "")
                if "/vdesk/" in location or "/vdesk/" in resp.url:
                    error_msg = (
                        f"No se pudo acceder al WSDL de consulta-lote. "
                        f"Probable falta/fracaso de certificado mTLS (redirect a /vdesk/hangup.php3). "
                        f"URL: {wsdl_url}, Status: {resp.status_code}, Location: {location}"
                    )
                    if debug_enabled:
                        logger.error(f"WSDL validation failed: {error_msg}")
                        logger.error(f"Response headers: {dict(resp.headers)}")
                    raise RuntimeError(error_msg)
                else:
                    # Redirect legítimo, seguir
                    resp = session.get(
                        resp.headers.get("Location", wsdl_url),
                        timeout=(self.connect_timeout, self.read_timeout)
                    )
            
            # Verificar status code
            if resp.status_code != 200:
                error_msg = (
                    f"WSDL no accesible: HTTP {resp.status_code}. "
                    f"URL: {wsdl_url}"
                )
                if debug_enabled:
                    logger.error(f"WSDL validation failed: {error_msg}")
                    logger.error(f"Response body (first 200 chars): {resp.text[:200]}")
                raise RuntimeError(error_msg)
            
            # Verificar que el body no esté vacío
            content = resp.content or b""
            if len(content) == 0:
                error_msg = (
                    f"WSDL vacío (body length=0). "
                    f"Probable falta/fracaso de certificado mTLS. "
                    f"URL: {wsdl_url}"
                )
                if debug_enabled:
                    logger.error(f"WSDL validation failed: {error_msg}")
                raise RuntimeError(error_msg)
            
            # Verificar que parezca XML (debe empezar con <?xml o <definitions)
            content_str = content.decode("utf-8", errors="ignore").strip()
            if not (content_str.startswith("<?xml") or content_str.startswith("<definitions")):
                error_msg = (
                    f"WSDL no parece ser XML válido. "
                    f"URL: {wsdl_url}, "
                    f"Primeros 200 chars: {content_str[:200]}"
                )
                if debug_enabled:
                    logger.error(f"WSDL validation failed: {error_msg}")
                raise RuntimeError(error_msg)
            
            if debug_enabled:
                logger.info(f"WSDL validation OK: {wsdl_url}, status={resp.status_code}, len={len(content)}")
                
        except RuntimeError:
            # Re-lanzar RuntimeError tal cual
            raise
        except Exception as e:
            # Otros errores (timeout, conexión, etc.)
            error_msg = (
                f"Error al validar acceso al WSDL: {e}. "
                f"URL: {wsdl_url}. "
                f"Verifique certificado mTLS y conectividad."
            )
            if debug_enabled:
                logger.error(f"WSDL validation exception: {error_msg}")
            raise RuntimeError(error_msg) from e

    def _get_client(self, service_key: str) -> Any:  # Client de Zeep
        if service_key in self.clients:
            return self.clients[service_key]

        wsdl_url = self.config.get_soap_service_url(service_key)
        wsdl_url_final = self._normalize_wsdl_url(wsdl_url)

        logger.info(f"Cargando WSDL para servicio '{service_key}': {wsdl_url_final}")

        # Validar acceso al WSDL antes de intentar cargarlo con zeep
        try:
            self._validate_wsdl_access(wsdl_url_final)
        except RuntimeError as e:
            raise SifenClientError(f"Error al validar WSDL: {e}") from e

        try:
            plugins = []
            debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")

            if debug_enabled:
                from zeep.plugins import HistoryPlugin

                history = HistoryPlugin()
                plugins.append(history)
                if not hasattr(self, "_history_plugins"):
                    self._history_plugins = {}
                self._history_plugins[service_key] = history

            # Client y Settings están disponibles porque ZEEP_AVAILABLE es True (verificado en __init__)
            client = Client(  # type: ignore
                wsdl=wsdl_url_final,
                transport=self.transport,
                settings=Settings(strict=False, xml_huge_tree=True),  # type: ignore
                plugins=plugins or None,
            )
            self.clients[service_key] = client

            # Extraer SOAP address desde zeep (si se puede)
            try:
                addr = None
                if hasattr(client.service, "_binding_options"):
                    addr = client.service._binding_options.get("address")
                if not addr:
                    for service in client.wsdl.services.values():
                        for port in service.ports.values():
                            if hasattr(port, "binding") and hasattr(
                                port.binding, "options"
                            ):
                                addr = port.binding.options.get("address")
                                if addr:
                                    break
                        if addr:
                            break
                if addr:
                    # En modo Roshka, NO normalizar el endpoint
                    if self.roshka_compat:
                        self._soap_address[service_key] = addr
                        logger.info(
                            f"SOAP address para '{service_key}' (desde Zeep, Roshka compat): {addr}"
                        )
                    else:
                        addr_normalized = self._normalize_soap_endpoint(addr)
                        self._soap_address[service_key] = addr_normalized
                        logger.info(
                            f"SOAP address para '{service_key}' (desde Zeep): {addr} -> {addr_normalized}"
                        )
            except Exception as e:
                logger.debug(f"No se pudo leer SOAP address desde Zeep: {e}")

            # Fallback: parsear WSDL (por si zeep no lo expone)
            if service_key not in self._soap_address:
                addr = self._extract_soap_address_from_wsdl(wsdl_url_final)
                if addr:
                    self._soap_address[service_key] = addr
                    logger.info(
                        f"SOAP address para '{service_key}' (desde WSDL): {addr}"
                    )

            return client

        except Exception as e:
            raise SifenClientError(
                f"Error al crear cliente SOAP para {service_key}: {e}"
            )

    # ---------------------------------------------------------------------
    # Size validation
    # ---------------------------------------------------------------------
    def _validate_size(self, service: str, content: str) -> None:
        size = len(content.encode("utf-8"))
        limit = SIZE_LIMITS.get(service)
        if limit and size > limit:
            error_code = {
                "siRecepDE": "0200",
                "rEnvioLote": "0270",
                "siConsRUC": "0460",
            }.get(service, "0000")
            raise SifenSizeLimitError(service, size, limit, error_code)

    # ---------------------------------------------------------------------
    # XML namespace normalization (para DE) - usa namespace DEFAULT sin prefijos
    # ---------------------------------------------------------------------
    def _clone_de_to_sifen_default_ns(self, de_original: Any) -> Any:
        """Clona el DE para que TODOS los elementos SIFEN estén en namespace default (sin prefijo).

        Reglas CRÍTICAS:
        - Root DE: <DE xmlns="http://ekuatia.set.gov.py/sifen/xsd" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        - TODOS los elementos SIFEN (incluyendo los que venían sin namespace) deben quedar en SIFEN_NS
        - NUNCA crear elementos sin namespace (etree.Element(local_name)) para elementos que deben ser SIFEN
        - Los elementos de firma (DS_NS) mantienen prefijo ds:
        - Esto evita que lxml inserte xmlns="" (que causa error "Prefijo [null] no reconocido")
        """
        import lxml.etree as etree  # noqa: F401

        def split_tag(tag: str) -> tuple[Optional[str], str]:
            if "}" in tag and tag.startswith("{"):
                ns, local = tag[1:].split("}", 1)
                return ns, local
            return None, tag

        def clone(node: Any, is_root: bool = False) -> Any:
            node_ns, local = split_tag(node.tag)

            # Regla CRÍTICA: si viene sin namespace (None), TRATARLO COMO SIFEN_NS
            # Esto evita que queden elementos en namespace None que generen xmlns=""
            if node_ns is None:
                node_ns = SIFEN_NS

            # Crear elemento según su namespace
            if node_ns == SIFEN_NS:
                # Elementos SIFEN: usar namespace DEFAULT (sin prefijo)
                if is_root:
                    # Root DE: declarar namespace default SIFEN y prefijo ds para firma
                    nsmap = {None: SIFEN_NS, "ds": DS_NS}
                    new_elem = etree.Element(f"{{{SIFEN_NS}}}{local}", nsmap=nsmap)
                else:
                    # Elementos hijos SIFEN: usar namespace SIFEN sin prefijo (heredan xmlns default)
                    # IMPORTANTE: siempre usar {SIFEN_NS}local, NUNCA solo local
                    new_elem = etree.Element(f"{{{SIFEN_NS}}}{local}")
            elif node_ns == DS_NS:
                # Elementos de firma: usar prefijo ds:
                new_elem = etree.Element(f"{{{DS_NS}}}{local}")
            else:
                # Otros namespaces: preservar (pero asegurar que no sea None)
                if node_ns:
                    new_elem = etree.Element(f"{{{node_ns}}}{local}")
                else:
                    # Fallback: si por alguna razón node_ns sigue siendo None, tratarlo como SIFEN
                    new_elem = etree.Element(f"{{{SIFEN_NS}}}{local}")

            # Copiar atributos (preservar namespaces en atributos si los tienen)
            for attr_name, attr_value in node.attrib.items():
                new_elem.set(attr_name, attr_value)

            # Copiar texto y tail
            if node.text:
                new_elem.text = node.text
            if node.tail:
                new_elem.tail = node.tail

            # Copiar hijos recursivamente
            for child in node:
                if isinstance(child, etree._Element):
                    cloned_child = clone(child, is_root=False)
                    new_elem.append(cloned_child)

            return new_elem

        return clone(de_original, is_root=True)

    def _extract_r_envi_de_substring(self, xml_sirecepde: str) -> bytes:
        """Extrae el rEnviDe original preservando namespaces y firma.

        Si no se puede extraer substring exacto, usa parse+serialize preservando estructura.
        """
        import lxml.etree as etree  # noqa: F401

        # Remover XML declaration si existe
        xml_clean = xml_sirecepde.strip()
        if xml_clean.startswith("<?xml"):
            end_decl = xml_clean.find("?>")
            if end_decl != -1:
                xml_clean = xml_clean[end_decl + 2 :].strip()

        # Intentar extraer substring exacto primero
        try:
            import re

            # Buscar <rEnviDe (puede tener prefijo o namespace)
            match = re.search(r"<[^>]*rEnviDe[^>]*>", xml_clean, re.IGNORECASE)
            if match:
                start_pos = match.start()
                # Buscar el cierre balanceado (método simple: contar tags)
                # Esto es aproximado pero funciona para la mayoría de casos
                depth = 0
                i = start_pos
                while i < len(xml_clean):
                    if xml_clean[i : i + 2] == "</":
                        # Buscar si es </rEnviDe
                        tag_end = xml_clean.find(">", i)
                        if tag_end != -1:
                            closing_tag = xml_clean[i + 2 : tag_end].strip()
                            if "rEnviDe" in closing_tag:
                                depth -= 1
                                if depth == 0:
                                    end_pos = tag_end + 1
                                    substring = xml_clean[start_pos:end_pos]
                                    # Validar que es XML válido
                                    etree.fromstring(substring.encode("utf-8"))
                                    return substring.encode("utf-8")
                    elif xml_clean[i] == "<" and xml_clean[i + 1] != "/":
                        # Opening tag
                        tag_end = xml_clean.find(">", i)
                        if tag_end != -1:
                            opening_tag = xml_clean[i : tag_end + 1]
                            if "rEnviDe" in opening_tag:
                                depth += 1
                            i = tag_end + 1
                            continue
                    i += 1
        except Exception as e:
            logger.debug(
                f"No se pudo extraer substring exacto, usando parse+serialize: {e}"
            )

        # Fallback: parsear y serializar preservando estructura
        try:
            root = etree.fromstring(xml_clean.encode("utf-8"))
            # Serializar solo el root (rEnviDe) sin declaration, preservando namespaces
            r_envi_de_bytes = etree.tostring(
                root,
                xml_declaration=False,
                encoding="UTF-8",
                pretty_print=False,
                method="xml",
            )
            return r_envi_de_bytes
        except Exception as e:
            raise SifenClientError(f"Error al extraer rEnviDe del XML: {e}")

    def _ensure_rde_wrapper(self, xml_root: Any) -> Any:
        """Asegura que xDE contenga rDE como wrapper de DE.

        Si xDE tiene un hijo directo <DE> (sin rDE), crea <rDE> con:
        - Namespace SIFEN como default (sin prefijo)
        - xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        - xsi:schemaLocation="http://ekuatia.set.gov.py/sifen/xsd siRecepDE_v150.xsd"
        - Mueve el <DE> dentro de <rDE>

        Si ya existe <rDE>, no hace nada.

        Args:
            xml_root: Elemento rEnviDe parseado (etree._Element)

        Returns:
            El mismo xml_root modificado (o sin cambios si ya tenía rDE)

        Validación:
            # Limpiar artifacts anteriores
            rm -f artifacts/soap_last_sent*.xml artifacts/soap_last_received*.xml

            # Enviar SOAP con modo Roshka
            SIFEN_DEBUG_SOAP=1 SIFEN_SOAP_COMPAT=roshka python -u -m tools.send_sirecepde --env test --xml latest

            # Verificar que xDE contiene rDE
            grep -n "<xDE><rDE" artifacts/soap_last_sent.xml

            # El error debería cambiar (idealmente dejar de ser 0100/0160)
        """
        import lxml.etree as etree  # noqa: F401

        def get_local_name(tag: str) -> str:
            """Extrae el nombre local de un tag (sin namespace)."""
            if "}" in tag and tag.startswith("{"):
                return tag.split("}")[1]
            return tag

        def get_namespace(tag: str) -> Optional[str]:
            """Extrae el namespace de un tag."""
            if "}" in tag and tag.startswith("{"):
                return tag.split("}")[0][1:]
            return None

        # Buscar xDE dentro de rEnviDe
        x_de = None
        for child in xml_root:
            if get_local_name(child.tag) == "xDE":
                x_de = child
                break

        if x_de is None:
            logger.warning(
                "No se encontró xDE en rEnviDe, no se puede agregar rDE wrapper"
            )
            return xml_root

        # Verificar si ya tiene rDE
        has_rde = False
        for child in x_de:
            if get_local_name(child.tag) == "rDE":
                has_rde = True
                break

        if has_rde:
            logger.debug("xDE ya contiene rDE, no se modifica")
            return xml_root

        # Buscar DE dentro de xDE
        de_elem = None
        for child in x_de:
            if get_local_name(child.tag) == "DE":
                de_elem = child
                break

        if de_elem is None:
            logger.warning("No se encontró DE en xDE, no se puede agregar rDE wrapper")
            return xml_root

        # Crear rDE con namespace default SIFEN
        # nsmap: None -> SIFEN_NS (default), "xsi" -> XSI_NS
        r_de = etree.Element(
            f"{{{SIFEN_NS}}}rDE", nsmap={None: SIFEN_NS, "xsi": XSI_NS}
        )

        # Agregar xsi:schemaLocation (debe estar en namespace XSI)
        r_de.set(f"{{{XSI_NS}}}schemaLocation", SIFEN_SCHEMA_LOCATION)

        # Mover DE dentro de rDE (esto preserva todo el contenido, incluyendo ds:Signature)
        r_de.append(de_elem)

        # Reemplazar contenido de xDE con rDE
        # Primero limpiar xDE
        x_de.clear()
        # Luego agregar rDE
        x_de.append(r_de)

        logger.info("Agregado wrapper rDE alrededor de DE en xDE")
        return xml_root

    def _build_raw_envelope_with_original_content(
        self, r_envi_de_bytes: bytes, action: Optional[str] = None
    ) -> bytes:
        """Construye SOAP 1.2 envelope embebiendo el rEnviDe original sin modificar.

        Esto preserva namespaces, prefijos y firma digital intactos.
        
        Args:
            r_envi_de_bytes: XML bytes a embeder (rEnviDe, rEnvioLote, rEnviConsLoteDe, etc.)
            action: Acción SOAP (opcional, para headers)
        """
        import lxml.etree as etree  # noqa: F401

        # Envelope SOAP 1.2
        envelope = etree.Element(f"{{{SOAP_NS}}}Envelope", nsmap={"soap-env": SOAP_NS})
        body = etree.SubElement(envelope, f"{{{SOAP_NS}}}Body")

        # Parsear el rEnviDe original y embederlo directamente (sin modificar)
        # Esto preserva namespaces y estructura original
        r_envi_de_elem = etree.fromstring(r_envi_de_bytes)
        body.append(r_envi_de_elem)

        # Serializar
        return etree.tostring(
            envelope, xml_declaration=True, encoding="UTF-8", pretty_print=False
        )

    # ---------------------------------------------------------------------
    # SOAP Helpers
    # ---------------------------------------------------------------------
    def _soap_headers(self, version: str, action: str) -> dict:
        """
        Genera headers HTTP según versión SOAP.
        
        Args:
            version: "1.2" o "1.1"
            action: Nombre de la acción SOAP (ej: "rEnvioLote")
            
        Returns:
            Dict con headers HTTP
        """
        if version == "1.2":
            return {
                "Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"',
                "Accept": "application/soap+xml, text/xml, */*",
            }
        elif version == "1.1":
            return {
                "Content-Type": "text/xml; charset=utf-8",
                "Accept": "text/xml, */*",
            }
        else:
            raise ValueError(f"Versión SOAP no soportada: {version}")

    def _wrap_body(self, payload_xml: bytes, wrapper: bool, action: str, ns: str) -> bytes:
        """
        Envuelve el payload XML en un Body SOAP, opcionalmente con wrapper de operación.
        
        Args:
            payload_xml: XML del payload (ej: <rEnvioLote>...</rEnvioLote>)
            wrapper: Si True, envuelve en <action>...</action>
            action: Nombre de la acción (ej: "rEnvioLote")
            ns: Namespace para el wrapper (ej: SIFEN_NS)
            
        Returns:
            Bytes del Body SOAP
        """
        if etree is None:
            raise SifenClientError("lxml.etree no está disponible")
        
        if wrapper:
            # Crear wrapper <action xmlns="ns"> + payload + </action>
            wrapper_elem = etree.Element(etree.QName(ns, action), nsmap={None: ns})  # type: ignore
            payload_root = etree.fromstring(payload_xml)  # type: ignore
            wrapper_elem.append(payload_root)
            return etree.tostring(wrapper_elem, xml_declaration=False, encoding="UTF-8")  # type: ignore
        else:
            # Retornar payload directo
            return payload_xml

    def _build_soap_envelope(
        self,
        body_content: bytes,
        version: str,
        header_msg_did: Optional[str] = None,
    ) -> bytes:
        """
        Construye un envelope SOAP 1.1 o 1.2.
        
        Args:
            body_content: Contenido del Body (ya envuelto si corresponde)
            version: "1.2" o "1.1"
            header_msg_did: dId para HeaderMsg (opcional)
            
        Returns:
            Bytes del envelope SOAP completo
        """
        if etree is None:
            raise SifenClientError("lxml.etree no está disponible")
        
        if version == "1.2":
            envelope_ns = "http://www.w3.org/2003/05/soap-envelope"
            prefix = "soap-env"
        elif version == "1.1":
            envelope_ns = "http://schemas.xmlsoap.org/soap/envelope/"
            prefix = "soap"
        else:
            raise ValueError(f"Versión SOAP no soportada: {version}")

        envelope = etree.Element(f"{{{envelope_ns}}}Envelope", nsmap={prefix: envelope_ns})  # type: ignore
        
        # Header (si hay HeaderMsg)
        if header_msg_did is not None:
            header = etree.SubElement(envelope, f"{{{envelope_ns}}}Header")  # type: ignore
            header_msg = etree.SubElement(  # type: ignore
                header, f"{{{SIFEN_NS}}}HeaderMsg", nsmap={None: SIFEN_NS}
            )
            header_d_id = etree.SubElement(header_msg, f"{{{SIFEN_NS}}}dId")  # type: ignore
            header_d_id.text = str(header_msg_did)
        else:
            # Header vacío para SOAP 1.2
            if version == "1.2":
                header = etree.SubElement(envelope, f"{{{envelope_ns}}}Header")  # type: ignore
        
        # Body
        body = etree.SubElement(envelope, f"{{{envelope_ns}}}Body")  # type: ignore
        body_root = etree.fromstring(body_content)  # type: ignore
        body.append(body_root)
        
        return etree.tostring(envelope, xml_declaration=True, encoding="UTF-8", pretty_print=False)  # type: ignore

    def _save_http_debug(
        self,
        post_url: str,
        original_url: str,
        version: str,
        action: str,
        headers: dict,
        soap_bytes: bytes,
        response_status: Optional[int] = None,
        response_headers: Optional[dict] = None,
        response_body: Optional[bytes] = None,
        mtls_cert_path: Optional[str] = None,
        mtls_key_path: Optional[str] = None,
        wsdl_url: Optional[str] = None,
        soap_address: Optional[str] = None,
        response_root: Optional[str] = None,
        body_has_wrapper_sireceplotede: Optional[bool] = None,
        body_has_renviolote: Optional[bool] = None,
        body_root_localname: Optional[str] = None,
        body_root_ns: Optional[str] = None,
        body_wrapper_localname: Optional[str] = None,
        body_wrapper_ns: Optional[str] = None,
        body_preview: Optional[str] = None,
        wsdl_info: Optional[Dict[str, Any]] = None,
        body_root_qname_sent: Optional[str] = None,
        body_children_sent: Optional[list] = None,
        xde_base64_len: Optional[int] = None,
        xde_base64_has_whitespace: Optional[bool] = None,
        suffix: str = "",
        exception_class: Optional[str] = None,
        exception_message: Optional[str] = None,
    ):
        """
        Guarda debug completo de un intento HTTP/SOAP.
        """
        import hashlib
        
        debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
        if not debug_enabled and response_status == 200:
            return  # Solo guardar en error si no está habilitado
        
        try:
            debug_file = Path("artifacts") / f"soap_last_http_debug{suffix}.txt"
            debug_file.parent.mkdir(exist_ok=True)
            
            soap_sha256 = hashlib.sha256(soap_bytes).hexdigest()
            soap_str = soap_bytes.decode("utf-8", errors="replace")
            
            with open(debug_file, "w", encoding="utf-8") as f:
                # Try label si está presente (para attempt matrix)
                if suffix and suffix.startswith("_try"):
                    try_label = suffix.replace("_", "")
                    f.write(f"TRY_LABEL={try_label}\n")
                
                # Información de excepción si existe
                if exception_class:
                    f.write(f"EXCEPTION_CLASS={exception_class}\n")
                if exception_message:
                    # Truncar mensaje largo
                    exc_msg = exception_message[:500] if len(exception_message) > 500 else exception_message
                    f.write(f"EXCEPTION_MESSAGE={exc_msg}\n")
                
                # Campos WSDL-driven
                if wsdl_info:
                    f.write(f"WSDL_TARGET_NAMESPACE={wsdl_info.get('target_namespace', '')}\n")
                    f.write(f"WSDL_OPERATION_NAME={wsdl_info.get('operation_name', '')}\n")
                    f.write(f"WSDL_INPUT_ELEMENT={wsdl_info.get('body_root_qname', {}).get('namespace', '')}:{wsdl_info.get('body_root_qname', {}).get('localname', '')}\n")
                    f.write(f"WSDL_SOAP_ACTION={wsdl_info.get('soap_action', '')}\n")
                    f.write(f"WSDL_ACTION_REQUIRED={wsdl_info.get('action_required', False)}\n")
                    f.write(f"WSDL_IS_WRAPPED={wsdl_info.get('is_wrapped', False)}\n")
                    f.write(f"WSDL_STYLE={wsdl_info.get('style', '')}\n")
                    f.write(f"WSDL_USE={wsdl_info.get('use', '')}\n")
                if wsdl_url:
                    f.write(f"WSDL_URL={wsdl_url}\n")
                if soap_address:
                    f.write(f"WSDL_SOAP_ADDRESS={soap_address}\n")
                f.write(f"POST_URL_USED={post_url}\n")
                f.write(f"SOAP_VERSION_USED={version}\n")
                f.write(f"ORIGINAL_URL={original_url}\n")
                f.write(f"ACTION_HEADER_USED={action}\n")
                
                # Headers FINALES (usar el dict headers tal cual se envió)
                content_type = headers.get("Content-Type", "")
                soap_action_header = headers.get("SOAPAction", "")
                f.write(f"CONTENT_TYPE_USED={content_type}\n")
                f.write(f"SOAP_ACTION_HEADER_USED={soap_action_header}\n")
                
                # Volcar headers finales completos (ordenados por key)
                f.write("\n---- REQUEST_HEADERS_FINAL ----\n")
                for key in sorted(headers.keys()):
                    f.write(f"{key}: {headers[key]}\n")
                f.write("---- END REQUEST_HEADERS_FINAL ----\n")
                
                # Body structure
                if body_root_qname_sent:
                    f.write(f"BODY_ROOT_QNAME_SENT={body_root_qname_sent}\n")
                if body_children_sent:
                    f.write(f"BODY_CHILDREN_SENT={','.join(body_children_sent)}\n")
                # Consulta lote: orden XSD y orden enviado
                consulta_xsd_order = getattr(self, '_consulta_xsd_order_debug', None)
                if consulta_xsd_order is not None:
                    f.write(f"CONSULTA_XSD_ORDER={','.join(consulta_xsd_order) if consulta_xsd_order else '(none)'}\n")
                consulta_body_order = getattr(self, '_consulta_body_order_debug', None)
                if consulta_body_order is not None:
                    f.write(f"BODY_CHILDREN_ORDER_SENT={','.join(consulta_body_order) if consulta_body_order else '(none)'}\n")
                if xde_base64_len is not None:
                    f.write(f"XDE_BASE64_LEN={xde_base64_len}\n")
                if xde_base64_has_whitespace is not None:
                    f.write(f"XDE_BASE64_HAS_WHITESPACE={'yes' if xde_base64_has_whitespace else 'no'}\n")
                
                f.write(f"HEADERS={headers}\n")
                if mtls_cert_path:
                    f.write(f"MTLS_CERT={mtls_cert_path}\n")
                if mtls_key_path:
                    f.write(f"MTLS_KEY={mtls_key_path}\n")
                f.write(f"SOAP_BYTES_SHA256={soap_sha256}\n")
                f.write(f"SOAP_BYTES_LEN={len(soap_bytes)}\n")
                f.write("---- SOAP BEGIN ----\n")
                f.write(soap_str)
                f.write("\n---- SOAP END ----\n")
                
                if response_status is not None:
                    f.write(f"HTTP_STATUS={response_status}\n")
                    f.write(f"RESPONSE_STATUS={response_status}\n")  # Mantener compatibilidad
                elif exception_class:
                    f.write(f"HTTP_STATUS=(exception)\n")
                if response_headers:
                    f.write(f"RESPONSE_HEADERS={response_headers}\n")
                if response_root:
                    f.write(f"RESPONSE_ROOT={response_root}\n")
                if response_body:
                    resp_body_str = response_body.decode("utf-8", errors="replace")
                    f.write(f"RESPONSE_FIRST_200={resp_body_str[:200]}\n")
                    # Extraer primeros 300 chars del body para análisis
                    try:
                        import lxml.etree as etree
                        soap_body = etree.fromstring(response_body)
                        body_str = etree.tostring(soap_body, encoding="unicode", method="xml")
                        f.write(f"FIRST_300_CHARS_OF_BODY={body_str[:300]}\n")
                    except Exception:
                        f.write(f"FIRST_300_CHARS_OF_BODY={resp_body_str[:300]}\n")
                elif not response_body and soap_bytes:
                    # Si no hay response_body pero hay request, mostrar primeros 300 chars del request
                    soap_str_preview = soap_bytes.decode("utf-8", errors="replace")[:300]
                    f.write(f"FIRST_300_CHARS_OF_BODY={soap_str_preview}\n")
                if body_has_wrapper_sireceplotede is not None:
                    f.write(f"BODY_HAS_WRAPPER_SIRECEPLOTEDE={body_has_wrapper_sireceplotede}\n")
                if body_has_renviolote is not None:
                    f.write(f"BODY_HAS_RENVIOLOTE={body_has_renviolote}\n")
                if body_root_localname:
                    f.write(f"BODY_ROOT_LOCALNAME={body_root_localname}\n")
                if body_root_ns:
                    f.write(f"BODY_ROOT_NS={body_root_ns}\n")
                if body_wrapper_localname:
                    f.write(f"BODY_WRAPPER_LOCALNAME={body_wrapper_localname}\n")
                if body_wrapper_ns:
                    f.write(f"BODY_WRAPPER_NS={body_wrapper_ns}\n")
                if body_preview:
                    # Redactar xDE si contiene base64 muy largo
                    preview = body_preview
                    if "<xDE>" in preview:
                        import re
                        preview = re.sub(r'(<xDE>)[^<]*(</xDE>)', r'\1__BASE64_REDACTED__\2', preview, flags=re.DOTALL)
                    f.write(f"FIRST_300_CHARS_OF_BODY={preview}\n")
                if response_body:
                    body_str = response_body.decode("utf-8", errors="replace")
                    f.write(f"RESPONSE_BODY_FIRST_2000={body_str[:2000]}\n")
            
            logger.debug(f"HTTP debug guardado en: {debug_file}")
            
            # Guardar headers finales en archivo separado
            try:
                headers_file = Path("artifacts") / f"soap_last_request_headers{suffix}.txt"
                with open(headers_file, "w", encoding="utf-8") as hf:
                    for key in sorted(headers.keys()):
                        hf.write(f"{key}: {headers[key]}\n")
                logger.debug(f"Headers guardados en: {headers_file}")
            except Exception as e2:
                logger.warning(f"Error al guardar headers: {e2}")
            
            # Guardar también los archivos XML (request y response)
            # IMPORTANTE: soap_bytes es el request REAL que se envió (con xDE completo)
            # Solo redactar para guardar en artifacts, NUNCA modificar soap_bytes antes del POST
            try:
                debug_soap = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
                
                # 1. Guardar request REAL si SIFEN_DEBUG_SOAP=1
                if debug_soap:
                    request_file_real = Path("artifacts") / f"soap_last_request_REAL{suffix}.xml"
                    request_file_real.write_bytes(soap_bytes)  # REAL sin redactar
                    logger.debug(f"SOAP request REAL guardado en: {request_file_real}")
                
                # 2. Redactar xDE solo para el archivo normal (artifacts/soap_last_request.xml)
                request_xml = soap_bytes.decode("utf-8", errors="replace")
                if "<xDE>" in request_xml or "<xsd:xDE>" in request_xml:
                    import re
                    # Buscar contenido de xDE y reemplazar con placeholder incluyendo longitud
                    def replace_xde(match):
                        prefix = match.group(1)
                        content = match.group(2)
                        suffix = match.group(3)
                        content_len = len(content.strip())
                        return f'{prefix}__BASE64_REDACTED_LEN_{content_len}__{suffix}'
                    
                    request_xml = re.sub(
                        r'(<xDE[^>]*>)([^<]+)(</xDE>)',
                        replace_xde,
                        request_xml,
                        flags=re.DOTALL
                    )
                    request_xml = re.sub(
                        r'(<xsd:xDE[^>]*>)([^<]+)(</xsd:xDE>)',
                        replace_xde,
                        request_xml,
                        flags=re.DOTALL
                    )
                
                request_file = Path("artifacts") / f"soap_last_request{suffix}.xml"
                request_file.write_text(request_xml, encoding="utf-8")
                logger.debug(f"SOAP request (redactado) guardado en: {request_file}")
                
                # Response XML (si existe, o crear placeholder si hay excepción)
                response_file = Path("artifacts") / f"soap_last_response{suffix}.xml"
                if response_body:
                    response_file.write_bytes(response_body)
                    logger.debug(f"SOAP response guardado en: {response_file}")
                elif exception_class:
                    # Crear placeholder XML para excepciones
                    import xml.etree.ElementTree as ET
                    error_root = ET.Element("error")
                    ET.SubElement(error_root, "exception_class").text = exception_class
                    if exception_message:
                        ET.SubElement(error_root, "exception_message").text = exception_message[:500]
                    error_xml = ET.tostring(error_root, encoding="unicode")
                    response_file.write_text(
                        f'<?xml version="1.0" encoding="UTF-8"?>\n{error_xml}',
                        encoding="utf-8"
                    )
                    logger.debug(f"SOAP response placeholder (exception) guardado en: {response_file}")
            except Exception as e2:
                logger.warning(f"Error al guardar archivos XML de debug: {e2}")
                
        except Exception as e:
            logger.warning(f"Error al guardar HTTP debug: {e}")

    # ---------------------------------------------------------------------
    # RAW POST (requests)
    # ---------------------------------------------------------------------
    def _post_raw_soap(self, service_key: str, soap_bytes: bytes, soap_version: str = "1.2") -> bytes:
        if service_key not in self._soap_address:
            self._get_client(service_key)  # intenta poblar _soap_address

        if service_key not in self._soap_address:
            raise SifenClientError(
                f"No se encontró SOAP address para servicio '{service_key}'. Verifique que el WSDL se cargó correctamente."
            )

        url = self._soap_address[service_key]
        logger.info(f"Enviando SOAP a endpoint: {url}")
        session = self.transport.session

        # Headers según modo de compatibilidad
        if self.roshka_compat:
            # Roshka usa: application/xml; charset=utf-8 (sin action, sin SOAPAction)
            headers = {
                "Content-Type": "application/xml; charset=utf-8",
            }
        else:
            # Headers SOAP 1.2 estándar: action va en Content-Type
            # Pero para recibe_lote, soapActionRequired=false, así que NO enviamos action
            # Determinar la acción según el servicio
            if service_key == "recibe_lote":
                # WSDL indica soapAction="" y soapActionRequired="false"
                # Por lo tanto, Content-Type sin action param
                headers = {
                    "Content-Type": "application/soap+xml; charset=utf-8",
                }
            elif service_key == "consulta_lote":
                action = "siConsLoteDE"
                headers = {
                    "Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"',
                }
            else:
                action = "rEnviDe"  # default para "recibe"
                headers = {
                    "Content-Type": f'application/soap+xml; charset=utf-8; action="{action}"',
                }

        artifacts_dir = self._get_artifacts_dir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Implementar retries con backoff exponencial y jitter (configurable)
        max_attempts = int(os.getenv("SIFEN_SOAP_MAX_RETRIES", "3")) + 1  # +1 para el intento inicial
        base_delay = float(os.getenv("SIFEN_SOAP_BACKOFF_BASE", "0.6"))
        max_delay = float(os.getenv("SIFEN_SOAP_BACKOFF_MAX", "8.0"))
        
        last_exception = None
        resp = None
        
        for attempt in range(1, max_attempts + 1):
            attempt_label = f"{service_key}_{timestamp}_try{attempt}"
            request_path = self._prepare_request_artifacts(
                artifacts_dir=artifacts_dir,
                label=attempt_label,
                post_url=url,
                headers=headers,
                soap_bytes=soap_bytes,
            )
            response_status: Optional[int] = None
            response_headers: Optional[Dict[str, Any]] = None
            response_body: Optional[bytes] = None
            error_message: Optional[str] = None
            try:
                logger.debug(f"Intento {attempt}/{max_attempts} para POST a {url}")
                resp = session.post(
                    url,
                    data=soap_bytes,
                    headers=headers,
                    cert=(self.config.cert_pem_path, self.config.key_pem_path),
                    verify=self.config.ca_bundle_path,
                    timeout=(self.connect_timeout, self.read_timeout),
                )
                response_status = resp.status_code
                response_headers = dict(resp.headers)
                response_body = resp.content
                self._persist_http_attempt(
                    artifacts_dir=artifacts_dir,
                    label=attempt_label,
                    service_key=service_key,
                    post_url=url,
                    soap_version=soap_version,
                    headers=headers,
                    request_path=request_path,
                    response_status=response_status,
                    response_headers=response_headers,
                    response_body=response_body,
                    error_message=None,
                )

                # Si llegamos aquí, el POST fue exitoso (no hubo error de conexión)
                break
                
            except (requests.exceptions.ConnectionError, 
                    requests.exceptions.Timeout,
                    requests.exceptions.HTTPError,
                    ConnectionResetError) as e:
                last_exception = e
                error_message = str(e)
                self._persist_http_attempt(
                    artifacts_dir=artifacts_dir,
                    label=attempt_label,
                    service_key=service_key,
                    post_url=url,
                    soap_version=soap_version,
                    headers=headers,
                    request_path=request_path,
                    response_status=response_status,
                    response_headers=response_headers,
                    response_body=response_body,
                    error_message=error_message,
                )
                
                if attempt < max_attempts:
                    # Calcular delay con backoff exponencial y jitter
                    delay = min(base_delay * (2 ** (attempt - 1)), max_delay)
                    # Agregar jitter aleatorio (±25%)
                    jitter = delay * 0.25 * (random.random() * 2 - 1)
                    final_delay = delay + jitter
                    
                    logger.warning(
                        f"Error de conexión (intento {attempt}/{max_attempts}): {e}. "
                        f"Reintentando en {final_delay:.2f}s..."
                    )
                    time.sleep(final_delay)
                else:
                    logger.error(f"Todos los intentos fallaron. Último error: {e}")
                    
        # Si todos los intentos fallaron, lanzar excepción
        if resp is None:
            raise SifenClientError(
                f"Error de conexión después de {max_attempts} intentos: {last_exception}"
            ) from last_exception
        
        # Persistir intento final si el status code no fue exitoso
        if resp.status_code != 200:
            self._persist_http_attempt(
                artifacts_dir=artifacts_dir,
                label=f"{service_key}_{timestamp}_final",
                service_key=service_key,
                post_url=url,
                soap_version=soap_version,
                headers=headers,
                request_path=request_path,
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=resp.content,
                error_message=f"HTTP {resp.status_code}",
            )

        # Guardar JSON de routing para evidencia (solo para recibe_lote)
        if service_key == "recibe_lote":
            self._save_route_probe_json(service_key, url, headers, soap_bytes, resp)
        
        if resp.status_code != 200:
            raise SifenClientError(
                f"Error HTTP {resp.status_code} al enviar SOAP: {resp.text[:500]}"
            )
        return resp.content

    def _save_route_probe_json(
        self,
        service_key: str,
        post_url: str,
        headers: dict,
        soap_bytes: bytes,
        resp: requests.Response,
    ):
        """
        Guarda JSON con evidencia de routing para diagnóstico 0301.
        
        Este método NUNCA debe romper el flujo principal.
        Si falla algo, se loguea warning y se continúa.
        """
        try:
            from pathlib import Path
            import json
            import xml.etree.ElementTree as ET
            from datetime import datetime
            
            out_dir = Path("artifacts")
            out_dir.mkdir(exist_ok=True)
            
            # Parsear response para extraer campos SIFEN
            dCodRes = dMsgRes = dProtConsLote = dTpoProces = None
            
            try:
                if resp.content:
                    resp_root = ET.fromstring(resp.content)
                    # Buscar en namespaces SOAP
                    ns = {
                        'soap': 'http://www.w3.org/2003/05/soap-envelope',
                        's': 'http://ekuatia.set.gov.py/sifen/xsd'
                    }
                    
                    # Buscar dCodRes
                    cod_res = resp_root.find('.//s:dCodRes', ns)
                    if cod_res is not None:
                        dCodRes = cod_res.text
                    
                    # Buscar dMsgRes
                    msg_res = resp_root.find('.//s:dMsgRes', ns)
                    if msg_res is not None:
                        dMsgRes = msg_res.text
                    
                    # Buscar dProtConsLote
                    prot = resp_root.find('.//s:dProtConsLote', ns)
                    if prot is not None:
                        dProtConsLote = prot.text
                    
                    # Buscar dTpoProces
                    tpo = resp_root.find('.//s:dTpoProces', ns)
                    if tpo is not None:
                        dTpoProces = tpo.text
            except Exception as e:
                logger.debug(f"No se pudo parsear response para routing JSON: {e}")
            
            # Detectar SOAP body root y namespace
            soap_body_root = "unknown"
            soap_body_ns = "unknown"
            try:
                if soap_bytes:
                    soap_root = ET.fromstring(soap_bytes)
                    body = soap_root.find('.//{http://www.w3.org/2003/05/soap-envelope}Body')
                    if body is not None and len(body) > 0:
                        first_child = body[0]
                        soap_body_root = first_child.tag.split('}')[-1] if '}' in first_child.tag else first_child.tag
                        soap_body_ns = first_child.tag.split('}')[0][1:] if '}' in first_child.tag and first_child.tag.startswith('{') else "none"
            except Exception as e:
                logger.debug(f"No se pudo parsear SOAP body para routing JSON: {e}")
            
            # Extraer action de headers si existe
            action_param = None
            content_type = headers.get('Content-Type', '')
            if 'action=' in content_type:
                # Extraer action="..." del Content-Type
                import re
                match = re.search(r'action="([^"]*)"', content_type)
                if match:
                    action_param = match.group(1)
            
            # Construir JSON
            route_data = {
                "timestamp": datetime.now().isoformat(),
                "env": "prod" if "prod" in post_url.lower() or "sifen.set.gov.py" in post_url.lower() else "test",
                "wsdl_url": self.config.get_soap_service_url(service_key),
                "post_url_final": post_url,
                "headers_final": headers,
                "action_param": action_param,
                "soap_body_root_localname": soap_body_root,
                "soap_body_namespace": soap_body_ns,
                "soap_sent_preview": soap_bytes.decode('utf-8', errors='replace')[:500] + "..." if len(soap_bytes) > 500 else soap_bytes.decode('utf-8', errors='replace'),
                "response": {
                    "status_code": resp.status_code,
                    "dCodRes": dCodRes,
                    "dMsgRes": dMsgRes,
                    "dProtConsLote": dProtConsLote,
                    "dTpoProces": dTpoProces
                }
            }
            
            # Guardar con timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]
            json_file = out_dir / f"route_probe_recibe_lote_{timestamp}.json"
            json_file.write_text(json.dumps(route_data, indent=2, ensure_ascii=False), encoding='utf-8')
            logger.debug(f"Route probe JSON guardado en: {json_file}")
            
        except Exception as e:
            logger.warning(f"No se pudo guardar route probe JSON (ignorado): {e}")

    def _save_raw_soap_debug(
        self,
        soap_bytes: bytes,
        response_bytes: Optional[bytes] = None,
        suffix: str = "",
    ):
        """
        Guarda SOAP RAW enviado/recibido para debugging.

        IMPORTANTE: Este método NUNCA debe romper el flujo principal.
        Si falla algo en el debug, se loguea warning y se continúa.
        """
        debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
        if not debug_enabled:
            return

        try:
            from pathlib import Path

            out_dir = Path("artifacts")
            out_dir.mkdir(exist_ok=True)

            # Guardar SOAP enviado
            sent_file = out_dir / f"soap_last_sent{suffix}.xml"
            sent_file.write_bytes(soap_bytes)
            logger.debug(f"SOAP RAW enviado guardado en: {sent_file}")

            # Guardar respuesta si existe
            if response_bytes is not None:
                received_file = out_dir / f"soap_last_received{suffix}.xml"
                received_file.write_bytes(response_bytes)
                logger.debug(f"SOAP RAW recibido guardado en: {received_file}")

            # Validaciones ligeras (NO deben lanzar excepciones)
            try:
                soap_str = soap_bytes.decode("utf-8", errors="replace")

                # 1) xmlns="" es CRÍTICO: causa error "Prefijo [null] no reconocido"
                if 'xmlns=""' in soap_str:
                    logger.warning(
                        "DEBUG SOAP: CRÍTICO - Se detectó 'xmlns=\"\"' en el SOAP enviado. "
                        "Esto causa error 'Prefijo [null] no reconocido' en SIFEN."
                    )

                # 2) ns0 no permitido (validación simple con 'in', no regex)
                if "ns0:" in soap_str:
                    logger.warning(
                        "DEBUG SOAP: Se detectó prefijo 'ns0:' en el SOAP enviado (no permitido)."
                    )

                # 3) xsns no permitido (ya no usamos prefijos)
                if "<xsns:" in soap_str:
                    logger.warning(
                        "DEBUG SOAP: Se detectó prefijo 'xsns:' en el SOAP enviado (no permitido)."
                    )

                # 4) Detectar namespaces raros (helper interno)
                self._debug_detect_rare_namespaces(soap_bytes)

            except Exception as e:
                logger.warning(f"DEBUG SOAP: validación interna falló (ignorado): {e}")

        except Exception as e:
            logger.warning(f"No se pudo guardar SOAP RAW para debug (ignorado): {e}")

    def _debug_detect_rare_namespaces(self, soap_bytes: bytes) -> None:
        """Helper para detectar namespaces raros en el SOAP (solo logs, no excepciones)."""
        try:
            import lxml.etree as etree  # noqa: F401

            # Parsear el SOAP
            root = etree.fromstring(soap_bytes)

            # Namespaces esperados (SOAP 1.1 y 1.2, SIFEN, XMLDSig)
            SOAP_NS_11 = "http://schemas.xmlsoap.org/soap/envelope/"
            expected_ns = {SOAP_NS, SOAP_NS_11, SIFEN_NS, DS_NS}

            # Recopilar elementos con namespaces raros
            rare_elements = []
            for elem in root.iter():
                if hasattr(elem, "tag"):
                    tag = elem.tag
                    if "}" in tag:
                        ns = tag.split("}")[0][1:]  # Extraer namespace
                        local = tag.split("}")[1]
                        if ns not in expected_ns:
                            rare_elements.append((local, ns))
                            if len(rare_elements) >= 20:
                                break

            # Loggear si hay namespaces raros
            if rare_elements:
                unique_rare = list(set(rare_elements))[:20]
                logger.warning(
                    f"DEBUG SOAP: Se detectaron elementos con namespaces no esperados "
                    f"(primeros {len(unique_rare)}): {unique_rare}"
                )

        except Exception as e:
            # NUNCA lanzar excepción desde debug
            logger.debug(f"DEBUG SOAP: No se pudo analizar namespaces (ignorado): {e}")

    # ---------------------------------------------------------------------
    # Parsing de respuesta (XML)
    # ---------------------------------------------------------------------
    def _parse_recepcion_response_from_xml(self, xml_root: Any) -> Dict[str, Any]:
        import lxml.etree as etree  # noqa: F401

        result = {
            "ok": False,
            "codigo_estado": None,
            "codigo_respuesta": None,
            "mensaje": None,
            "cdc": None,
            "estado": None,
            "raw_response": None,
            "parsed_fields": {},
        }

        def find_text(xpath_expr: str) -> Optional[str]:
            try:
                nodes = xml_root.xpath(xpath_expr)
                if nodes:
                    val = nodes[0].text
                    return val.strip() if val else None
            except Exception:
                return None
            return None

        # Busca por local-name para tolerar prefijos
        result["codigo_respuesta"] = find_text('//*[local-name()="dCodRes"]')
        result["mensaje"] = find_text('//*[local-name()="dMsgRes"]')
        result["estado"] = find_text('//*[local-name()="dEstRes"]')
        result["cdc"] = find_text('//*[local-name()="Id"]') or find_text(
            '//*[local-name()="cdc"]'
        )
        # Para respuestas de lote, extraer también dProtConsLote y dTpoProces
        result["d_prot_cons_lote"] = find_text('//*[local-name()="dProtConsLote"]')
        result["d_tpo_proces"] = find_text('//*[local-name()="dTpoProces"]')

        result["parsed_fields"] = {"xml": etree.tostring(xml_root, encoding="unicode")}

        codigo = (result.get("codigo_respuesta") or "").strip()
        result["ok"] = codigo in ("0200", "0300", "0301", "0302")

        return result

    # ---------------------------------------------------------------------
    # Public API
    # ---------------------------------------------------------------------
    def recepcion_de(self, xml_sirecepde: str) -> Dict[str, Any]:
        """Envía un rEnviDe (siRecepDE) a SIFEN vía SOAP 1.2 (RAW).

        IMPORTANTE: NO re-serializa el XML para evitar romper firma/namespaces.
        Extrae el substring original del rEnviDe y lo embede directamente en el envelope SOAP.
        """
        service = "siRecepDE"

        if isinstance(xml_sirecepde, bytes):
            xml_sirecepde = xml_sirecepde.decode("utf-8")

        self._validate_size(service, xml_sirecepde)

        # Validación mínima: verificar que el root sea rEnviDe (solo para validar estructura)
        import lxml.etree as etree  # noqa: F401

        try:
            xml_root = etree.fromstring(xml_sirecepde.encode("utf-8"))
        except Exception as e:
            raise SifenClientError(f"Error al parsear XML siRecepDE: {e}")

        # Verificar root (con o sin namespace)
        expected_tag = f"{{{SIFEN_NS}}}rEnviDe"
        if xml_root.tag != expected_tag and xml_root.tag != "rEnviDe":
            try:
                if etree.QName(xml_root).localname != "rEnviDe":
                    raise SifenClientError(
                        f"XML root debe ser 'rEnviDe', encontrado: {xml_root.tag}"
                    )
            except Exception:
                raise SifenClientError(
                    f"XML root debe ser 'rEnviDe', encontrado: {xml_root.tag}"
                )

        # Asegurar que xDE contenga rDE como wrapper de DE (estructura esperada por SIFEN)
        xml_root = self._ensure_rde_wrapper(xml_root)

        # Re-serializar el XML modificado para extraer el substring
        # Esto preserva namespaces y estructura, incluyendo el nuevo rDE
        r_envi_de_content = etree.tostring(
            xml_root,
            xml_declaration=False,
            encoding="UTF-8",
            pretty_print=False,
            method="xml",
        )

        # Construir envelope SOAP 1.2 con el rEnviDe original embebido
        soap_bytes = self._build_raw_envelope_with_original_content(r_envi_de_content)

        response_bytes = None
        try:
            response_bytes = self._post_raw_soap("recibe", soap_bytes)
            self._save_raw_soap_debug(soap_bytes, response_bytes, suffix="")
        except Exception:
            self._save_raw_soap_debug(soap_bytes, None, suffix="")
            raise

        try:
            resp_root = etree.fromstring(response_bytes)
        except Exception as e:
            raise SifenClientError(f"Error al parsear respuesta XML de SIFEN: {e}")

        return self._parse_recepcion_response_from_xml(resp_root)

    def _save_dump_http_artifacts(
        self,
        artifacts_dir: Path,
        sent_headers: Dict[str, str],
        sent_xml: str,
        received_status: int,
        received_headers: Dict[str, str],
        received_body: str
    ) -> None:
        """
        Guarda artefactos HTTP completos para diagnóstico cuando --dump-http está activo.
        
        Args:
            artifacts_dir: Directorio donde guardar
            sent_headers: Headers HTTP enviados
            sent_xml: XML SOAP enviado
            received_status: Status code HTTP recibido
            received_headers: Headers HTTP recibidos
            received_body: Body HTTP recibido
        """
        import json
        from datetime import datetime
        
        try:
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # 1. SOAP raw sent
            sent_file = artifacts_dir / f"soap_raw_sent_lote_{timestamp}.xml"
            sent_file.write_text(sent_xml, encoding="utf-8")
            
            # 2. HTTP headers sent
            headers_sent_file = artifacts_dir / f"http_headers_sent_lote_{timestamp}.json"
            headers_sent_file.write_text(
                json.dumps(sent_headers, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            
            # 3. HTTP response headers
            headers_resp_file = artifacts_dir / f"http_response_headers_lote_{timestamp}.json"
            headers_resp_file.write_text(
                json.dumps({
                    "status_code": received_status,
                    "headers": received_headers
                }, ensure_ascii=False, indent=2),
                encoding="utf-8"
            )
            
            # 4. SOAP raw response
            resp_file = artifacts_dir / f"soap_raw_response_lote_{timestamp}.xml"
            resp_file.write_text(received_body, encoding="utf-8")
            
        except Exception as e:
            logger.warning(f"Error al guardar dump HTTP artifacts: {e}")

    def _assert_request_is_valid(self, soap_bytes: bytes, artifacts_dir: Path) -> None:
        """
        Valida el request SOAP antes de enviarlo (HARD FAIL si está mal).
        Guarda información de diagnóstico en artifacts/diag_*.
        """
        import base64
        import zipfile
        import hashlib
        from io import BytesIO
        
        try:
            # Parsear SOAP body
            soap_root = etree.fromstring(soap_bytes)
            
            # Extraer Body
            soap_env_ns = "http://www.w3.org/2003/05/soap-envelope"
            body_elem = soap_root.find(f".//{{{soap_env_ns}}}Body")
            if body_elem is None:
                raise RuntimeError("SOAP Body no encontrado")
            
            # Buscar rEnvioLote (puede estar directamente en Body o dentro de un wrapper)
            r_envio_lote = None
            for child in body_elem:
                if etree.QName(child).localname == "rEnvioLote":
                    r_envio_lote = child
                    break
                # Si hay wrapper, buscar dentro
                for grandchild in child:
                    if etree.QName(grandchild).localname == "rEnvioLote":
                        r_envio_lote = grandchild
                        break
                if r_envio_lote:
                    break
            
            if r_envio_lote is None:
                raise RuntimeError("rEnvioLote no encontrado en SOAP Body")
            
            # 1. Extraer dId
            d_id_elem = r_envio_lote.find(f".//{{{SIFEN_NS}}}dId")
            if d_id_elem is None:
                d_id_elem = r_envio_lote.find(".//dId")
            
            d_id_text = d_id_elem.text if d_id_elem is not None and d_id_elem.text else "NOT_FOUND"
            artifacts_dir.joinpath("diag_dId.txt").write_text(
                f"dId: {d_id_text}\n",
                encoding="utf-8"
            )
            
            # 2. Extraer xDE
            xde_elem = r_envio_lote.find(f".//{{{SIFEN_NS}}}xDE")
            if xde_elem is None:
                xde_elem = r_envio_lote.find(".//xDE")
            
            if xde_elem is None or not xde_elem.text:
                raise RuntimeError("xDE no encontrado o vacío en rEnvioLote")
            
            xde_base64 = xde_elem.text.strip()
            xde_len = len(xde_base64)
            xde_sha256 = hashlib.sha256(xde_base64.encode("utf-8")).hexdigest()
            
            artifacts_dir.joinpath("diag_xDE.txt").write_text(
                f"xDE len: {xde_len}\n"
                f"xDE sha256: {xde_sha256}\n"
                f"xDE preview (first 100 chars): {xde_base64[:100]}...\n",
                encoding="utf-8"
            )
            
            # 3. Validar que xDE es base64 decodificable
            try:
                # Remover espacios/linebreaks del base64
                import re
                xde_base64_clean = re.sub(r'\s+', '', xde_base64)
                zip_bytes = base64.b64decode(xde_base64_clean)
            except Exception as e:
                raise RuntimeError(f"xDE no es Base64 válido: {e}")
            
            # 4. Validar que decodifica a ZIP válido
            try:
                with zipfile.ZipFile(BytesIO(zip_bytes), mode='r') as zf:
                    namelist = zf.namelist()
                    if "lote.xml" not in namelist:
                        raise RuntimeError(f"ZIP no contiene 'lote.xml'. Archivos encontrados: {namelist}")
                    
                    # 5. Extraer lote.xml
                    lote_xml_bytes = zf.read("lote.xml")
                    artifacts_dir.joinpath("diag_lote_from_request.xml").write_bytes(lote_xml_bytes)
                    
                    # 6. Validar estructura de lote.xml
                    try:
                        lote_root = etree.fromstring(lote_xml_bytes)
                        root_localname = etree.QName(lote_root).localname
                        root_ns = None
                        if "}" in lote_root.tag:
                            root_ns = lote_root.tag.split("}", 1)[0][1:]
                        
                        children_local = [etree.QName(c).localname for c in list(lote_root)]
                        rde_count = len([c for c in list(lote_root) if etree.QName(c).localname == "rDE"])
                        xde_count = len([c for c in list(lote_root) if etree.QName(c).localname == "xDE"])
                        
                        artifacts_dir.joinpath("diag_lote_structure.txt").write_text(
                            f"root localname: {root_localname}\n"
                            f"root namespace: {root_ns}\n"
                            f"children(local): {children_local}\n"
                            f"rDE count: {rde_count}\n"
                            f"xDE count: {xde_count}\n"
                            f"lote.xml bytes: {len(lote_xml_bytes)}\n",
                            encoding="utf-8"
                        )
                        
                        # 7. Extraer primer rDE/DE y validar firma
                        if rde_count > 0:
                            rde_elem = None
                            for c in list(lote_root):
                                if etree.QName(c).localname == "rDE":
                                    rde_elem = c
                                    break
                            
                            if rde_elem is not None:
                                # Buscar DE dentro de rDE
                                de_elem = None
                                for elem in rde_elem.iter():
                                    if etree.QName(elem).localname == "DE":
                                        de_elem = elem
                                        break
                                
                                if de_elem is not None:
                                    de_id = de_elem.get("Id") or de_elem.get("id")
                                    artifacts_dir.joinpath("diag_de_id.txt").write_text(
                                        f"DE Id: {de_id or 'NOT_FOUND'}\n",
                                        encoding="utf-8"
                                    )
                                    
                                    # Buscar Signature dentro de rDE (como hermano de DE)
                                    # Según solución error 0160, la Signature debe estar dentro de rDE
                                    sig_elem = None
                                    for child in rde_elem:
                                        if etree.QName(child).localname == "Signature" and child.tag.split("}", 1)[0][1:] == DS_NS:
                                            sig_elem = child
                                            break
                                    
                                    if sig_elem is None:
                                        # Fallback: buscar en todo rDE
                                        for elem in rde_elem.iter():
                                            elem_ns = None
                                            if "}" in elem.tag:
                                                elem_ns = elem.tag.split("}", 1)[0][1:]
                                            if etree.QName(elem).localname == "Signature" and elem_ns == DS_NS:
                                                sig_elem = elem
                                                break
                                    
                                    if sig_elem is None:
                                        raise RuntimeError("No se encontró ds:Signature dentro de rDE")
                                    
                                    # Buscar Reference URI
                                    ref_elem = sig_elem.find(f".//{{{DS_NS}}}Reference")
                                    if ref_elem is not None:
                                        ref_uri = ref_elem.get("URI") or ref_elem.get("uri")
                                        artifacts_dir.joinpath("diag_sig_reference_uri.txt").write_text(
                                            f"Reference URI: {ref_uri or 'NOT_FOUND'}\n"
                                            f"DE Id: {de_id or 'NOT_FOUND'}\n"
                                            f"Expected URI: #{de_id if de_id else 'MISSING_DE_ID'}\n"
                                            f"Match: {'YES' if ref_uri == f'#{de_id}' else 'NO'}\n",
                                            encoding="utf-8"
                                        )
                                        
                                        if de_id and ref_uri != f"#{de_id}":
                                            raise RuntimeError(
                                                f"Reference URI no coincide con DE Id: URI={ref_uri}, DE@Id={de_id}"
                                            )
                                    else:
                                        raise RuntimeError("No se encontró Reference dentro de Signature")
                                else:
                                    raise RuntimeError("No se encontró DE dentro de rDE")
                            else:
                                raise RuntimeError("No se pudo encontrar rDE en lote.xml")
                        else:
                            raise RuntimeError(f"lote.xml no contiene rDE. xDE count: {xde_count}")
                        
                        # Validar que NO contiene xDE en lote.xml
                        if xde_count > 0:
                            raise RuntimeError(f"lote.xml NO debe contener xDE (pertenece al SOAP). Encontrado: {xde_count}")
                        
                    except etree.XMLSyntaxError as e:
                        raise RuntimeError(f"lote.xml no es well-formed XML: {e}")
                    
            except zipfile.BadZipFile as e:
                raise RuntimeError(f"xDE no decodifica a ZIP válido: {e}")
            
            # 8. Comparar con request REAL guardado (si existe)
            try:
                real_file = artifacts_dir / "soap_last_request_REAL.xml"
                if real_file.exists():
                    real_bytes = real_file.read_bytes()
                    real_root = etree.fromstring(real_bytes)
                    real_xde = real_root.find(f".//{{{SIFEN_NS}}}xDE")
                    if real_xde is None:
                        real_xde = real_root.find(".//xDE")
                    
                    if real_xde is not None and real_xde.text:
                        real_xde_sha256 = hashlib.sha256(real_xde.text.strip().encode("utf-8")).hexdigest()
                        match = "YES" if real_xde_sha256 == xde_sha256 else "NO"
                        artifacts_dir.joinpath("diag_compare.txt").write_text(
                            f"SENT xDE sha256: {xde_sha256}\n"
                            f"REAL xDE sha256: {real_xde_sha256}\n"
                            f"Match: {match}\n",
                            encoding="utf-8"
                        )
            except Exception as e:
                # No crítico si falla la comparación
                logger.debug(f"Error al comparar con REAL: {e}")
            
        except RuntimeError:
            raise  # Re-raise RuntimeError tal cual
        except Exception as e:
            raise RuntimeError(f"Error al validar request: {e}") from e
    
    def recepcion_lote(self, xml_renvio_lote: str, dump_http: bool = False) -> Dict[str, Any]:
        """Envía un rEnvioLote (rEnvioLote) a SIFEN vía SOAP 1.2 document/literal.

        Formato esperado según guía SIFEN:
        - SOAP 1.2 envelope con Header vacío
        - Body contiene DIRECTAMENTE <xsd:rEnvioLote> (con prefijo xsd, SIN wrapper rEnvioLote)
        - Headers HTTP sin action= en Content-Type
        - Endpoint extraído del WSDL usando mTLS
        """
        service = "rEnvioLote"

        if isinstance(xml_renvio_lote, bytes):
            xml_renvio_lote = xml_renvio_lote.decode("utf-8")

        self._validate_size(service, xml_renvio_lote)

        # Validación mínima: verificar que el root sea rEnvioLote
        import lxml.etree as etree  # noqa: F401

        try:
            xml_root = etree.fromstring(xml_renvio_lote.encode("utf-8"))
        except Exception as e:
            raise SifenClientError(f"Error al parsear XML rEnvioLote: {e}")

        # Verificar root (con o sin namespace)
        expected_tag = f"{{{SIFEN_NS}}}rEnvioLote"
        if xml_root.tag != expected_tag and xml_root.tag != "rEnvioLote":
            try:
                if etree.QName(xml_root).localname != "rEnvioLote":
                    raise SifenClientError(
                        f"XML root debe ser 'rEnvioLote', encontrado: {xml_root.tag}"
                    )
            except Exception:
                raise SifenClientError(
                    f"XML root debe ser 'rEnvioLote', encontrado: {xml_root.tag}"
                )

        # Re-serializar el XML del rEnvioLote (payload)
        r_envio_lote_content = etree.tostring(
            xml_root,
            xml_declaration=False,
            encoding="UTF-8",
            pretty_print=False,
            method="xml",
        )

        # Validaciones locales ANTES de enviar (falla rápido)
        # 1. Extraer xDE (Base64 ZIP) y validar
        xde_elem = xml_root.find(f".//{{{SIFEN_NS}}}xDE")
        if xde_elem is None:
            xde_elem = xml_root.find(".//xDE")
        
        if xde_elem is not None and xde_elem.text:
            import base64
            import zipfile
            import hashlib
            from io import BytesIO
            
            xde_base64 = xde_elem.text.strip()
            
            # Validar que el Base64 no tenga espacios/whitespace extra
            if xde_base64 != xde_elem.text:
                logger.warning("xDE Base64 contiene whitespace extra (será eliminado al decodificar)")
            
            try:
                # Decodificar Base64
                zip_bytes = base64.b64decode(xde_base64)
                zip_sha256 = hashlib.sha256(zip_bytes).hexdigest()
                logger.debug(f"ZIP SHA256: {zip_sha256}")
                print(f"📦 ZIP SHA256: {zip_sha256}")  # Para reproducibilidad
                
                # Descomprimir y verificar que lote.xml existe
                with zipfile.ZipFile(BytesIO(zip_bytes), mode='r') as zf:
                    namelist = zf.namelist()
                    if "lote.xml" not in namelist:
                        raise SifenClientError(f"ZIP no contiene 'lote.xml'. Archivos encontrados: {namelist}")
                    
                    # Leer y parsear lote.xml para verificar que es well-formed
                    lote_xml_bytes = zf.read("lote.xml")
                    try:
                        lote_root = etree.fromstring(lote_xml_bytes)
                        logger.debug(f"lote.xml es well-formed, root: {etree.QName(lote_root).localname}")
                    except etree.XMLSyntaxError as e:
                        raise SifenClientError(f"lote.xml dentro del ZIP no es well-formed XML: {e}")
                
            except zipfile.BadZipFile as e:
                raise SifenClientError(f"xDE no es un ZIP válido: {e}")
            except ValueError as e:
                # base64.b64decode puede lanzar binascii.Error (que es ValueError)
                if "base64" in str(type(e)).lower() or "Invalid base64" in str(e) or "incorrect padding" in str(e).lower():
                    raise SifenClientError(f"xDE no es Base64 válido: {e}")
                raise SifenClientError(f"Error al validar xDE/ZIP: {e}")
            except SifenClientError:
                raise  # Re-raise SifenClientError tal cual
            except Exception as e:
                raise SifenClientError(f"Error al validar xDE/ZIP: {e}")

        # WSDL-driven: inspeccionar WSDL para construir request exacto
        service_key = "recibe_lote"
        wsdl_url = self._normalize_wsdl_url(
            self.config.get_soap_service_url(service_key)
        )
        
        # Inspeccionar WSDL (con cache opcional)
        wsdl_info = None
        env_tag = (getattr(self.config, "env", None) or os.getenv("SIFEN_ENV", "test")).strip().lower()
        wsdl_cache_path = Path(f"/tmp/recibe-lote_{env_tag}.wsdl")
        wsdl_inspected_path = Path("artifacts/wsdl_inspected.json")
        
        if inspect_wsdl is None:
            raise SifenClientError("wsdl_introspect no disponible. Instalar dependencias.")
        
        # Intentar usar WSDL cacheado local si existe
        wsdl_source = wsdl_url
        if wsdl_cache_path.exists():
            try:
                wsdl_info = inspect_wsdl(str(wsdl_cache_path))
                logger.debug(f"Usando WSDL cacheado: {wsdl_cache_path}")
            except Exception as e:
                logger.debug(f"No se pudo usar WSDL cacheado: {e}, usando URL")
        
        # Si no hay cache o falló, intentar desde URL con mTLS
        if wsdl_info is None:
            try:
                # Para descargar WSDL con mTLS, usar el transport session
                session = self.transport.session
                resp_wsdl = session.get(wsdl_url, timeout=(self.connect_timeout, self.read_timeout))
                resp_wsdl.raise_for_status()
                wsdl_content = resp_wsdl.content
                
                # Guardar en cache
                wsdl_cache_path.parent.mkdir(parents=True, exist_ok=True)
                wsdl_cache_path.write_bytes(wsdl_content)
                
                wsdl_info = inspect_wsdl(str(wsdl_cache_path))
            except Exception as e:
                raise SifenClientError(f"Error al inspeccionar WSDL: {e}")
        
        # Guardar información del WSDL inspeccionado
        if save_wsdl_inspection is not None:
            try:
                save_wsdl_inspection(wsdl_info, wsdl_inspected_path)
                
                # 5. Guardar expectativas del WSDL para diagnóstico
                artifacts_dir = Path("artifacts")
                artifacts_dir.mkdir(parents=True, exist_ok=True)
                
                wsdl_expectations = []
                wsdl_expectations.append(f"Operation name: {wsdl_info.get('operation_name', 'NOT_FOUND')}")
                wsdl_expectations.append(f"Body root QName: {wsdl_info.get('body_root_qname', {})}")
                wsdl_expectations.append(f"Is wrapped: {wsdl_info.get('is_wrapped', False)}")
                wsdl_expectations.append(f"SOAP action: {wsdl_info.get('soap_action', 'NOT_FOUND')}")
                wsdl_expectations.append(f"Target namespace: {wsdl_info.get('target_namespace', 'NOT_FOUND')}")
                
                # Intentar leer wsdl_inspected.json para más detalles
                if wsdl_inspected_path.exists():
                    try:
                        import json
                        with open(wsdl_inspected_path, 'r', encoding='utf-8') as f:
                            wsdl_json = json.load(f)
                            wsdl_expectations.append(f"\nWSDL JSON keys: {list(wsdl_json.keys())}")
                            if 'messages' in wsdl_json:
                                wsdl_expectations.append(f"Messages: {list(wsdl_json['messages'].keys())}")
                            if 'port_types' in wsdl_json:
                                wsdl_expectations.append(f"Port types: {list(wsdl_json['port_types'].keys())}")
                    except Exception:
                        pass
                
                artifacts_dir.joinpath("diag_wsdl_expectations.txt").write_text(
                    "\n".join(wsdl_expectations),
                    encoding="utf-8"
                )
            except Exception:
                pass  # No crítico si falla guardar
        
        # Usar información del WSDL para construir request
        # POST URL: siempre usar soap12:address/ del WSDL cacheado (source of truth)
        post_url = None
        try:
            import lxml.etree as _et
            wsdl_xml = wsdl_cache_path.read_bytes()
            wsdl_root = _et.fromstring(wsdl_xml)
            _ns = {
                "wsdl": "http://schemas.xmlsoap.org/wsdl/",
                "soap12": "http://schemas.xmlsoap.org/wsdl/soap12/",
                "soap": "http://schemas.xmlsoap.org/wsdl/soap/",
            }
            addr = wsdl_root.find(".//soap12:address", namespaces=_ns)
            if addr is None:
                addr = wsdl_root.find(".//soap:address", namespaces=_ns)
            if addr is not None and addr.get("location"):
                post_url = addr.get("location").strip()
        except Exception as _e:
            logger.debug(f"No se pudo extraer soap:address del WSDL cacheado: {_e}")

        # Fallback: si no se pudo leer el address, usar WSDL URL sin query
        if not post_url:
            post_url = wsdl_url.split("?")[0]

        # NOTE: post_url YA fue determinado arriba desde soap12:address/@location (NO sobreescribir)
        wsdl_url_clean = wsdl_url.split("?")[0]  # útil para logs/debug si querés
        body_root_qname = wsdl_info["body_root_qname"]
        is_wrapped = wsdl_info["is_wrapped"]
        soap_action = wsdl_info["soap_action"]
        action_required = wsdl_info["action_required"]
        soap_version = wsdl_info["soap_version"]
        target_ns = wsdl_info["target_namespace"]
        
        # Construir envelope SOAP según versión del WSDL
        if soap_version == "1.2":
            soap_env_ns = "http://www.w3.org/2003/05/soap-envelope"
        else:
            soap_env_ns = "http://schemas.xmlsoap.org/soap/envelope/"
        
        envelope = etree.Element(
            f"{{{soap_env_ns}}}Envelope",
            nsmap={"soap": soap_env_ns, "xsd": SIFEN_NS}
        )
        
        # Header vacío
        header = etree.SubElement(envelope, f"{{{soap_env_ns}}}Header")
        
        # Body según estilo (wrapped o bare)
        body = etree.SubElement(envelope, f"{{{soap_env_ns}}}Body")
        
        # Parsear rEnvioLote y reconstruirlo según el WSDL
        r_envio_lote_elem = etree.fromstring(r_envio_lote_content)
        
        if is_wrapped:
            # Wrapped: crear wrapper con nombre de operación, y dentro rEnvioLote
            wrapper = etree.SubElement(
                body,
                etree.QName(target_ns, wsdl_info["operation_name"]),
                nsmap={"tns": target_ns}
            )
            
            # Crear rEnvioLote con prefijo xsd: dentro del wrapper
            r_envio_lote_prefixed = etree.Element(
                etree.QName(SIFEN_NS, "rEnvioLote"),
                nsmap={"xsd": SIFEN_NS}
            )
            
            # Copiar hijos
            for child in r_envio_lote_elem:
                child_local = etree.QName(child).localname
                new_child = etree.SubElement(
                    r_envio_lote_prefixed,
                    etree.QName(SIFEN_NS, child_local)
                )
                new_child.text = child.text
                new_child.tail = child.tail
                for attr_name, attr_value in child.attrib.items():
                    new_child.set(attr_name, attr_value)
            
            wrapper.append(r_envio_lote_prefixed)
        else:
            # Bare: rEnvioLote va directamente en el Body
            r_envio_lote_prefixed = etree.Element(
                etree.QName(body_root_qname["namespace"], body_root_qname["localname"]),
                nsmap={"xsd": body_root_qname["namespace"]}
            )
            
            # Copiar hijos
            for child in r_envio_lote_elem:
                child_local = etree.QName(child).localname
                new_child = etree.SubElement(
                    r_envio_lote_prefixed,
                    etree.QName(SIFEN_NS, child_local)
                )
                new_child.text = child.text
                new_child.tail = child.tail
                for attr_name, attr_value in child.attrib.items():
                    new_child.set(attr_name, attr_value)
            
            body.append(r_envio_lote_prefixed)
        
        # IMPORTANTE: soap_bytes contiene el SOAP REAL con xDE completo (base64 real del ZIP)
        # NUNCA redactar soap_bytes antes del POST - solo redactar para guardar en artifacts
        soap_bytes = etree.tostring(
            envelope, xml_declaration=True, encoding="UTF-8", pretty_print=False
        )
        
        # Headers FINALES (SOAP 1.2 con action para rEnvioLote)
        # IMPORTANTE: Construir UNA sola vez y usar para POST y debug
        headers_final = {
            "Content-Type": "application/soap+xml; charset=utf-8",
            "Accept": "application/soap+xml, text/xml, */*",
        }
        
        # POST con mTLS (la sesión ya tiene cert configurado)
        session = self.transport.session
        
        # Obtener paths de certificado para debug
        mtls_cert_path = None
        mtls_key_path = None
        if hasattr(self, '_temp_pem_files') and self._temp_pem_files:
            mtls_cert_path, mtls_key_path = self._temp_pem_files
        elif session.cert:
            if isinstance(session.cert, tuple):
                mtls_cert_path, mtls_key_path = session.cert
            else:
                mtls_cert_path = session.cert
        
        # SOURCE OF TRUTH: Guardar bytes exactos que se enviarán por HTTP
        artifacts_dir = Path("artifacts")
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        
        # 1. Guardar bytes exactos y XML textual del request que se enviará
        try:
            artifacts_dir.joinpath("soap_last_request_BYTES.bin").write_bytes(soap_bytes)
            artifacts_dir.joinpath("soap_last_request_SENT.xml").write_bytes(soap_bytes)
            logger.debug("Guardado: soap_last_request_BYTES.bin y soap_last_request_SENT.xml")
        except Exception as e:
            logger.warning(f"Error al guardar request bytes: {e}")
        
        # 2. Validar request antes de enviar (HARD FAIL si está mal)
        try:
            self._assert_request_is_valid(soap_bytes, artifacts_dir)
        except Exception as e:
            error_msg = f"VALIDACIÓN DE REQUEST FALLÓ ANTES DE ENVIAR HTTP: {e}"
            logger.error(error_msg)
            # Guardar en diag para diagnóstico
            try:
                artifacts_dir.joinpath("diag_validation_failed.txt").write_text(
                    f"{error_msg}\n\nTraceback:\n{str(e)}",
                    encoding="utf-8"
                )
            except Exception:
                pass
            raise RuntimeError(error_msg) from e
        
        # 3. Marcador antes de enviar HTTP
        try:
            import random
            import uuid
            nonce = str(uuid.uuid4())[:8]
            marker_before = artifacts_dir / "soap_marker_before.txt"
            marker_before.write_text(
                f"timestamp: {time.time()}\n"
                f"nonce: {nonce}\n"
                f"about_to_send: true\n",
                encoding="utf-8"
            )
        except Exception:
            pass
        
        # POST: usar SIEMPRE soap_bytes REAL (con xDE completo, sin redactar)
        try:
            # mTLS: PEM vs P12
            resolved_cert_path = None
            resolved_key_path = None
            temp_pem_files = None

            key_path_env = os.environ.get("SIFEN_KEY_PATH")
            if key_path_env:
                # Modo PEM: cert + key
                resolved_cert_path, resolved_key_path = get_mtls_cert_and_key_paths()
                session.cert = (resolved_cert_path, resolved_key_path)   # ✅ PEM tuple
            else:
                # Modo P12: convertir a PEM temporales para requests/urllib3
                resolved_cert_path, resolved_cert_password = get_mtls_cert_path_and_password()
                try:
                    cert_pem_path, key_pem_path = p12_to_temp_pem_files(
                        resolved_cert_path, resolved_cert_password
                    )
                    temp_pem_files = (cert_pem_path, key_pem_path)
                    session.cert = (cert_pem_path, key_pem_path)
                except PKCS12Error as e:
                    raise SifenClientError(f"Error al convertir P12 a PEM: {e}") from e
            
            resp = session.post(
                post_url,
                data=soap_bytes,  # soap_bytes REAL con xDE completo
                headers=headers_final,  # Usar headers_final único
                timeout=(self.connect_timeout, self.read_timeout),
            )
            
            # Cleanup de archivos PEM temporales si se usaron
            if temp_pem_files:
                try:
                    cleanup_pem_files(temp_pem_files[0], temp_pem_files[1])
                except Exception as e:
                    logger.warning(f"No se pudo limpiar archivos PEM temporales: {e}")
            
            # Dump HTTP completo si está habilitado
            if dump_http:
                self._save_dump_http_artifacts(
                    artifacts_dir=artifacts_dir,
                    sent_headers=headers_final,
                    sent_xml=soap_bytes.decode("utf-8", errors="replace"),
                    received_status=resp.status_code,
                    received_headers=dict(resp.headers),
                    received_body=resp.text
                )
            
            # 4. Marcador después de recibir respuesta
            try:
                marker_after = artifacts_dir / "soap_marker_after.txt"
                marker_after.write_text(
                    f"timestamp: {time.time()}\n"
                    f"nonce: {nonce if 'nonce' in locals() else 'unknown'}\n"
                    f"received: true\n"
                    f"status_code: {resp.status_code}\n",
                    encoding="utf-8"
                )
            except Exception:
                pass
            
            # Parsear respuesta para debug
            resp_root = None
            resp_root_localname = None
            try:
                resp_root = etree.fromstring(resp.content)
                resp_root_localname = etree.QName(resp_root).localname
            except Exception:
                pass
            
            # Extraer información del body para debug (WSDL-driven)
            body_root_qname_sent = f"{body_root_qname['namespace']}:{body_root_qname['localname']}"
            body_children_sent = []
            xde_base64_len = None
            xde_base64_has_whitespace = False
            
            try:
                soap_root = etree.fromstring(soap_bytes)
                body_elem = soap_root.find(f".//{{{soap_env_ns}}}Body")
                if body_elem is not None and len(body_elem) > 0:
                    first_child = body_elem[0]
                    body_root_localname = etree.QName(first_child).localname
                    if "}" in first_child.tag:
                        body_root_ns = first_child.tag.split("}", 1)[0][1:]
                    else:
                        body_root_ns = first_child.nsmap.get(None) or target_ns
                    
                    # Obtener hijos
                    for child in first_child:
                        child_qname = f"{etree.QName(child).namespace}:{etree.QName(child).localname}"
                        body_children_sent.append(child_qname)
                        
                        # Buscar xDE y analizar Base64
                        if etree.QName(child).localname == "xDE" and child.text:
                            xde_base64 = child.text.strip()
                            xde_base64_len = len(xde_base64)
                            xde_base64_has_whitespace = xde_base64 != child.text
            except Exception:
                pass
            
            # Guardar debug con información WSDL-driven (usar headers_final único)
            self._save_http_debug(
                post_url=post_url,
                original_url=wsdl_url,
                version=soap_version,
                action="",  # No action según evidencia externa
                headers=headers_final,  # Usar headers_final único
                soap_bytes=soap_bytes,
                response_status=resp.status_code,
                response_headers=dict(resp.headers),
                response_body=resp.content,
                mtls_cert_path=mtls_cert_path,
                mtls_key_path=mtls_key_path,
                wsdl_url=wsdl_url,
                soap_address=post_url,
                response_root=resp_root_localname,
                wsdl_info=wsdl_info,
                body_root_qname_sent=body_root_qname_sent,
                body_children_sent=body_children_sent,
                xde_base64_len=xde_base64_len,
                xde_base64_has_whitespace=xde_base64_has_whitespace,
            )
            
            # Verificar que la respuesta sea rResEnviLoteDe (no rRetEnviDe)
            # Si viene rRetEnviDe, significa que el servidor enrutó a recepción individual (routing incorrecto)
            resp_body_str = resp.content.decode("utf-8", errors="replace")
            has_r_res_envi_lote_de = "<rResEnviLoteDe" in resp_body_str or "<rResEnviLoteDe" in resp_body_str
            has_r_ret_envi_de = "<rRetEnviDe" in resp_body_str or "<rRetEnviDe" in resp_body_str
            
            if has_r_ret_envi_de and not has_r_res_envi_lote_de:
                # El servidor respondió con rRetEnviDe, lo que indica routing incorrecto
                error_msg = (
                    "Servidor respondió rRetEnviDe; esto indica que NO se enrutó a recibe-lote. "
                    "Revisar action/headers/endpoint. "
                    f"Response preview: {resp_body_str[:500]}"
                )
                self._save_raw_soap_debug(soap_bytes, resp.content, suffix="_lote")
                raise SifenClientError(error_msg)
            
            # Verificar éxito
            is_success = False
            if resp.status_code == 200:
                is_success = True
            else:
                # Verificar si hay respuesta XML válida aunque HTTP != 200
                try:
                    if has_r_res_envi_lote_de or has_r_ret_envi_de or "<dCodRes>" in resp_body_str:
                        is_success = True
                except Exception:
                    pass
            
            if is_success:
                # Guardar SOAP debug adicional
                self._save_raw_soap_debug(soap_bytes, resp.content, suffix="_lote")
                
                if resp_root is None:
                    try:
                        resp_root = etree.fromstring(resp.content)
                    except Exception as e:
                        raise SifenClientError(f"Error al parsear respuesta XML de SIFEN: {e}")
                
                response = self._parse_recepcion_response_from_xml(resp_root)
                
                # Add HTTP metadata to response
                import hashlib
                response_sha256 = hashlib.sha256(resp.content).hexdigest()
                request_sha256 = hashlib.sha256(soap_bytes).hexdigest()
                
                response.update({
                    "post_url": post_url,
                    "wsdl_url": wsdl_url,
                    "soap_version": soap_version,
                    "content_type": headers_final.get("Content-Type"),
                    "http_status": resp.status_code,
                    "sent_headers": headers_final,
                    "received_headers": dict(resp.headers),
                    "request_bytes_len": len(soap_bytes),
                    "request_sha256": request_sha256,
                    "response_bytes_len": len(resp.content),
                    "response_sha256": response_sha256,
                    "response_dCodRes": response.get("codigo_respuesta"),
                    "response_dMsgRes": response.get("mensaje"),
                    "response_dProtConsLote": response.get("d_prot_cons_lote"),
                })
                
                # 7. Resumen final para diagnóstico
                try:
                    # Leer información de diag_* para el resumen
                    d_id_text = "NOT_FOUND"
                    xde_len = "NOT_FOUND"
                    xde_sha256 = "NOT_FOUND"
                    zip_namelist = "NOT_FOUND"
                    lote_root = "NOT_FOUND"
                    rde_count = "NOT_FOUND"
                    xde_count = "NOT_FOUND"
                    de_id = "NOT_FOUND"
                    ref_uri = "NOT_FOUND"
                    
                    try:
                        d_id_file = artifacts_dir / "diag_dId.txt"
                        if d_id_file.exists():
                            d_id_text = d_id_file.read_text(encoding="utf-8").strip()
                    except Exception:
                        pass
                    
                    try:
                        xde_file = artifacts_dir / "diag_xDE.txt"
                        if xde_file.exists():
                            xde_content = xde_file.read_text(encoding="utf-8")
                            for line in xde_content.split("\n"):
                                if "xDE len:" in line:
                                    xde_len = line.split(":", 1)[1].strip()
                                elif "xDE sha256:" in line:
                                    xde_sha256 = line.split(":", 1)[1].strip()
                    except Exception:
                        pass
                    
                    try:
                        lote_structure_file = artifacts_dir / "diag_lote_structure.txt"
                        if lote_structure_file.exists():
                            lote_content = lote_structure_file.read_text(encoding="utf-8")
                            for line in lote_content.split("\n"):
                                if "root localname:" in line:
                                    lote_root = line.split(":", 1)[1].strip()
                                elif "rDE count:" in line:
                                    rde_count = line.split(":", 1)[1].strip()
                                elif "xDE count:" in line:
                                    xde_count = line.split(":", 1)[1].strip()
                    except Exception:
                        pass
                    
                    try:
                        # Leer xDE del request SENT (soap_bytes, no el archivo redactado)
                        import zipfile
                        from io import BytesIO
                        import base64
                        import re
                        sent_root = etree.fromstring(soap_bytes)
                        sent_xde = sent_root.find(f".//{{{SIFEN_NS}}}xDE")
                        if sent_xde is None:
                            sent_xde = sent_root.find(".//xDE")
                        if sent_xde is not None and (sent_xde.text or "").strip():
                            xde_b64_clean = re.sub(r'\s+', '', sent_xde.text.strip())
                            zip_bytes = base64.b64decode(xde_b64_clean)
                            with zipfile.ZipFile(BytesIO(zip_bytes), 'r') as zf:
                                zip_namelist = str(zf.namelist())
                    except Exception as e:
                        logger.debug(f"Error al extraer zip_namelist del resumen: {e}")
                        pass
                    
                    try:
                        de_id_file = artifacts_dir / "diag_de_id.txt"
                        if de_id_file.exists():
                            de_id = de_id_file.read_text(encoding="utf-8").strip()
                    except Exception:
                        pass
                    
                    try:
                        ref_uri_file = artifacts_dir / "diag_sig_reference_uri.txt"
                        if ref_uri_file.exists():
                            ref_content = ref_uri_file.read_text(encoding="utf-8")
                            for line in ref_content.split("\n"):
                                if "Reference URI:" in line:
                                    ref_uri = line.split(":", 1)[1].strip()
                                    break
                    except Exception:
                        pass
                    
                    # Extraer respuesta de SIFEN
                    d_cod_res = response.get("codigo_respuesta", "NOT_FOUND")
                    d_msg_res = response.get("mensaje", "NOT_FOUND")
                    
                    summary = (
                        f"=== RESUMEN DE ENVÍO ===\n"
                        f"dId: {d_id_text}\n"
                        f"xDE len: {xde_len}\n"
                        f"xDE sha256: {xde_sha256}\n"
                        f"zip namelist: {zip_namelist}\n"
                        f"lote root: {lote_root}\n"
                        f"rDE count: {rde_count}\n"
                        f"xDE count: {xde_count}\n"
                        f"DE Id: {de_id}\n"
                        f"Reference URI: {ref_uri}\n"
                        f"\n=== RESPUESTA SIFEN ===\n"
                        f"dCodRes: {d_cod_res}\n"
                        f"dMsgRes: {d_msg_res}\n"
                        f"dProtConsLote: {response.get('d_prot_cons_lote', 'NOT_FOUND')}\n"
                        f"dTpoProces: {response.get('d_tpo_proces', 'NOT_FOUND')}\n"
                    )
                    
                    artifacts_dir.joinpath("diag_summary.txt").write_text(
                        summary,
                        encoding="utf-8"
                    )
                    
                    # Imprimir resumen en consola
                    print("\n" + "="*60)
                    print("RESUMEN DE ENVÍO Y RESPUESTA")
                    print("="*60)
                    print(f"dId: {d_id_text}")
                    print(f"xDE len: {xde_len}")
                    print(f"xDE sha256: {xde_sha256}")
                    print(f"zip namelist: {zip_namelist}")
                    print(f"lote root: {lote_root}")
                    print(f"rDE count: {rde_count}")
                    print(f"xDE count: {xde_count}")
                    print(f"DE Id: {de_id}")
                    print(f"Reference URI: {ref_uri}")
                    print(f"\nRESPUESTA SIFEN:")
                    print(f"  dCodRes: {d_cod_res}")
                    print(f"  dMsgRes: {d_msg_res}")
                    print(f"  dProtConsLote: {response.get('d_prot_cons_lote', 'NOT_FOUND')}")
                    print(f"  dTpoProces: {response.get('d_tpo_proces', 'NOT_FOUND')}")
                    print("="*60 + "\n")
                    
                except Exception as e:
                    logger.debug(f"Error al generar resumen: {e}")
                
                return response
            else:
                # Error HTTP pero con respuesta XML válida
                error_msg = f"Error HTTP {resp.status_code} al enviar SOAP: {resp.text[:500]}"
                self._save_raw_soap_debug(soap_bytes, resp.content, suffix="_lote")
                raise SifenClientError(error_msg)
                
        except Exception as e:
            # Verificar estructura del SOAP para debug
            soap_str = soap_bytes.decode("utf-8", errors="replace")
            body_has_wrapper = "<rEnvioLote" in soap_str or "<tns:rEnvioLote" in soap_str
            body_has_renviolote = "<xsd:rEnvioLote" in soap_str or ("<rEnvioLote" in soap_str and 'xmlns:xsd="http://ekuatia.set.gov.py/sifen/xsd"' in soap_str)
            
            # Extraer información del body para debug
            body_root_localname = None
            body_root_ns = None
            body_wrapper_localname = None
            body_wrapper_ns = None
            body_preview = None
            try:
                soap_root = etree.fromstring(soap_bytes)
                body_elem = soap_root.find(f".//{{{SOAP_NS}}}Body")
                if body_elem is not None and len(body_elem) > 0:
                    first_child = body_elem[0]
                    body_root_localname = etree.QName(first_child).localname
                    # Detectar namespace: puede estar en el tag {ns}local o en nsmap
                    # El root del Body ahora es rEnvioLote (TARGET_NS)
                    if "}" in first_child.tag:
                        body_root_ns = first_child.tag.split("}", 1)[0][1:]
                    else:
                        # Buscar en nsmap (puede estar como None o como prefijo)
                        body_root_ns = first_child.nsmap.get(None)
                        if not body_root_ns:
                            # Buscar por valor del namespace en nsmap
                            for prefix, ns in first_child.nsmap.items():
                                if ns == SIFEN_NS:
                                    body_root_ns = ns
                                    break
                        body_root_ns = body_root_ns or None
                    # Verificar si hay wrapper (rEnvioLote dentro de rEnvioLote)
                    if len(first_child) > 0:
                        wrapper_child = first_child[0]
                        body_wrapper_localname = etree.QName(wrapper_child).localname
                        if "}" in wrapper_child.tag:
                            body_wrapper_ns = wrapper_child.tag.split("}", 1)[0][1:]
                        else:
                            body_wrapper_ns = wrapper_child.nsmap.get(None)
                            if not body_wrapper_ns:
                                # Buscar por valor del namespace en nsmap (SIFEN_NS para rEnvioLote)
                                for prefix, ns in wrapper_child.nsmap.items():
                                    if ns == SIFEN_NS:
                                        body_wrapper_ns = ns
                                        break
                            body_wrapper_ns = body_wrapper_ns or None
                    # Preview de los primeros 300 caracteres del body
                    body_xml = etree.tostring(body_elem, encoding="unicode", pretty_print=False)
                    body_preview = body_xml[:300]
            except Exception:
                pass  # Si falla, dejar valores None
            
            # Guardar debug incluso en error (usar headers_final si existe, sino construir mínimo)
            if 'headers_final' not in locals():
                headers_final = {
                    "Content-Type": "application/soap+xml; charset=utf-8",
                    "SOAPAction": '"rEnvioLote"',
                    "Accept": "application/soap+xml, text/xml, */*",
                }
            self._save_http_debug(
                post_url=post_url,
                original_url=wsdl_url,
                version="1.2",
                action="",  # No action según evidencia externa
                headers=headers_final,
                soap_bytes=soap_bytes,
                response_status=None,
                response_headers=None,
                response_body=None,
                mtls_cert_path=mtls_cert_path,
                mtls_key_path=mtls_key_path,
                wsdl_url=wsdl_url,
                soap_address=post_url,
                response_root=None,
                body_has_wrapper_sireceplotede=body_has_wrapper,
                body_has_renviolote=body_has_renviolote,
                body_root_localname=body_root_localname,
                body_root_ns=body_root_ns,
                body_wrapper_localname=body_wrapper_localname,
                body_wrapper_ns=body_wrapper_ns,
                body_preview=body_preview,
            )
            self._save_raw_soap_debug(soap_bytes, None, suffix="_lote")
            raise SifenClientError(f"Error al enviar SOAP a SIFEN: {e}") from e

    def _detect_xsd_dir(self) -> Optional[Path]:
        """
        Detecta automáticamente el directorio XSD.
        
        Prioridad:
        1. SIFEN_XSD_DIR env var
        2. rshk-jsifenlib/docs/set/ekuatia.set.gov.py/sifen/xsd (relativo desde repo root)
        3. None (no encontrado)
        """
        xsd_dir_env = os.getenv("SIFEN_XSD_DIR")
        if xsd_dir_env:
            xsd_path = Path(xsd_dir_env)
            if xsd_path.exists():
                return xsd_path.resolve()
        
        # Buscar rshk-jsifenlib desde repo root (asumiendo que estamos en tesaka-cv/)
        # Intentar múltiples paths posibles
        possible_roots = [
            Path(__file__).parent.parent.parent,  # tesaka-cv/ desde app/sifen_client/
            Path(__file__).parent.parent.parent.parent,  # repo root desde tesaka-cv/
        ]
        
        for repo_root in possible_roots:
            xsd_path = repo_root / "rshk-jsifenlib" / "docs" / "set" / "ekuatia.set.gov.py" / "sifen" / "xsd"
            if xsd_path.exists():
                return xsd_path.resolve()
        
        return None
    
    def _find_consulta_lote_request_root_from_xsd(self, xsd_dir: Path) -> Optional[str]:
        """
        Busca el elemento root del request de consulta lote en los XSD locales.
        
        Busca un xs:element global cuyo complexType/sequence contenga un xs:element
        con name="dProtConsLote".
        
        Args:
            xsd_dir: Directorio donde buscar XSDs
            
        Returns:
            Nombre del elemento root (ej: "rEnviConsLoteDe") o None si no se encuentra
        """
        import lxml.etree as etree
        
        NS_XSD = "http://www.w3.org/2001/XMLSchema"
        SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"
        
        # Buscar XSDs que contengan "ConsLote" (pero NO "Cons" solo, para evitar consultas individuales)
        xsd_files = list(xsd_dir.glob("*ConsLote*.xsd"))
        
        if not xsd_files:
            # Fallback: buscar cualquier XSD que contenga "Cons" y "Lote"
            xsd_files = [
                f for f in xsd_dir.glob("*.xsd")
                if "Cons" in f.name and "Lote" in f.name and "ConsLote" in f.name
            ]
        
        for xsd_file in xsd_files:
            try:
                tree = etree.parse(str(xsd_file))
                root = tree.getroot()
                
                # Buscar todos los xs:element globales
                elements = root.findall(f".//{{{NS_XSD}}}element[@name]", namespaces={"xs": NS_XSD})
                
                for elem in elements:
                    elem_name = elem.get("name")
                    if not elem_name:
                        continue
                    
                    # Buscar dentro del complexType/sequence si contiene dProtConsLote
                    complex_type = elem.find(f"{{{NS_XSD}}}complexType", namespaces={"xs": NS_XSD})
                    if complex_type is not None:
                        sequence = complex_type.find(f"{{{NS_XSD}}}sequence", namespaces={"xs": NS_XSD})
                        if sequence is not None:
                            # Buscar elemento con name="dProtConsLote"
                            for child in sequence.findall(f"{{{NS_XSD}}}element", namespaces={"xs": NS_XSD}):
                                if child.get("name") == "dProtConsLote":
                                    logger.debug(f"Encontrado request root '{elem_name}' en {xsd_file.name}")
                                    return elem_name
            except Exception as e:
                logger.debug(f"Error al parsear {xsd_file.name}: {e}")
                continue
        
        return None
    
    def _xsd_order_for_request_root(self, xsd_dir: Path, root_element_name: str) -> list[str]:
        """
        Devuelve lista de nombres de elementos hijos EN ORDEN (xs:sequence) del root global `root_element_name`.
        Busca en todos los .xsd del directorio.
        
        Args:
            xsd_dir: Directorio donde buscar XSDs
            root_element_name: Nombre del elemento root (ej: "rEnviConsLoteDe")
            
        Returns:
            Lista de nombres de elementos hijos en orden, o lista vacía si no se encuentra
        """
        import lxml.etree as etree
        
        NS_XSD = "http://www.w3.org/2001/XMLSchema"
        
        # Buscar XSDs que contengan "ConsLote" para consulta lote
        xsd_files = list(xsd_dir.glob("*ConsLote*.xsd"))
        
        if not xsd_files:
            # Fallback: buscar cualquier XSD que contenga "Cons" y "Lote"
            xsd_files = [
                f for f in xsd_dir.glob("*.xsd")
                if "Cons" in f.name and "Lote" in f.name and "ConsLote" in f.name
            ]
        
        for xsd_file in xsd_files:
            try:
                tree = etree.parse(str(xsd_file))
                root = tree.getroot()
                
                # Buscar el elemento global con el nombre especificado
                # Soporta prefijos xs: y xsd:
                namespaces = {
                    "xs": NS_XSD,
                    "xsd": NS_XSD,
                }
                
                element = root.find(f".//xs:element[@name='{root_element_name}']", namespaces)
                if element is None:
                    # Intentar con otro namespace prefix
                    element = root.find(f".//{{{NS_XSD}}}element[@name='{root_element_name}']")
                
                if element is None:
                    continue
                
                # Buscar complexType (inline o por referencia type="...")
                complex_type = element.find(f"xs:complexType", namespaces)
                if complex_type is None:
                    complex_type = element.find(f"{{{NS_XSD}}}complexType")
                
                if complex_type is None:
                    # Si tiene type="...", necesitaríamos resolverlo (por ahora solo inline)
                    continue
                
                # Buscar sequence dentro del complexType
                sequence = complex_type.find(f"xs:sequence", namespaces)
                if sequence is None:
                    sequence = complex_type.find(f"{{{NS_XSD}}}sequence")
                
                if sequence is None:
                    continue
                
                # Extraer nombres de elementos hijos en orden
                children_order = []
                for child_elem in sequence.findall(f"xs:element", namespaces):
                    child_name = child_elem.get("name")
                    if child_name:
                        children_order.append(child_name)
                
                # También intentar con namespace completo si no se encontró nada
                if not children_order:
                    for child_elem in sequence.findall(f"{{{NS_XSD}}}element"):
                        child_name = child_elem.get("name")
                        if child_name:
                            children_order.append(child_name)
                
                if children_order:
                    logger.debug(f"Orden XSD para {root_element_name}: {children_order} (desde {xsd_file.name})")
                    return children_order
                    
            except Exception as e:
                logger.debug(f"Error al parsear {xsd_file.name} para orden: {e}")
                continue
        
        return []
    
    def consulta_lote_de(self, dprot_cons_lote: str, did: int = 1) -> Dict[str, Any]:
        """Consulta estado de lote (siConsLoteDE) a SIFEN usando zeep Client (WSDL-driven).
        
        Usa zeep Client para construir el SOAP envelope correctamente según el WSDL.
        Incluye retries solo para errores de conexión (ConnectionReset, timeouts).
        Si HTTP=400 y dCodRes=0160, NO reintenta: devuelve error inmediato.
        
        Args:
            dprot_cons_lote: dProtConsLote (número de lote devuelto por rEnvioLote)
            did: dId (default: 1)
            
        Returns:
            Dict con ok, codigo_respuesta, mensaje, parsed_fields, response_xml, etc.
        """
        import lxml.etree as etree
        from pathlib import Path
        
        service_key = "consulta_lote"
        operation_name = "siConsLoteDE"
        
        # Obtener cliente zeep para consulta_lote
        try:
            client = self._get_client(service_key)
        except Exception as e:
            # Fallback a consulta_lote_raw si falla el WSDL/zeep
            logger.warning(f"Fallo zeep/WSDL en consulta_lote_de: {e}. Usando consulta_lote_raw.")
            raw = self.consulta_lote_raw(dprot_cons_lote, did=str(did))
            if "codigo_respuesta" not in raw:
                raw["codigo_respuesta"] = raw.get("dCodResLot") or raw.get("dCodRes")
            if "mensaje" not in raw:
                raw["mensaje"] = raw.get("dMsgResLot") or raw.get("dMsgRes")
            return raw
        
        # Obtener history plugin si está disponible (para debug)
        history = None
        debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
        if debug_enabled and hasattr(self, "_history_plugins") and service_key in self._history_plugins:
            history = self._history_plugins[service_key]
        
        # Construir parámetros para la operación
        # Según el WSDL, la operación siConsLoteDE espera rEnviConsLoteDe con dId y dProtConsLote
        try:
            # Intentar llamar a la operación usando zeep
            # zeep puede requerir diferentes formas según el binding del WSDL
            # Primero intentar con el formato más común (dict con estructura del tipo)
            request_data = {
                "dId": str(did),
                "dProtConsLote": str(dprot_cons_lote)
            }
            
            # Llamar a la operación
            # zeep puede requerir el wrapper o no, dependiendo del WSDL
            # Intentar primero sin wrapper (bare style)
            try:
                result = client.service.siConsLoteDE(**request_data)
            except (Fault, TransportError, AttributeError) as e:
                # Si falla, intentar con wrapper explícito
                try:
                    result = client.service.siConsLoteDE(rEnviConsLoteDe=request_data)
                except (Fault, TransportError, AttributeError) as e2:
                    # Si sigue fallando, intentar con estructura anidada
                    try:
                        result = client.service.siConsLoteDE(
                            rEnviConsLoteDe={
                                "dId": str(did),
                                "dProtConsLote": str(dprot_cons_lote)
                            }
                        )
                    except Exception as e3:
                        # Si todos fallan, intentar obtener el mensaje desde el binding
                        # y construir manualmente solo si es necesario
                        raise SifenClientError(
                            f"Error al llamar a {operation_name} con zeep. "
                            f"Intentos fallaron: {e}, {e2}, {e3}. "
                            f"Verificar estructura del WSDL."
                        )
            
            # Guardar artifacts de debug si está habilitado
            if debug_enabled and history:
                try:
                    artifacts_dir = Path("artifacts")
                    artifacts_dir.mkdir(exist_ok=True)
                    
                    # Guardar request
                    if hasattr(history, "last_sent") and history.last_sent:
                        request_envelope = history.last_sent.get("envelope", "")
                        if request_envelope:
                            request_file = artifacts_dir / "consulta_last_request.xml"
                            request_file.write_text(
                                request_envelope.decode("utf-8", errors="ignore") if isinstance(request_envelope, bytes) else request_envelope,
                                encoding="utf-8"
                            )
                    
                    # Guardar response
                    if hasattr(history, "last_received") and history.last_received:
                        response_envelope = history.last_received.get("envelope", "")
                        if response_envelope:
                            response_file = artifacts_dir / "consulta_last_response.xml"
                            response_file.write_text(
                                response_envelope.decode("utf-8", errors="ignore") if isinstance(response_envelope, bytes) else response_envelope,
                                encoding="utf-8"
                            )
                except Exception as debug_err:
                    logger.warning(f"Error al guardar artifacts de consulta lote: {debug_err}")
            
            # Parsear respuesta XML desde history si está disponible
            response_xml = ""
            if history and hasattr(history, "last_received") and history.last_received:
                response_envelope = history.last_received.get("envelope", "")
                if response_envelope:
                    response_xml = response_envelope.decode("utf-8", errors="ignore") if isinstance(response_envelope, bytes) else response_envelope
            
            # Construir respuesta en formato esperado
            parsed_result = {
                "ok": False,
                "codigo_respuesta": None,
                "mensaje": None,
                "parsed_fields": {},
                "response_xml": response_xml,
            }
            
            # Extraer código y mensaje desde response_xml (más confiable)
            if response_xml:
                try:
                    resp_root = etree.fromstring(response_xml.encode("utf-8") if isinstance(response_xml, str) else response_xml)
                    
                    # Extraer dCodResLot/dCodRes y dMsgResLot/dMsgRes
                    cod_res = resp_root.xpath('//*[local-name()="dCodResLot"] | //*[local-name()="dCodRes"]')
                    msg_res = resp_root.xpath('//*[local-name()="dMsgResLot"] | //*[local-name()="dMsgRes"]')
                    if cod_res and cod_res[0].text:
                        parsed_result["codigo_respuesta"] = cod_res[0].text.strip()
                    if msg_res and msg_res[0].text:
                        parsed_result["mensaje"] = msg_res[0].text.strip()
                    
                    # Extraer gResProcLote (lista de resultados por DE)
                    g_res_proc_lote = resp_root.xpath('//*[local-name()="gResProcLote"]')
                    if g_res_proc_lote:
                        de_results = []
                        for de_elem in g_res_proc_lote[0].xpath('.//*[local-name()="dResProc"]'):
                            de_result = {}
                            # Extraer campos comunes de dResProc
                            for child in de_elem:
                                local_name = etree.QName(child.tag).localname
                                if child.text:
                                    de_result[local_name] = child.text.strip()
                            if de_result:
                                de_results.append(de_result)
                        if de_results:
                            parsed_result["parsed_fields"]["gResProcLote"] = de_results
                except Exception as parse_err:
                    logger.debug(f"Error al parsear response_xml: {parse_err}")
                    pass
            
            # También intentar extraer desde result (zeep puede devolver objetos complejos)
            try:
                # Convertir resultado de zeep a dict si es posible
                if serialize_object:
                    result_dict = serialize_object(result)
                    if isinstance(result_dict, dict):
                        parsed_result["parsed_fields"] = result_dict
                        if not parsed_result["codigo_respuesta"]:
                            parsed_result["codigo_respuesta"] = result_dict.get("dCodResLot") or result_dict.get("dCodRes")
                        if not parsed_result["mensaje"]:
                            parsed_result["mensaje"] = result_dict.get("dMsgResLot") or result_dict.get("dMsgRes")
                elif hasattr(result, "__dict__"):
                    parsed_result["parsed_fields"] = result.__dict__
                elif isinstance(result, dict):
                    parsed_result["parsed_fields"] = result
                    if not parsed_result["codigo_respuesta"]:
                        parsed_result["codigo_respuesta"] = result.get("dCodResLot") or result.get("dCodRes")
                    if not parsed_result["mensaje"]:
                        parsed_result["mensaje"] = result.get("dMsgResLot") or result.get("dMsgRes")
                else:
                    # Fallback: convertir a string
                    parsed_result["parsed_fields"] = {"result": str(result)}
            except Exception:
                # Si falla la conversión, continuar con parsed_fields vacío
                pass
            
            # Determinar éxito
            codigo = parsed_result["codigo_respuesta"]
            if codigo in ("0361", "0362"):
                parsed_result["ok"] = True
            elif codigo == "0160":
                # XML Mal Formado: no reintentar, devolver error inmediato
                error_msg = f"Error 0160 (XML Mal Formado) en consulta lote. Mensaje: {parsed_result.get('mensaje', 'N/A')}"
                if debug_enabled:
                    error_msg += f"\nResponse guardado en artifacts/consulta_last_response.xml"
                raise SifenClientError(error_msg)
            
            return parsed_result
            
        except SifenClientError as e:
            msg = str(e)
            if "operation" in msg.lower() or "wsdl" in msg.lower():
                logger.warning(f"Fallback a consulta_lote_raw por error WSDL/operación: {msg}")
                raw = self.consulta_lote_raw(dprot_cons_lote, did=str(did))
                if "codigo_respuesta" not in raw:
                    raw["codigo_respuesta"] = raw.get("dCodResLot") or raw.get("dCodRes")
                if "mensaje" not in raw:
                    raw["mensaje"] = raw.get("dMsgResLot") or raw.get("dMsgRes")
                return raw
            raise  # Re-raise otros errores
        except ConnectionResetError as e:
            # Reintentar solo para ConnectionResetError (máximo 2 veces)
            delays = [0.4, 0.8]
            last_exception = e
            for attempt in range(2):
                try:
                    time.sleep(delays[attempt] if attempt < len(delays) else delays[-1])
                    logger.debug(f"ConnectionResetError en consulta lote, reintentando {attempt + 1}/2...")
                    # Reintentar la llamada
                    result = client.service.siConsLoteDE(
                        rEnviConsLoteDe={
                            "dId": str(did),
                            "dProtConsLote": str(dprot_cons_lote)
                        }
                    )
                    # Si llegamos aquí, el reintento funcionó
                    # Parsear respuesta (mismo código de arriba)
                    response_xml = ""
                    if history and hasattr(history, "last_received") and history.last_received:
                        response_envelope = history.last_received.get("envelope", "")
                        if response_envelope:
                            response_xml = response_envelope.decode("utf-8", errors="ignore") if isinstance(response_envelope, bytes) else response_envelope
                    
                    parsed_result = {
                        "ok": False,
                        "codigo_respuesta": None,
                        "mensaje": None,
                        "parsed_fields": {},
                        "response_xml": response_xml,
                    }
                    
                    if response_xml:
                        try:
                            resp_root = etree.fromstring(response_xml.encode("utf-8") if isinstance(response_xml, str) else response_xml)
                            
                            # Extraer dCodResLot/dCodRes y dMsgResLot/dMsgRes
                            cod_res = resp_root.xpath('//*[local-name()="dCodResLot"] | //*[local-name()="dCodRes"]')
                            msg_res = resp_root.xpath('//*[local-name()="dMsgResLot"] | //*[local-name()="dMsgRes"]')
                            if cod_res and cod_res[0].text:
                                parsed_result["codigo_respuesta"] = cod_res[0].text.strip()
                            if msg_res and msg_res[0].text:
                                parsed_result["mensaje"] = msg_res[0].text.strip()
                            
                            # Extraer gResProcLote (lista de resultados por DE)
                            g_res_proc_lote = resp_root.xpath('//*[local-name()="gResProcLote"]')
                            if g_res_proc_lote:
                                de_results = []
                                for de_elem in g_res_proc_lote[0].xpath('.//*[local-name()="dResProc"]'):
                                    de_result = {}
                                    for child in de_elem:
                                        local_name = etree.QName(child.tag).localname
                                        if child.text:
                                            de_result[local_name] = child.text.strip()
                                    if de_result:
                                        de_results.append(de_result)
                                if de_results:
                                    parsed_result["parsed_fields"]["gResProcLote"] = de_results
                        except Exception:
                            pass
                    
                    # También intentar desde result
                    try:
                        if serialize_object:
                            result_dict = serialize_object(result)
                            if isinstance(result_dict, dict):
                                parsed_result["parsed_fields"] = result_dict
                                if not parsed_result["codigo_respuesta"]:
                                    parsed_result["codigo_respuesta"] = result_dict.get("dCodResLot") or result_dict.get("dCodRes")
                                if not parsed_result["mensaje"]:
                                    parsed_result["mensaje"] = result_dict.get("dMsgResLot") or result_dict.get("dMsgRes")
                        elif isinstance(result, dict):
                            parsed_result["parsed_fields"] = result
                            if not parsed_result["codigo_respuesta"]:
                                parsed_result["codigo_respuesta"] = result.get("dCodResLot") or result.get("dCodRes")
                            if not parsed_result["mensaje"]:
                                parsed_result["mensaje"] = result.get("dMsgResLot") or result.get("dMsgRes")
                    except Exception:
                        pass
                    
                    codigo = parsed_result["codigo_respuesta"]
                    if codigo in ("0361", "0362"):
                        parsed_result["ok"] = True
                    elif codigo == "0160":
                        error_msg = f"Error 0160 (XML Mal Formado) en consulta lote. Mensaje: {parsed_result.get('mensaje', 'N/A')}"
                        if debug_enabled:
                            error_msg += f"\nResponse guardado en artifacts/consulta_last_response.xml"
                        raise SifenClientError(error_msg)
                    
                    return parsed_result
                except ConnectionResetError:
                    last_exception = e
                    continue
                except Exception as retry_e:
                    # Otro tipo de error en el reintento: lanzar el error original
                    raise last_exception from retry_e
            
            # Si llegamos aquí, todos los reintentos fallaron
            raise SifenClientError(f"ConnectionResetError después de 2 reintentos: {last_exception}") from last_exception
        except Fault as e:
            # Fault de SOAP: extraer información y lanzar SifenClientError
            fault_code = getattr(e, "code", None)
            fault_message = getattr(e, "message", str(e))
            
            # Guardar artifacts si está habilitado
            if debug_enabled and history:
                try:
                    artifacts_dir = Path("artifacts")
                    artifacts_dir.mkdir(exist_ok=True)
                    if hasattr(history, "last_sent") and history.last_sent:
                        request_envelope = history.last_sent.get("envelope", "")
                        if request_envelope:
                            request_file = artifacts_dir / "consulta_last_request.xml"
                            request_file.write_text(
                                request_envelope.decode("utf-8", errors="ignore") if isinstance(request_envelope, bytes) else request_envelope,
                                encoding="utf-8"
                            )
                    if hasattr(history, "last_received") and history.last_received:
                        response_envelope = history.last_received.get("envelope", "")
                        if response_envelope:
                            response_file = artifacts_dir / "consulta_last_response.xml"
                            response_file.write_text(
                                response_envelope.decode("utf-8", errors="ignore") if isinstance(response_envelope, bytes) else response_envelope,
                                encoding="utf-8"
                            )
                except Exception:
                    pass
            
            raise SifenClientError(f"SOAP Fault en consulta lote: {fault_message} (code: {fault_code})")
        except TransportError as e:
            # Error de transporte: puede ser timeout, conexión, etc.
            error_msg = f"Error de transporte en consulta lote: {e}"
            if debug_enabled and history:
                error_msg += "\nArtifacts guardados en artifacts/consulta_last_*.xml"
            raise SifenClientError(error_msg) from e
        except Exception as e:
            # Error inesperado
            error_msg = f"Error inesperado en consulta lote: {e}"
            if debug_enabled and history:
                error_msg += "\nArtifacts guardados en artifacts/consulta_last_*.xml"
            raise SifenClientError(error_msg) from e

    def _parse_consulta_lote_response_from_xml(self, xml_root: Any) -> Dict[str, Any]:
        """Parsea la respuesta de consulta de lote desde XML."""
        import lxml.etree as etree  # noqa: F401

        body_child = None
        local_name = etree.QName(xml_root).localname
        if local_name == "Envelope":
            body_nodes = xml_root.xpath("//*[local-name()='Body']")
            if not body_nodes:
                raise SifenClientError("Respuesta SOAP inválida: Body no encontrado en consulta_lote")
            for child in body_nodes[0]:
                if isinstance(getattr(child, "tag", None), str):
                    body_child = child
                    break
            if body_child is None:
                raise SifenClientError("Respuesta SOAP inválida: Body sin payload en consulta_lote")
            xml_root = body_child
            local_name = etree.QName(xml_root).localname

        if local_name == "Fault":
            fault_code = xml_root.xpath('string(.//*[local-name()="Value"][1])') or None
            fault_string = xml_root.xpath('string(.//*[local-name()="Text"][1])') or xml_root.xpath(
                'string(.//*[local-name()="faultstring"][1])'
            )
            detail_text = xml_root.xpath('string(.//*[local-name()="detail"][1])') or None
            raise SifenClientError(
                "SOAP Fault en consulta_lote: "
                f"fault_code={fault_code or 'N/A'} "
                f"fault_string={fault_string or 'N/A'} "
                f"detail={detail_text or 'N/A'}"
            )

        if local_name != "rResEnviConsLoteDe":
            raise SifenClientError(
                "Respuesta inesperada en consulta_lote: "
                f"root={local_name!r}, esperado='rResEnviConsLoteDe'. "
                "Revisar endpoint/operación SOAP."
            )
        
        result: Dict[str, Any] = {
            "ok": False,
            "codigo_respuesta": None,
            "mensaje": None,
            "parsed_fields": {},
            "response_xml": etree.tostring(xml_root, encoding="unicode"),
        }
        
        def find_text(xpath_expr: str) -> Optional[str]:
            try:
                nodes = xml_root.xpath(xpath_expr)
                if nodes:
                    val = nodes[0].text
                    return val.strip() if val else None
            except Exception:
                return None
            return None
        
        # Buscar campos de respuesta de consulta lote
        # Pueden estar en diferentes ubicaciones según la estructura de respuesta
        cod_res_lot = find_text('//*[local-name()="dCodResLot"]')
        msg_res_lot = find_text('//*[local-name()="dMsgResLot"]')
        
        # También buscar dCodRes y dMsgRes (formato genérico)
        if not cod_res_lot:
            cod_res_lot = find_text('//*[local-name()="dCodRes"]')
        if not msg_res_lot:
            msg_res_lot = find_text('//*[local-name()="dMsgRes"]')
        
        result["codigo_respuesta"] = cod_res_lot
        result["mensaje"] = msg_res_lot
        result["parsed_fields"]["dCodResLot"] = cod_res_lot
        result["parsed_fields"]["dMsgResLot"] = msg_res_lot
        
        # Buscar otros campos opcionales
        d_prot_cons_lote = find_text('//*[local-name()="dProtConsLote"]')
        if d_prot_cons_lote:
            result["parsed_fields"]["dProtConsLote"] = d_prot_cons_lote
        
        # Determinar éxito basado en código
        if cod_res_lot in ("0361", "0362"):
            result["ok"] = True
        elif cod_res_lot == "0364":
            result["ok"] = False  # Requiere CDC
        else:
            result["ok"] = False
        
        return result

    def consulta_lote_raw(
        self,
        dprot_cons_lote: str,
        did: Optional[str] = None,
        dump_http: bool = False,
        artifacts_dir: Optional[Path] = None,
    ) -> Dict[str, Any]:
        """Consulta lote sin depender de zeep/WSDL y genera artifacts detallados."""

        if not dprot_cons_lote or not str(dprot_cons_lote).strip():
            raise SifenClientError("dProtConsLote es obligatorio para consulta_lote_raw")

        if did is None or not str(did).strip():
            did = datetime.utcnow().strftime("%Y%m%d%H%M%S") + str(random.randint(0, 9))

        artifacts_dir_path = resolve_artifacts_dir(artifacts_dir) if artifacts_dir else self._get_artifacts_dir()
        session = self.transport.session

        wsdl_url = self.config.get_soap_service_url("consulta_lote")
        endpoint = self._normalize_soap_endpoint(wsdl_url)

        soap_bytes = build_consulta_lote_raw_envelope(str(did), str(dprot_cons_lote).strip())
        soap_xml_str = soap_bytes.decode("utf-8", errors="replace")
        soap_last_request_path = artifacts_dir_path / "soap_last_request.xml"
        try:
            soap_last_request_path.write_bytes(soap_bytes)
        except Exception as exc:
            logger.warning(f"No se pudo guardar soap_last_request.xml: {exc}")

        try:
            validate_xml_bytes_or_raise(soap_bytes, "consulta_lote_raw request")
        except Exception as exc:
            invalid_path = artifacts_dir_path / "soap_invalid_request.xml"
            try:
                invalid_path.write_bytes(soap_bytes)
            except Exception:
                pass
            raise SifenClientError(
                "SOAP inválido para consulta_lote_raw; "
                f"request guardado en {invalid_path}"
            ) from exc

        # Para consulta-lote, el POST debe mantener .wsdl para enrutamiento correcto.
        endpoint_candidates = [endpoint]

        content_type_variants = ['application/soap+xml; charset=utf-8; action=""']
        attempts: List[Dict[str, Any]] = []
        last_error: Optional[Exception] = None

        for endpoint in endpoint_candidates:
            for content_type in content_type_variants:
                attempt_index = len(attempts) + 1
                label = f"consulta_lote_raw_{attempt_index:02d}"
                headers = {
                    "Content-Type": content_type,
                    "Accept": "application/soap+xml",
                }
                request_path = self._prepare_request_artifacts(
                    artifacts_dir=artifacts_dir_path,
                    label=label,
                    post_url=endpoint,
                    headers=headers,
                    soap_bytes=soap_bytes,
                )

                attempt_ctx: Dict[str, Any] = {
                    "label": label,
                    "endpoint": endpoint,
                    "content_type": content_type,
                    "timestamp": datetime.utcnow().isoformat(),
                    "request_path": str(request_path),
                }

                try:
                    resp = session.post(
                        endpoint,
                        data=soap_bytes,
                        headers=headers,
                        cert=(self.config.cert_pem_path, self.config.key_pem_path),
                        verify=self.config.ca_bundle_path,
                        timeout=(self.connect_timeout, self.read_timeout),
                    )
                    response_body = resp.content or b""
                    response_headers = dict(resp.headers)
                    soap_last_response_path = artifacts_dir_path / "soap_last_response.xml"
                    try:
                        soap_last_response_path.write_bytes(response_body)
                    except Exception as exc:
                        logger.warning(f"No se pudo guardar soap_last_response.xml: {exc}")
                    attempt_ctx["http_status"] = resp.status_code
                    attempt_ctx["response_path"] = str(
                        (artifacts_dir_path / f"{label}_response.xml").resolve()
                    )

                    self._persist_http_attempt(
                        artifacts_dir=artifacts_dir_path,
                        label=label,
                        service_key="consulta_lote_raw",
                        post_url=endpoint,
                        soap_version="1.2",
                        headers=headers,
                        request_path=request_path,
                        response_status=resp.status_code,
                        response_headers=response_headers,
                        response_body=response_body,
                        error_message=None,
                    )

                    if resp.status_code >= 500 or not response_body:
                        last_error = SifenClientError(
                            f"HTTP {resp.status_code} sin cuerpo al consultar lote"
                        )
                        attempt_ctx["error"] = str(last_error)
                        continue

                    try:
                        xml_root = etree.fromstring(response_body)
                    except Exception as parse_exc:
                        parse_error_path = artifacts_dir_path / "soap_last_response_parse_error.txt"
                        try:
                            parse_error_path.write_text(f"{type(parse_exc).__name__}: {parse_exc}\n", encoding="utf-8")
                        except Exception:
                            pass
                        last_error = SifenClientError(
                            "No se pudo parsear response SOAP de consulta_lote_raw; "
                            f"ver {parse_error_path}"
                        )
                        attempt_ctx["error"] = str(last_error)
                        continue

                    parsed = self._parse_consulta_lote_response_from_xml(xml_root)
                    parsed.setdefault("parsed_fields", {})
                    parsed["parsed_fields"].setdefault("dProtConsLote", str(dprot_cons_lote))
                    parsed["parsed_fields"].setdefault("dId", str(did))
                    parsed_result = {
                        **parsed,
                        "http_status": resp.status_code,
                        "endpoint": endpoint,
                        "attempts": attempts + [attempt_ctx],
                        "headers_sent": headers.copy(),
                        "headers_received": response_headers,
                        "response_xml": response_body.decode("utf-8", errors="replace"),
                        "request_xml": soap_xml_str,
                    }

                    # Copiar campos útiles al nivel raíz para heurísticas existentes
                    for key in ("dCodResLot", "dMsgResLot", "dCodRes", "dMsgRes"):
                        val = parsed_result["parsed_fields"].get(key)
                        if val and key not in parsed_result:
                            parsed_result[key] = val

                    if dump_http:
                        parsed_result["sent_headers"] = headers.copy()
                        parsed_result["sent_xml"] = soap_xml_str
                        parsed_result["received_headers"] = response_headers
                        parsed_result["received_body"] = parsed_result["response_xml"]

                    return parsed_result

                except Exception as exc:
                    last_error = exc
                    attempt_ctx["error"] = str(exc)
                    soap_last_response_error_path = artifacts_dir_path / "soap_last_response_error.txt"
                    try:
                        soap_last_response_error_path.write_text(
                            f"{type(exc).__name__}: {exc}\n", encoding="utf-8"
                        )
                    except Exception:
                        pass
                    self._persist_http_attempt(
                        artifacts_dir=artifacts_dir_path,
                        label=label,
                        service_key="consulta_lote_raw",
                        post_url=endpoint,
                        soap_version="1.2",
                        headers=headers,
                        request_path=request_path,
                        response_status=None,
                        response_headers=None,
                        response_body=None,
                        error_message=str(exc),
                    )
                finally:
                    attempts.append(attempt_ctx)

        raise SifenClientError(
            f"consulta_lote_raw falló tras {len(attempts)} intentos: {last_error}"
        )
    
    def consulta_de_por_cdc_raw(self, cdc: str, dump_http: bool = False, did: Optional[str] = None) -> Dict[str, Any]:
        """Consulta estado de un DE individual por CDC (sin depender del WSDL).
        
        Args:
            cdc: CDC (Código de Control) del documento electrónico
            dump_http: Si True, retorna también sent_headers y sent_xml para debug
            did: dId opcional (si None, se genera automáticamente con formato YYYYMMDDHHMMSS + 1 dígito = 15 dígitos)
            
        Returns:
            Dict con http_status, raw_xml, y opcionalmente dCodRes/dMsgRes/dProtAut.
            Si dump_http=True, también incluye sent_headers y sent_xml.
        """
        import lxml.etree as etree  # noqa: F401
        import datetime as _dt
        import random
        import time
        
        # Generar dId de 15 dígitos si no se proporciona (formato: YYYYMMDDHHMMSS + 1 dígito aleatorio)
        # Igual que en rEnvioLote
        if did is None:
            base = _dt.datetime.now().strftime("%Y%m%d%H%M%S")  # 14 dígitos
            did = f"{base}{random.randint(0, 9)}"  # + 1 dígito = 15 dígitos total
        
        # Construir SOAP 1.2 envelope con estructura exacta requerida según XSD
        # XSD: WS_SiConsDE_v141.xsd define rEnviConsDeRequest con dId y dCDC
        SOAP_12_NS = "http://www.w3.org/2003/05/soap-envelope"
        
        # Envelope SOAP 1.2
        envelope = etree.Element(
            f"{{{SOAP_12_NS}}}Envelope",
            nsmap={"soap": SOAP_12_NS}
        )
        
        # Header vacío
        header = etree.SubElement(envelope, f"{{{SOAP_12_NS}}}Header")
        
        # Body
        body = etree.SubElement(envelope, f"{{{SOAP_12_NS}}}Body")
        
        # rEnviConsDeRequest según XSD (targetNamespace: http://ekuatia.set.gov.py/sifen/xsd)
        # XSD define: <xs:element name="rEnviConsDeRequest">
        # IMPORTANTE: Usar "rEnviConsDeRequest" (con D mayúscula y "Request")
        r_envi_cons_de_request = etree.SubElement(
            body, "rEnviConsDeRequest", nsmap={None: SIFEN_NS}
        )
        
        # dId OBLIGATORIO según XSD (tipo: dIdType) - debe ser hijo directo y primero
        d_id_elem = etree.SubElement(r_envi_cons_de_request, "dId")
        d_id_elem.text = str(did)
        
        # dCDC requerido según XSD (tipo: tCDC) - debe ser hijo directo y segundo
        d_cdc_elem = etree.SubElement(r_envi_cons_de_request, "dCDC")
        d_cdc_elem.text = str(cdc)
        
        # Serializar SOAP
        soap_bytes = etree.tostring(
            envelope, xml_declaration=True, encoding="UTF-8", pretty_print=False
        )
        
        # HARD-FAIL LOCAL ANTES DE ENVIAR: Verificar que el SOAP generado parsea correctamente
        try:
            # Intentar parsear el SOAP generado
            test_root = etree.fromstring(soap_bytes)
            
            # Validar estructura básica: Envelope->Body->rEnviConsDeRequest
            soap_env_ns = "http://www.w3.org/2003/05/soap-envelope"
            body_elem = test_root.find(f".//{{{soap_env_ns}}}Body")
            if body_elem is None:
                raise RuntimeError(f"SOAP Body no encontrado después de generar. SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}")
            
            # Validar que rEnviConsDeRequest existe en Body (hijo directo)
            request_elem = body_elem.find(f"{{{SIFEN_NS}}}rEnviConsDeRequest")
            if request_elem is None:
                # Intentar sin namespace
                request_elem = body_elem.find(".//rEnviConsDeRequest")
            
            if request_elem is None:
                # Intentar buscar cualquier hijo directo de Body para debug
                body_children = [etree.QName(ch.tag).localname if isinstance(ch.tag, str) else str(ch.tag) for ch in body_elem]
                raise RuntimeError(
                    f"rEnviConsDeRequest no encontrado en SOAP Body. "
                    f"Hijos directos de Body: {body_children}. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            
            # Verificar que rEnviConsDeRequest es hijo directo de Body (no descendiente)
            if request_elem.getparent() is not body_elem:
                raise RuntimeError(
                    f"rEnviConsDeRequest no es hijo directo de Body. "
                    f"Parent: {etree.QName(request_elem.getparent().tag).localname if request_elem.getparent() is not None else 'None'}. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            
            # Validar que tiene dId y dCDC como hijos directos y no vacíos
            d_id_check = request_elem.find(f"{{{SIFEN_NS}}}dId")
            if d_id_check is None:
                d_id_check = request_elem.find("dId")
            if d_id_check is None:
                raise RuntimeError(
                    f"dId no encontrado en rEnviConsDeRequest. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            if not d_id_check.text or not d_id_check.text.strip():
                raise RuntimeError(
                    f"dId está vacío en rEnviConsDeRequest. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            
            d_cdc_check = request_elem.find(f"{{{SIFEN_NS}}}dCDC")
            if d_cdc_check is None:
                d_cdc_check = request_elem.find("dCDC")
            if d_cdc_check is None:
                raise RuntimeError(
                    f"dCDC no encontrado en rEnviConsDeRequest. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            if not d_cdc_check.text or not d_cdc_check.text.strip():
                raise RuntimeError(
                    f"dCDC está vacío en rEnviConsDeRequest. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            
            # Validar orden según XSD: primero dId, luego dCDC
            children = list(request_elem)
            if len(children) < 2:
                raise RuntimeError(
                    f"rEnviConsDeRequest debe tener al menos 2 hijos (dId y dCDC), encontrados: {len(children)}. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            
            first_child_local = etree.QName(children[0]).localname if children[0].tag else None
            second_child_local = etree.QName(children[1]).localname if len(children) > 1 and children[1].tag else None
            
            if first_child_local != "dId":
                raise RuntimeError(
                    f"Primer hijo de rEnviConsDeRequest debe ser 'dId', encontrado: '{first_child_local}'. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            if second_child_local != "dCDC":
                raise RuntimeError(
                    f"Segundo hijo de rEnviConsDeRequest debe ser 'dCDC', encontrado: '{second_child_local}'. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            
            # Imprimir SOAP generado para validación (siempre en debug, también en consola si dump_http)
            soap_xml_str = soap_bytes.decode("utf-8", errors="replace")
            logger.debug(f"SOAP generado para consulta DE por CDC (validado OK):\n{soap_xml_str}")
            
            # Si dump_http está activo, también imprimir en consola
            if dump_http:
                print("\n" + "="*70)
                print("SOAP GENERADO PARA CONSULTA DE POR CDC (VALIDADO)")
                print("="*70)
                print(soap_xml_str)
                print("="*70)
                print(f"✅ Validación previa: SOAP parsea correctamente")
                print(f"   - Elemento root: rEnviConsDeRequest")
                print(f"   - Namespace: {SIFEN_NS}")
                print(f"   - dId: {d_id_check.text} (15 dígitos: {len(d_id_check.text) == 15})")
                print(f"   - dCDC: {d_cdc_check.text}")
                print("="*70 + "\n")
                
        except etree.XMLSyntaxError as e:
            raise RuntimeError(f"SOAP generado no es XML válido: {e}\nSOAP:\n{soap_bytes.decode('utf-8', errors='replace')}") from e
        except Exception as e:
            raise RuntimeError(f"Error al validar SOAP generado: {e}") from e
        
        # Determinar endpoint según ambiente (usar config existente)
        endpoint = self.config.get_soap_service_url("consulta")
        
        # Headers SOAP 1.2 (application/soap+xml con action="siConsDE", NO "rEnviConsDE")
        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8",
            "Accept": "application/soap+xml, text/xml, */*",
        }
        
        # Si dump_http está activo, guardar headers y XML enviados
        soap_xml_str = soap_bytes.decode("utf-8", errors="replace")
        result: Dict[str, Any] = {
            "http_status": 0,
            "raw_xml": "",
        }
        if dump_http:
            result["sent_headers"] = headers.copy()
            result["sent_xml"] = soap_xml_str
        
        # POST usando la sesión existente con mTLS
        session = self.transport.session
        
        # RETRY por errores de conexión (solo para esta consulta, NO para envíos)
        max_attempts = 3
        retry_delays = [0.5, 1.5]  # 0.5s después del primer intento, 1.5s después del segundo
        
        last_exception = None
        for attempt in range(1, max_attempts + 1):
            try:
                resp = session.post(
                    endpoint,
                    data=soap_bytes,
                    headers=headers,
                    timeout=(self.connect_timeout, self.read_timeout),
                )
                result["http_status"] = resp.status_code
                result["raw_xml"] = resp.text
                
                # Si dump_http está activo, agregar headers y body recibidos
                if dump_http:
                    result["received_headers"] = dict(resp.headers)
                    body_lines = resp.text.split("\n") if resp.text else []
                    if len(body_lines) > 500:
                        result["received_body_preview"] = "\n".join(body_lines[:500]) + f"\n... (truncado, total {len(body_lines)} líneas)"
                    else:
                        result["received_body_preview"] = resp.text
                
                # Guardar debug incluso si HTTP != 200
                debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
                if debug_enabled:
                    try:
                        from pathlib import Path
                        out_dir = Path("artifacts")
                        out_dir.mkdir(exist_ok=True)
                        received_file = out_dir / "soap_last_received_consulta_de.xml"
                        received_file.write_bytes(resp.content)
                    except Exception:
                        pass  # No romper el flujo si falla debug
                
                # Guardar artifacts de dump_http incluso si hay error HTTP
                if dump_http:
                    try:
                        from pathlib import Path
                        artifacts_dir = Path("artifacts")
                        artifacts_dir.mkdir(exist_ok=True)
                        timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                        
                        # Guardar SOAP enviado
                        sent_file = artifacts_dir / f"consulta_de_sent_{timestamp}.xml"
                        sent_file.write_text(soap_xml_str, encoding="utf-8")
                        
                        # Guardar headers enviados
                        headers_sent_file = artifacts_dir / f"consulta_de_headers_sent_{timestamp}.json"
                        import json
                        headers_sent_file.write_text(
                            json.dumps(headers, indent=2, ensure_ascii=False),
                            encoding="utf-8"
                        )
                        
                        # Guardar headers recibidos
                        headers_recv_file = artifacts_dir / f"consulta_de_headers_received_{timestamp}.json"
                        headers_recv_file.write_text(
                            json.dumps(dict(resp.headers), indent=2, ensure_ascii=False),
                            encoding="utf-8"
                        )
                        
                        # Guardar body recibido
                        body_recv_file = artifacts_dir / f"consulta_de_response_{timestamp}.xml"
                        body_recv_file.write_text(resp.text, encoding="utf-8")
                    except Exception:
                        pass  # No romper el flujo si falla guardar artifacts
                
                # Intentar parsear XML y extraer dCodRes/dMsgRes/dProtAut si existen
                try:
                    resp_root = etree.fromstring(resp.content)
                    cod_res = resp_root.find(".//{http://ekuatia.set.gov.py/sifen/xsd}dCodRes")
                    msg_res = resp_root.find(".//{http://ekuatia.set.gov.py/sifen/xsd}dMsgRes")
                    prot_aut = resp_root.find(".//{http://ekuatia.set.gov.py/sifen/xsd}dProtAut")
                    if cod_res is not None and cod_res.text:
                        result["dCodRes"] = cod_res.text.strip()
                    if msg_res is not None and msg_res.text:
                        result["dMsgRes"] = msg_res.text.strip()
                    if prot_aut is not None and prot_aut.text:
                        result["dProtAut"] = prot_aut.text.strip()
                except Exception:
                    pass  # Si no se puede parsear, solo devolver raw_xml
                
                # Éxito: salir del loop de retry
                break
                
            except (ConnectionResetError, requests.exceptions.ConnectionError) as e:
                # Errores de conexión: retry
                last_exception = e
                if attempt < max_attempts:
                    delay = retry_delays[attempt - 1] if attempt <= len(retry_delays) else retry_delays[-1]
                    logger.warning(f"Error de conexión al consultar DE por CDC (intento {attempt}/{max_attempts}): {e}. Reintentando en {delay}s...")
                    time.sleep(delay)
                else:
                    # Último intento falló: guardar artifacts si dump_http y luego re-raise
                    if dump_http:
                        try:
                            from pathlib import Path
                            artifacts_dir = Path("artifacts")
                            artifacts_dir.mkdir(exist_ok=True)
                            timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                            
                            # Guardar SOAP enviado (aunque falló)
                            sent_file = artifacts_dir / f"consulta_de_sent_ERROR_{timestamp}.xml"
                            sent_file.write_text(soap_xml_str, encoding="utf-8")
                            
                            # Guardar headers enviados
                            headers_sent_file = artifacts_dir / f"consulta_de_headers_sent_ERROR_{timestamp}.json"
                            import json
                            headers_sent_file.write_text(
                                json.dumps(headers, indent=2, ensure_ascii=False),
                                encoding="utf-8"
                            )
                            
                            # Guardar error
                            error_file = artifacts_dir / f"consulta_de_error_{timestamp}.txt"
                            error_file.write_text(
                                f"Error de conexión después de {max_attempts} intentos:\n{type(e).__name__}: {e}\n",
                                encoding="utf-8"
                            )
                        except Exception:
                            pass
                    raise SifenClientError(f"Error de conexión al consultar DE por CDC después de {max_attempts} intentos: {e}") from e
            except Exception as e:
                # Otros errores: no retry, guardar artifacts si dump_http y re-raise
                last_exception = e
                if dump_http:
                    try:
                        from pathlib import Path
                        artifacts_dir = Path("artifacts")
                        artifacts_dir.mkdir(exist_ok=True)
                        timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                        
                        # Guardar SOAP enviado (aunque falló)
                        sent_file = artifacts_dir / f"consulta_de_sent_ERROR_{timestamp}.xml"
                        sent_file.write_text(soap_xml_str, encoding="utf-8")
                        
                        # Guardar headers enviados
                        headers_sent_file = artifacts_dir / f"consulta_de_headers_sent_ERROR_{timestamp}.json"
                        import json
                        headers_sent_file.write_text(
                            json.dumps(headers, indent=2, ensure_ascii=False),
                            encoding="utf-8"
                        )
                        
                        # Guardar error
                        error_file = artifacts_dir / f"consulta_de_error_{timestamp}.txt"
                        error_file.write_text(
                            f"Error al consultar DE por CDC:\n{type(e).__name__}: {e}\n",
                            encoding="utf-8"
                        )
                    except Exception:
                        pass
                raise SifenClientError(f"Error al consultar DE por CDC: {e}") from e
        
        return result
        
        # SNIPPET DE PRUEBA (comentado):
        # from app.sifen_client.config import get_sifen_config
        # from app.sifen_client.soap_client import SoapClient
        # 
        # OLD_CDC = "01045547378001001000000112025123011234567892"
        # NEW_CDC = "01045547378001001000000212025123011234567890"
        # 
        # config = get_sifen_config(env="test")
        # with SoapClient(config) as client:
        #     result = client.consulta_de_por_cdc_raw(OLD_CDC, dump_http=True)
        #     print(f"dCodRes: {result.get('dCodRes', 'N/A')}")
        #     print(f"dMsgRes: {result.get('dMsgRes', 'N/A')}")
        #     print(f"dProtAut: {result.get('dProtAut', 'N/A')}")

    def consulta_ruc_raw(self, ruc: str, dump_http: bool = False, did: Optional[str] = None) -> Dict[str, Any]:
        """Consulta estado y habilitación de un RUC (sin depender del WSDL).
        
        Args:
            ruc: RUC del contribuyente (puede incluir DV si viene como "RUC-DV", ej: "4554737-8")
            dump_http: Si True, retorna también sent_headers y sent_xml para debug
            did: dId opcional (si None, se genera automáticamente con formato YYYYMMDDHHMMSS + 1 dígito = 15 dígitos)
            
        Returns:
            Dict con http_status, raw_xml, y opcionalmente:
            - dCodRes, dMsgRes (siempre presentes si la respuesta es válida)
            - xContRUC (opcional): dict con dRUCCons, dRazCons, dCodEstCons, dDesEstCons, dRUCFactElec
            Si dump_http=True, también incluye sent_headers y sent_xml.
        """
        import lxml.etree as etree  # noqa: F401
        import datetime as _dt
        import random
        import time
        
        # Parsear RUC: puede venir como "RUC-DV" (ej: "4554737-8") o "RUC+DV" (ej: "45547378")
        # Por defecto enviamos el RUC con DV integrado (sin guión), configurable vía env.
        from app.sifen_client.cdc_utils import calc_dv_mod11

        ruc_clean = (ruc or "").strip()
        digits = re.sub(r"\\D", "", ruc_clean)
        use_dv = (os.getenv("SIFEN_RUC_WITH_DV") or "1").strip().lower() in ("1", "true", "yes")
        ruc_final = digits
        if not use_dv and len(digits) >= 2:
            base = digits[:-1]
            try:
                dv = calc_dv_mod11(base)
                if str(dv) == digits[-1]:
                    ruc_final = base
            except Exception:
                ruc_final = digits
        
        # Generar dId de 15 dígitos si no se proporciona (formato: YYYYMMDDHHMMSS + 1 dígito aleatorio)
        # Igual que en rEnvioLote y consulta_de_por_cdc_raw
        if did is None:
            base = _dt.datetime.now().strftime("%Y%m%d%H%M%S")  # 14 dígitos
            did = f"{base}{random.randint(0, 9)}"  # + 1 dígito = 15 dígitos total
        
        # Construir SOAP 1.2 envelope con estructura exacta requerida según XSD
        # XSD: WS_SiConsRUC_v141.xsd define rEnviConsRUC con dId y dRUCCons
        # Elemento root: rEnviConsRUC (NO rEnviConsRucRequest)
        SOAP_12_NS = "http://www.w3.org/2003/05/soap-envelope"
        
        # Envelope SOAP 1.2
        envelope = etree.Element(
            f"{{{SOAP_12_NS}}}Envelope",
            nsmap={"soap": SOAP_12_NS}
        )
        
        # Header vacío
        header = etree.SubElement(envelope, f"{{{SOAP_12_NS}}}Header")
        
        # Body
        body = etree.SubElement(envelope, f"{{{SOAP_12_NS}}}Body")
        
        # rEnviConsRUC según XSD (targetNamespace: http://ekuatia.set.gov.py/sifen/xsd)
        # XSD define: <xs:element name="rEnviConsRUC">
        # IMPORTANTE: Usar namespace default (sin prefijo) para consulta_ruc
        r_envi_cons_ruc = etree.SubElement(
            body, "rEnviConsRUC", nsmap={None: SIFEN_NS}
        )
        
        # dId OBLIGATORIO según XSD (tipo: dIdType) - debe ser hijo directo y primero
        d_id_elem = etree.SubElement(r_envi_cons_ruc, f"{{{SIFEN_NS}}}dId")
        d_id_elem.text = str(did)
        
        # dRUCCons requerido según XSD (tipo: tRuc) - debe ser hijo directo y segundo
        # tRuc: minLength=5, maxLength=8, pattern=[1-9][0-9]*[0-9A-D]? (puede incluir DV)
        d_ruc_cons_elem = etree.SubElement(r_envi_cons_ruc, f"{{{SIFEN_NS}}}dRUCCons")
        d_ruc_cons_elem.text = str(ruc_final)
        
        # Serializar SOAP
        soap_bytes = etree.tostring(
            envelope, xml_declaration=True, encoding="UTF-8", pretty_print=False
        )
        
        # HARD-FAIL LOCAL ANTES DE ENVIAR: Verificar que el SOAP generado parsea correctamente
        try:
            # Intentar parsear el SOAP generado
            test_root = etree.fromstring(soap_bytes)
            
            # Validar estructura básica: Envelope->Body->rEnviConsRUC
            soap_env_ns = "http://www.w3.org/2003/05/soap-envelope"
            body_elem = test_root.find(f".//{{{soap_env_ns}}}Body")
            if body_elem is None:
                raise RuntimeError(f"SOAP Body no encontrado después de generar. SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}")
            
            # Validar que rEnviConsRUC existe en Body (hijo directo)
            # Buscar con prefijo xsd (nuevo formato)
            request_elem = body_elem.find(f"{{{SIFEN_NS}}}rEnviConsRUC")
            if request_elem is None:
                # Intentar buscar con prefijo xsd usando QName local
                for child in body_elem:
                    if etree.QName(child.tag).localname == "rEnviConsRUC":
                        request_elem = child
                        break
            
            if request_elem is None:
                # Intentar sin namespace (fallback original)
                request_elem = body_elem.find(".//rEnviConsRUC")
            
            if request_elem is None:
                # Intentar buscar cualquier hijo directo de Body para debug
                body_children = [etree.QName(ch.tag).localname if isinstance(ch.tag, str) else str(ch.tag) for ch in body_elem]
                raise RuntimeError(
                    f"rEnviConsRUC no encontrado en SOAP Body. "
                    f"Hijos directos de Body: {body_children}. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            
            # Verificar que rEnviConsRUC es hijo directo de Body (no descendiente)
            if request_elem.getparent() is not body_elem:
                raise RuntimeError(
                    f"rEnviConsRUC no es hijo directo de Body. "
                    f"Parent: {etree.QName(request_elem.getparent().tag).localname if request_elem.getparent() is not None else 'None'}. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            
            # Validar que tiene dId y dRUCCons como hijos directos y no vacíos
            d_id_check = request_elem.find(f"{{{SIFEN_NS}}}dId")
            if d_id_check is None:
                # Buscar hijo con localname "dId" (para manejar namespace con prefijo)
                for child in request_elem:
                    if etree.QName(child.tag).localname == "dId":
                        d_id_check = child
                        break
            if d_id_check is None:
                # Intentar sin namespace (fallback original)
                d_id_check = request_elem.find("dId")
            if d_id_check is None:
                raise RuntimeError(
                    f"dId no encontrado en rEnviConsRUC. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            if not d_id_check.text or not d_id_check.text.strip():
                raise RuntimeError(
                    f"dId está vacío en rEnviConsRUC. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            
            d_ruc_check = request_elem.find(f"{{{SIFEN_NS}}}dRUCCons")
            if d_ruc_check is None:
                # Buscar hijo con localname "dRUCCons" (para manejar namespace con prefijo)
                for child in request_elem:
                    if etree.QName(child.tag).localname == "dRUCCons":
                        d_ruc_check = child
                        break
            if d_ruc_check is None:
                # Intentar sin namespace (fallback original)
                d_ruc_check = request_elem.find("dRUCCons")
            if d_ruc_check is None:
                raise RuntimeError(
                    f"dRUCCons no encontrado en rEnviConsRUC. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            if not d_ruc_check.text or not d_ruc_check.text.strip():
                raise RuntimeError(
                    f"dRUCCons está vacío en rEnviConsRUC. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            
            # Validar orden según XSD: primero dId, luego dRUCCons
            children = list(request_elem)
            if len(children) < 2:
                raise RuntimeError(
                    f"rEnviConsRUC debe tener al menos 2 hijos (dId y dRUCCons), encontrados: {len(children)}. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            
            first_child_local = etree.QName(children[0]).localname if children[0].tag else None
            second_child_local = etree.QName(children[1]).localname if len(children) > 1 and children[1].tag else None
            
            if first_child_local != "dId":
                raise RuntimeError(
                    f"Primer hijo de rEnviConsRUC debe ser 'dId', encontrado: '{first_child_local}'. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            if second_child_local != "dRUCCons":
                raise RuntimeError(
                    f"Segundo hijo de rEnviConsRUC debe ser 'dRUCCons', encontrado: '{second_child_local}'. "
                    f"SOAP:\n{soap_bytes.decode('utf-8', errors='replace')}"
                )
            
            # Imprimir SOAP generado para validación (siempre en debug, también en consola si dump_http)
            soap_xml_str = soap_bytes.decode("utf-8", errors="replace")
            logger.debug(f"SOAP generado para consulta RUC (validado OK):\n{soap_xml_str}")
            
            # Si dump_http está activo, también imprimir en consola
            if dump_http:
                print("\n" + "="*70)
                print("SOAP GENERADO PARA CONSULTA RUC (VALIDADO)")
                print("="*70)
                print(soap_xml_str)
                print("="*70)
                print(f"✅ Validación previa: SOAP parsea correctamente")
                print(f"   - Elemento root: rEnviConsRUC")
                print(f"   - Namespace: {SIFEN_NS}")
                print(f"   - dId: {d_id_check.text} (15 dígitos: {len(d_id_check.text) == 15})")
                print(f"   - dRUCCons: {d_ruc_check.text}")
                print("="*70 + "\n")
                
        except etree.XMLSyntaxError as e:
            raise RuntimeError(f"SOAP generado no es XML válido: {e}\nSOAP:\n{soap_bytes.decode('utf-8', errors='replace')}") from e
        except Exception as e:
            raise RuntimeError(f"Error al validar SOAP generado: {e}") from e
        
        # Determinar endpoint según ambiente (usar config existente)
        # NOTA: get_soap_service_url devuelve el WSDL, para consulta_ruc necesitamos el endpoint POST
        endpoint = self.config.get_soap_service_url("consulta_ruc")
        if dump_http:
            print(f"[SIFEN DEBUG] POST URL (consulta_ruc): {endpoint}")
        # Para consulta_ruc, el endpoint POST es el WSDL sin .wsdl (diferente de recibe-lote)
        # IMPORTANTE: NO se quita .wsdl para consulta_ruc, SIFEN lo requiere con .wsdl
                
        # Headers SOAP 1.2 (application/soap+xml SIN action=)
        # SIFEN NO requiere action para consulta_ruc
        headers = {
            "Content-Type": "application/soap+xml; charset=utf-8; action=\"siConsRUC\"",
            "Accept": "application/soap+xml, text/xml, */*",
        }
        
        # Si dump_http está activo, guardar headers y XML enviados
        soap_xml_str = soap_bytes.decode("utf-8", errors="replace")
        result: Dict[str, Any] = {
            "http_status": 0,
            "raw_xml": "",
        }
        if dump_http:
            result["sent_headers"] = headers.copy()
            result["sent_xml"] = soap_xml_str
        
        # POST usando la sesión existente con mTLS
        session = self.transport.session
        
        # mTLS: la configuración ya está aplicada en _create_transport()
        # No necesitamos hacer nada más aquí
        
        # RETRY por errores de conexión (solo para esta consulta, NO para envíos)
        max_attempts = 3
        retry_delays = [0.5, 1.5]  # 0.5s después del primer intento, 1.5s después del segundo
        
        last_exception = None
        for attempt in range(1, max_attempts + 1):
            try:
                resp = session.post(
                    endpoint,
                    data=soap_bytes,
                    headers=headers,
                    timeout=(self.connect_timeout, self.read_timeout),
                )
                result["http_status"] = resp.status_code
                result["raw_xml"] = resp.text
                
                # Si dump_http está activo, agregar headers y body recibidos
                if dump_http:
                    result["received_headers"] = dict(resp.headers)
                    body_lines = resp.text.split("\n") if resp.text else []
                    if len(body_lines) > 500:
                        result["received_body_preview"] = "\n".join(body_lines[:500]) + f"\n... (truncado, total {len(body_lines)} líneas)"
                    else:
                        result["received_body_preview"] = resp.text
                
                # Guardar debug incluso si HTTP != 200
                debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
                if debug_enabled:
                    try:
                        from pathlib import Path
                        out_dir = Path("artifacts")
                        out_dir.mkdir(exist_ok=True)
                        received_file = out_dir / "soap_last_received_consulta_ruc.xml"
                        received_file.write_bytes(resp.content)
                    except Exception:
                        pass  # No romper el flujo si falla debug
                
                # Guardar artifacts de dump_http incluso si hay error HTTP
                if dump_http:
                    try:
                        from pathlib import Path
                        artifacts_dir = Path("artifacts")
                        artifacts_dir.mkdir(exist_ok=True)
                        timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                        
                        # Guardar SOAP enviado
                        sent_file = artifacts_dir / f"consulta_ruc_sent_{timestamp}.xml"
                        sent_file.write_text(soap_xml_str, encoding="utf-8")
                        
                        # Guardar headers enviados
                        headers_sent_file = artifacts_dir / f"consulta_ruc_headers_sent_{timestamp}.json"
                        import json
                        headers_sent_file.write_text(
                            json.dumps(headers, indent=2, ensure_ascii=False),
                            encoding="utf-8"
                        )
                        
                        # Guardar headers recibidos
                        headers_recv_file = artifacts_dir / f"consulta_ruc_headers_received_{timestamp}.json"
                        headers_recv_file.write_text(
                            json.dumps(dict(resp.headers), indent=2, ensure_ascii=False),
                            encoding="utf-8"
                        )
                        
                        # Guardar body recibido
                        body_recv_file = artifacts_dir / f"consulta_ruc_response_{timestamp}.xml"
                        body_recv_file.write_text(resp.text, encoding="utf-8")
                        
                        # Guardar JSON completo con evidencia forense
                        forensic_file = artifacts_dir / f"consulta_ruc_forensic_{timestamp}.json"
                        forensic_data = {
                            "timestamp": _dt.datetime.now().isoformat(),
                            "post_url_final": endpoint,
                            "sent_headers": headers,
                            "received_headers": dict(resp.headers),
                            "http_status": resp.status_code,
                            "soap_envelope": soap_xml_str,
                            "response_body": resp.text,
                        }
                        forensic_file.write_text(
                            json.dumps(forensic_data, indent=2, ensure_ascii=False),
                            encoding="utf-8"
                        )
                    except Exception:
                        pass  # No romper el flujo si falla guardar artifacts
                
                # Intentar parsear XML y extraer campos clave
                try:
                    resp_root = etree.fromstring(resp.content)
                    
                    # Extraer dCodRes y dMsgRes
                    cod_res = resp_root.find(".//{http://ekuatia.set.gov.py/sifen/xsd}dCodRes")
                    msg_res = resp_root.find(".//{http://ekuatia.set.gov.py/sifen/xsd}dMsgRes")
                    if cod_res is not None and cod_res.text:
                        result["dCodRes"] = cod_res.text.strip()
                    if msg_res is not None and msg_res.text:
                        result["dMsgRes"] = msg_res.text.strip()
                    
                    # Extraer xContRUC si está presente
                    x_cont_ruc = resp_root.find(".//{http://ekuatia.set.gov.py/sifen/xsd}xContRUC")
                    if x_cont_ruc is not None:
                        cont_ruc_dict: Dict[str, Any] = {}
                        
                        # dRUCCons
                        d_ruc_cons = x_cont_ruc.find(".//{http://ekuatia.set.gov.py/sifen/xsd}dRUCCons")
                        if d_ruc_cons is not None and d_ruc_cons.text:
                            cont_ruc_dict["dRUCCons"] = d_ruc_cons.text.strip()
                        
                        # dRazCons (razón social)
                        d_raz_cons = x_cont_ruc.find(".//{http://ekuatia.set.gov.py/sifen/xsd}dRazCons")
                        if d_raz_cons is not None and d_raz_cons.text:
                            cont_ruc_dict["dRazCons"] = d_raz_cons.text.strip()
                        
                        # dCodEstCons (código de estado del contribuyente)
                        d_cod_est_cons = x_cont_ruc.find(".//{http://ekuatia.set.gov.py/sifen/xsd}dCodEstCons")
                        if d_cod_est_cons is not None and d_cod_est_cons.text:
                            cont_ruc_dict["dCodEstCons"] = d_cod_est_cons.text.strip()
                        
                        # dDesEstCons (descripción del estado)
                        d_des_est_cons = x_cont_ruc.find(".//{http://ekuatia.set.gov.py/sifen/xsd}dDesEstCons")
                        if d_des_est_cons is not None and d_des_est_cons.text:
                            cont_ruc_dict["dDesEstCons"] = d_des_est_cons.text.strip()
                        
                        # dRUCFactElec (habilitado para Facturación Electrónica: "1" = sí, "0" = no)
                        d_ruc_fact_elec = x_cont_ruc.find(".//{http://ekuatia.set.gov.py/sifen/xsd}dRUCFactElec")
                        if d_ruc_fact_elec is not None and d_ruc_fact_elec.text:
                            cont_ruc_dict["dRUCFactElec"] = d_ruc_fact_elec.text.strip()
                        
                        if cont_ruc_dict:
                            result["xContRUC"] = cont_ruc_dict
                            
                except Exception:
                    pass  # Si no se puede parsear, solo devolver raw_xml
                
                # Éxito: salir del loop de retry
                break
                
            except (ConnectionResetError, requests.exceptions.ConnectionError) as e:
                # Errores de conexión: retry
                last_exception = e
                if attempt < max_attempts:
                    delay = retry_delays[attempt - 1] if attempt <= len(retry_delays) else retry_delays[-1]
                    logger.warning(f"Error de conexión al consultar RUC (intento {attempt}/{max_attempts}): {e}. Reintentando en {delay}s...")
                    time.sleep(delay)
                else:
                    # Último intento falló: guardar artifacts si dump_http y luego re-raise
                    if dump_http:
                        try:
                            from pathlib import Path
                            artifacts_dir = Path("artifacts")
                            artifacts_dir.mkdir(exist_ok=True)
                            timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                            
                            # Guardar SOAP enviado (aunque falló)
                            sent_file = artifacts_dir / f"consulta_ruc_sent_ERROR_{timestamp}.xml"
                            sent_file.write_text(soap_xml_str, encoding="utf-8")
                            
                            # Guardar headers enviados
                            headers_sent_file = artifacts_dir / f"consulta_ruc_headers_sent_ERROR_{timestamp}.json"
                            import json
                            headers_sent_file.write_text(
                                json.dumps(headers, indent=2, ensure_ascii=False),
                                encoding="utf-8"
                            )
                            
                            # Guardar error
                            error_file = artifacts_dir / f"consulta_ruc_error_{timestamp}.txt"
                            error_file.write_text(
                                f"Error de conexión después de {max_attempts} intentos:\n{type(e).__name__}: {e}\n",
                                encoding="utf-8"
                            )
                        except Exception:
                            pass
                    raise SifenClientError(f"Error de conexión al consultar RUC después de {max_attempts} intentos: {e}") from e
            except Exception as e:
                # Otros errores: no retry, guardar artifacts si dump_http y re-raise
                last_exception = e
                if dump_http:
                    try:
                        from pathlib import Path
                        artifacts_dir = Path("artifacts")
                        artifacts_dir.mkdir(exist_ok=True)
                        timestamp = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                        
                        # Guardar SOAP enviado (aunque falló)
                        sent_file = artifacts_dir / f"consulta_ruc_sent_ERROR_{timestamp}.xml"
                        sent_file.write_text(soap_xml_str, encoding="utf-8")
                        
                        # Guardar headers enviados
                        headers_sent_file = artifacts_dir / f"consulta_ruc_headers_sent_ERROR_{timestamp}.json"
                        import json
                        headers_sent_file.write_text(
                            json.dumps(headers, indent=2, ensure_ascii=False),
                            encoding="utf-8"
                        )
                        
                        # Guardar error
                        error_file = artifacts_dir / f"consulta_ruc_error_{timestamp}.txt"
                        error_file.write_text(
                            f"Error al consultar RUC:\n{type(e).__name__}: {e}\n",
                            encoding="utf-8"
                        )
                    except Exception:
                        pass
                raise SifenClientError(f"Error al consultar RUC: {e}") from e
        
        return result

    def close(self) -> None:
        if (
            hasattr(self, "transport")
            and self.transport
            and hasattr(self.transport, "session")
        ):
            try:
                self.transport.session.close()
            except Exception:
                pass

        if self._temp_pem_files:
            cert_path, key_path = self._temp_pem_files
            cleanup_pem_files(cert_path, key_path)
            self._temp_pem_files = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
