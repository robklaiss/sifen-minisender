"""
Módulo para consultar estado de lotes SIFEN
"""
import os
import logging
import time
from typing import Dict, Any, Optional
from pathlib import Path
import sys

# Agregar tools al path para importar call_consulta_lote_raw
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from requests import Session
from lxml import etree

logger = logging.getLogger(__name__)

# Importar función de consulta desde tools y helper PKCS12
try:
    from tools.consulta_lote_de import call_consulta_lote_raw
except ImportError:
    logger.error("No se pudo importar call_consulta_lote_raw desde tools.consulta_lote_de")
    raise

# Importar helper PKCS12 desde módulo correcto
try:
    from app.sifen_client.pkcs12_utils import p12_to_temp_pem_files
except ImportError:
    logger.error("No se pudo importar p12_to_temp_pem_files desde app.sifen_client.pkcs12_utils")
    raise


def validate_prot_cons_lote(prot: str) -> bool:
    """
    Valida que dProtConsLote sea solo dígitos.

    Args:
        prot: Número de lote a validar

    Returns:
        True si es válido, False si no
    """
    if not prot:
        return False
    return prot.strip().isdigit()


def parse_lote_response(xml_response: str) -> Dict[str, Any]:
    """
    Parsea la respuesta XML de consulta de lote para extraer dCodResLot y dMsgResLot.

    Args:
        xml_response: XML de respuesta como string

    Returns:
        Dict con:
            - cod_res_lot: Código de respuesta (ej: "0361", "0362", "0364")
            - msg_res_lot: Mensaje de respuesta
            - ok: True si el parsing fue exitoso
    """
    result = {
        "cod_res_lot": None,
        "msg_res_lot": None,
        "ok": False,
    }

    try:
        root = etree.fromstring(xml_response.encode("utf-8"))

        def find_text(xpath_expr: str) -> Optional[str]:
            try:
                nodes = root.xpath(xpath_expr)
                if nodes:
                    val = nodes[0].text
                    return val.strip() if val else None
            except Exception:
                return None
            return None

        # Buscar dCodResLot y dMsgResLot por local-name
        result["cod_res_lot"] = find_text('//*[local-name()="dCodResLot"]')
        result["msg_res_lot"] = find_text('//*[local-name()="dMsgResLot"]')

        result["ok"] = True

    except Exception as e:
        logger.warning(f"Error al parsear respuesta XML de lote: {e}")
        result["ok"] = False

    return result


def check_lote_status(
    env: str,
    prot: str,
    p12_path: Optional[str] = None,
    p12_password: Optional[str] = None,
    timeout: int = 30,
) -> Dict[str, Any]:
    """
    Consulta el estado de un lote en SIFEN usando SOAP RAW.

    Args:
        env: Ambiente ('test' o 'prod')
        prot: dProtConsLote (debe ser solo dígitos)
        p12_path: Ruta al certificado P12 (opcional, usa env vars si no se proporciona)
        p12_password: Contraseña del P12 (opcional, usa env vars si no se proporciona)
        timeout: Timeout HTTP en segundos

    Returns:
        Dict con:
            - success: True si la consulta fue exitosa
            - cod_res_lot: Código de respuesta (ej: "0361", "0362", "0364")
            - msg_res_lot: Mensaje de respuesta
            - response_xml: XML completo de respuesta
            - error: Mensaje de error si falló

    Raises:
        ValueError: Si prot no es válido (no es solo dígitos)
    """
    # Validar prot
    if not validate_prot_cons_lote(prot):
        raise ValueError(
            f"dProtConsLote debe ser solo dígitos. Valor recibido: '{prot}'"
        )

    # Resolver certificado desde env vars si no se proporciona - usar helper unificado
    if not p12_path or not p12_password:
        try:
            from app.sifen_client.config import get_cert_path_and_password
            env_cert_path, env_cert_password = get_cert_path_and_password()
            p12_path = p12_path or env_cert_path
            p12_password = p12_password or env_cert_password
        except RuntimeError as e:
            # El helper ya valida y lanza RuntimeError con mensaje claro
            return {
                "success": False,
                "error": str(e),
            }

    # Convertir P12 a PEM temporales (una sola vez, no por cada reintento)
    cert_path = None
    key_path = None
    try:
        cert_path, key_path = p12_to_temp_pem_files(p12_path, p12_password)
        
        # Debug: verificar que los archivos PEM existen
        print(f"[SIFEN DEBUG] cert_path={os.path.basename(cert_path)} exists={os.path.exists(cert_path)}")
        print(f"[SIFEN DEBUG] key_path={os.path.basename(key_path)} exists={os.path.exists(key_path)}")

        # Consultar lote con retry/backoff para errores transitorios de red
        # NOTA: NO recrear session en cada reintento - el transport dentro de call_consulta_lote_raw
        # ya tiene retries configurados y reutiliza la misma session con cookies
        logger.info(f"Consultando lote {prot} en ambiente {env}")
        print(f"[SIFEN DEBUG] check_lote_status: prot={prot} env={env} timeout={timeout}")
        
        # Backoff: 0.5s, 1.5s, 3s
        backoff_times = [0.5, 1.5, 3.0]
        last_error = None
        
        for attempt in range(3):
            try:
                # NO recrear session - reusar la misma para mantener cookies
                # El transport dentro de call_consulta_lote_raw ya tiene retries configurados
                if attempt > 0:
                    print(f"[SIFEN DEBUG] check_lote_status: retry {attempt+1}/3")
                
                xml_response = call_consulta_lote_raw(
                    session=None, env=env, prot=prot, timeout=timeout
                )
                
                # Guardar respuesta cruda de SIFEN para diagnóstico
                try:
                    from datetime import datetime
                    artifacts_dir = Path("artifacts")
                    artifacts_dir.mkdir(parents=True, exist_ok=True)
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    out = artifacts_dir / f"consulta_lote_{prot}_{ts}.xml"
                    out.write_text(xml_response, encoding="utf-8")
                    print(f"[SIFEN DEBUG] consulta_lote XML guardado: {out}")
                except Exception as e:
                    print(f"[SIFEN DEBUG] no se pudo guardar XML de consulta_lote: {e}")
                
                # Éxito, salir del loop
                print(f"[SIFEN DEBUG] check_lote_status: consulta exitosa, xml_response length={len(xml_response) if xml_response else 0}")
                break
            except Exception as e:
                # Capturar errores de conexión transitorios
                error_str = str(e).lower()
                error_type = type(e).__name__
                
                # Detectar errores de conexión transitorios
                is_connection_error = (
                    isinstance(e, (ConnectionError, OSError)) or
                    "connection reset" in error_str or
                    "connection aborted" in error_str or
                    "connection refused" in error_str or
                    "reset by peer" in error_str or
                    error_type in ("ConnectionError", "ConnectionResetError", "OSError")
                )
                
                if is_connection_error:
                    last_error = e
                    if attempt < 2:  # No es el último intento
                        wait_time = backoff_times[attempt]
                        logger.warning(
                            f"Error de conexión transitorio al consultar lote {prot} "
                            f"(intento {attempt + 1}/3): {e}. Reintentando en {wait_time}s..."
                        )
                        print(f"[SIFEN DEBUG] check_lote_status: error de conexión (intento {attempt + 1}/3): {type(e).__name__}: {str(e)[:200]}")
                        time.sleep(wait_time)
                        continue
                    else:
                        # Último intento falló, lanzar error
                        logger.error(f"Error de conexión tras 3 intentos al consultar lote {prot}: {e}")
                        print(f"[SIFEN DEBUG] check_lote_status: error de conexión tras 3 intentos: {type(e).__name__}: {str(e)[:200]}")
                        raise
                else:
                    # Otro tipo de error, no reintentar
                    print(f"[SIFEN DEBUG] check_lote_status: EXC {type(e).__name__}: {str(e)[:200]}")
                    raise

        # Parsear respuesta
        parsed = parse_lote_response(xml_response)

        result = {
            "success": True,
            "cod_res_lot": parsed.get("cod_res_lot"),
            "msg_res_lot": parsed.get("msg_res_lot"),
            "response_xml": xml_response,
        }

        return result

    except Exception as e:
        # Error de conexión transitorio (tras 3 intentos) u otro error
        error_str = str(e).lower()
        error_type = type(e).__name__
        
        print(f"[SIFEN DEBUG] check_lote_status: EXC final {error_type}: {str(e)[:200]}")
        
        # Detectar errores de conexión transitorios
        is_connection_error = (
            isinstance(e, (ConnectionError, OSError)) or
            "connection reset" in error_str or
            "connection aborted" in error_str or
            "reset by peer" in error_str or
            error_type in ("ConnectionError", "ConnectionResetError", "OSError")
        )
        
        if is_connection_error:
            error_msg = "SIFEN no respondió (reset by peer). Reintentar."
            logger.error(f"Error de conexión al consultar lote {prot} tras 3 intentos: {e}")
        else:
            error_msg = str(e)
            logger.error(f"Error al consultar lote {prot}: {e}")
        
        return {
            "success": False,
            "error": error_msg,
            "response_xml": None,
        }
    finally:
        # Limpiar archivos PEM temporales
        if cert_path and key_path:
            try:
                os.unlink(cert_path)
                os.unlink(key_path)
            except Exception as e:
                logger.warning(f"Error al limpiar archivos PEM temporales: {e}")


def determine_status_from_cod_res_lot(cod_res_lot: Optional[str]) -> str:
    """
    Determina el estado del lote basado en el código de respuesta.

    Args:
        cod_res_lot: Código de respuesta (ej: "0361", "0362", "0364")

    Returns:
        Estado: 'processing', 'done', 'expired_window', 'requires_cdc', o 'error'
    """
    # Importar estados desde lotes_db (evitar import circular)
    LOTE_STATUS_PROCESSING = "processing"
    LOTE_STATUS_DONE = "done"
    LOTE_STATUS_EXPIRED_WINDOW = "expired_window"
    LOTE_STATUS_REQUIRES_CDC = "requires_cdc"
    LOTE_STATUS_ERROR = "error"

    if not cod_res_lot:
        return LOTE_STATUS_ERROR

    cod_res_lot = cod_res_lot.strip()

    # Códigos según documentación SIFEN
    if cod_res_lot == "0361":
        # Lote en procesamiento
        return LOTE_STATUS_PROCESSING
    elif cod_res_lot == "0362":
        # Lote procesado exitosamente
        return LOTE_STATUS_DONE
    elif cod_res_lot == "0364":
        # Ventana de 48h expirada (en TEST), requiere consulta por CDC
        return LOTE_STATUS_REQUIRES_CDC
    else:
        # Otros códigos (errores u otros estados)
        return LOTE_STATUS_ERROR

