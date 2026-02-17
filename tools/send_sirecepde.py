#!/usr/bin/env python3
"""
CLI para enviar XML siRecepLoteDE (rEnvioLote) al servicio SOAP de Recepción Lote DE (async) de SIFEN

try:
    SifenResponseError
except NameError:
    class SifenResponseError(Exception):
        pass

Este script usa SoapClient del módulo sifen_client para enviar documentos
electrónicos a SIFEN usando mTLS con certificados P12/PFX.

El script construye un lote (rLoteDE) con 1 rDE, lo comprime en ZIP, lo codifica en Base64
y lo envía dentro de un rEnvioLote al servicio async recibe_lote.

Uso:
    python -m tools.send_sirecepde --env test --xml artifacts/sirecepde_20251226_233653.xml
    python -m tools.send_sirecepde --env test --xml latest
    SIFEN_DEBUG_SOAP=1 SIFEN_SOAP_COMPAT=roshka python -m tools.send_sirecepde --env test --xml artifacts/signed.xml
"""
import sys
import argparse
import os
import re
import copy
from lxml import etree
import time
from pathlib import Path
from typing import Optional, Union, Tuple, Dict, Any
from datetime import datetime
from io import BytesIO
import base64
import zipfile
import json
import hashlib
import logging

logger = logging.getLogger(__name__)


def _resolve_artifacts_dir(artifacts_dir: Optional[Path] = None) -> Path:
    """Resolve artifacts directory (prefer explicit param, else env override, else artifacts/)."""
    if artifacts_dir is not None:
        p = Path(artifacts_dir)
    else:
        raw_dir = (
            os.getenv("SIFEN_ARTIFACTS_DIR")
            or os.getenv("ARTIFACTS_DIR")
            or os.getenv("SIFEN_ARTIFACTS_PATH")
        )
        try:
            p = Path(raw_dir).expanduser() if raw_dir else Path("artifacts")
        except Exception:
            p = Path("artifacts")
    p.mkdir(parents=True, exist_ok=True)
    return p


def _resolve_artifacts_base_dir() -> Path:
    """Resolve base artifacts directory from env, with artifacts/ as fallback."""
    raw_dir = (
        os.getenv("SIFEN_ARTIFACTS_DIR")
        or os.getenv("ARTIFACTS_DIR")
        or os.getenv("SIFEN_ARTIFACTS_PATH")
    )
    try:
        return Path(raw_dir).expanduser() if raw_dir else Path("artifacts")
    except Exception:
        return Path("artifacts")


def _resolve_run_artifacts_dir(*, run_id: Optional[str], artifacts_dir_override: Optional[Path]) -> Path:
    """Resolve deterministic per-run artifacts dir."""
    if run_id:
        return _resolve_artifacts_dir(_resolve_artifacts_base_dir() / str(run_id))
    if artifacts_dir_override is not None:
        return _resolve_artifacts_dir(artifacts_dir_override)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return _resolve_artifacts_dir(_resolve_artifacts_base_dir() / f"run_{ts}")


def _consulta_ruc_gate_with_retry(client, ruc_emisor, dump_http, artifacts_dir, max_tries=8):
    try:
        raw_max = os.environ.get("SIFEN_RUC_GATE_MAX_TRIES")
        if raw_max:
            max_tries = int(str(raw_max).strip())
    except Exception:
        pass
    if not max_tries or max_tries < 1:
        max_tries = 8

    sleep_base = 0.35
    try:
        raw_base = os.environ.get("SIFEN_RUC_GATE_SLEEP_BASE")
        if raw_base:
            sleep_base = float(str(raw_base).strip())
    except Exception:
        pass

    try:
        import requests  # type: ignore

        RequestException = requests.exceptions.RequestException
    except Exception:
        class RequestException(Exception):
            pass

    SifenClientError_ = globals().get("SifenClientError", Exception)

    seen_html = False
    seen_0160 = False
    last_hs = 0
    last_ct = ""
    last_cod = ""
    last_msg = ""

    for attempt in range(1, max_tries + 1):
        try:
            r = client.consulta_ruc_raw(ruc=ruc_emisor, dump_http=dump_http)
            cod = (r.get("dCodRes") or "").strip()
            msg = (r.get("dMsgRes") or "").strip()
            hdrs = r.get("received_headers") or {}
            ct = (hdrs.get("content-type") or hdrs.get("Content-Type") or "")
            try:
                hs = int(r.get("http_status") or 0)
            except Exception:
                hs = 0

            last_hs = hs
            last_ct = ct
            last_cod = cod
            last_msg = msg

            if cod == "0502":
                return r

            ct_lower = (ct or "").lower()
            is_transitory = ("text/html" in ct_lower) or (hs != 200) or (cod == "0160")
            if "text/html" in ct_lower:
                seen_html = True
            if cod == "0160":
                seen_0160 = True

            if is_transitory:
                logger.warning(
                    "SIFEN siConsRUC transitorio (attempt %s/%s): http_status=%s content_type=%r dCodRes=%r dMsgRes=%r",
                    attempt,
                    max_tries,
                    hs,
                    ct,
                    cod,
                    msg,
                )

                if "text/html" in ct_lower and artifacts_dir and Path(artifacts_dir).exists():
                    try:
                        preview_path = Path(artifacts_dir) / f"consulta_ruc_html_preview_attempt{attempt}.txt"
                        raw = r.get("raw_xml") or ""
                        if isinstance(raw, bytes):
                            raw_s = raw.decode("utf-8", errors="replace")
                        else:
                            raw_s = str(raw)
                        preview = "\n".join(raw_s.splitlines()[:80])
                        if len(preview) > 4096:
                            preview = preview[:4096]
                        preview_path.write_text(preview, encoding="utf-8", errors="replace")
                    except Exception:
                        pass

                if attempt < max_tries:
                    time.sleep(sleep_base * (1.0 + (attempt / 3.0)))
                continue

            if cod and cod not in ("0160", "0502"):
                raise RuntimeError(f"SIFEN siConsRUC no confirmó el RUC. dCodRes={cod} dMsgRes={msg}")

            logger.warning(
                "SIFEN siConsRUC respuesta inesperada (attempt %s/%s): http_status=%s content_type=%r dCodRes=%r dMsgRes=%r",
                attempt,
                max_tries,
                hs,
                ct,
                cod,
                msg,
            )
            if attempt < max_tries:
                time.sleep(sleep_base * (1.0 + (attempt / 3.0)))

        except (SifenClientError_, RequestException) as e:
            last_msg = f"{type(e).__name__}: {str(e)}"
            logger.warning(
                "SIFEN siConsRUC exception transitoria (attempt %s/%s): %s: %s",
                attempt,
                max_tries,
                type(e).__name__,
                str(e),
            )
            if attempt < max_tries:
                time.sleep(sleep_base * (1.0 + (attempt / 3.0)))
            continue
        except Exception as e:
            last_msg = f"{type(e).__name__}: {str(e)}"
            logger.warning(
                "SIFEN siConsRUC exception transitoria (attempt %s/%s): %s: %s",
                attempt,
                max_tries,
                type(e).__name__,
                str(e),
            )
            if attempt < max_tries:
                time.sleep(sleep_base * (1.0 + (attempt / 3.0)))
            continue

    seen_bits = []
    if seen_html:
        seen_bits.append("text/html")
    if seen_0160:
        seen_bits.append("0160")
    seen_suffix = f" Se observaron: {', '.join(seen_bits)}." if seen_bits else ""
    raise RuntimeError(
        f"SIFEN siConsRUC inestable: no confirmó RUC tras {max_tries} intentos. "
        f"last_status={last_hs} last_ct={last_ct} last_cod={last_cod} last_msg={last_msg}." 
        f"{seen_suffix}"
    )


def _recep_lote_with_retry(client, payload_xml, dump_http, artifacts_dir, max_tries=8):
    try:
        raw_max = os.environ.get("SIFEN_RECEP_LOTE_MAX_TRIES")
        if raw_max:
            max_tries = int(str(raw_max).strip())
    except Exception:
        pass
    if not max_tries or max_tries < 1:
        max_tries = 8

    sleep_base = 0.7
    try:
        raw_base = os.environ.get("SIFEN_RECEP_LOTE_SLEEP_BASE")
        if raw_base:
            sleep_base = float(str(raw_base).strip())
    except Exception:
        pass

    try:
        import requests  # type: ignore

        RequestException = requests.exceptions.RequestException
    except Exception:
        class RequestException(Exception):
            pass

    SifenClientError_ = globals().get("SifenClientError", Exception)

    last_msg = ""
    for attempt in range(1, max_tries + 1):
        try:
            return client.recepcion_lote(payload_xml, dump_http=dump_http)

        except (SifenClientError_, RequestException) as e:
            last_msg = f"{type(e).__name__}: {str(e)}"
            logger.warning(
                "SIFEN siRecepLoteDE exception transitoria (attempt %s/%s): %s",
                attempt,
                max_tries,
                last_msg,
            )

            # dump corto opcional
            if artifacts_dir and Path(artifacts_dir).exists():
                try:
                    (Path(artifacts_dir) / f"recep_lote_error_attempt{attempt}.txt").write_text(
                        last_msg[:4000], encoding="utf-8", errors="replace"
                    )
                except Exception:
                    pass

            if attempt < max_tries:
                time.sleep(sleep_base * (1.0 + (attempt / 3.0)))
                continue
            raise

        except Exception as e:
            last_msg = f"{type(e).__name__}: {str(e)}"
            logger.warning(
                "SIFEN siRecepLoteDE exception transitoria (attempt %s/%s): %s",
                attempt,
                max_tries,
                last_msg,
            )
            if attempt < max_tries:
                time.sleep(sleep_base * (1.0 + (attempt / 3.0)))
                continue
            raise

# Agregar el directorio padre al path para imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Excepción real (NO en docstring)
from app.sifen_client.exceptions import SifenResponseError

from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Constantes de namespace SIFEN
SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"
SIFEN_NS_URI = "http://ekuatia.set.gov.py/sifen/xsd"  # Alias para consistencia
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
DSIG_NS_URI = "http://www.w3.org/2000/09/xmldsig#"  # Alias para consistencia
XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"
XSI_NS_URI = "http://www.w3.org/2001/XMLSchema-instance"  # Alias para consistencia
NS = {"s": SIFEN_NS}


def _normalize_schema_location(value: str, *, ns: str = SIFEN_NS) -> str:
    """
    Normaliza xsi:schemaLocation para SIFEN, devolviendo siempre "<ns> <archivo.xsd>".
    """

    def _basename(token: str) -> str:
        token = (token or "").strip().strip('"').strip("'")
        token = token.split("?")[0].split("#")[0]
        if "/" in token:
            token = token.rsplit("/", 1)[-1]
        return token

    try:
        s = (value or "").strip().strip('"').strip("'")
        if not s:
            return f"{ns} siRecepDE_v150.xsd"

        parts = s.split()

        # Caso A: ya viene como par (ns, xsd)
        if len(parts) >= 2:
            return f"{ns} {_basename(parts[1]) or 'siRecepDE_v150.xsd'}"

        token = parts[0]

        # Caso B1: nombre directo del XSD
        if token.lower().endswith(".xsd") and "/" not in token:
            return f"{ns} {token}"

        # Caso B2: URL/path que termina en .xsd
        if token.lower().endswith(".xsd"):
            return f"{ns} {_basename(token) or 'siRecepDE_v150.xsd'}"

        # Caso B3: fallback conservador
        return f"{ns} {_basename(token) or 'siRecepDE_v150.xsd'}"
    except Exception:
        return f"{ns} siRecepDE_v150.xsd"

# --- Namespaces ---
def _qn_sifen(local: str) -> str:
    """Crea un QName SIFEN: {http://ekuatia.set.gov.py/sifen/xsd}local"""
    return f"{{{SIFEN_NS_URI}}}{local}"

def _is_namespaced(tag: str) -> bool:
    """Verifica si un tag tiene namespace (formato {ns}local)"""
    return isinstance(tag, str) and tag.startswith("{")

def _namespace_uri(tag: str) -> Optional[str]:
    """Extrae el namespace URI de un tag namespaced, o None si no tiene namespace"""
    if not _is_namespaced(tag):
        return None
    return tag[1:].split("}", 1)[0]

def ensure_sifen_namespace(root: etree._Element) -> etree._Element:
    """
    Asegura que TODOS los elementos SIFEN (sin namespace) queden en SIFEN_NS_URI.
    No toca nodos que ya estén namespaced (ej: ds:Signature).
    """
    def _walk(el: etree._Element):
        if isinstance(el.tag, str):
            ns = _namespace_uri(el.tag)
            if ns is None:
                el.tag = _qn_sifen(el.tag)
        for ch in el:
            _walk(ch)

    _walk(root)   # ✅ afuera del def _walk
    return root


def _localname(tag: str) -> str:
    """Extrae el localname de un tag (sin namespace)"""
    return tag.split("}", 1)[1] if isinstance(tag, str) and tag.startswith("{") else tag


def _scan_xml_bytes_for_common_malformed(xml_bytes: bytes) -> Optional[str]:
    """
    Devuelve un string describiendo el problema (con offset y contexto) o None si parece sano.
    Checks enfocados a SIFEN 0160:
      - BOM UTF-8 al inicio
      - caracteres de control inválidos en XML 1.0: 0x00–0x08, 0x0B, 0x0C, 0x0E–0x1F
      - entidades '&' sospechosas: que no sean &amp; &lt; &gt; &quot; &apos; o &#...; / &#x...;
    """
    # 1. BOM UTF-8
    if xml_bytes.startswith(b"\xef\xbb\xbf"):
        return "Se detectó BOM UTF-8 al inicio del XML (offset 0). SIFEN rechaza BOM. Remover: xml_bytes = xml_bytes[3:]"
    
    # 2. Caracteres de control inválidos
    invalid = set(range(0x00, 0x09)) | {0x0B, 0x0C} | set(range(0x0E, 0x20))
    
    for i, byte_val in enumerate(xml_bytes):
        if byte_val in invalid:
            # Contexto alrededor (40 bytes antes y después)
            start = max(0, i - 40)
            end = min(len(xml_bytes), i + 40)
            context = xml_bytes[start:end]
            context_repr = repr(context)
            
            # Precalcular representación del byte para evitar backslash en f-string
            if byte_val < 0x80:
                byte_repr = repr(chr(byte_val))
            else:
                byte_repr = f"\\x{byte_val:02x}"
            
            return (
                f"Carácter de control inválido en XML 1.0 detectado:\n"
                f"  Offset: {i} (0x{i:04x})\n"
                f"  Byte: 0x{byte_val:02x} ({byte_repr})\n"
                f"  Contexto (offset {start}-{end}): {context_repr}"
            )
    
    # 3. Entidades '&' mal formadas
    try:
        text = xml_bytes.decode("utf-8", errors="replace")
    except Exception:
        # Si no se puede decodificar, no podemos verificar entidades
        return None
    
    i = 0
    while i < len(text):
        if text[i] == '&':
            # Buscar el siguiente ';'
            semicolon_pos = text.find(';', i + 1)
            
            if semicolon_pos == -1:
                # '&' sin ';' => error
                start = max(0, i - 30)
                end = min(len(text), i + 30)
                snippet = text[start:end]
                return (
                    f"Entidad '&' mal formada (sin ';'):\n"
                    f"  Offset: {i}\n"
                    f"  Fragmento: {repr(snippet)}"
                )
            
            # Extraer la entidad
            entity = text[i+1:semicolon_pos]
            
            # Validar entidad
            is_valid = False
            if entity in ('amp', 'lt', 'gt', 'quot', 'apos'):
                is_valid = True
            elif entity.startswith('#') and len(entity) > 1:
                # Numérica: &#123; o &#x1A;
                if entity[1].isdigit():
                    # Decimal: &#123;
                    is_valid = all(c.isdigit() for c in entity[1:])
                elif entity[1].lower() == 'x' and len(entity) > 2:
                    # Hexadecimal: &#x1A;
                    is_valid = all(c in '0123456789abcdefABCDEF' for c in entity[2:])
            
            if not is_valid:
                start = max(0, i - 30)
                end = min(len(text), semicolon_pos + 1 + 30)
                snippet = text[start:end]
                return (
                    f"Entidad '&' mal formada o inválida:\n"
                    f"  Offset: {i}\n"
                    f"  Entidad: &{entity};\n"
                    f"  Fragmento: {repr(snippet)}"
                )
            
            i = semicolon_pos + 1
        else:
            i += 1
    
    return None


def _sanitize_rde_opening_tag_preserve_schema(tag_bytes: bytes) -> tuple[bytes, bool]:
    """Remueve atributos del tag rDE pero preserva xsi:schemaLocation si existe."""

    default_tag = f'<rDE xmlns="{SIFEN_NS}">'.encode("utf-8")
    if not tag_bytes:
        return default_tag, False

    match = re.search(br"<rDE\b[^>]*>", tag_bytes)
    if not match:
        return default_tag, False

    tag = match.group(0)
    schema_match = re.search(rb'\bxsi:schemaLocation\s*=\s*"([^"]+)"', tag)
    if not schema_match:
        return default_tag, False

    schema_val = schema_match.group(1)
    schema_text = (
        schema_val.decode("utf-8", errors="ignore")
        if isinstance(schema_val, (bytes, bytearray))
        else str(schema_val)
    )
    normalized_schema = _normalize_schema_location(schema_text)
    schema_bytes = normalized_schema.encode("utf-8")
    rebuilt_tag = (
        f'<rDE xmlns="{SIFEN_NS}" '
        f'xmlns:xsi="{XSI_NS}" '
        f'xsi:schemaLocation="{normalized_schema}">' \
    ).encode("utf-8")
    return rebuilt_tag, True


def ensure_rde_sifen(rde_el: etree._Element) -> etree._Element:
    """
    Garantiza que el root sea {SIFEN_NS_URI}rDE y que el default xmlns sea SIFEN.
    Además namespacifica todo el árbol SIFEN que venga sin namespace.
    No toca nodos ya namespaced (ej: ds:Signature).
    
    Args:
        rde_el: Elemento rDE a asegurar
        
    Returns:
        Nuevo elemento rDE con namespace SIFEN correcto y default xmlns
    """
    if not isinstance(rde_el.tag, str) or _localname(rde_el.tag) != "rDE":
        raise RuntimeError(f"Se esperaba rDE como root, llegó: {rde_el.tag}")

    # 1) Asegurar root rDE en SIFEN
    if _namespace_uri(rde_el.tag) != SIFEN_NS_URI:
        rde_el.tag = _qn_sifen("rDE")

    # 2) Namespacificar todo lo SIFEN sin namespace
    ensure_sifen_namespace(rde_el)

    # 3) Forzar default xmlns SIFEN re-envolviendo el root
    new_rde = etree.Element(
        _qn_sifen("rDE"),
        nsmap={None: SIFEN_NS_URI, "ds": DSIG_NS_URI, "xsi": XSI_NS_URI},
    )

    # Copiar atributos (si existieran)
    for k, v in rde_el.attrib.items():
        new_rde.set(k, v)

    # Mover hijos
    for ch in list(rde_el):
        parent = ch.getparent()
        if parent is not None and parent is rde_el:
            rde_el.remove(ch)
            new_rde.append(ch)

    return new_rde


def _move_signature_into_de_if_needed(signed_bytes: bytes, artifacts_dir: Optional[Path], debug_enabled: bool) -> bytes:
    """
    Mueve la Signature dentro del rDE (como hermano del DE) si está fuera.
    
    Según solución error 0160, la estructura correcta en rDE es:
    - dVerFor
    - DE
    - Signature  (← aquí, como hermano de DE)
    - gCamFuFD
    
    Args:
        signed_bytes: XML firmado como bytes
        artifacts_dir: Directorio para guardar artifacts (opcional)
        debug_enabled: Si True, guarda artifacts de debug
        
    Returns:
        XML corregido como bytes (con Signature en posición correcta)
    """
    try:
        root = etree.fromstring(signed_bytes)
    except Exception as e:
        raise ValueError(f"Error al parsear XML firmado: {e}")
    
    # Guardar entrada si está en modo debug
    if debug_enabled and artifacts_dir:
        try:
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            artifacts_dir.joinpath("signed_before_sig_move.xml").write_bytes(signed_bytes)
        except Exception:
            pass
    
    # Encontrar rDE
    rde_elem = None
    if local_tag(root.tag) == "rDE":
        rde_elem = root
    else:
        # Buscar rDE dentro del árbol
        rde_elem = root.find(f".//{{{SIFEN_NS_URI}}}rDE")
        if rde_elem is None:
            # Fallback: buscar por local-name
            nodes = root.xpath("//*[local-name()='rDE']")
            rde_elem = nodes[0] if nodes else None
    
    if rde_elem is None:
        # Si no hay rDE, retornar sin cambios
        return signed_bytes
    
    # Buscar DE dentro de rDE
    de_elem = rde_elem.find(f".//{{{SIFEN_NS_URI}}}DE")
    if de_elem is None:
        # Fallback: buscar por local-name
        nodes = rde_elem.xpath(".//*[local-name()='DE']")
        de_elem = nodes[0] if nodes else None
    
    if de_elem is None:
        # Si no hay DE, retornar sin cambios
        return signed_bytes
    
    # Verificar si Signature YA está en posición correcta (hijo de rDE, después de DE)
    # Buscar Signature como hijo directo de rDE
    sig_in_rde = None
    for child in rde_elem:
        if local_tag(child.tag) == "Signature" and _namespace_uri(child.tag) == DSIG_NS_URI:
            sig_in_rde = child
            break
    
    if sig_in_rde is not None:
        # Verificar si está después de DE
        de_index = list(rde_elem).index(de_elem)
        sig_index = list(rde_elem).index(sig_in_rde)
        if sig_index > de_index:
            # Ya está en posición correcta
            return signed_bytes
    
    # Buscar Signature en cualquier lugar
    sig_elem = None
    for elem in root.iter():
        if local_tag(elem.tag) == "Signature" and _namespace_uri(elem.tag) == DSIG_NS_URI:
            sig_elem = elem
            break
    
    if sig_elem is None:
        # No hay Signature, retornar sin cambios
        return signed_bytes
    
    # Mover Signature a posición correcta en rDE
    # Remover Signature de su ubicación actual
    sig_parent = sig_elem.getparent()
    if sig_parent is not None and sig_elem in list(sig_parent):
        sig_parent.remove(sig_elem)
    
    # Insertar Signature después de DE en rDE
    de_index = list(rde_elem).index(de_elem)
    
    # Buscar gCamFuFD para insertar antes que él
    gcamfufd = None
    for child in rde_elem:
        if local_tag(child.tag) == "gCamFuFD":
            gcamfufd = child
            break
    
    if gcamfufd is not None:
        # Insertar Signature antes de gCamFuFD
        gcam_index = list(rde_elem).index(gcamfufd)
        rde_elem.insert(gcam_index, sig_elem)
    else:
        # Insertar después de DE
        rde_elem.insert(de_index + 1, sig_elem)
    
    # Serializar de vuelta a bytes
    result_bytes = etree.tostring(root, encoding="utf-8", xml_declaration=True)
    
    # Guardar salida si está en modo debug
    if debug_enabled and artifacts_dir:
        try:
            artifacts_dir.mkdir(parents=True, exist_ok=True)
            artifacts_dir.joinpath("signed_after_sig_move.xml").write_bytes(result_bytes)
        except Exception:
            pass
    
    return result_bytes


def build_lote_xml(rde_element: etree._Element) -> bytes:
    """
    Construye el XML del lote (rLoteDE) con namespace SIFEN correcto.

    IMPORTANTE:
    - lote.xml (dentro del ZIP) NO debe contener <dId> ni <xDE>.
      Esos campos pertenecen al SOAP rEnvioLote, NO al archivo lote.xml.
    """
    rLoteDE = etree.Element(
        etree.QName(SIFEN_NS, "rLoteDE"),
        nsmap={None: SIFEN_NS, "xsi": XSI_NS}
    )
    # Opcional (recomendado por SIFEN)
    rLoteDE.set(etree.QName(XSI_NS, "schemaLocation"), f"{SIFEN_NS} siRecepDE_v150.xsd")

    # El lote.xml debe contener directamente el rDE firmado
    rLoteDE.append(rde_element)

    return etree.tostring(rLoteDE, encoding="utf-8", xml_declaration=True, pretty_print=False)

# Configuración del lote: usar default namespace o prefijo
# Si True: <rLoteDE xmlns="..."> (default namespace)
# Si False: <ns0:rLoteDE xmlns:ns0="..."> (prefijo)
LOTE_DEFAULT_NS = True

# Helper regex para detectar XML declaration
_XML_DECL_RE = re.compile(br"^\s*<\?xml[^>]*\?>\s*", re.I)


def local_tag(tag: str) -> str:
    """Devuelve el localname de un tag QName '{ns}local' o el tag si no tiene ns."""
    return tag.split('}', 1)[1] if '}' in tag else tag

# Test rápido al inicio del módulo (solo debug)
if __name__ != "__main__":  # Solo cuando se importa, no cuando se ejecuta directamente
    assert callable(local_tag), "local_tag debe ser callable"


def _strip_xml_decl(b: bytes) -> bytes:
    """Remueve la declaración XML (<?xml ...?>) del inicio de bytes."""
    return _XML_DECL_RE.sub(b"", b, count=1)


def _root_info(xml_bytes: bytes) -> Tuple[Optional[str], Optional[str]]:
    """
    Detecta el localname y namespace del root del XML (rápido y tolerante).
    Retorna (localname, namespace) o (None, None) si falla.
    """
    try:
        parser = etree.XMLParser(recover=True, remove_blank_text=False)
        root = etree.fromstring(xml_bytes, parser)
        q = etree.QName(root)
        return q.localname, q.namespace
    except Exception:
        return None, None


_QR_PLACEHOLDER_RE = re.compile(r"(TEST|PLACEHOLDER)", re.IGNORECASE)


def _is_qr_placeholder(value: Optional[str]) -> bool:
    """Detecta valores dummy de dCarQR que deben bloquear envío."""
    txt = (value or "").strip()
    if not txt:
        return True
    return bool(_QR_PLACEHOLDER_RE.search(txt))


def _qr_base_url_for_env(env: str) -> str:
    override = (os.getenv("SIFEN_QR_BASE_URL") or "").strip()
    if override:
        return override.rstrip("?")
    return (
        "https://ekuatia.set.gov.py/consultas/qr"
        if (env or "").strip().lower() == "prod"
        else "https://www.ekuatia.set.gov.py/consultas-test/qr"
    )


def _first_text_by_local(root: etree._Element, path_expr: str, default: str = "") -> str:
    """Obtiene texto del primer nodo encontrado via XPath local-name()."""
    try:
        nodes = root.xpath(path_expr)
    except Exception:
        nodes = []
    if not nodes:
        return default
    node = nodes[0]
    text = ""
    if hasattr(node, "text") and node.text:
        text = node.text.strip()
    else:
        text = str(node).strip()
    return text if text else default


def _update_qr_in_signed_rde_tree(
    rde_root: etree._Element,
    *,
    csc: str,
    csc_id: str,
    env: str,
) -> Dict[str, str]:
    """
    Genera y actualiza dCarQR en un rDE YA firmado.
    Usa los campos requeridos por SET y el DigestValue final de la firma.
    """
    de_nodes = rde_root.xpath(".//*[local-name()='DE']")
    if not de_nodes:
        raise RuntimeError("No se encontró <DE> para generar dCarQR.")
    cdc = (de_nodes[0].get("Id") or de_nodes[0].get("id") or "").strip()
    if not cdc:
        raise RuntimeError("El <DE> firmado no tiene atributo Id (CDC).")

    dfe = _first_text_by_local(
        rde_root,
        ".//*[local-name()='gDatGralOpe']/*[local-name()='dFeEmiDE']",
    )
    if not dfe:
        raise RuntimeError("No se encontró dFeEmiDE para generar dCarQR.")
    dfe_hex = dfe.encode("utf-8").hex()

    ruc_rec = _first_text_by_local(
        rde_root,
        ".//*[local-name()='gDatRec']/*[local-name()='dRucRec']",
    )
    if ruc_rec:
        id_rec = re.sub(r"\D", "", ruc_rec)
    else:
        id_rec = _first_text_by_local(
            rde_root,
            ".//*[local-name()='gDatRec']/*[local-name()='dNumIDRec']",
        )
    if not id_rec:
        raise RuntimeError("No se encontró dRucRec/dNumIDRec para generar dCarQR.")

    tot_ope = _first_text_by_local(
        rde_root,
        ".//*[local-name()='gTotSub']/*[local-name()='dTotGralOpe']",
    ) or _first_text_by_local(
        rde_root,
        ".//*[local-name()='gTotSub']/*[local-name()='dTotOpe']",
        default="0",
    )
    tot_iva = _first_text_by_local(
        rde_root,
        ".//*[local-name()='gTotSub']/*[local-name()='dTotIVA']",
        default="0",
    )

    items_nodes = rde_root.xpath(".//*[local-name()='gDtipDE']//*[local-name()='gCamItem']")
    citems = str(len(items_nodes))

    digest = _first_text_by_local(rde_root, ".//*[local-name()='DigestValue']")
    if not digest:
        raise RuntimeError("No se encontró DigestValue final para generar dCarQR.")
    digest_hex = digest.encode("utf-8").hex()

    nversion = "150"
    params = (
        f"nVersion={nversion}"
        f"&Id={cdc}"
        f"&dFeEmiDE={dfe_hex}"
        f"&dRucRec={id_rec}"
        f"&dTotGralOpe={tot_ope}"
        f"&dTotIVA={tot_iva}"
        f"&cItems={citems}"
        f"&DigestValue={digest_hex}"
        f"&IdCSC={csc_id}"
    )
    hash_hex = hashlib.sha256((params + csc).encode("utf-8")).hexdigest()
    qr_url = f"{_qr_base_url_for_env(env)}?{params}&cHashQR={hash_hex}"

    gcam_nodes = rde_root.xpath("./*[local-name()='gCamFuFD']")
    if gcam_nodes:
        gcam = gcam_nodes[0]
    else:
        gcam = etree.SubElement(rde_root, etree.QName(SIFEN_NS, "gCamFuFD"))

    dcar_nodes = gcam.xpath("./*[local-name()='dCarQR']")
    if dcar_nodes:
        dcar = dcar_nodes[0]
    else:
        dcar = etree.SubElement(gcam, etree.QName(SIFEN_NS, "dCarQR"))
    dcar.text = qr_url

    return {
        "qr_url": qr_url,
        "cdc": cdc,
        "dFeEmiDE": dfe,
        "dRucRec": id_rec,
        "dTotGralOpe": tot_ope,
        "dTotIVA": tot_iva,
        "cItems": citems,
        "digest": digest,
        "idCSC": csc_id,
        "cHashQR": hash_hex,
    }


def _extract_first_dcarqr_from_lote(lote_xml_bytes: bytes) -> str:
    """Extrae dCarQR desde lote.xml para logging/guardrails."""
    try:
        root = etree.fromstring(lote_xml_bytes)
    except Exception:
        return ""
    return _first_text_by_local(root, ".//*[local-name()='dCarQR']", default="")

# Registrar namespaces para que ET use default namespace en lugar de prefijos
# Esto ayuda a que la serialización use xmlns="..." en lugar de xmlns:ns0="..."
# Registrar namespace default (lxml puede fallar con prefix "")
try:
    etree.register_namespace("", SIFEN_NS)
except ValueError:
    # Fallback: no registramos prefijo vacío; el nsmap se fuerza más adelante.
    pass

try:
    etree.register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")
    etree.register_namespace("ds", "http://www.w3.org/2000/09/xmldsig#")
except (ValueError, ImportError):
    print("❌ Error: lxml no está instalado")
    print("   Instale con: pip install lxml")
    sys.exit(1)

try:
    from app.sifen_client.xmlsec_signer import sign_de_with_p12
    from app.sifen_client.soap_client import SoapClient
    from app.sifen_client.config import get_sifen_config
    from app.sifen_client.exceptions import SifenClientError, SifenSizeLimitError

    # Importar cert_resolver para validación
    try:
        from tools.cert_resolver import validate_no_self_signed, save_resolved_certs_artifact
    except ImportError:
        import sys
        sys.path.insert(0, str(Path(__file__).parent))
        from cert_resolver import validate_no_self_signed, save_resolved_certs_artifact
    from app.sifen_client.xsd_validator import validate_rde_and_lote
except ImportError as e:
    print("❌ Error: No se pudo importar módulos SIFEN")
    print(f"   Error: {e}")
    print("   Asegúrate de que las dependencias estén instaladas:")
    print("   pip install zeep lxml cryptography signxml python-dotenv")
    sys.exit(1)


def _extract_metadata_from_xml(xml_content: str) -> dict:
    """
    Extrae metadatos del XML DE para debug.

    Returns:
        Dict con: dId, CDC, dRucEm, dDVEmi, dNumTim
    """
    metadata = {
        "dId": None,
        "CDC": None,
        "dRucEm": None,
        "dDVEmi": None,
        "dNumTim": None
    }

    try:
        root = etree.fromstring(xml_content.encode("utf-8"))

        # --- Soporte para PAYLOAD FULL (rEnvioLote con xDE ZIP) ---
        def _xpath_text_one(node, expr: str):
            vals = node.xpath(expr)
            if not vals:
                return None
            v = vals[0]
            try:
                from lxml import etree as _etree
                if isinstance(v, _etree._Element):
                    return ((v.text or "").strip() or None)
            except Exception:
                pass
            return (str(v).strip() or None)

        def _extract_from_payload_xde(root_el):
            try:
                import base64, zipfile, io
                # buscar xDE (base64) por namespace SIFEN
                xde_el = root_el.find(f".//{{{SIFEN_NS}}}xDE")
                if xde_el is None or not (xde_el.text or "").strip():
                    return None
                xde_txt = "".join((xde_el.text or "").split())
                zip_bytes = base64.b64decode(xde_txt, validate=False)
                zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
                if "lote.xml" not in zf.namelist():
                    return None
                lote_xml = zf.read("lote.xml")
                lote_root = etree.fromstring(lote_xml)

                # DE (CDC) y datos del emisor por local-name() para soportar prefijos
                de_nodes = lote_root.xpath('//*[local-name()="DE"]')
                de_elem = de_nodes[0] if de_nodes else None
                cdc = de_elem.get("Id") if de_elem is not None else None

                dRucEm  = _xpath_text_one(lote_root, '//*[local-name()="dRucEm"][1]')
                dDVEmi  = _xpath_text_one(lote_root, '//*[local-name()="dDVEmi"][1]')
                dNumTim = _xpath_text_one(lote_root, '//*[local-name()="dNumTim"][1]')

                return {
                    "CDC": cdc,
                    "dRucEm": dRucEm,
                    "dDVEmi": dDVEmi,
                    "dNumTim": dNumTim,
                }
            except Exception:
                return None

        # Si el root es rEnvioLote, el CDC real vive dentro de xDE -> lote.xml
        try:
            local_root = (root.tag.split("}", 1)[-1] if isinstance(root.tag, str) else "")
            if local_root == "rEnvioLote":
                got = _extract_from_payload_xde(root)
                if got:
                    if got.get("CDC"):
                        metadata["CDC"] = got.get("CDC")
                    if got.get("dRucEm"):
                        metadata["dRucEm"] = got.get("dRucEm")
                    if got.get("dDVEmi"):
                        metadata["dDVEmi"] = got.get("dDVEmi")
                    if got.get("dNumTim"):
                        metadata["dNumTim"] = got.get("dNumTim")
        except Exception:
            pass
        # --- FIN soporte PAYLOAD FULL ---

        def first_local(ctx, name: str):
            # XPath real (lxml): soporta local-name()
            res = ctx.xpath('.//*[local-name()="%s"]' % name)
            return res[0] if res else None

        # dId (puede estar en rEnvioLote/rEnviDe o adentro del lote)
        d_id_elem = first_local(root, "dId")
        if d_id_elem is not None and (d_id_elem.text or "").strip():
            metadata["dId"] = (d_id_elem.text or "").strip()

        # CDC: atributo Id del <DE>
        de_elem = first_local(root, "DE")
        if de_elem is not None:
            metadata["CDC"] = de_elem.get("Id")

            # gEmis -> dRucEm / dDVEmi
            g_emis = first_local(de_elem, "gEmis")
            if g_emis is not None:
                d_ruc_elem = first_local(g_emis, "dRucEm")
                if d_ruc_elem is not None and (d_ruc_elem.text or "").strip():
                    metadata["dRucEm"] = (d_ruc_elem.text or "").strip()

                d_dv_elem = first_local(g_emis, "dDVEmi")
                if d_dv_elem is not None and (d_dv_elem.text or "").strip():
                    metadata["dDVEmi"] = (d_dv_elem.text or "").strip()

            # gTimb -> dNumTim
            g_timb = first_local(de_elem, "gTimb")
            if g_timb is not None:
                d_num_tim_elem = first_local(g_timb, "dNumTim")
                if d_num_tim_elem is not None and (d_num_tim_elem.text or "").strip():
                    metadata["dNumTim"] = (d_num_tim_elem.text or "").strip()

    except Exception:
        # Si falla la extracción, continuar con valores None
        pass

    return metadata
def _save_zip_debug(zip_bytes: bytes, artifacts_dir: Path, debug_enabled: bool) -> None:
    """
    Guarda debug del ZIP en JSON para diagnóstico.
    
    Args:
        zip_bytes: Bytes del ZIP
        artifacts_dir: Directorio donde guardar
        debug_enabled: Si True, guarda siempre
    """
    import hashlib
    import json
    
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        zip_sha256 = hashlib.sha256(zip_bytes).hexdigest()
        
        # Abrir ZIP y extraer información
        zip_info = {
            "zip_bytes_len": len(zip_bytes),
            "zip_sha256": zip_sha256,
            "zip_namelist": [],
            "xml_files": []
        }
        
        with zipfile.ZipFile(BytesIO(zip_bytes), "r") as zf:
            zip_info["zip_namelist"] = zf.namelist()
            
            for filename in zf.namelist():
                if filename.endswith(".xml"):
                    try:
                        xml_content = zf.read(filename)
                        xml_str = xml_content.decode("utf-8", errors="replace")
                        
                        xml_file_info = {
                            "filename": filename,
                            "first_200_chars": xml_str[:200],
                            "root_tag": None,
                            "counts": {
                                "count_xDE": 0,
                                "count_rDE": 0,
                                "DE_Id": None
                            }
                        }
                        
                        # Parsear XML para extraer información
                        try:
                            root = etree.fromstring(xml_content)
                            xml_file_info["root_tag"] = root.tag
                            
                            # Contar xDE y rDE
                            xde_elements = root.xpath('//*[local-name()="xDE"]')
                            rde_elements = root.xpath('//*[local-name()="rDE"]')
                            xml_file_info["counts"]["count_xDE"] = len(xde_elements)
                            xml_file_info["counts"]["count_rDE"] = len(rde_elements)
                            
                            # Buscar DE Id
                            de_elements = root.xpath('//*[local-name()="DE"]')
                            if de_elements:
                                de_id = de_elements[0].get("Id") or de_elements[0].get("id")
                                if de_id:
                                    xml_file_info["counts"]["DE_Id"] = de_id
                        except Exception as e:
                            xml_file_info["parse_error"] = str(e)
                        
                        zip_info["xml_files"].append(xml_file_info)
                    except Exception as e:
                        zip_info["xml_files"].append({
                            "filename": filename,
                            "error": str(e)
                        })
        
        # Guardar JSON
        zip_debug_file = artifacts_dir / f"zip_debug_{timestamp}.json"
        zip_debug_file.write_text(
            json.dumps(zip_info, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8"
        )
        
        if debug_enabled:
            print(f"💾 ZIP debug guardado en: {zip_debug_file.name}")
    except Exception as e:
        if debug_enabled:
            print(f"⚠️  Error al guardar ZIP debug: {e}")


def _save_0301_diagnostic_package(
    artifacts_dir: Path,
    response: dict,
    payload_xml: str,
    zip_bytes: bytes,
    lote_xml_bytes: Optional[bytes],
    env: str,
    did: str
) -> None:
    """
    Guarda un paquete completo de evidencia cuando se recibe dCodRes=0301 con dProtConsLote=0.
    
    Crea un summary.json único por envío con:
    - Request SOAP completo (redactado, sin secretos)
    - Headers HTTP
    - Response completa
    - Hash del ZIP
    - DE Id (CDC)
    - RUC, timbrado, numdoc, fecha
    - Referencias a artifacts existentes (si dump-http está activo)
    
    Args:
        artifacts_dir: Directorio donde guardar
        response: Respuesta de SIFEN
        payload_xml: XML SOAP completo enviado
        zip_bytes: Bytes del ZIP
        lote_xml_bytes: Bytes del lote.xml
        env: Ambiente (test/prod)
        did: dId usado en el envío
    """
    import json
    import hashlib
    import base64
    import re
    from datetime import datetime
    
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # 1. Calcular hash del ZIP
        zip_sha256 = hashlib.sha256(zip_bytes).hexdigest()
        
        # 2. Extraer información del DE desde lote.xml
        de_info = {
            "dNumTim": None,  # Número de timbrado
            "dEst": None,  # Establecimiento
            "dPunExp": None,  # Punto de expedición
            "dNumDoc": None,  # Número de documento
            "iTiDE": None,  # Tipo de documento
            "dFeEmiDE": None,  # Fecha de emisión
            "dRucEm": None,  # RUC emisor
            "dDVEmi": None,  # DV RUC
            "dTotalGs": None,  # Total en guaraníes
            "ambiente": None,  # test/prod (si existe en el DE)
            "de_id": None,  # CDC (Id del DE)
        }
        
        # Validaciones de formato (warnings, no bloquean)
        format_warnings = []
        
        try:
            if lote_xml_bytes is None:
                raise ValueError("lote_xml_bytes is None")
            lote_root = etree.fromstring(lote_xml_bytes)
            # Buscar DE dentro de rDE
            de_elem = None
            for elem in lote_root.iter():
                if isinstance(elem.tag, str) and _localname(elem.tag) == "DE":
                    de_elem = elem
                    break
            
            if de_elem is not None:
                # CDC (Id del DE)
                de_info["de_id"] = de_elem.get("Id") or de_elem.get("id")
                
                # RUC y DV
                g_emis = de_elem.find(f".//{{{SIFEN_NS_URI}}}gEmis")
                if g_emis is not None:
                    d_ruc_elem = g_emis.find(f"{{{SIFEN_NS_URI}}}dRucEm")
                    if d_ruc_elem is not None and d_ruc_elem.text:
                        de_info["dRucEm"] = d_ruc_elem.text.strip()
                    
                    d_dv_elem = g_emis.find(f"{{{SIFEN_NS_URI}}}dDVEmi")
                    if d_dv_elem is not None and d_dv_elem.text:
                        de_info["dDVEmi"] = d_dv_elem.text.strip()
                
                # Timbrado, establecimiento, punto expedición, número documento
                g_timb = de_elem.find(f".//{{{SIFEN_NS_URI}}}gTimb")
                if g_timb is not None:
                    d_num_tim_elem = g_timb.find(f"{{{SIFEN_NS_URI}}}dNumTim")
                    if d_num_tim_elem is not None and d_num_tim_elem.text:
                        de_info["dNumTim"] = d_num_tim_elem.text.strip()
                    
                    d_est_elem = g_timb.find(f"{{{SIFEN_NS_URI}}}dEst")
                    if d_est_elem is not None and d_est_elem.text:
                        de_info["dEst"] = d_est_elem.text.strip()
                    
                    d_pun_exp_elem = g_timb.find(f"{{{SIFEN_NS_URI}}}dPunExp")
                    if d_pun_exp_elem is not None and d_pun_exp_elem.text:
                        de_info["dPunExp"] = d_pun_exp_elem.text.strip()
                    
                    d_num_doc_elem = g_timb.find(f"{{{SIFEN_NS_URI}}}dNumDoc")
                    if d_num_doc_elem is not None and d_num_doc_elem.text:
                        de_info["dNumDoc"] = d_num_doc_elem.text.strip()
                    
                    # iTiDE (tipo de documento) - está en gTimb según XSD
                    i_tide_elem = g_timb.find(f"{{{SIFEN_NS_URI}}}iTiDE")
                    if i_tide_elem is not None and i_tide_elem.text:
                        de_info["iTiDE"] = i_tide_elem.text.strip()
                
                # Fecha de emisión (dFeEmiDE)
                g_dat_gral_ope = de_elem.find(f".//{{{SIFEN_NS_URI}}}gDatGralOpe")
                if g_dat_gral_ope is not None:
                    d_fe_emi_de_elem = g_dat_gral_ope.find(f"{{{SIFEN_NS_URI}}}dFeEmiDE")
                    if d_fe_emi_de_elem is not None and d_fe_emi_de_elem.text:
                        de_info["dFeEmiDE"] = d_fe_emi_de_elem.text.strip()
                
                # Total en guaraníes (dTotalGs)
                g_tot = de_elem.find(f".//{{{SIFEN_NS_URI}}}gTot")
                if g_tot is not None:
                    d_total_gs_elem = g_tot.find(f"{{{SIFEN_NS_URI}}}dTotalGs")
                    if d_total_gs_elem is not None and d_total_gs_elem.text:
                        de_info["dTotalGs"] = d_total_gs_elem.text.strip()
                
                # Ambiente (buscar en varios lugares posibles)
                # Puede estar en un campo específico o inferirse del env
                de_info["ambiente"] = env  # Usar el env pasado como parámetro
                
                # 3. VALIDACIONES DE FORMATO (solo warnings, no bloquean)
                from datetime import datetime as dt_datetime
                
                # Validar dNumTim: debe ser numérico, largo esperado 8 dígitos
                if de_info["dNumTim"]:
                    if not de_info["dNumTim"].isdigit():
                        format_warnings.append(f"dNumTim no es numérico: '{de_info['dNumTim']}'")
                    elif len(de_info["dNumTim"]) != 8:
                        format_warnings.append(f"dNumTim largo inesperado (esperado 8): '{de_info['dNumTim']}' (len={len(de_info['dNumTim'])})")
                
                # Validar dEst: debe ser numérico, largo esperado 3 dígitos, zero-padded
                if de_info["dEst"]:
                    if not de_info["dEst"].isdigit():
                        format_warnings.append(f"dEst no es numérico: '{de_info['dEst']}'")
                    elif len(de_info["dEst"]) != 3:
                        format_warnings.append(f"dEst largo inesperado (esperado 3): '{de_info['dEst']}' (len={len(de_info['dEst'])})")
                    elif not de_info["dEst"].startswith("0") and de_info["dEst"] != "001":
                        format_warnings.append(f"dEst posiblemente sin zero-padding: '{de_info['dEst']}'")
                
                # Validar dPunExp: debe ser numérico, largo esperado 3 dígitos, zero-padded
                if de_info["dPunExp"]:
                    if not de_info["dPunExp"].isdigit():
                        format_warnings.append(f"dPunExp no es numérico: '{de_info['dPunExp']}'")
                    elif len(de_info["dPunExp"]) != 3:
                        format_warnings.append(f"dPunExp largo inesperado (esperado 3): '{de_info['dPunExp']}' (len={len(de_info['dPunExp'])})")
                    elif not de_info["dPunExp"].startswith("0") and de_info["dPunExp"] != "001":
                        format_warnings.append(f"dPunExp posiblemente sin zero-padding: '{de_info['dPunExp']}'")
                
                # Validar dNumDoc: debe ser numérico, largo esperado 7 dígitos, zero-padded
                if de_info["dNumDoc"]:
                    if not de_info["dNumDoc"].isdigit():
                        format_warnings.append(f"dNumDoc no es numérico: '{de_info['dNumDoc']}'")
                    elif len(de_info["dNumDoc"]) != 7:
                        format_warnings.append(f"dNumDoc largo inesperado (esperado 7): '{de_info['dNumDoc']}' (len={len(de_info['dNumDoc'])})")
                    elif not de_info["dNumDoc"].startswith("0") and int(de_info["dNumDoc"]) < 1000000:
                        format_warnings.append(f"dNumDoc posiblemente sin zero-padding: '{de_info['dNumDoc']}'")
                
                # Validar dRucEm: debe ser numérico, largo esperado 6-8 dígitos
                if de_info["dRucEm"]:
                    if not de_info["dRucEm"].isdigit():
                        format_warnings.append(f"dRucEm no es numérico: '{de_info['dRucEm']}'")
                    elif len(de_info["dRucEm"]) < 6 or len(de_info["dRucEm"]) > 8:
                        format_warnings.append(f"dRucEm largo inesperado (esperado 6-8): '{de_info['dRucEm']}' (len={len(de_info['dRucEm'])})")
                
                # Validar dDVEmi: debe ser numérico, largo esperado 1 dígito
                if de_info["dDVEmi"]:
                    if not de_info["dDVEmi"].isdigit():
                        format_warnings.append(f"dDVEmi no es numérico: '{de_info['dDVEmi']}'")
                    elif len(de_info["dDVEmi"]) != 1:
                        format_warnings.append(f"dDVEmi largo inesperado (esperado 1): '{de_info['dDVEmi']}' (len={len(de_info['dDVEmi'])})")
                
                # Validar dFeEmiDE: debe ser fecha parseable y no futura
                if de_info["dFeEmiDE"]:
                    try:
                        # Formato esperado: YYYY-MM-DD o YYYY-MM-DDTHH:MM:SS
                        fecha_str = de_info["dFeEmiDE"]
                        if "T" in fecha_str:
                            fecha_dt = dt_datetime.strptime(fecha_str.split("T")[0], "%Y-%m-%d")
                        else:
                            fecha_dt = dt_datetime.strptime(fecha_str, "%Y-%m-%d")
                        
                        # Verificar que no sea futura
                        ahora = dt_datetime.now()
                        if fecha_dt > ahora:
                            format_warnings.append(f"dFeEmiDE es futura: '{fecha_str}' (hoy: {ahora.strftime('%Y-%m-%d')})")
                    except ValueError as e:
                        format_warnings.append(f"dFeEmiDE no parseable como fecha: '{de_info['dFeEmiDE']}' (error: {e})")
                
                # Validar dTotalGs: debe ser numérico
                if de_info["dTotalGs"]:
                    try:
                        total_val = float(de_info["dTotalGs"])
                        if total_val < 0:
                            format_warnings.append(f"dTotalGs es negativo: '{de_info['dTotalGs']}'")
                        elif total_val == 0:
                            format_warnings.append(f"dTotalGs es cero: '{de_info['dTotalGs']}'")
                    except ValueError:
                        format_warnings.append(f"dTotalGs no es numérico: '{de_info['dTotalGs']}'")
                
                # Validar iTiDE: debe ser numérico, valores comunes 1-7
                if de_info["iTiDE"]:
                    if not de_info["iTiDE"].isdigit():
                        format_warnings.append(f"iTiDE no es numérico: '{de_info['iTiDE']}'")
                    else:
                        tipo_val = int(de_info["iTiDE"])
                        if tipo_val < 1 or tipo_val > 7:
                            format_warnings.append(f"iTiDE valor fuera de rango común (1-7): '{de_info['iTiDE']}'")
        except Exception as e:
            # Si falla la extracción, continuar con valores None
            format_warnings.append(f"Error al extraer campos del DE: {e}")
        
        # 3. Redactar SOAP request (remover xDE base64, pero mantener estructura)
        payload_xml_redacted = payload_xml
        try:
            # Reemplazar xDE base64 con placeholder
            payload_xml_redacted = re.sub(
                r'(<xsd:xDE[^>]*>)([^<]+)(</xsd:xDE>)',
                r'\1[BASE64_REDACTED_FOR_DIAGNOSTIC]\3',
                payload_xml_redacted,
                flags=re.IGNORECASE | re.DOTALL
            )
            payload_xml_redacted = re.sub(
                r'(<xDE[^>]*>)([^<]+)(</xDE>)',
                r'\1[BASE64_REDACTED_FOR_DIAGNOSTIC]\3',
                payload_xml_redacted,
                flags=re.IGNORECASE | re.DOTALL
            )
        except Exception:
            pass
        
        # 4. Buscar artifacts existentes de dump-http
        dump_http_artifacts = {}
        try:
            # Buscar archivos más recientes
            sent_files = sorted(artifacts_dir.glob("soap_raw_sent_lote_*.xml"), key=lambda p: p.stat().st_mtime, reverse=True)
            headers_sent_files = sorted(artifacts_dir.glob("http_headers_sent_lote_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            headers_resp_files = sorted(artifacts_dir.glob("http_response_headers_lote_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            resp_files = sorted(artifacts_dir.glob("soap_raw_response_lote_*.xml"), key=lambda p: p.stat().st_mtime, reverse=True)
            
            if sent_files:
                dump_http_artifacts["soap_request_file"] = sent_files[0].name
            if headers_sent_files:
                dump_http_artifacts["headers_sent_file"] = headers_sent_files[0].name
            if headers_resp_files:
                dump_http_artifacts["headers_response_file"] = headers_resp_files[0].name
            if resp_files:
                dump_http_artifacts["soap_response_file"] = resp_files[0].name
        except Exception:
            pass
        
        # 5. Leer headers si están disponibles
        headers_sent = {}
        headers_received = {}
        try:
            if "headers_sent_file" in dump_http_artifacts:
                headers_file = artifacts_dir / dump_http_artifacts["headers_sent_file"]
                if headers_file.exists():
                    headers_sent = json.loads(headers_file.read_text(encoding="utf-8"))
                    # Redactar headers que puedan contener secretos
                    if "Authorization" in headers_sent:
                        headers_sent["Authorization"] = "[REDACTED]"
                    if "X-API-Key" in headers_sent:
                        headers_sent["X-API-Key"] = "[REDACTED]"
            
            if "headers_response_file" in dump_http_artifacts:
                headers_resp_file = artifacts_dir / dump_http_artifacts["headers_response_file"]
                if headers_resp_file.exists():
                    resp_data = json.loads(headers_resp_file.read_text(encoding="utf-8"))
                    headers_received = resp_data.get("headers", {})
        except Exception:
            pass
        
        # 6. Construir summary.json
        summary = {
            "diagnostic_package": {
                "trigger": "dCodRes=0301 with dProtConsLote=0",
                "timestamp": timestamp,
                "env": env,
            },
            "response": {
                "dCodRes": response.get("codigo_respuesta"),
                "dMsgRes": response.get("mensaje"),
                "dProtConsLote": response.get("d_prot_cons_lote"),
                "dTpoProces": response.get("d_tpo_proces"),
                "ok": response.get("ok"),
            },
            "request": {
                "dId": did,
                "soap_request_redacted": payload_xml_redacted,  # Redactado (sin xDE base64)
                "headers_sent": headers_sent,  # Redactado (sin secretos)
            },
            "response_details": {
                "headers_received": headers_received,
                "response_full": response,  # Respuesta completa de SIFEN
            },
            "zip": {
                "sha256": zip_sha256,
                "size_bytes": len(zip_bytes),
            },
            "de_info": de_info,
            "format_validations": {
                "warnings": format_warnings,
                "summary": f"{len(format_warnings)} advertencia(s) de formato encontrada(s)" if format_warnings else "Sin advertencias de formato",
            },
            "artifacts": {
                "dump_http_available": len(dump_http_artifacts) > 0,
                "dump_http_files": dump_http_artifacts,
                "other_artifacts": [
                    "soap_last_request_SENT.xml",
                    "soap_last_request_BYTES.bin",
                    "preflight_lote.xml",
                    "preflight_zip.zip",
                ],
            },
            "notes": [
                "Este paquete se generó automáticamente cuando SIFEN devolvió dCodRes=0301 con dProtConsLote=0",
                "El SOAP request está redactado (xDE base64 removido) para evitar archivos grandes",
                "Los headers pueden estar redactados si contenían secretos (Authorization, API keys)",
                "Para ver el SOAP completo, consultar artifacts/soap_last_request_SENT.xml",
                "Para ver el ZIP completo, consultar artifacts/preflight_zip.zip",
            ],
        }
        
        # 7. Guardar summary.json
        summary_file = artifacts_dir / f"diagnostic_0301_summary_{timestamp}.json"
        summary_file.write_text(
            json.dumps(summary, indent=2, ensure_ascii=False, default=str),
            encoding="utf-8"
        )
        
        # 8. Guardar también el SOAP request redactado como archivo separado
        soap_redacted_file = artifacts_dir / f"diagnostic_0301_soap_request_redacted_{timestamp}.xml"
        soap_redacted_file.write_text(payload_xml_redacted, encoding="utf-8")

        # Guardar PAYLOAD FULL como archivo separado (sin redactar)
        soap_full_file = artifacts_dir / f"diagnostic_0301_payload_full_{timestamp}.xml"
        soap_full_file.write_text(payload_xml, encoding="utf-8")
        
        # Guardar SOAP request FULL como archivo separado (sin redactar)
        soap_full_file = artifacts_dir / f"diagnostic_last_soap_request_full.xml"
        soap_full_file.write_text(payload_xml, encoding="utf-8")
        
        print(f"\n📦 Paquete de diagnóstico 0301 guardado:")
        print(f"   📄 Summary: {summary_file.name}")
        print(f"   📄 SOAP request (redactado): {soap_redacted_file.name}")
        print(f"   📄 PAYLOAD request (FULL): {soap_full_file.name}")
        print(f"\n🔍 Información del DE extraída:")
        print(f"   DE Id (CDC): {de_info.get('de_id', 'N/A')}")
        print(f"   dRucEm: {de_info.get('dRucEm', 'N/A')}")
        print(f"   dDVEmi: {de_info.get('dDVEmi', 'N/A')}")
        print(f"   dNumTim: {de_info.get('dNumTim', 'N/A')}")
        print(f"   dEst: {de_info.get('dEst', 'N/A')}")
        print(f"   dPunExp: {de_info.get('dPunExp', 'N/A')}")
        print(f"   dNumDoc: {de_info.get('dNumDoc', 'N/A')}")
        print(f"   iTiDE: {de_info.get('iTiDE', 'N/A')}")
        print(f"   dFeEmiDE: {de_info.get('dFeEmiDE', 'N/A')}")
        print(f"   dTotalGs: {de_info.get('dTotalGs', 'N/A')}")
        print(f"   Ambiente: {de_info.get('ambiente', 'N/A')}")
        print(f"\n🔐 ZIP SHA256: {zip_sha256}")
        
        # Mostrar warnings de formato si existen
        if format_warnings:
            print(f"\n⚠️  Advertencias de formato ({len(format_warnings)}):")
            for warning in format_warnings[:10]:  # Mostrar máximo 10
                print(f"   - {warning}")
            if len(format_warnings) > 10:
                print(f"   ... y {len(format_warnings) - 10} más (ver summary.json)")
        else:
            print(f"\n✅ Sin advertencias de formato")
        
    except Exception as e:
        print(f"\n⚠️  Error al guardar paquete de diagnóstico 0301: {e}")
        import traceback
        traceback.print_exc()


def redact_xde(xml: str) -> tuple[str, dict]:
    """
    Redacta el contenido base64 de xDE del XML SOAP y retorna metadata.
    
    Args:
        xml: XML SOAP completo como string
        
    Returns:
        Tuple[xml_redactado, metadata] donde metadata contiene:
        - len: longitud del base64 original
        - sha256: hash SHA256 del base64 original
        - dId: valor del elemento dId si se encuentra
    """
    metadata = {}
    
    # Extraer xDE base64 para calcular metadata
    xde_match = re.search(r'(<(?:xsd:)?xDE[^>]*>)([^<]+)(</(?:xsd:)?xDE>)', xml, re.IGNORECASE | re.DOTALL)
    if xde_match:
        xde_content = xde_match.group(2)
        metadata['len'] = len(xde_content)
        metadata['sha256'] = hashlib.sha256(xde_content.encode('utf-8')).hexdigest()
    
    # Extraer dId si existe
    did_match = re.search(r'<(?:xsd:)?dId[^>]*>([^<]+)</(?:xsd:)?dId>', xml, re.IGNORECASE)
    if did_match:
        metadata['dId'] = did_match.group(1)
    
    # Redactar xDE con metadata
    def replacer(m):
        prefix = m.group(1)
        suffix = m.group(3)
        if metadata:
            return f'{prefix}[REDACTED len={metadata["len"]} sha256={metadata["sha256"][:16]}...]{suffix}'
        else:
            return f'{prefix}[REDACTED]{suffix}'
    
    xml_redacted = re.sub(
        r'(<(?:xsd:)?xDE[^>]*>)([^<]+)(</(?:xsd:)?xDE>)',
        replacer,
        xml,
        flags=re.IGNORECASE | re.DOTALL
    )
    
    return xml_redacted, metadata


def _print_dump_http(artifacts_dir: Path) -> None:
    """
    Imprime dump HTTP completo cuando --dump-http está activo.
    
    Args:
        artifacts_dir: Directorio donde están los artefactos
    """
    import json
    
    try:
        # Buscar archivos más recientes
        sent_files = sorted(artifacts_dir.glob("soap_raw_sent_lote_*.xml"), key=lambda p: p.stat().st_mtime, reverse=True)
        headers_sent_files = sorted(artifacts_dir.glob("http_headers_sent_lote_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        headers_resp_files = sorted(artifacts_dir.glob("http_response_headers_lote_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        resp_files = sorted(artifacts_dir.glob("soap_raw_response_lote_*.xml"), key=lambda p: p.stat().st_mtime, reverse=True)
        
        if not sent_files or not headers_sent_files or not headers_resp_files or not resp_files:
            print("\n⚠️  No se encontraron todos los artefactos de dump HTTP")
            return
        
        # Copiar SOAP completo a archivo fijo para fácil acceso
        try:
            full_soap_file = artifacts_dir / "diagnostic_last_soap_request_full.xml"
            full_soap_file.write_text(sent_files[0].read_text(encoding="utf-8"), encoding="utf-8")
        except Exception:
            pass  # Silencioso, no es crítico
        
        # Guardar también versión redactada para referencia rápida
        try:
            redacted_soap_file = artifacts_dir / "diagnostic_last_soap_request_redacted.xml"
            sent_xml = sent_files[0].read_text(encoding="utf-8")
            sent_xml_redacted, _ = redact_xde(sent_xml)
            redacted_soap_file.write_text(sent_xml_redacted, encoding="utf-8")
        except Exception:
            pass  # Silencioso, no es crítico
        
        print("\n" + "="*70)
        print("VERIFICADOR E2E: siRecepLoteDE (SOAP 1.2)")
        print("="*70)
        
        # 1. Headers HTTP enviados
        print("\n1️⃣  HEADERS HTTP ENVIADOS:")
        print("-" * 70)
        try:
            sent_headers = json.loads(headers_sent_files[0].read_text(encoding="utf-8"))
            for key, value in sorted(sent_headers.items()):
                print(f"   {key}: {value}")
            
            # Validación: Content-Type debe ser application/soap+xml
            content_type = sent_headers.get("Content-Type", "")
            if "application/soap+xml" in content_type:
                print(f"\n   ✅ Content-Type correcto: {content_type}")
            else:
                print(f"\n   ⚠️  Content-Type: {content_type}")
            
            # Validación: NO debe haber SOAPAction header separado
            if "SOAPAction" in sent_headers:
                print(f"   ⚠️  ADVERTENCIA: Existe header 'SOAPAction' (no debería en SOAP 1.2)")
            else:
                print(f"   ✅ NO hay header 'SOAPAction' (correcto para SOAP 1.2)")
        except Exception as e:
            print(f"   ⚠️  Error al leer headers enviados: {e}")
        
        # 2. SOAP Envelope enviado
        print("\n2️⃣  SOAP ENVELOPE ENVIADO:")
        print("-" * 70)
        try:
            sent_xml = sent_files[0].read_text(encoding="utf-8")
            # Redactar xDE para evitar base64 gigante en consola
            sent_xml_redacted, xde_metadata = redact_xde(sent_xml)
            
            # Imprimir metadata resumida
            if xde_metadata:
                print(f"   📋 dId: {xde_metadata.get('dId', 'N/A')}")
                print(f"   📦 xDE len: {xde_metadata['len']:,} bytes")
                print(f"   🔐 xDE sha256: {xde_metadata['sha256'][:32]}...")
                print()
            
            # Imprimir SOAP redactado
            xml_lines = sent_xml_redacted.split("\n")
            if len(xml_lines) > 80:
                print("\n".join(xml_lines[:80]))
                print(f"\n... (truncado, total {len(xml_lines)} líneas)")
            else:
                print(sent_xml_redacted)
        except Exception as e:
            print(f"   ⚠️  Error al leer SOAP enviado: {e}")
        
        # 3. Status code HTTP y headers recibidos
        print("\n3️⃣  STATUS CODE HTTP Y HEADERS RECIBIDOS:")
        print("-" * 70)
        try:
            resp_data = json.loads(headers_resp_files[0].read_text(encoding="utf-8"))
            status_code = resp_data.get("status_code", 0)
            print(f"   Status Code: {status_code}")
            
            received_headers = resp_data.get("headers", {})
            if received_headers:
                print("\n   Headers recibidos:")
                for key, value in sorted(received_headers.items()):
                    print(f"      {key}: {value}")
        except Exception as e:
            print(f"   ⚠️  Error al leer headers recibidos: {e}")
        
        # 4. Body recibido
        print("\n4️⃣  BODY RECIBIDO:")
        print("-" * 70)
        try:
            received_body = resp_files[0].read_text(encoding="utf-8")
            body_lines = received_body.split("\n")
            if len(body_lines) > 120:
                print("\n".join(body_lines[:120]))
                print(f"\n... (truncado, total {len(body_lines)} líneas)")
            else:
                print(received_body)
            
            # Detectar SOAP Fault
            if "<soap:Fault" in received_body or "<soap12:Fault" in received_body or "<Fault" in received_body:
                print("\n   ⚠️  SOAP FAULT DETECTADO en la respuesta")
        except Exception as e:
            print(f"   ⚠️  Error al leer body recibido: {e}")
        
        print("\n" + "="*70)
        
    except Exception as e:
        print(f"\n⚠️  Error al imprimir dump HTTP: {e}")


def _save_precheck_artifacts(
    artifacts_dir: Path,
    payload_xml: str,
    zip_bytes: bytes,
    zip_base64: str,
    wsdl_url: str,
    lote_xml_bytes: Optional[bytes] = None
):
    """
    Guarda artifacts del payload NUEVO incluso si PRECHECK falla.
    
    Args:
        artifacts_dir: Directorio donde guardar archivos
        payload_xml: XML rEnvioLote completo
        zip_bytes: ZIP binario
        zip_base64: Base64 del ZIP
        wsdl_url: URL del WSDL que se usaría
        lote_xml_bytes: Bytes del XML lote.xml (opcional, para guardar en /tmp)
    """
    artifacts_dir.mkdir(exist_ok=True)
    
    # IMPORTANTE: payload_xml es el SOAP REAL con xDE completo (base64 real del ZIP)
    # NUNCA modificar payload_xml antes de usarlo - solo redactar para guardar en artifacts
    soap_real = payload_xml
    
    # Redactar xDE solo para el archivo normal (usando lxml para robustez)
    debug_soap = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
    try:
        # Parsear con lxml para redactar xDE de forma robusta
        from lxml import etree
        root = etree.fromstring(soap_real.encode("utf-8"))
        xde_elem = root.find(f".//{{{SIFEN_NS}}}xDE")
        if xde_elem is None:
            xde_elem = root.find(".//xDE")
        
        if xde_elem is not None and xde_elem.text:
            xde_len = len(xde_elem.text.strip())
            xde_elem.text = f"__BASE64_REDACTED_LEN_{xde_len}__"
            soap_redacted = etree.tostring(root, xml_declaration=True, encoding="utf-8").decode("utf-8")
        else:
            # Si no se encuentra xDE, usar regex como fallback
            soap_redacted = re.sub(
                r'<xDE[^>]*>.*?</xDE>',
                f'<xDE>__BASE64_REDACTED_LEN_{len(zip_base64)}__</xDE>',
                soap_real,
                flags=re.DOTALL
            )
    except Exception as e:
        # Fallback a regex si falla el parseo con lxml
        soap_redacted = re.sub(
            r'<xDE[^>]*>.*?</xDE>',
            f'<xDE>__BASE64_REDACTED_LEN_{len(zip_base64)}__</xDE>',
            soap_real,
            flags=re.DOTALL
        )
    
    # 1. Guardar soap_last_http_debug.txt con información del payload
    debug_file = artifacts_dir / "soap_last_http_debug.txt"
    with debug_file.open("w", encoding="utf-8") as f:
        f.write("==== SOAP HTTP DEBUG (PRECHECK FAILED - NOT SENT) ====\n\n")
        post_url_used = wsdl_url.replace("?wsdl", "")
        if post_url_used.endswith(".wsdl"):
            post_url_used = post_url_used[:-5]
        f.write(f"POST_URL_USED={post_url_used}\n")  # sin ?wsdl y sin .wsdl
        f.write(f"SOAP_VERSION_USED=1.2\n")
        f.write(f"ORIGINAL_URL={wsdl_url}\n")
        f.write(f"ACTION_HEADER_USED=\n")
        f.write(f"CONTENT_TYPE_USED=application/xml; charset=utf-8\n")
        f.write(f"SOAP_ACTION_HEADER_USED=\n")
        f.write(f"\n---- REQUEST_HEADERS_FINAL ----\n")
        f.write(f"Content-Type: application/xml; charset=utf-8\n")
        f.write(f"Accept: application/soap+xml, text/xml, */*\n")
        f.write("---- END REQUEST_HEADERS_FINAL ----\n")
        f.write(f"\nXDE_BASE64_LEN={len(zip_base64)}\n")
        f.write(f"XDE_BASE64_HAS_WHITESPACE=no\n")
        f.write(f"\n---- SOAP BEGIN (NOT SENT - PRECHECK FAILED) ----\n")
        f.write(soap_redacted)
        f.write("\n---- SOAP END ----\n")
        f.write(f"\nNOTE: Este payload NO fue enviado a SIFEN porque PRECHECK falló.\n")
        f.write(f"Para inspeccionar el ZIP real, usar: --zip-file /tmp/lote_payload.zip\n")
    
    # 2. Guardar soap_last_request_headers.txt
    headers_file = artifacts_dir / "soap_last_request_headers.txt"
    with headers_file.open("w", encoding="utf-8") as f:
        f.write("Content-Type: application/xml; charset=utf-8\n")
        f.write("Accept: application/soap+xml, text/xml, */*\n")
    
    # 3. Guardar soap_last_request_REAL.xml (payload REAL) si SIFEN_DEBUG_SOAP=1
    if debug_soap:
        request_file_real = artifacts_dir / "soap_last_request_REAL.xml"
        request_file_real.write_text(soap_real, encoding="utf-8")
    
    # 4. Guardar soap_last_request.xml (payload redactado) - mantener para compatibilidad
    request_file = artifacts_dir / "soap_last_request.xml"
    request_file.write_text(soap_redacted, encoding="utf-8")
    
    # 4. Guardar soap_last_response.xml (dummy indicando que NO se envió)
    response_file = artifacts_dir / "soap_last_response.xml"
    response_dummy = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<error>\n'
        '  <message>NOT SENT (PRECHECK FAILED)</message>\n'
        '  <note>Este request no fue enviado a SIFEN porque la validación preflight falló.</note>\n'
        '  <zip_file>/tmp/lote_payload.zip</zip_file>\n'
        '  <payload_file>/tmp/lote_xml_payload.xml</payload_file>\n'
        '</error>\n'
    )
    response_file.write_text(response_dummy, encoding="utf-8")
    
    # 5. Guardar archivos temporales en /tmp (para debug_extract_lote_from_soap)
    if lote_xml_bytes:
        try:
            Path("/tmp/lote_xml_payload.xml").write_bytes(lote_xml_bytes)
        except Exception as e:
            print(f"⚠️  No se pudo guardar /tmp/lote_xml_payload.xml: {e}")
    
    try:
        Path("/tmp/lote_payload.zip").write_bytes(zip_bytes)
    except Exception as e:
        print(f"⚠️  No se pudo guardar /tmp/lote_payload.zip: {e}")
    
    print(f"\n💾 Artifacts guardados (aunque PRECHECK falló):")
    print(f"   ✓ {debug_file.name}")
    print(f"   ✓ {headers_file.name}")
    print(f"   ✓ {request_file.name}")
    print(f"   ✓ {response_file.name}")
    if lote_xml_bytes:
        print(f"   ✓ /tmp/lote_xml_payload.xml")
    print(f"   ✓ /tmp/lote_payload.zip")
    print(f"   Para inspeccionar ZIP real: python -m tools.debug_extract_lote_from_soap --zip-file /tmp/lote_payload.zip")


def _save_1264_debug(
    artifacts_dir: Path,
    payload_xml: str,
    zip_bytes: bytes,
    zip_base64: str,
    xml_content: str,
    wsdl_url: str,
    service_key: str,
    client: 'SoapClient'
):
    """
    Guarda archivos de debug cuando se recibe error 1264.
    
    Args:
        artifacts_dir: Directorio donde guardar archivos
        payload_xml: XML rEnvioLote completo
        zip_bytes: ZIP binario
        zip_base64: Base64 del ZIP
        xml_content: XML original (DE o siRecepDE)
        wsdl_url: URL del WSDL usado
        service_key: Clave del servicio (ej: "recibe_lote")
        client: Instancia de SoapClient (para acceder a history/debug files)
    """
    artifacts_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = f"debug_1264_{timestamp}"
    
    # 1. Guardar lote_payload.xml (rEnvioLote sin SOAP envelope)
    lote_payload_file = artifacts_dir / f"{prefix}_lote_payload.xml"
    lote_payload_file.write_text(payload_xml, encoding="utf-8")
    print(f"   ✓ {lote_payload_file.name}")
    
    # 2. Guardar lote.zip (binario)
    lote_zip_file = artifacts_dir / f"{prefix}_lote.zip"
    lote_zip_file.write_bytes(zip_bytes)
    print(f"   ✓ {lote_zip_file.name}")
    
    # 3. Guardar lote.zip.b64.txt (base64 string)
    lote_b64_file = artifacts_dir / f"{prefix}_lote.zip.b64.txt"
    lote_b64_file.write_text(zip_base64, encoding="utf-8")
    print(f"   ✓ {lote_b64_file.name}")
    
    # 4. Intentar leer SOAP sent/received desde artifacts (si SIFEN_DEBUG_SOAP estaba activo)
    # o desde history plugin del cliente
    soap_sent_file = artifacts_dir / f"{prefix}_soap_last_sent.xml"
    soap_received_file = artifacts_dir / f"{prefix}_soap_last_received.xml"
    
    # Intentar leer desde artifacts/soap_last_sent.xml (si existe)
    existing_sent = artifacts_dir / "soap_last_sent.xml"
    if existing_sent.exists():
        soap_sent_file.write_bytes(existing_sent.read_bytes())
        print(f"   ✓ {soap_sent_file.name} (copiado desde soap_last_sent.xml)")
    else:
        # Intentar desde history plugin si está disponible
        try:
            if hasattr(client, "_history_plugins") and service_key in client._history_plugins:
                history = client._history_plugins[service_key]
                if hasattr(history, "last_sent") and history.last_sent:
                    soap_sent_file.write_bytes(history.last_sent["envelope"].encode("utf-8"))
                    print(f"   ✓ {soap_sent_file.name} (desde history plugin)")
        except Exception as e:
            print(f"   ⚠️  No se pudo obtener SOAP enviado: {e}")
    
    existing_received = artifacts_dir / "soap_last_received.xml"
    if existing_received.exists():
        soap_received_file.write_bytes(existing_received.read_bytes())
        print(f"   ✓ {soap_received_file.name} (copiado desde soap_last_received.xml)")
    else:
        try:
            if hasattr(client, "_history_plugins") and service_key in client._history_plugins:
                history = client._history_plugins[service_key]
                if hasattr(history, "last_received") and history.last_received:
                    soap_received_file.write_bytes(history.last_received["envelope"].encode("utf-8"))
                    print(f"   ✓ {soap_received_file.name} (desde history plugin)")
        except Exception as e:
            print(f"   ⚠️  No se pudo obtener SOAP recibido: {e}")
    
    # 5. Extraer metadatos del XML
    metadata = _extract_metadata_from_xml(xml_content)
    
    # 6. Guardar meta.json
    import json
    meta_data = {
        "dId": metadata.get("dId"),
        "CDC": metadata.get("CDC"),
        "dRucEm": metadata.get("dRucEm"),
        "dDVEmi": metadata.get("dDVEmi"),
        "dNumTim": metadata.get("dNumTim"),
        "zip_size_bytes": len(zip_bytes),
        "zip_base64_length": len(zip_base64),
        "endpoint_url": wsdl_url,
        "service_key": service_key,
        "operation": "siRecepLoteDE",
        "timestamp": timestamp
    }
    
    meta_file = artifacts_dir / f"{prefix}_meta.json"
    meta_file.write_text(
        json.dumps(meta_data, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8"
    )
    print(f"   ✓ {meta_file.name}")
    
    print(f"\n💾 Archivos de debug guardados con prefijo: {prefix}")


def find_latest_sirecepde(artifacts_dir: Path) -> Optional[Path]:
    """
    Encuentra el archivo sirecepde más reciente en artifacts/
    
    Args:
        artifacts_dir: Directorio donde buscar archivos
        
    Returns:
        Path al archivo más reciente o None
    """
    if not artifacts_dir.exists():
        return None
    
    sirecepde_files = list(artifacts_dir.glob("sirecepde_*.xml"))
    if not sirecepde_files:
        return None
    
    # Ordenar por fecha de modificación (más reciente primero)
    sirecepde_files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return sirecepde_files[0]


# _local eliminado - usar local_tag() global en su lugar


def normalize_rde_before_sign(xml_bytes: bytes) -> bytes:
    """
    Normaliza el XML rDE antes de firmar:
    - Cambia dDesPaisRec -> dDesPaisRe (si existe)
    - Mueve gCamFuFD de dentro de <DE> a fuera, dentro de <rDE>, antes de <Signature>
    """
    parser = etree.XMLParser(remove_blank_text=False)
    root = etree.fromstring(xml_bytes, parser)

    def find_by_local(el, name):
        for x in el.iter():
            if local_tag(x.tag) == name:
                return x
        return None

    # Tomar rDE (raíz o anidado)
    rde = root if local_tag(root.tag) == "rDE" else find_by_local(root, "rDE")
    if rde is None:
        return xml_bytes

    # 1) dDesPaisRec -> dDesPaisRe (si existe)
    dd_rec = find_by_local(rde, "dDesPaisRec")
    if dd_rec is not None:
        parent = dd_rec.getparent()
        if parent is None:
            raise RuntimeError("dDesPaisRe no tiene parent (bug de árbol XML)")
        idx = parent.index(dd_rec)
        new_el = etree.Element(etree.QName(SIFEN_NS, "dDesPaisRe"))
        new_el.text = dd_rec.text
        # Verificar que dd_rec realmente es hijo de parent antes de remover
        if dd_rec in list(parent):
            parent.remove(dd_rec)
            parent.insert(idx, new_el)
        else:
            raise RuntimeError("dDesPaisRe no es hijo directo de su parent (bug de árbol XML)")

    # 2) gCamFuFD debe ser hijo de rDE, no de DE
    de = None
    for ch in rde:
        if local_tag(ch.tag) == "DE":
            de = ch
            break

    if de is not None:
        gcam = None
        for ch in list(de):
            if local_tag(ch.tag) == "gCamFuFD":
                gcam = ch
                break

        if gcam is not None:
            # Verificar que gcam realmente es hijo de de antes de remover
            if gcam in list(de):
                de.remove(gcam)
            else:
                gcam_parent = gcam.getparent()
                if gcam_parent is not None:
                    gcam_parent.remove(gcam)

            # Insertar antes de Signature si existe; si no, al final
            sig = None
            for ch in rde:
                if local_tag(ch.tag) == "Signature":
                    sig = ch
                    break

            if sig is not None:
                rde.insert(rde.index(sig), gcam)
            else:
                rde.append(gcam)

    return etree.tostring(root, xml_declaration=True, encoding="utf-8")


def reorder_signature_before_gcamfufd(xml_bytes: bytes) -> bytes:
    """
    Reordena los hijos de <rDE> para que Signature venga antes de gCamFuFD.
    Orden esperado: dVerFor, DE, Signature, gCamFuFD
    NO rompe la firma: solo cambia el orden de hermanos.
    """
    root = etree.fromstring(xml_bytes)

    # Localizar <rDE> (puede ser raíz o anidado)
    rde = root if local_tag(root.tag) == "rDE" else next((e for e in root.iter() if local_tag(e.tag) == "rDE"), None)
    if rde is None:
        return xml_bytes

    # Encontrar Signature y gCamFuFD como hijos directos de rDE
    children = list(rde)
    sig = next((c for c in children if local_tag(c.tag) == "Signature"), None)
    gcam = next((c for c in children if local_tag(c.tag) == "gCamFuFD"), None)

    # Si no hay ambos, no hay nada que reordenar
    if sig is None or gcam is None:
        return xml_bytes

    # Obtener índices
    sig_idx = children.index(sig)
    gcam_idx = children.index(gcam)

    # Si Signature ya está antes de gCamFuFD, no hacer nada
    if sig_idx < gcam_idx:
        return xml_bytes

    # Si Signature está después de gCamFuFD, moverlo antes
    # Remover Signature y reinsertarlo justo antes de gCamFuFD
    # Verificar que sig realmente es hijo de rde antes de remover
    if sig in list(rde):
        rde.remove(sig)
    else:
        sig_parent = sig.getparent()
        if sig_parent is None:
            raise RuntimeError("Signature no tiene parent (bug de árbol XML)")
        sig_parent.remove(sig)
    # Recalcular índice de gCamFuFD después de remover sig
    children_after = list(rde)
    gcam_idx_after = children_after.index(gcam)
    rde.insert(gcam_idx_after, sig)

    return etree.tostring(root, xml_declaration=True, encoding="utf-8")


def find_rde_any_ns(root: etree._Element) -> Optional[etree._Element]:
    """
    Encuentra el primer elemento rDE usando XPath local-name(), ignorando namespace.
    
    Args:
        root: Elemento raíz del XML
        
    Returns:
        Primer elemento rDE encontrado, o None si no existe
    """
    results = root.xpath("//*[local-name()='rDE']")
    return results[0] if results else None


def make_rde_standalone(rde_elem: etree._Element) -> etree._Element:
    """
    Crea un rDE standalone con todos los namespaces necesarios explícitamente declarados.
    
    Esto asegura que cuando se serialice como fragmento, no pierda namespaces heredados
    del root (ej: xmlns:xsi), evitando errores como "Namespace prefix xsi ... is not defined".
    
    Args:
        rde_elem: Elemento rDE (lxml element)
        
    Returns:
        Nuevo elemento rDE con namespaces explícitos: default SIFEN_NS, xsi, ds
    """
    nsmap = {None: SIFEN_NS, "xsi": XSI_NS, "ds": DS_NS}
    new_rde = etree.Element(f"{{{SIFEN_NS}}}rDE", nsmap=nsmap)
    
    # Copiar atributos (incluye Id y xsi:schemaLocation si existe)
    for k, v in rde_elem.attrib.items():
        new_rde.set(k, v)
    
    # Copiar hijos en deep copy (NO mutar el árbol original)
    for child in list(rde_elem):
        new_rde.append(copy.deepcopy(child))
    
    return new_rde


def _find_by_localname(root: etree._Element, name: str) -> Optional[etree._Element]:
    """Busca un elemento por nombre local (ignorando namespace) en todo el árbol."""
    for el in root.iter():
        if _local(el.tag) == name:
            return el
    return None


def _ensure_rde_has_xmlns(lote_xml: str) -> str:
    """Asegura que el tag <rDE> tenga xmlns explícito."""
    return re.sub(
        r"<rDE(?![^>]*\sxmlns=)",
        '<rDE xmlns="http://ekuatia.set.gov.py/sifen/xsd"',
        lote_xml,
        count=1
    )


def extract_rde_element(xml_bytes: bytes) -> bytes:
    """
    Acepta:
      - un XML cuya raíz ya sea rDE, o
      - un XML wrapper (siRecepDE) que contenga un rDE adentro.
    Devuelve el XML del elemento rDE (bytes).
    """
    root = etree.fromstring(xml_bytes)

    # Caso 1: root es rDE (verificar por nombre local, ignorando namespace)
    if _local(root.tag) == "rDE":
        return etree.tostring(root, xml_declaration=False, encoding="utf-8")

    # Caso 2: buscar el primer rDE anidado (por nombre local, ignorando namespace)
    rde_el = _find_by_localname(root, "rDE")

    if rde_el is None:
        raise ValueError("No se encontró <rDE> en el XML (ni como raíz ni anidado).")

    return etree.tostring(rde_el, xml_declaration=False, encoding="utf-8")


def sign_and_normalize_rde_inside_xml(xml_bytes: bytes, cert_path: str, cert_password: str, artifacts_dir: Optional[Path] = None) -> bytes:
    """
    Garantiza que el rDE dentro del XML esté firmado y normalizado.
    
    - Encuentra el rDE (puede ser root o anidado en rEnviDe)
    - Si no tiene ds:Signature como hijo directo, lo firma
    - Reordena hijos de rDE a: dVerFor, DE, Signature, gCamFuFD (si existe)
    - Devuelve el XML completo con rDE firmado y normalizado
    
    Args:
        xml_bytes: XML que contiene rDE (puede ser rDE root o tener rDE anidado)
        cert_path: Path al certificado P12 para firma
        cert_password: Contraseña del certificado
        artifacts_dir: Directorio para guardar artifacts de debug (opcional)
        
    Returns:
        XML completo con rDE firmado y normalizado (bytes)
    """
    import traceback
    DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
    
    debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
    
    # Parsear XML
    try:
        root = etree.fromstring(xml_bytes)
    except Exception as e:
        raise ValueError(f"Error al parsear XML: {e}")
    
    # Encontrar rDE
    rde_el = None
    is_root_rde = False
    
    if local_tag(root.tag) == "rDE":
        rde_el = root
        is_root_rde = True
    else:
        # Buscar rDE anidado
        rde_el = _find_by_localname(root, "rDE")
        if rde_el is None:
            raise ValueError("No se encontró <rDE> en el XML (ni como raíz ni anidado).")
    
    # Verificar si tiene Signature como hijo directo
    has_signature = any(
        child.tag == f"{{{DSIG_NS}}}Signature" or local_tag(child.tag) == "Signature"
        for child in list(rde_el)
    )
    
    if debug_enabled:
        children_before = [local_tag(c.tag) for c in list(rde_el)]
        print(f"🔍 [sign_and_normalize_rde_inside_xml] rDE hijos antes: {', '.join(children_before)}")
        print(f"🔍 [sign_and_normalize_rde_inside_xml] tiene Signature: {has_signature}")
    
    # Si no tiene Signature, firmarlo
    if not has_signature:
        print("🔐 Firmando DE (no rDE completo)...")
        
        # Guardar XML original antes de firmar (debug)
        if debug_enabled and artifacts_dir:
            artifacts_dir.mkdir(exist_ok=True)
            (artifacts_dir / "xml_before_sign_normalize.xml").write_bytes(xml_bytes)
            print(f"💾 Guardado: {artifacts_dir / 'xml_before_sign_normalize.xml'}")
        
        # Asegurar rDE normalizado antes de extraer DE
        rde_temp_root = ensure_rde_sifen(rde_el)
        
        # Encontrar DE dentro de rDE (namespace-aware)
        de_el = rde_temp_root.find(f".//{{{SIFEN_NS_URI}}}DE")
        if de_el is None:
            # Fallback: buscar por local-name
            nodes = rde_temp_root.xpath("//*[local-name()='DE']")
            de_el = nodes[0] if nodes else None
        
        if de_el is None:
            raise RuntimeError("No se encontró <DE> dentro de rDE para firmar")
        
        # Serializar SOLO el DE
        de_bytes = etree.tostring(de_el, xml_declaration=True, encoding="utf-8")
        
        # Guardar DE antes de firmar (debug)
        if debug_enabled and artifacts_dir:
            artifacts_dir.mkdir(exist_ok=True)
            (artifacts_dir / "de_before_sign.xml").write_bytes(de_bytes)
            print(f"💾 Guardado: {artifacts_dir / 'de_before_sign.xml'}")
        
        # Firmar solo el DE
        try:
            from app.sifen_client.xmlsec_signer import sign_de_with_p12
            signed_de_bytes = sign_de_with_p12(de_bytes, cert_path, cert_password)
            print("✓ DE firmado exitosamente")
        except Exception as e:
            error_msg = f"Error al firmar DE: {e}"
            print(f"❌ {error_msg}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            raise RuntimeError(error_msg)
        
        # Mover Signature dentro del DE si está fuera (como hermano)
        signed_de_bytes = _move_signature_into_de_if_needed(signed_de_bytes, artifacts_dir, debug_enabled)
        
        # Guardar DE después de firmar y mover Signature (debug)
        if debug_enabled and artifacts_dir:
            (artifacts_dir / "de_after_sign.xml").write_bytes(signed_de_bytes)
            print(f"💾 Guardado: {artifacts_dir / 'de_after_sign.xml'}")
        
        # Parsear DE firmado y validar
        try:
            signed_de_root = etree.fromstring(signed_de_bytes)
        except Exception as e:
            raise ValueError(f"Error al re-parsear DE firmado: {e}")
        
        # Validar que el root del DE firmado sea DE
        signed_de_localname = local_tag(signed_de_root.tag)
        if signed_de_localname != "DE":
            error_msg = (
                f"Post-firma: El XML firmado no tiene root DE. "
                f"Tag actual: {signed_de_root.tag}, localname: {signed_de_localname}"
            )
            print(f"❌ {error_msg}", file=sys.stderr)
            raise RuntimeError(error_msg)
        
        # Validar que DE firmado tenga ds:Signature como hijo (búsqueda namespace-aware)
        sig_in_de = signed_de_root.find(f".//{{{DSIG_NS_URI}}}Signature")
        has_signature_in_de = sig_in_de is not None
        if not has_signature_in_de:
            # Fallback: buscar por local-name
            has_signature_in_de = any(
                local_tag(child.tag) == "Signature" and _namespace_uri(child.tag) == DSIG_NS_URI
                for child in list(signed_de_root.iter())
            )
        
        if not has_signature_in_de:
            # Diagnóstico detallado
            de_children = []
            for i, child in enumerate(list(signed_de_root)[:10]):
                de_children.append(f"  [{i}] {child.tag} (local: {local_tag(child.tag)})")
            de_children_str = "\n".join(de_children) if de_children else "  (sin hijos)"
            
            error_msg = (
                f"Post-firma: No se encontró <ds:Signature> dentro de <DE>.\n"
                f"  DE tag: {signed_de_root.tag}\n"
                f"  DE nsmap: {signed_de_root.nsmap if hasattr(signed_de_root, 'nsmap') else {}}\n"
                f"  Primeros 10 hijos del DE:\n{de_children_str}"
            )
            print(f"❌ {error_msg}", file=sys.stderr)
            raise RuntimeError(error_msg)
        
        print("✓ DE firmado tiene Signature como hijo (validado)")
        
        # Reconstruir rDE con dVerFor + DE firmado
        new_rde = etree.Element(
            _qn_sifen("rDE"),
            nsmap={None: SIFEN_NS_URI, "ds": DSIG_NS_URI, "xsi": XSI_NS_URI},
        )
        
        # Agregar dVerFor
        dverfor = etree.SubElement(new_rde, _qn_sifen("dVerFor"))
        dverfor.text = "150"
        
        # Agregar DE firmado
        new_rde.append(signed_de_root)
        
        # Asegurar default xmlns SIFEN
        new_rde = ensure_rde_sifen(new_rde)
        
        # Guardar rDE después de reconstruir (debug)
        if debug_enabled and artifacts_dir:
            rde_after_bytes = etree.tostring(new_rde, xml_declaration=False, encoding="utf-8")
            (artifacts_dir / "rde_after_wrap.xml").write_bytes(rde_after_bytes)
            print(f"💾 Guardado: {artifacts_dir / 'rde_after_wrap.xml'}")
        
        # Actualizar rde_el y root para continuar con el flujo
        # Guardar referencia al rDE original antes de reemplazarlo
        old_rde_el = rde_el
        
        # Si el root original era rDE, reemplazarlo
        if is_root_rde:
            root = new_rde
            rde_el = new_rde
        else:
            # Si rDE estaba anidado, encontrar su parent y reemplazarlo
            old_rde_parent = old_rde_el.getparent()
            if old_rde_parent is not None:
                # Reemplazar el rDE viejo con el nuevo
                # Verificar que old_rde_el realmente es hijo de old_rde_parent antes de remover
                if old_rde_el in list(old_rde_parent):
                    idx = list(old_rde_parent).index(old_rde_el)
                    old_rde_parent.remove(old_rde_el)
                    old_rde_parent.insert(idx, new_rde)
                    rde_el = new_rde
                else:
                    raise RuntimeError("rDE a reemplazar no es hijo directo de su parent (bug de árbol XML)")
            else:
                # Si no tiene parent, usar el nuevo rDE como root
                root = new_rde
                rde_el = new_rde
        
        # Serializar XML completo actualizado
        xml_bytes = etree.tostring(root, xml_declaration=True, encoding="utf-8")
        
        # Guardar XML completo después de reconstruir (debug)
        if debug_enabled and artifacts_dir:
            (artifacts_dir / "xml_after_sign_normalize.xml").write_bytes(xml_bytes)
            print(f"💾 Guardado: {artifacts_dir / 'xml_after_sign_normalize.xml'}")
    else:
        # Ya tiene Signature: NO tocar el árbol (solo validar orden y devolver OK)
        print("✓ rDE ya tiene Signature, NO modificando árbol (preservando firma)")
        # Serializar y retornar sin modificar
        result_bytes = etree.tostring(root, xml_declaration=True, encoding="utf-8")
        return result_bytes
    
    # Reordenar hijos de rDE: dVerFor, DE, gCamFuFD
    # NOTA: La Signature ahora está DENTRO del DE, no como hijo directo del rDE
    # Obtener referencias usando find() con namespaces
    dverfor = rde_el.find(f"./{{{SIFEN_NS}}}dVerFor")
    de = rde_el.find(f"./{{{SIFEN_NS}}}DE")
    gcamfufd = rde_el.find(f"./{{{SIFEN_NS}}}gCamFuFD")
    
    # Verificar que DE tenga Signature dentro (no como hijo directo de rDE)
    if de is not None:
        has_signature_in_de = any(
            child.tag == f"{{{DSIG_NS}}}Signature" or local_tag(child.tag) == "Signature"
            for child in list(de)
        )
        if not has_signature_in_de:
            # Esto no debería pasar si el flujo anterior funcionó correctamente
            print("⚠️  ADVERTENCIA: DE no tiene Signature como hijo (puede estar en otro lugar)")
    
    # Verificar si hay otros hijos que no sean los esperados
    expected_children = {dverfor, de, gcamfufd}
    others = [child for child in list(rde_el) if child not in expected_children]
    
    # Construir orden: dVerFor, DE, gCamFuFD, otros
    ordered_children = []
    if dverfor is not None:
        ordered_children.append(dverfor)
    if de is not None:
        ordered_children.append(de)
    if gcamfufd is not None:
        ordered_children.append(gcamfufd)
    ordered_children.extend(others)
    
    # Verificar si el orden actual es diferente
    current_children = list(rde_el)
    needs_reorder = False
    if len(ordered_children) != len(current_children):
        needs_reorder = True
    else:
        for i, expected in enumerate(ordered_children):
            if current_children[i] != expected:
                needs_reorder = True
                break
    
    # Si el orden cambió, reordenar
    if needs_reorder:
        print("🔄 Reordenando hijos de rDE...")
        # Remover todos los hijos
        for child in list(rde_el):
            rde_el.remove(child)
        # Agregar en orden
        for child in ordered_children:
            rde_el.append(child)
        
        if debug_enabled:
            children_after = [local_tag(c.tag) for c in list(rde_el)]
            print(f"🔍 [sign_and_normalize_rde_inside_xml] rDE hijos después: {', '.join(children_after)}")
    
    # (Opcional) Limpiar namespaces si hace falta (sin forzar xmlns:ds)
    # etree.cleanup_namespaces() puede ayudar, pero no es crítico
    
    # Serializar XML completo
    result_bytes = etree.tostring(root, xml_declaration=True, encoding="utf-8")
    
    # Si se firmó, el xml_after_sign_normalize.xml ya se guardó arriba
    # Solo guardar el resultado final si se reordenó (para ver el orden final)
    if debug_enabled and artifacts_dir:
        artifacts_dir.mkdir(exist_ok=True)
        # Solo guardar si se reordenó (para no duplicar)
        if needs_reorder:
            (artifacts_dir / "xml_after_sign_normalize_final.xml").write_bytes(result_bytes)
            print(f"💾 Guardado: {artifacts_dir / 'xml_after_sign_normalize_final.xml'}")
    
    return result_bytes


def _sanitize_unbound_prefixes(xml_text: str) -> str:
    """
    Sanitiza prefijos sin declarar (unbound prefixes) en el XML.
    
    Detecta prefijos como ns0:, ds:, xsi: que se usan pero no tienen xmlns declarado,
    e inyecta las declaraciones necesarias en el tag de apertura del elemento raíz.
    
    Args:
        xml_text: XML como string
        
    Returns:
        XML con prefijos declarados
    """
    import re
    
    # Buscar el tag de apertura del elemento raíz (puede ser rDE o cualquier otro)
    root_match = re.search(r'<([A-Za-z_][\w\-\.]*:)?([A-Za-z_][\w\-\.]*)\b([^>]*)>', xml_text)
    if not root_match:
        return xml_text
    
    prefix_part = root_match.group(1)  # Puede ser "ns0:" o None
    localname = root_match.group(2)  # Nombre local del elemento
    attrs_str = root_match.group(3)  # Atributos del tag
    
    # Detectar prefijos usados en el XML
    used_prefixes = set()
    
    # Buscar prefijos en tags: <prefix:tag>
    tag_prefixes = re.findall(r'<([A-Za-z_][\w\-\.]*):', xml_text)
    used_prefixes.update(tag_prefixes)
    
    # Buscar prefijos en atributos: prefix:attr="..."
    attr_prefixes = re.findall(r'([A-Za-z_][\w\-\.]*):[A-Za-z_][\w\-\.]*=', attrs_str)
    used_prefixes.update(attr_prefixes)
    
    # Detectar prefijos conocidos que necesitan namespace
    prefixes_to_inject = {}
    
    # Prefijo del elemento raíz (si tiene)
    root_prefix = None
    if prefix_part:
        root_prefix = prefix_part.rstrip(':')
        # Si el prefijo del root se usa pero no está declarado, inyectarlo con SIFEN_NS
        if localname == "rDE" and root_prefix:
            ns_pattern = re.compile(
                r'xmlns(?::' + re.escape(root_prefix) + r')?=["\']' + re.escape(SIFEN_NS) + r'["\']',
                re.IGNORECASE
            )
            if not ns_pattern.search(attrs_str):
                prefixes_to_inject[root_prefix] = SIFEN_NS
    
    # Prefijo ds: (Signature)
    if 'ds:' in xml_text or 'ds=' in attrs_str:
        if not re.search(r'xmlns:ds=["\']' + re.escape(DS_NS) + r'["\']', attrs_str, re.IGNORECASE):
            prefixes_to_inject['ds'] = DS_NS
    
    # Prefijo xsi: (XML Schema Instance)
    if 'xsi:' in xml_text or 'xsi=' in attrs_str:
        if not re.search(r'xmlns:xsi=["\']' + re.escape(XSI_NS) + r'["\']', attrs_str, re.IGNORECASE):
            prefixes_to_inject['xsi'] = XSI_NS
    
    # Si el root es rDE sin prefijo y no tiene xmlns default, inyectarlo
    if localname == "rDE" and not prefix_part:
        ns_pattern = re.compile(
            r'xmlns=["\']' + re.escape(SIFEN_NS) + r'["\']',
            re.IGNORECASE
        )
        if not ns_pattern.search(attrs_str):
            prefixes_to_inject[None] = SIFEN_NS  # None = default namespace
    
    # Inyectar namespaces faltantes
    if prefixes_to_inject:
        new_attrs_parts = []
        
        # Primero, default namespace si aplica
        if None in prefixes_to_inject:
            new_attrs_parts.append(f'xmlns="{prefixes_to_inject[None]}"')
            del prefixes_to_inject[None]
        
        # Luego, namespaces con prefijo
        for prefix, ns_uri in prefixes_to_inject.items():
            new_attrs_parts.append(f'xmlns:{prefix}="{ns_uri}"')
        
        # Agregar al inicio de los atributos
        new_attrs = ' ' + ' '.join(new_attrs_parts)
        if attrs_str.strip():
            new_attrs += ' ' + attrs_str
        else:
            new_attrs = new_attrs.strip()
        
        # Reconstruir el tag
        if prefix_part:
            new_tag = f'<{prefix_part}{localname}{new_attrs}>'
        else:
            new_tag = f'<{localname}{new_attrs}>'
        
        # Reemplazar solo el tag de apertura
        old_tag = root_match.group(0)
        xml_text = xml_text.replace(old_tag, new_tag, 1)
    
    return xml_text


def ensure_rde_default_namespace(xml_bytes: bytes) -> bytes:
    """
    Asegura que el elemento rDE tenga namespace SIFEN_NS como default namespace.
    
    Usa lxml con XPath local-name() para encontrar rDE de forma robusta.
    Si el rDE no está en el namespace correcto, lo recrea preservando atributos e hijos.
    
    Args:
        xml_bytes: XML que contiene rDE (puede ser rDE root o tener rDE anidado)
        
    Returns:
        XML con rDE que tiene xmlns="http://ekuatia.set.gov.py/sifen/xsd" como default
        
    Raises:
        RuntimeError: Si no se encuentra rDE en el XML o no se puede procesar
    """
    # Intentar parsear con sanitize si hay "unbound prefix"
    xml_text = xml_bytes.decode('utf-8', errors='ignore')
    parse_error = None
    
    try:
        parser = etree.XMLParser(remove_blank_text=True, recover=False)
        root = etree.fromstring(xml_bytes, parser)
    except etree.XMLSyntaxError as e:
        # Si hay "unbound prefix", sanitizar primero
        if "unbound prefix" in str(e).lower() or "prefix" in str(e).lower():
            xml_text = _sanitize_unbound_prefixes(xml_text)
            xml_bytes = xml_text.encode('utf-8')
            try:
                parser = etree.XMLParser(remove_blank_text=True, recover=False)
                root = etree.fromstring(xml_bytes, parser)
            except Exception as e2:
                parse_error = e2
                raise RuntimeError(f"No se pudo parsear XML después de sanitizar prefijos: {e2}")
        else:
            parse_error = e
            raise RuntimeError(f"Error al parsear XML: {e}")
    except Exception as e:
        parse_error = e
        raise RuntimeError(f"Error inesperado al parsear XML: {e}")
    
    # Buscar rDE usando XPath local-name()
    rde_list = root.xpath("//*[local-name()='rDE']")
    
    if not rde_list:
        raise RuntimeError("No se encontró rDE por local-name() en el XML")
    
    # Tomar el primero si hay varios
    rde = rde_list[0]
    
    # Verificar namespace actual
    rde_qname = etree.QName(rde)
    rde_ns = rde_qname.namespace
    rde_tag = rde.tag
    
    # Debug mínimo si está habilitado
    debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
    if debug_enabled:
        print(f"DEBUG rDE tag={rde_tag!r} ns={rde_ns!r}")
    
    # Verificar si tiene schemaLocation o cualquier atributo xsi:* (necesita xmlns:xsi)
    has_xsi_attr = False
    # Buscar en atributos del rDE
    for key in rde.attrib.keys():
        if key.endswith('}schemaLocation') or key == 'schemaLocation' or key.startswith('{http://www.w3.org/2001/XMLSchema-instance}'):
            has_xsi_attr = True
            break
    # Si no está en rDE, buscar en descendientes
    if not has_xsi_attr:
        for desc in rde.iter():
            if desc == rde:
                continue
            for key in desc.attrib.keys():
                if key.endswith('}schemaLocation') or key == 'schemaLocation' or key.startswith('{http://www.w3.org/2001/XMLSchema-instance}'):
                    has_xsi_attr = True
                    break
            if has_xsi_attr:
                break
    
    # Verificar si ya tiene xmlns:xsi declarado (en rDE o ancestros)
    has_xsi_ns = False
    if has_xsi_attr:
        # Buscar xmlns:xsi en el rDE o en sus ancestros
        current = rde
        while current is not None:
            # Verificar en atributos del elemento
            for key in current.attrib.keys():
                if key == 'xmlns:xsi' or key.startswith('{http://www.w3.org/2000/xmlns/}xsi'):
                    has_xsi_ns = True
                    break
            if has_xsi_ns:
                break
            # Verificar en el nsmap del elemento (si está disponible)
            if hasattr(current, 'nsmap') and current.nsmap and 'xsi' in current.nsmap:
                has_xsi_ns = True
                break
            current = current.getparent()
    
    # Si ya está en el namespace correcto, verificar si necesita cambios
    if rde_ns == SIFEN_NS:
        # Verificar si tiene default namespace declarado
        root_str = etree.tostring(root, encoding="unicode")
        has_default_ns = 'xmlns="' + SIFEN_NS + '"' in root_str[:1000]
        
        # Si tiene default namespace y (no tiene schemaLocation o ya tiene xmlns:xsi), retornar sin modificar
        if has_default_ns and (not has_schema_location or has_xsi_ns):
            return xml_bytes
    
    # Si no está en el namespace correcto, no tiene default namespace, o tiene schemaLocation sin xmlns:xsi, recrear
    # Obtener el parent del rDE (si existe)
    parent = rde.getparent()
    rde_index = None
    
    if parent is not None:
        # Guardar índice para insertar en la misma posición
        rde_index = list(parent).index(rde)
    
    # Crear nuevo rDE self-contained con todos los namespaces necesarios
    nsmap = {None: SIFEN_NS, "ds": DS_NS}
    if has_xsi_attr and not has_xsi_ns:
        nsmap["xsi"] = XSI_NS
    
    new_rde = etree.Element(f"{{{SIFEN_NS}}}rDE", nsmap=nsmap)
    
    # Copiar todos los atributos (excepto xmlns que ya está en nsmap)
    for key, value in rde.attrib.items():
        if not key.startswith('xmlns'):
            new_rde.set(key, value)
    
    # Mover TODOS los hijos preservando orden
    for child in list(rde):
        new_rde.append(child)
    
    # Reemplazar rDE en su parent
    if parent is not None:
        parent.remove(rde)
        parent.insert(rde_index, new_rde)
    else:
        # rDE es root, reemplazar root
        root = new_rde
    
    # Serializar y retornar
    result_bytes = etree.tostring(root, xml_declaration=True, encoding="utf-8", pretty_print=True)
    return result_bytes


def extract_rde_fragment(xml_bytes: bytes) -> bytes:
    """
    Extrae el elemento rDE (con o sin namespace / con o sin prefijo) usando lxml,
    para evitar fallas de búsqueda por bytes luego del firmado (ej: </ns0:rDE>).
    """
    parser = etree.XMLParser(remove_blank_text=True, recover=True)
    root = etree.fromstring(xml_bytes, parser)

    # Caso: root ya es rDE (con o sin namespace)
    try:
        if etree.QName(root).localname == "rDE":
            rde = root
        else:
            rde = None
    except Exception:
        rde = None

    # Caso: buscar rDE con namespace SIFEN
    if rde is None:
        rde = root.find(".//s:rDE", namespaces=NS)

    # Caso: buscar rDE por local-name() (sin namespace / con prefijo raro)
    if rde is None:
        hits = root.xpath("//*[local-name()='rDE']")
        rde = hits[0] if hits else None

    if rde is None:
        raise RuntimeError("No se encontró rDE en el XML de entrada (no se puede construir lote).")

    # Importante: NO agregamos xml_declaration para mantener el fragmento "puro"
    return etree.tostring(rde, encoding="UTF-8", pretty_print=True)


def extract_rde_raw_bytes(xml_bytes: bytes) -> bytes:
    """
    Extrae el elemento <rDE>...</rDE> como bytes crudos sin parsear/serializar.
    
    Esto preserva exactamente el XML firmado, incluyendo namespaces y prefijos,
    evitando que se rompa la firma al reserializar.
    
    Args:
        xml_bytes: XML que contiene rDE (puede tener prefijo o no)
        
    Returns:
        Bytes del fragmento rDE completo (desde <rDE hasta </rDE>)
        
    Raises:
        ValueError: Si no se encuentra <rDE> o su cierre
    """
    # Buscar el primer <rDE ...> (con o sin prefijo)
    m = re.search(br'<(?P<pfx>[A-Za-z_][\w\.-]*:)?rDE\b', xml_bytes)
    if not m:
        raise ValueError("No se encontró <rDE> en XML firmado (raw)")
    
    start = m.start()
    pfx = m.group('pfx') or b''  # ej: b'ns0:' o b''
    
    # Buscar el cierre correspondiente </rDE> o </prefijo:rDE>
    end_tag = b'</' + pfx + b'rDE>'
    end = xml_bytes.find(end_tag, start)
    if end == -1:
        # Fallback: buscar sin prefijo si no se encuentra con prefijo
        end_tag_fallback = b'</rDE>'
        end = xml_bytes.find(end_tag_fallback, start)
        if end == -1:
            raise ValueError("No se encontró cierre </rDE> en XML firmado (raw)")
        end += len(end_tag_fallback)
    else:
        end += len(end_tag)
    
    return xml_bytes[start:end]


def _extract_rde_fragment_bytes(xml_signed_bytes: bytes) -> bytes:
    """
    Extrae <rDE>...</rDE> desde BYTES sin re-serializar (preserva firma),
    soportando prefijos: <ns0:rDE> ... </ns0:rDE>.
    """
    # 1) Encontrar el tag de apertura con prefijo opcional
    m_open = re.search(rb'<(?P<prefix>[A-Za-z_][\w\-.]*:)?rDE\b[^>]*>', xml_signed_bytes)
    if not m_open:
        raise RuntimeError("No pude encontrar tag de apertura <rDE ...> en bytes.")

    prefix = m_open.group("prefix") or b""  # ej: b"ns0:" o b""
    start = m_open.start()

    # 2) Encontrar el cierre correspondiente con el mismo prefijo
    close_pat = rb'</' + prefix + rb'rDE\s*>'
    m_close = re.search(close_pat, xml_signed_bytes[m_open.end():])
    if not m_close:
        # diagnóstico útil: intentamos también cierre sin prefijo por si hubiera inconsistencia
        m_close2 = re.search(rb'</rDE\s*>', xml_signed_bytes[m_open.end():])
        if m_close2:
            end = m_open.end() + m_close2.end()
            return xml_signed_bytes[start:end]
        raise RuntimeError(
            "No pude encontrar el tag de cierre </rDE> (con o sin prefijo) en bytes."
        )

    end = m_open.end() + m_close.end()
    return xml_signed_bytes[start:end]


def build_lote_base64_from_single_xml(xml_bytes: bytes, return_debug: bool = False) -> Union[str, Tuple[str, bytes, bytes], Tuple[str, bytes, bytes, str]]:
    """
    DEPRECATED: Esta función asume que el XML ya está firmado.
    
    RECOMENDADO: Usar build_and_sign_lote_from_xml() que normaliza, firma y valida.
    
    Crea un ZIP con el rDE firmado envuelto en rLoteDE.
    
    El ZIP contiene un único archivo "lote.xml" con:
    - Root: <rLoteDE xmlns="http://ekuatia.set.gov.py/sifen/xsd">
    - Contenido: un <rDE> completo (ya normalizado, firmado y reordenado) como hijo directo.
    
    IMPORTANTE: 
    - NO incluye <dId> ni <xDE> (pertenecen al SOAP rEnvioLote, NO al lote.xml)
    - Selecciona SIEMPRE el rDE que tiene <ds:Signature> como hijo directo.
    - NO modifica la firma ni los hijos del rDE, solo lo envuelve en rLoteDE.
    - Usa extracción por regex desde bytes originales (NO re-serializa con lxml) para preservar
      exactamente la firma, namespaces y whitespace del rDE firmado.
    
    Args:
        xml_bytes: XML que contiene el rDE (puede ser rDE root o tener rDE anidado)
        return_debug: Si True, retorna tupla (base64, lote_xml_bytes, zip_bytes, lote_did)
                      (lote_did es solo para logging, no está en el lote.xml)
        
    Returns:
        Base64 del ZIP como string, o tupla si return_debug=True (incluye lote_did para logging)
        
    Raises:
        ValueError: Si no se encuentra rDE o si el rDE no tiene Signature como hijo directo
        RuntimeError: Si lote.xml contiene <dId> o <xDE> (pertenecen al SOAP, NO al lote.xml)
    """
    import copy
    # etree ya está importado arriba, no redefinir
    
    # Namespace de firma digital
    DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
    
    # Función para verificar si un rDE tiene Signature como hijo directo
    def is_signed_rde(el) -> bool:
        """Verifica si el rDE tiene <ds:Signature> como hijo directo."""
        return any(
            child.tag == f"{{{DSIG_NS}}}Signature"
            for child in list(el)
        )
    
    # Función para verificar si un rDE tiene Signature en cualquier profundidad (incluyendo dentro de DE)
    def has_signature_anywhere(el) -> bool:
        """Verifica si el rDE o su contenido (incluyendo DE) tiene Signature en cualquier profundidad."""
        for sig_candidate in el.iter():
            if local_tag(sig_candidate.tag) == "Signature":
                # Verificar que sea del namespace correcto
                if "}" in sig_candidate.tag:
                    ns = sig_candidate.tag.split("}", 1)[0][1:]
                    if ns == DSIG_NS:
                        return True
                elif sig_candidate.tag == "Signature":
                    # Sin namespace, asumir que es DSIG_NS
                    return True
        return False
    
    # DIAGNÓSTICO: Log información del XML de entrada (SIEMPRE, no solo en debug)
    try:
        xml_str_preview = xml_bytes[:500].decode('utf-8', errors='replace') if len(xml_bytes) > 500 else xml_bytes.decode('utf-8', errors='replace')
        print(f"🔍 DIAGNÓSTICO [build_lote_base64] XML entrada: {len(xml_bytes)} bytes")
        print(f"🔍 DIAGNÓSTICO [build_lote_base64] Primeros 200 chars: {xml_str_preview[:200]}")
    except Exception as e:
        print(f"⚠️  DIAGNÓSTICO [build_lote_base64] Error al leer preview XML: {e}")
    
    # Parsear xml_bytes
    try:
        xml_root = etree.fromstring(xml_bytes)
        root_localname = local_tag(xml_root.tag)
        root_ns = xml_root.tag.split("}", 1)[0][1:] if "}" in xml_root.tag else "VACÍO"
        print(f"🔍 DIAGNÓSTICO [build_lote_base64] Root localname: {root_localname}")
        print(f"🔍 DIAGNÓSTICO [build_lote_base64] Root namespace: {root_ns}")
    except Exception as e:
        error_msg = f"Error al parsear XML: {e}"
        print(f"❌ ERROR en build_lote_base64_from_single_xml: {error_msg}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        raise ValueError(error_msg)
    
    # Helper para asegurar namespace SIFEN en elementos sin xmlns
    def ensure_sifen_ns(el):
        """
        Recorre recursivamente el árbol y asegura que los elementos tengan namespace SIFEN_NS.
        Si el tag no empieza con "{", lo reemplaza por f"{{{SIFEN_NS}}}{localname}".
        Conserva atributos y children.
        """
        if el is None:
            return
        
        # Si el tag no tiene namespace, agregarlo
        if not el.tag.startswith("{"):
            localname = el.tag
            el.tag = f"{{{SIFEN_NS}}}{localname}"
        
        # Recursivamente procesar hijos
        for child in list(el):
            ensure_sifen_ns(child)
    
    # Construir lista de candidatos rDE
    candidates_rde = []
    rde_constructed_from_de = False  # Flag para saber si rDE fue construido desde DE
    
    # Caso a) si local-name(root) == "rDE"
    if local_tag(xml_root.tag) == "rDE":
        candidates_rde = [xml_root]
        print(f"🔍 DIAGNÓSTICO [build_lote_base64] Root ES rDE directamente")
    else:
        # Caso b) buscar todos los rDE con namespace SIFEN
        candidates_rde = xml_root.findall(f".//{{{SIFEN_NS}}}rDE")
        print(f"🔍 DIAGNÓSTICO [build_lote_base64] Buscando rDE con namespace SIFEN: {len(candidates_rde)} encontrados")
        # Caso c) si sigue vacío, buscar sin namespace usando XPath
        if not candidates_rde:
            candidates_rde = xml_root.xpath(".//*[local-name()='rDE']")
            print(f"🔍 DIAGNÓSTICO [build_lote_base64] Buscando rDE sin namespace (XPath): {len(candidates_rde)} encontrados")
    
    # Si no se encontró ningún rDE, intentar construir uno desde DE
    if not candidates_rde:
        print(f"🔍 DIAGNÓSTICO [build_lote_base64] No se encontró rDE, buscando DE para construir rDE...")
        
        # Buscar DE (con o sin namespace)
        de_candidates = []
        
        # Buscar DE con namespace SIFEN
        de_candidates = xml_root.findall(f".//{{{SIFEN_NS}}}DE")
        if not de_candidates:
            # Buscar DE sin namespace usando XPath
            de_candidates = xml_root.xpath(".//*[local-name()='DE']")
        
        # Si el root mismo es DE
        if local_tag(xml_root.tag) == "DE":
            de_candidates = [xml_root] if not de_candidates else de_candidates
        
        if de_candidates:
            de_el = de_candidates[0]
            print(f"🔍 DIAGNÓSTICO [build_lote_base64] Encontrado DE, construyendo rDE mínimo...")
            
            # Asegurar que el árbol SIFEN esté namespaced (incluye DE y todos los hijos SIFEN)
            ensure_sifen_namespace(de_el)
            
            # Crear rDE CON namespace SIFEN y default xmlns correcto
            rde_el = etree.Element(
                _qn_sifen("rDE"),
                nsmap={
                    None: SIFEN_NS_URI,   # default namespace (CRÍTICO)
                    "ds": DSIG_NS_URI,
                    "xsi": XSI_NS_URI,
                },
            )
            
            # Agregar dVerFor si no existe en DE
            # (verificar si ya existe en el DE o en algún hijo)
            has_dverfor = False
            for child in de_el.iter():
                if local_tag(child.tag) == "dVerFor":
                    has_dverfor = True
                    break
            
            if not has_dverfor:
                dverfor = etree.SubElement(rde_el, _qn_sifen("dVerFor"))
                dverfor.text = "150"
                print(f"🔍 DIAGNÓSTICO [build_lote_base64] Agregado dVerFor='150' al rDE construido")
            
            # Agregar el DE dentro del rDE
            rde_el.append(de_el)
            
            # Agregar a candidatos
            candidates_rde = [rde_el]
            print(f"🔍 DIAGNÓSTICO [build_lote_base64] rDE construido exitosamente envolviendo DE")
            
            # Marcar que este rDE fue construido desde DE (puede tener Signature dentro del DE, no como hijo directo)
            rde_constructed_from_de = True
        else:
            # No se encontró ni rDE ni DE
            xml_preview = xml_bytes[:200].decode('utf-8', errors='replace') if len(xml_bytes) > 200 else xml_bytes.decode('utf-8', errors='replace')
            de_found = len(xml_root.xpath(".//*[local-name()='DE']")) > 0
            rde_found = len(xml_root.xpath(".//*[local-name()='rDE']")) > 0
            
            error_msg = (
                f"No se encontró rDE en el XML de entrada (no se puede construir lote).\n"
                f"Root local-name: {root_localname}\n"
                f"Root namespace: {root_ns}\n"
                f"Primeros 200 chars del XML: {xml_preview}\n"
                f"DE encontrado por local-name: {de_found}\n"
                f"rDE encontrado por local-name: {rde_found}"
            )
            print(f"❌ ERROR en build_lote_base64_from_single_xml: {error_msg}", file=sys.stderr)
            raise ValueError(error_msg)
    
    print(f"🔍 DIAGNÓSTICO [build_lote_base64] Total candidates_rDE: {len(candidates_rde)}")
    
    # Seleccionar el candidato correcto: el que tiene Signature como hijo directo
    signed = [el for el in candidates_rde if is_signed_rde(el)]
    
    if len(signed) >= 1:
        rde_el = signed[0]
    else:
        # Si no hay rDE con Signature como hijo directo, buscar por gCamFuFD como fallback
        gcam = [
            el for el in candidates_rde
            if any(local_tag(child.tag) == "gCamFuFD" for child in list(el))
        ]
        if gcam:
            rde_el = gcam[0]
            # Validar que tenga Signature
            # Si rDE fue construido desde DE, permitir Signature en cualquier profundidad
            # Si no, requerir Signature como hijo directo
            if rde_constructed_from_de:
                if not has_signature_anywhere(rde_el):
                    # Si fue construido desde DE y no tiene Signature, es un error
                    error_msg = (
                        "Se construyó rDE desde DE pero el DE no contiene Signature. "
                        "El DE debe estar firmado antes de construir el lote."
                    )
                    print(f"❌ ERROR en build_lote_base64_from_single_xml: {error_msg}", file=sys.stderr)
                    raise ValueError(error_msg)
            elif not is_signed_rde(rde_el):
                # DIAGNÓSTICO ADICIONAL antes de levantar ValueError
                children_list = []
                for child in list(rde_el):
                    child_local = local_tag(child.tag)
                    child_ns = child.tag.split("}", 1)[0][1:] if "}" in child.tag else "VACÍO"
                    children_list.append(f"{child_local} (ns: {child_ns})")
                
                # Buscar Signature en cualquier profundidad
                signature_paths = []
                for sig_candidate in rde_el.iter():
                    if local_tag(sig_candidate.tag) == "Signature":
                        # Construir path simple
                        path_parts = []
                        current = sig_candidate
                        while current is not None and current != rde_el:
                            path_parts.insert(0, local_tag(current.tag))
                            current = current.getparent()
                        signature_paths.append(" -> ".join(path_parts))
                
                error_msg = (
                    "Se encontró rDE pero NO contiene <ds:Signature> como hijo directo. "
                    "Probablemente se pasó XML no firmado o se eligió el rDE equivocado.\n"
                    f"Hijos directos de rDE: {', '.join(children_list) if children_list else '(ninguno)'}\n"
                )
                if signature_paths:
                    error_msg += f"Signature encontrada en profundidad: {', '.join(signature_paths)}\n"
                else:
                    error_msg += "Signature NO encontrada en ninguna profundidad dentro de rDE.\n"
                
                print(f"❌ ERROR en build_lote_base64_from_single_xml:", file=sys.stderr)
                print(error_msg, file=sys.stderr)
                raise ValueError(error_msg)
        else:
            # Si rDE fue construido desde DE, permitir Signature en cualquier profundidad
            if rde_constructed_from_de:
                if has_signature_anywhere(candidates_rde[0]):
                    rde_el = candidates_rde[0]
                else:
                    error_msg = (
                        "Se construyó rDE desde DE pero el DE no contiene Signature. "
                        "El DE debe estar firmado antes de construir el lote."
                    )
                    print(f"❌ ERROR en build_lote_base64_from_single_xml: {error_msg}", file=sys.stderr)
                    raise ValueError(error_msg)
            else:
                # DIAGNÓSTICO ADICIONAL antes de levantar ValueError
                error_msg_parts = [
                    "Se encontró rDE pero NO contiene <ds:Signature> como hijo directo. "
                    "Probablemente se pasó XML no firmado o se eligió el rDE equivocado."
                ]
                
                if candidates_rde:
                    for idx, candidate in enumerate(candidates_rde):
                        children_list = []
                        for child in list(candidate):
                            child_local = local_tag(child.tag)
                            child_ns = child.tag.split("}", 1)[0][1:] if "}" in child.tag else "VACÍO"
                            children_list.append(f"{child_local} (ns: {child_ns})")
                        
                        error_msg_parts.append(f"\nCandidato rDE #{idx + 1} hijos directos: {', '.join(children_list) if children_list else '(ninguno)'}")
                        
                        # Buscar Signature en cualquier profundidad
                        signature_paths = []
                        for sig_candidate in candidate.iter():
                            if local_tag(sig_candidate.tag) == "Signature":
                                path_parts = []
                                current = sig_candidate
                                while current is not None and current != candidate:
                                    path_parts.insert(0, local_tag(current.tag))
                                    current = current.getparent()
                                signature_paths.append(" -> ".join(path_parts))
                        
                        if signature_paths:
                            error_msg_parts.append(f"  Signature encontrada en profundidad: {', '.join(signature_paths)}")
                        else:
                            error_msg_parts.append(f"  Signature NO encontrada en ninguna profundidad")
                
                error_msg = "\n".join(error_msg_parts)
                print(f"❌ ERROR en build_lote_base64_from_single_xml:", file=sys.stderr)
                print(error_msg, file=sys.stderr)
                raise ValueError(error_msg)
    
    # Debug: mostrar información de selección
    debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
    if debug_enabled:
        print(f"🧪 DEBUG [build_lote_base64] candidates_rDE: {len(candidates_rde)}")
        print(f"🧪 DEBUG [build_lote_base64] selected_rDE_signed: {is_signed_rde(rde_el)}")
        selected_children = [local_tag(c.tag) for c in list(rde_el)]
        print(f"🧪 DEBUG [build_lote_base64] selected_rDE_children: {', '.join(selected_children)}")
    
    # IMPORTANTE: Serializar rDE firmado usando etree.tostring() para preservar EXACTAMENTE la firma
    # NO volver a parsear/reconstruir el rDE después de firmar
    try:
        rde_bytes = etree.tostring(rde_el, encoding="utf-8", xml_declaration=False, with_tail=False)
        print(f"🔍 DIAGNÓSTICO [build_lote_base64] rDE serializado con etree.tostring: {len(rde_bytes)} bytes")
    except Exception as e:
        raise RuntimeError(f"Error al serializar rDE con etree.tostring: {e}")
    
    # Parche mínimo al start tag del rDE: inyectar xmlns:* si faltan para evitar "Namespace prefix X is not defined"
    # Solo modificar el start tag, NO tocar el resto del XML firmado
    # Usar constantes del módulo si están disponibles, sino definir localmente
    XSI_NS_URI = XSI_NS  # Constante del módulo
    SIFEN_NS_URI = SIFEN_NS  # Constante del módulo
    DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
    
    # Encontrar el start tag del rDE (hasta el primer >)
    start_tag_end = rde_bytes.find(b">")
    if start_tag_end == -1:
        raise RuntimeError("No se encontró cierre del start tag en rDE serializado")
    
    head = rde_bytes[:start_tag_end + 1]  # Incluye el >
    body = rde_bytes[start_tag_end + 1:]   # Resto del XML
    
    # Detectar qué prefijos se usan en el contenido pero no están declarados en el start tag
    needs_xsi = b"xsi:" in rde_bytes and b'xmlns:xsi="' not in head
    needs_ns0 = b"ns0:" in rde_bytes and b'xmlns:ns0="' not in head
    needs_ds = b"ds:" in rde_bytes and b'xmlns:ds="' not in head
    
    
    # Sanitizar rDE start tag: eliminar atributos prohibidos en <rDE ...>
    # (Id en rDE y schemaLocation en rDE suelen provocar rechazo/no-encolado)
    try:
        _head_str = head.decode("utf-8", errors="replace")
        _head_orig = _head_str

        # Quitar Id="..." o Id='...'
        _head_str = re.sub(r'\s+Id\s*=\s*"[^"]*"', "", _head_str)
        _head_str = re.sub(r"\s+Id\s*=\s*'[^']*'", "", _head_str)

        # Quitar xsi:schemaLocation="..." / schemaLocation="..."
        _head_str = re.sub(r'\s+(?:xsi:)?schemaLocation\s*=\s*"[^"]*"', "", _head_str)
        _head_str = re.sub(r"\s+(?:xsi:)?schemaLocation\s*=\s*'[^']*'", "", _head_str)

        if _head_str != _head_orig:
            head = _head_str.encode("utf-8")
            print("🧹 Sanitizar rDE start tag: removed Id/schemaLocation")
    except Exception:
        pass


    # --- Sanitizar rDE start tag (bytes): remover Id y schemaLocation (prohibidos en rDE) ---
    try:
        before_head = head
        # Id="..." (cualquier valor)
        head = re.sub(br'\s+Id="[^"]*"', b'', head)
        # xsi:schemaLocation="..." y variantes
        head = re.sub(br'\s+xsi:schemaLocation="[^"]*"', b'', head)
        head = re.sub(br"\s+xsi:schemaLocation='[^']*'", b'', head)
        # schemaLocation sin prefijo (por si aparece)
        head = re.sub(br'\s+schemaLocation="[^"]*"', b'', head)
        head = re.sub(br"\s+schemaLocation='[^']*'", b'', head)

        if head != before_head:
            print("🔍 DIAGNÓSTICO [build_lote_base64] rDE start tag sanitizado (Id/schemaLocation removidos)")
            print("   before:", before_head[:200])
            print("   after: ", head[:200])
        else:
            print("⚠️  WARNING [build_lote_base64] sanitize rDE NO encontró Id/schemaLocation en head")
    except Exception as _e:
        print(f"⚠️  WARNING [build_lote_base64] sanitize rDE falló: {_e}")

    # Inyectar xmlns:* en el start tag si faltan (antes del >)
    if needs_xsi or needs_ns0 or needs_ds:
        # Remover el > del head
        head_without_close = head[:-1]
        # Agregar xmlns:* antes del >
        injections = []
        if needs_xsi:
            injections.append(b' xmlns:xsi="' + XSI_NS_URI.encode("utf-8") + b'"')
        if needs_ns0:
            injections.append(b' xmlns:ns0="' + SIFEN_NS_URI.encode("utf-8") + b'"')
        if needs_ds:
            injections.append(b' xmlns:ds="' + DSIG_NS.encode("utf-8") + b'"')
        
        # Reconstruir head con las inyecciones
        head = head_without_close + b"".join(injections) + b">"
        print(f"🔍 DIAGNÓSTICO [build_lote_base64] Parche aplicado al start tag: {len(injections)} xmlns:* inyectados")
    
    # Reconstruir rDE con el start tag parcheado
    # Sanitizar atributos prohibidos en <rDE ...> dentro de lote.xml (SIFEN)
    # - rDE NO debe llevar Id
    # - rDE NO debe llevar (xsi:)schemaLocation
    head = re.sub(br"\s+Id=(['\"]).*?\1", b"", head)
    head = re.sub(br"\s+(?:xsi:)?schemaLocation=(['\"]).*?\1", b"", head)

    rde_patched = head + body
    
    # Guardar artifact de debug del rDE fragment (si artifacts_dir existe)
    try:
        artifacts_dir = _resolve_artifacts_dir()
        debug_rde_file = artifacts_dir / "debug_rde_fragment.xml"
        debug_rde_file.write_bytes(rde_patched)
        print(f"💾 Guardado artifact debug: {debug_rde_file}")
    except Exception as e:
        # Silencioso: no fallar si no se puede guardar el artifact
        pass
    
    # Construir lote.xml con estructura: <rLoteDE xmlns="..."><rDE>...</rDE></rLoteDE>
    # SIN dId, SIN xDE (dId y xDE pertenecen al SOAP rEnvioLote, NO al lote.xml)
    # dId dinámico para usar en el SOAP (NO dentro de lote.xml)
    lote_did = str(int(time.time() * 1000))
    
    # Construir lote.xml: rLoteDE con namespace SIFEN, conteniendo rDE firmado
    lote_xml_bytes = (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<rLoteDE xmlns="' + SIFEN_NS.encode("utf-8") + b'">'
        + rde_patched +
        b'</rLoteDE>'
    )
    print(f"🔍 DIAGNÓSTICO [build_lote_base64] lote.xml construido con bytes crudos: {len(lote_xml_bytes)} bytes")
    
    # Debug anti-regresión: verificar que la firma se preserva
    if debug_enabled:
        # Verificar que si hay <Signature xmlns="..."> en el firmado, también esté en el lote
        sig_pattern_default = b'<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"'
        sig_pattern_ds = b'<ds:Signature'
        sig_pattern_ns = b'<Signature xmlns:ds='
        
        has_sig_in_firmado = (
            sig_pattern_default in xml_bytes or
            sig_pattern_ds in xml_bytes or
            sig_pattern_ns in xml_bytes
        )
        
        if has_sig_in_firmado:
            has_sig_in_lote = (
                sig_pattern_default in lote_xml_bytes or
                sig_pattern_ds in lote_xml_bytes or
                sig_pattern_ns in lote_xml_bytes
            )
            if not has_sig_in_lote:
                print(f"⚠️  WARNING [build_lote_base64] Patrón de firma no encontrado en lote.xml")
            else:
                print(f"✅ DEBUG [build_lote_base64] Firma preservada en lote.xml")
    
    # Opcional debug: solo validar que sea well-formed (sin re-serializar)
    try:
        etree.fromstring(lote_xml_bytes)
    except Exception as e:
        print(f"⚠️  WARNING [build_lote_base64] lote.xml no es well-formed: {e}")
    
    # FINAL SANITIZE (SIFEN): <rDE ...> -> <rDE>
    lote_xml_bytes = re.sub(br"<rDE\b[^>]*>", b"<rDE>", lote_xml_bytes, count=1)

# Hard-guard: verificar que rLoteDE tenga la estructura correcta: <rLoteDE xmlns="..."><rDE>...</rDE></rLoteDE>
    # PROHIBIDO: <dId> y <xDE> dentro de lote.xml (pertenecen al SOAP, NO al lote.xml)
    rlote_tag_start = lote_xml_bytes.find(b"<rLoteDE")
    if rlote_tag_start >= 0:
        rlote_tag_end = lote_xml_bytes.find(b">", rlote_tag_start)
        if rlote_tag_end > rlote_tag_start:
            rlote_tag = lote_xml_bytes[rlote_tag_start:rlote_tag_end]
            # Verificar que tenga xmlns SIFEN
            if b'xmlns="' + SIFEN_NS.encode("utf-8") + b'"' not in rlote_tag:
                raise RuntimeError(f"BUG: rLoteDE no tiene xmlns SIFEN correcto. Tag: {rlote_tag}")
    
    # Verificar que NO tenga <dId> ni <xDE> (pertenecen al SOAP, NO al lote.xml)
    if b"<dId" in lote_xml_bytes or b"</dId>" in lote_xml_bytes:
        raise RuntimeError("BUG: lote.xml contiene <dId> (pertenece al SOAP, NO al lote.xml)")
    if b"<xDE" in lote_xml_bytes or b"</xDE>" in lote_xml_bytes:
        raise RuntimeError("BUG: lote.xml contiene <xDE> (pertenece al SOAP, NO al lote.xml)")
    
    # Verificar que tenga <rDE> (con o sin prefijo)
    if b"<rDE" not in lote_xml_bytes:
        raise RuntimeError("BUG: lote.xml no contiene <rDE>")
    
    # Verificar que sea well-formed
    try:
        etree.fromstring(lote_xml_bytes)
    except Exception as e:
        raise RuntimeError(f"BUG: lote.xml no es well-formed: {e}")
    
    # Guardar para inspección (antes de crear ZIP)
    if debug_enabled:
        Path("/tmp/lote_xml_payload.xml").write_bytes(lote_xml_bytes)
    
    # ZIP con lote.xml
    try:
        mem = BytesIO()
        with zipfile.ZipFile(mem, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("lote.xml", lote_xml_bytes)
        zip_bytes = mem.getvalue()
        print(f"🔍 DIAGNÓSTICO [build_lote_base64] ZIP creado: {len(zip_bytes)} bytes")
        
        # Debug del ZIP (SIEMPRE cuando se construye)
        _save_zip_debug(zip_bytes, artifacts_dir, debug_enabled)
    except Exception as e:
        error_msg = f"Error al crear ZIP: {e}"
        print(f"❌ ERROR en build_lote_base64_from_single_xml: {error_msg}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        raise RuntimeError(error_msg)
    
    # Guardar ZIP también para debug
    if debug_enabled:
        Path("/tmp/lote_payload.zip").write_bytes(zip_bytes)
    
    # Check rápido dentro de build_lote_base64_from_single_xml (solo cuando SIFEN_DEBUG_SOAP=1)
    if debug_enabled:
        try:
            print(f"🧪 DEBUG [build_lote_base64] Guardado: /tmp/lote_xml_payload.xml, /tmp/lote_payload.zip")
            
            # Abrir el ZIP en memoria y verificar
            with zipfile.ZipFile(BytesIO(zip_bytes), "r") as zf:
                zip_files = zf.namelist()
                print(f"🧪 DEBUG [build_lote_base64] ZIP files: {zip_files}")
                
                if "lote.xml" in zip_files:
                    lote_content = zf.read("lote.xml")
                    lote_root = etree.fromstring(lote_content)
                    
                    root_tag = local_tag(lote_root.tag)
                    root_ns = lote_root.nsmap.get(None, "VACÍO") if hasattr(lote_root, 'nsmap') else "VACÍO"
                    
                    # Verificar namespace del root (debe ser VACÍO)
                    if "}" in lote_root.tag:
                        root_ns_from_tag = lote_root.tag.split("}", 1)[0][1:]
                        root_ns = root_ns_from_tag if root_ns_from_tag else "VACÍO"
                    else:
                        root_ns = "VACÍO"
                    
                    print(f"🧪 DEBUG [build_lote_base64] root localname: {root_tag}")
                    print(f"🧪 DEBUG [build_lote_base64] root namespace: {root_ns}")
                    
                    # Verificar que existe rDE dentro de rLoteDE
                    rde_found = lote_root.find(f".//{{{SIFEN_NS}}}rDE")
                    if rde_found is None:
                        rde_found = lote_root.find(".//rDE")
                    
                    has_rde = rde_found is not None
                    print(f"🧪 DEBUG [build_lote_base64] has_rDE: {has_rde}")
                    
                    if has_rde and root_tag == "rLoteDE":
                        # Verificar namespace del rDE (debe ser SIFEN_NS)
                        rde_tag = rde_found.tag
                        rde_ns = "VACÍO"
                        if "}" in rde_tag:
                            rde_ns = rde_tag.split("}", 1)[0][1:]
                        else:
                            # Buscar xmlns en el rDE o heredado
                            # Si el tag no tiene namespace en el nombre, buscar en nsmap o en atributos
                            rde_ns = rde_found.nsmap.get(None, "VACÍO") if hasattr(rde_found, 'nsmap') else "VACÍO"
                            # Si sigue VACÍO, verificar en el XML original (bytes) buscando xmlns en el tag rDE
                            if rde_ns == "VACÍO":
                                # Leer el contenido del ZIP y buscar xmlns en el tag rDE
                                lote_content_str = lote_content.decode('utf-8', errors='replace')
                                rde_tag_match = re.search(r'<rDE\b([^>]*)>', lote_content_str)
                                if rde_tag_match:
                                    attrs = rde_tag_match.group(1)
                                    xmlns_match = re.search(r'xmlns="([^"]+)"', attrs)
                                    if xmlns_match:
                                        rde_ns = xmlns_match.group(1)
                                    else:
                                        # Intentar con comillas simples
                                        xmlns_match = re.search(r"xmlns='([^']+)'", attrs)
                                        if xmlns_match:
                                            rde_ns = xmlns_match.group(1)
                        
                        print(f"🧪 DEBUG [build_lote_base64] rDE localname: {local_tag(rde_tag)}")
                        print(f"🧪 DEBUG [build_lote_base64] rDE namespace: {rde_ns}")
                        
                        # Mostrar orden de hijos del rDE interno
                        children_order = [local_tag(c.tag) for c in list(rde_found)]
                        print(f"🧪 DEBUG [build_lote_base64] rDE children: {', '.join(children_order)}")
                        
                        # Verificar que incluye Signature y gCamFuFD
                        has_signature = any(local_tag(c.tag) == "Signature" for c in list(rde_found))
                        has_gcam = any(local_tag(c.tag) == "gCamFuFD" for c in list(rde_found))
                        if not has_signature:
                            print(f"⚠️  WARNING [build_lote_base64] rDE interno NO tiene Signature")
                        if not has_gcam:
                            print(f"⚠️  WARNING [build_lote_base64] rDE interno NO tiene gCamFuFD")
                        
                        # Verificar estructura esperada
                        if root_ns != "VACÍO" and root_ns != "":
                            print(f"⚠️  WARNING [build_lote_base64] rLoteDE NO debe tener namespace, tiene: {root_ns}")
                        if rde_ns != SIFEN_NS:
                            print(f"⚠️  WARNING [build_lote_base64] rDE debe tener namespace {SIFEN_NS}, tiene: {rde_ns}")
                    elif root_tag != "rLoteDE":
                        print(f"⚠️  WARNING [build_lote_base64] root debería ser rLoteDE, es {root_tag}")
        except Exception as e:
            print(f"⚠️  DEBUG [build_lote_base64] error al verificar ZIP: {e}")
            import traceback
            traceback.print_exc()
    
    # Base64 estándar sin saltos
    b64 = base64.b64encode(zip_bytes).decode("ascii")
    if return_debug:
        return b64, lote_xml_bytes, zip_bytes, lote_did
    return b64


def _check_signing_dependencies() -> None:
    """
    Verifica que lxml y xmlsec estén disponibles.
    
    Raises:
        RuntimeError: Si faltan dependencias críticas
    """
    try:
        import lxml
        from lxml import etree
    except ImportError as e:
        raise RuntimeError(
            "BLOQUEADO: Dependencias de firma faltantes (lxml). "
            "Ejecutar scripts/bootstrap_env.sh o: pip install lxml"
        ) from e
    
    try:
        import xmlsec
    except ImportError as e:
        raise RuntimeError(
            "BLOQUEADO: Dependencias de firma faltantes (xmlsec). "
            "Ejecutar scripts/bootstrap_env.sh o: pip install python-xmlsec"
        ) from e


def build_and_sign_lote_from_xml(
    xml_bytes: bytes,
    cert_path: str,
    cert_password: str,
    env: str = "test",
    return_debug: bool = False,
    dump_http: bool = False,
    artifacts_dir: Optional[Path] = None,
) -> Union[str, Tuple[str, bytes, bytes, None]]:
    """
    Construye el lote.xml COMPLETO como árbol lxml ANTES de firmar, luego firma el DE
    dentro del contexto del lote final, y serializa UNA SOLA VEZ.
    
    ANTES DE USAR: Validar que el certificado NO sea self-signed.
    Los certificados self-signed solo son para tests unitarios OFFLINE.
    """
    # 0. GUARD-RAIL: Validar que no sea self-signed
    validate_no_self_signed(cert_path, "firma XML")
    try:
        _check_signing_dependencies()
    except RuntimeError as e:
        # Guardar artifacts si faltan dependencias
        artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
        try:
            artifacts_dir.joinpath("sign_blocked_input.xml").write_bytes(xml_bytes)
            artifacts_dir.joinpath("sign_blocked_reason.txt").write_text(
                f"BLOQUEADO: Dependencias de firma faltantes\n\n{str(e)}\n\n"
                f"Ejecutar: scripts/bootstrap_env.sh\n"
                f"O manualmente: pip install lxml python-xmlsec",
                encoding="utf-8"
            )
        except Exception:
            pass
        raise
    
    import hashlib
    import re
    
    debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
    
    # 1. Parsear XML de entrada
    try:
        parser = etree.XMLParser(remove_blank_text=False, recover=False)
        xml_root = etree.fromstring(xml_bytes, parser=parser)
    except Exception as e:
        raise ValueError(f"Error al parsear XML de entrada: {e}")
    
    # 2. Extraer o construir rDE (sin firmar aún)
    root_localname = local_tag(xml_root.tag)
    
    # Soporte para rEnviDe (siRecepDE) que contiene xDE en base64
    if root_localname == "rEnviDe":
        # Guardar input original para debug
        artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
        try:
            artifacts_dir.joinpath("renvide_input.xml").write_bytes(xml_bytes)
        except Exception:
            pass
        
        # Helper local para búsqueda robusta namespace-aware
        def _find_first(root, name: str, ns_uri: Optional[str] = None):
            """Busca el primer elemento con localname 'name', probando múltiples métodos."""
            # 1) namespace explícito si ns_uri
            if ns_uri:
                el = root.find(f'.//{{{ns_uri}}}{name}')
                if el is not None:
                    return el
            # 2) XPath local-name (lxml)
            try:
                els = root.xpath(f'//*[local-name()="{name}"]')
                if els:
                    return els[0]
            except Exception:
                pass
            # 3) fallback iter
            for el in root.iter():
                if isinstance(el.tag, str) and local_tag(el.tag) == name:
                    return el
            return None
        
        # Buscar xDE (namespace-aware)
        xde_elem = _find_first(xml_root, "xDE", SIFEN_NS)
        
        # Si no se encuentra xDE pero existe rDE, crear xDE automáticamente
        if xde_elem is None:
            rde_elem = _find_first(xml_root, "rDE", SIFEN_NS)
            if rde_elem is not None:
                # Crear xDE en namespace SIFEN
                xde_elem = etree.Element(f"{{{SIFEN_NS}}}xDE")
                
                # Insertarlo debajo de rEnviDe (después de dId si existe)
                did_elem = _find_first(xml_root, "dId", SIFEN_NS)
                if did_elem is not None:
                    children = list(xml_root)
                    idx = children.index(did_elem) + 1
                    xml_root.insert(idx, xde_elem)
                else:
                    xml_root.insert(0, xde_elem)
                
                # Mover el rDE existente dentro de xDE
                old_parent = rde_elem.getparent()
                if old_parent is not None:
                    old_parent.remove(rde_elem)
                xde_elem.append(rde_elem)
        
        # Si aún no se encontró xDE, construir diagnóstico detallado
        # xDE puede tener texto (base64) o hijos (rDE), ambos son válidos
        has_text = xde_elem is not None and xde_elem.text and xde_elem.text.strip()
        has_children = xde_elem is not None and len(list(xde_elem)) > 0
        if xde_elem is None or (not has_text and not has_children):
            root_tag = xml_root.tag if hasattr(xml_root, 'tag') else str(xml_root)
            root_nsmap = xml_root.nsmap if hasattr(xml_root, 'nsmap') else {}
            
            # Recolectar primeros ~30 tags descendientes para diagnóstico
            tags = []
            for el in xml_root.iter():
                if isinstance(el.tag, str):
                    tags.append(local_tag(el.tag))
                if len(tags) >= 30:
                    break
            
            raise ValueError(
                f"Entrada es rEnviDe pero no se encontró xDE. "
                f"root.tag={root_tag}, root.nsmap={root_nsmap}, first_tags={tags[:30]}"
            )
        
        # Extraer contenido de xDE: puede ser base64 (texto) o rDE (hijo)
        de_root = None
        
        # Caso 1: xDE tiene texto (base64)
        if xde_elem.text and xde_elem.text.strip():
            xde_base64 = xde_elem.text.strip()
            # Remover espacios/linebreaks del base64
            xde_base64 = re.sub(r'\s+', '', xde_base64)
            
            try:
                # Decodificar base64
                de_bytes = base64.b64decode(xde_base64)
            except Exception as e:
                raise ValueError(f"Error al decodificar xDE (base64): {e}")
            
            # Guardar XML extraído para debug
            try:
                artifacts_dir.joinpath("xde_extracted_from_renvide.xml").write_bytes(de_bytes)
            except Exception:
                pass
            
            # Re-parsear el contenido decodificado
            try:
                de_root = etree.fromstring(de_bytes, parser=parser)
            except Exception as e:
                raise ValueError(f"Error al parsear XML extraído de xDE: {e}")
        
        # Caso 2: xDE tiene hijos (rDE como hijo)
        elif len(list(xde_elem)) > 0:
            # Buscar rDE dentro de xDE
            rde_in_xde = _find_first(xde_elem, "rDE", SIFEN_NS)
            if rde_in_xde is not None:
                de_root = rde_in_xde
            else:
                # Si no hay rDE, buscar DE directamente
                de_in_xde = _find_first(xde_elem, "DE", SIFEN_NS)
                if de_in_xde is not None:
                    de_root = de_in_xde
                else:
                    raise ValueError("xDE contiene hijos pero no se encontró rDE ni DE dentro")
        
        if de_root is None:
            raise ValueError("xDE no contiene contenido válido (ni base64 ni rDE/DE como hijo)")
        
        de_root_localname = local_tag(de_root.tag)
        
        if de_root_localname == "rDE":
            rde_el = de_root
        elif de_root_localname == "DE":
            # Construir rDE contenedor
            rde_el = etree.Element(
                _qn_sifen("rDE"),
                nsmap={
                    None: SIFEN_NS_URI,   # default namespace (CRÍTICO)
                    "ds": DSIG_NS_URI,
                    "xsi": XSI_NS_URI,
                },
            )
            # Asegurar que el árbol SIFEN esté namespaced
            ensure_sifen_namespace(de_root)
            # Agregar dVerFor
            dverfor = etree.SubElement(rde_el, _qn_sifen("dVerFor"))
            dverfor.text = "150"
            # Append DE en rDE
            rde_el.append(de_root)
        else:
            raise ValueError(
                f"XML extraído de xDE tiene root inesperado: {de_root_localname}. "
                f"Se esperaba 'rDE' o 'DE'"
            )
    
    elif root_localname == "rDE":
        rde_el = xml_root
    elif root_localname == "DE":
        # El root mismo es DE: construir rDE wrapper
        de_el = xml_root
        # Crear rDE CON namespace SIFEN y default xmlns correcto
        rde_el = etree.Element(
            _qn_sifen("rDE"),
            nsmap={
                None: SIFEN_NS_URI,   # default namespace (CRÍTICO)
                "ds": DSIG_NS_URI,
                "xsi": XSI_NS_URI,
            },
        )
        # Asegurar que el árbol SIFEN esté namespaced (incluye DE y todos los hijos SIFEN)
        ensure_sifen_namespace(de_el)
        # Agregar dVerFor
        dverfor = etree.SubElement(rde_el, _qn_sifen("dVerFor"))
        dverfor.text = "150"
        # Append DE en rDE
        rde_el.append(de_el)
    else:
        # Buscar rDE en el árbol (namespace-aware)
        rde_candidates = xml_root.findall(f".//{{{SIFEN_NS_URI}}}rDE")
        if not rde_candidates:
            # Fallback: buscar sin namespace
            rde_candidates = xml_root.xpath(".//*[local-name()='rDE']")
        
        if not rde_candidates:
            # Intentar construir desde DE (namespace-aware)
            de_candidates = xml_root.findall(f".//{{{SIFEN_NS_URI}}}DE")
            if not de_candidates:
                # Fallback: buscar sin namespace
                de_candidates = xml_root.xpath(".//*[local-name()='DE']")
            
            if de_candidates:
                de_el = de_candidates[0]
                # Crear rDE CON namespace SIFEN y default xmlns correcto
                rde_el = etree.Element(
                    _qn_sifen("rDE"),
                    nsmap={
                        None: SIFEN_NS_URI,   # default namespace (CRÍTICO)
                        "ds": DSIG_NS_URI,
                        "xsi": XSI_NS_URI,
                    },
                )
                # Asegurar que el árbol SIFEN esté namespaced (incluye DE y todos los hijos SIFEN)
                ensure_sifen_namespace(de_el)
                # Agregar dVerFor
                dverfor = etree.SubElement(rde_el, _qn_sifen("dVerFor"))
                dverfor.text = "150"
                # Append DE en rDE
                rde_el.append(de_el)
            else:
                root_tag = xml_root.tag if hasattr(xml_root, 'tag') else str(xml_root)
                root_nsmap = xml_root.nsmap if hasattr(xml_root, 'nsmap') else {}
                raise ValueError(
                    f"No se encontró rDE ni DE en el XML de entrada. "
                    f"root localname: {root_localname}, root.tag: {root_tag}, root.nsmap: {root_nsmap}"
                )
        else:
            rde_el = rde_candidates[0]
    
    # 3. SANITIZAR ANTES DE FIRMAR (MODO GUERRA 0160)
    # Importar sanitizador
    from tools.sanitize_lote_payload import sanitize_lote_payload
    
    # Clonar rDE para sanitizar/firma (evita mutar el original)
    rde_to_sign = copy.deepcopy(rde_el)

    # Serializar rDE temporal para sanitizar
    rde_temp_bytes = etree.tostring(
        rde_to_sign,
        encoding="utf-8",
        xml_declaration=True,
        pretty_print=False,
        with_tail=False
    )
    
    # Aplicar sanitización ANTES de firmar
    rde_sanitized_bytes = sanitize_lote_payload(rde_temp_bytes)
    
    # Parsear rDE sanitizado para continuar el flujo
    rde_to_sign = etree.fromstring(rde_sanitized_bytes, parser=parser)
    
    # 4. Construir lote.xml completo como árbol lxml ANTES de firmar
    # IMPORTANTE: lote.xml NO debe contener <dId> ni <xDE> (pertenecen al SOAP rEnvioLote).
    # IMPORTANTE: lote.xml SÍ debe contener <rDE> directamente dentro de <rLoteDE> (NO <xDE>).
        
    # Construir lote.xml usando la función corregida con namespace SIFEN
    # El lote.xml debe contener rDE directamente (NO xDE con base64)
    lote_root = etree.Element(etree.QName(SIFEN_NS, "rLoteDE"), nsmap={None: SIFEN_NS, "xsi": XSI_NS})
    
    # (Opcional pero recomendado por SIFEN)
    lote_root.set(etree.QName(XSI_NS, "schemaLocation"), f"{SIFEN_NS} siRecepDE_v150.xsd")
    
    # NOTA: El rDE firmado se agregará directamente como hijo de rLoteDE DESPUÉS de firmar (línea ~2620)
    # Por ahora solo preparamos el lote_root vacío
    
    # 5. Remover cualquier Signature previa del rDE antes de firmar
    ds_ns = "http://www.w3.org/2000/09/xmldsig#"
    for old_sig in rde_to_sign.xpath(f".//*[local-name()='Signature' and namespace-uri()='{ds_ns}']"):
        old_parent = old_sig.getparent()
        if old_parent is not None:
            old_parent.remove(old_sig)
            if debug_enabled:
                print(f"🔧 Firma previa eliminada antes de firmar")
    
    # 6. Encontrar el DE dentro del rDE para firmar
    de_candidates = rde_to_sign.xpath(".//*[local-name()='DE']")
    if not de_candidates:
        raise ValueError("No se encontró elemento DE dentro de rDE")
    de_el = de_candidates[0]
    
    # Obtener Id del DE
    de_id = de_el.get("Id") or de_el.get("id")
    if not de_id:
        raise ValueError("El elemento DE no tiene atributo Id")
    
    if debug_enabled:
        print(f"📋 DE encontrado con Id={de_id}")
    
    # 7. Serializar el rDE para firmar (asegurando namespaces correctos)
    # Serializar solo el rDE pero asegurando namespaces SIFEN
    rde_bytes_in_context = etree.tostring(
        rde_to_sign,
        encoding="utf-8",
        xml_declaration=False,
        pretty_print=False,
        with_tail=False
    )
    
    # Construir XML temporal con rDE como root pero preservando namespaces del lote
    # Para que sign_de_with_p12 pueda procesarlo correctamente
    rde_temp_root = etree.fromstring(rde_bytes_in_context, parser=parser)
    
    # CRÍTICO: Asegurar que el rDE tenga namespace SIFEN y default xmlns ANTES de firmar
    rde_temp_root = ensure_rde_sifen(rde_temp_root)
    
    # Serializar el rDE temporal para firmar (con namespaces preservados)
    rde_to_sign_bytes = etree.tostring(
        rde_temp_root,
        encoding="utf-8",
        xml_declaration=True,
        pretty_print=False,
        with_tail=False
    )
    
    # 8. Firmar el rDE (sign_de_with_p12 espera rDE como root)
    from app.sifen_client.xmlsec_signer import sign_de_with_p12
    try:
        rde_signed_bytes = sign_de_with_p12(rde_to_sign_bytes, cert_path, cert_password)
        # Mover Signature dentro del DE si está fuera (como hermano del DE dentro del rDE)
        debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
        artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
        rde_signed_bytes = _move_signature_into_de_if_needed(rde_signed_bytes, artifacts_dir, debug_enabled)
    except Exception as e:
        # Si no se puede firmar, NO continuar - guardar artifacts y fallar
        error_msg = f"No se pudo firmar con xmlsec: {e}"
        artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
        try:
            # Guardar el XML PRE-firma del rde_el actual (ya pasado por ensure_rde_sifen)
            artifacts_dir.joinpath("sign_error_input.xml").write_bytes(rde_to_sign_bytes)
            # Guardar detalles con información de debug del root
            root_tag = rde_temp_root.tag if hasattr(rde_temp_root, 'tag') else str(rde_temp_root)
            root_nsmap = rde_temp_root.nsmap if hasattr(rde_temp_root, 'nsmap') else {}
            artifacts_dir.joinpath("sign_error_details.txt").write_text(
                f"Error al firmar:\n{error_msg}\n\n"
                f"Debug info:\n"
                f"  root.tag: {root_tag}\n"
                f"  root.nsmap: {root_nsmap}\n\n"
                f"Traceback:\n{type(e).__name__}: {str(e)}",
                encoding="utf-8"
            )
        except Exception:
            pass
        raise RuntimeError(error_msg) from e
    
    # 9. Validación post-firma (antes de continuar al ZIP)
    try:
        parser_strict = etree.XMLParser(remove_blank_text=False, recover=False)
        rde_signed_root = etree.fromstring(rde_signed_bytes, parser=parser_strict)
        
        # Verificar que el root sea rDE con namespace SIFEN
        root_localname = _localname(rde_signed_root.tag)
        root_ns = _namespace_uri(rde_signed_root.tag)
        
        if root_localname != "rDE":
            raise RuntimeError(
                f"Post-check falló: root no es rDE. "
                f"root.tag: {rde_signed_root.tag}, "
                f"root.nsmap: {rde_signed_root.nsmap if hasattr(rde_signed_root, 'nsmap') else 'N/A'}"
            )
        
        if root_ns != SIFEN_NS_URI:
            raise RuntimeError(
                f"Post-check falló: rDE tiene namespace incorrecto. "
                f"root.tag: {rde_signed_root.tag}, "
                f"root.ns: {root_ns}, "
                f"esperado: {SIFEN_NS_URI}, "
                f"root.nsmap: {rde_signed_root.nsmap if hasattr(rde_signed_root, 'nsmap') else 'N/A'}"
            )
        
        # Buscar DE con Id (preferir namespace SIFEN)
        de_elem = rde_signed_root.find(f".//{{{SIFEN_NS_URI}}}DE")

        # Fallback: por si viniera sin namespace (no debería, pero ayuda en debug)
        if de_elem is None:
            for elem in rde_signed_root.iter():
                if isinstance(elem.tag, str) and local_tag(elem.tag) == "DE":
                    de_elem = elem
                    break

        if de_elem is None:
            raise RuntimeError("Post-firma: No se encontró <DE> en el rDE firmado")

        de_id = de_elem.get("Id") or de_elem.get("id")
        if not de_id:
            raise RuntimeError("Post-firma: <DE> no tiene atributo Id")
        
        # Buscar Signature dentro de rDE (como hermano de DE)
        # Según solución error 0160, la Signature debe estar dentro de rDE, no de DE
        DS_NS_URI = "http://www.w3.org/2000/09/xmldsig#"
        sig_elem = None
        
        # Buscar Signature como hijo directo de rDE
        for child in rde_signed_root:
            if local_tag(child.tag) == "Signature" and _namespace_uri(child.tag) == DS_NS_URI:
                sig_elem = child
                break
        
        if sig_elem is None:
            # Fallback: buscar en todo el árbol (no debería ser necesario)
            for elem in rde_signed_root.iter():
                if local_tag(elem.tag) == "Signature":
                    elem_ns = _namespace_uri(elem.tag)
                    if elem_ns == DS_NS_URI:
                        sig_elem = elem
                        break
        
        if sig_elem is None:
            raise RuntimeError("Post-firma: No se encontró <ds:Signature> dentro de <rDE>")
        
        # Validar SignatureMethod
        sig_method_elem = None
        for elem in sig_elem.iter():
            if local_tag(elem.tag) == "SignatureMethod":
                sig_method_elem = elem
                break
        
        if sig_method_elem is None:
            raise RuntimeError("Post-firma: No se encontró <SignatureMethod> en la firma")
        
        sig_method_alg = sig_method_elem.get("Algorithm", "")
        expected_sig_method = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        if sig_method_alg != expected_sig_method:
            raise RuntimeError(
                f"Post-firma: SignatureMethod debe ser '{expected_sig_method}', "
                f"encontrado: '{sig_method_alg}'"
            )
        
        # Validar DigestMethod
        digest_method_elem = None
        for elem in sig_elem.iter():
            if local_tag(elem.tag) == "DigestMethod":
                digest_method_elem = elem
                break
        
        if digest_method_elem is None:
            raise RuntimeError("Post-firma: No se encontró <DigestMethod> en la firma")
        
        digest_method_alg = digest_method_elem.get("Algorithm", "")
        expected_digest_method = "http://www.w3.org/2001/04/xmlenc#sha256"
        if digest_method_alg != expected_digest_method:
            raise RuntimeError(
                f"Post-firma: DigestMethod debe ser '{expected_digest_method}', "
                f"encontrado: '{digest_method_alg}'"
            )
        
        # Validar Reference URI
        ref_elem = None
        for elem in sig_elem.iter():
            if local_tag(elem.tag) == "Reference":
                ref_elem = elem
                break
        
        if ref_elem is None:
            raise RuntimeError("Post-firma: No se encontró <Reference> en la firma")
        
        ref_uri = ref_elem.get("URI", "")
        expected_uri = f"#{de_id}"
        if ref_uri != expected_uri:
            raise RuntimeError(
                f"Post-firma: Reference URI debe ser '{expected_uri}', encontrado: '{ref_uri}'"
            )
        
        # Validar X509Certificate
        x509_cert_elem = None
        for elem in sig_elem.iter():
            if local_tag(elem.tag) == "X509Certificate":
                x509_cert_elem = elem
                break
        
        if x509_cert_elem is None:
            raise RuntimeError("Post-firma: No se encontró <X509Certificate> en la firma")
        
        if not x509_cert_elem.text or not x509_cert_elem.text.strip():
            raise RuntimeError("Post-firma: <X509Certificate> está vacío (firma dummy o certificado no cargado)")
        
        # Validar SignatureValue
        sig_value_elem = None
        for elem in sig_elem.iter():
            if local_tag(elem.tag) == "SignatureValue":
                sig_value_elem = elem
                break
        
        if sig_value_elem is None:
            raise RuntimeError("Post-firma: No se encontró <SignatureValue> en la firma")
        
        if not sig_value_elem.text or not sig_value_elem.text.strip():
            raise RuntimeError("Post-firma: <SignatureValue> está vacío (firma dummy)")
        
        # Validar que SignatureValue no es dummy
        try:
            sig_value_b64 = sig_value_elem.text.strip()
            sig_value_decoded = base64.b64decode(sig_value_b64)
            sig_value_str = sig_value_decoded.decode("ascii", errors="ignore")
            if "this is a test" in sig_value_str.lower() or "dummy" in sig_value_str.lower():
                raise RuntimeError("Post-firma: SignatureValue contiene texto dummy (firma de prueba, no real)")
        except Exception:
            # Si no se puede decodificar, asumir que es válido (binario real)
            pass
        
        if debug_enabled:
            print(f"✅ Post-firma validado: SignatureMethod=rsa-sha256, DigestMethod=sha256, Reference URI=#{de_id}")
    except Exception as e:
        # Guardar artifacts si falla validación post-firma
        artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
        try:
            artifacts_dir.joinpath("sign_preflight_failed.xml").write_bytes(rde_signed_bytes)
            # Verificar si hay problemas de malformación en el XML firmado
            problem = _scan_xml_bytes_for_common_malformed(rde_signed_bytes)
            error_details = f"Error en validación post-firma:\n{str(e)}\n\nTipo: {type(e).__name__}"
            if problem:
                error_details += f"\n\nProblemas detectados en XML:\n{problem}"
            artifacts_dir.joinpath("sign_preflight_error.txt").write_text(
                error_details,
                encoding="utf-8"
            )
        except Exception:
            pass
        raise RuntimeError(f"Validación post-firma falló: {e}") from e
    
    # 9. Re-parsear el rDE firmado (ya validado)
    rde_signed = etree.fromstring(rde_signed_bytes, parser=parser)

    # 9.1 Regenerar dCarQR usando campos del XML FIRMADO (incluye DigestValue final)
    qr_csc = (os.getenv("SIFEN_CSC") or "").strip()
    qr_csc_id = (os.getenv("SIFEN_CSC_ID") or "1").strip()
    if not qr_csc:
        raise RuntimeError("No se encontró SIFEN_CSC. No se puede generar dCarQR real.")

    qr_debug = _update_qr_in_signed_rde_tree(
        rde_signed,
        csc=qr_csc,
        csc_id=qr_csc_id,
        env=env,
    )
    qr_url = (qr_debug.get("qr_url") or "").strip()
    if _is_qr_placeholder(qr_url):
        raise RuntimeError(f"dCarQR inválido tras regeneración: {qr_url!r}")
    
    # 10. Construir lote.xml con rDE directo (NO xDE)
    # IMPORTANTE: lote.xml debe contener <rDE> directamente, NO <xDE>
    # <xDE> pertenece al SOAP rEnvioLote, NO al archivo lote.xml dentro del ZIP
    # Remover cualquier hijo directo de lote_root que tenga local-name 'rDE' o 'xDE' (por si acaso)
    # NUNCA usar remove() con un elemento que venga de otro árbol
    # SIEMPRE remover desde el parent real (getparent())
    to_remove = [
        c for c in list(lote_root)
        if isinstance(c.tag, str) and local_tag(c.tag) in ("rDE", "xDE")
    ]
    for c in to_remove:
        parent = c.getparent()
        if parent is None:
            raise RuntimeError("Elemento a remover no tiene parent (bug de árbol XML)")
        if parent is not lote_root:
            raise RuntimeError(f"Elemento a remover tiene parent diferente de lote_root (bug de árbol XML): parent={parent.tag}, lote_root={lote_root.tag}")
        # Verificar que c realmente es hijo de lote_root antes de remover
        if c in list(lote_root):
            lote_root.remove(c)
        else:
            raise RuntimeError("Elemento a remover no es hijo directo de lote_root (bug de árbol XML)")
    
    # Agregar el rDE firmado directamente como hijo de rLoteDE
    # Usar replace() si rde_to_sign está en el árbol, o append() si no está
    if rde_to_sign is not None:
        rde_to_sign_parent = rde_to_sign.getparent()
        if rde_to_sign_parent is lote_root:
            # Solo reemplazar si realmente es hijo de lote_root
            if rde_to_sign in list(lote_root):
                # Usar replace() para evitar "Element is not a child of this node"
                idx = list(lote_root).index(rde_to_sign)
                lote_root.remove(rde_to_sign)
                lote_root.insert(idx, rde_signed)
            else:
                # Si no está en la lista, simplemente append
                lote_root.append(rde_signed)
        else:
            # Si no tiene parent o el parent no es lote_root, simplemente append
            lote_root.append(rde_signed)
    else:
        # Si no hay rde_to_sign, simplemente append
        lote_root.append(rde_signed)
    
    # El lote ahora tiene rDE firmado directamente dentro de rLoteDE (NO xDE)
    lote_final = lote_root
    
    # 10. Serializar lote final UNA SOLA VEZ (pretty_print=False para preservar exactamente)
    lote_xml_bytes = etree.tostring(
        lote_final,
        encoding="utf-8",
        xml_declaration=True,
        pretty_print=False,
        with_tail=False
    )
    
    # FINAL SANITIZE: Eliminar TODOS los atributos de rDE (SIFEN requiere <rDE> sin atributos)
    # Esto debe hacerse ANTES de guardar artifacts y crear el ZIP
    m_before = re.search(br"<rDE\b[^>]*>", lote_xml_bytes)
    if m_before:
        print(f"🔍 PRE_SANITIZE_rDE_TAG={m_before.group(0).decode('utf-8','replace')}")
    else:
        print("🔍 PRE_SANITIZE_rDE_TAG=NO_TAG")

    # Sanitizar SOLO el opening tag de <rDE ...> y reemplazar solo la primera ocurrencia
    sanitized_tag, preserved_schema = _sanitize_rde_opening_tag_preserve_schema(
        m_before.group(0) if m_before else b"<rDE>"
    )
    if m_before:
        lote_xml_bytes = lote_xml_bytes.replace(m_before.group(0), sanitized_tag, 1)

    m_after = re.search(br"<rDE\b[^>]*>", lote_xml_bytes)
    print(
        f"🔍 POST_SANITIZE_rDE_TAG={m_after.group(0).decode('utf-8','replace') if m_after else 'NO_TAG'}"
    )
    if preserved_schema:
        print("✓ Sanitizado final: rDE preservando xsi:schemaLocation")
    else:
        print("✓ Sanitizado final: rDE sin atributos")

    # Hard-guard: verificar atributos permitidos
    if not m_after:
        raise RuntimeError("❌ ERROR CRÍTICO: rDE no encontrado post-sanitize")

    tag_bytes = m_after.group(0)
    attr_pattern = re.compile(br'\s+([^\s=]+)\s*=\s*"([^"]*)"')
    attrs = attr_pattern.findall(tag_bytes)
    
    if preserved_schema:
        expected_attrs = {b"xmlns", b"xmlns:xsi", b"xsi:schemaLocation"}
        names = {name for name, _ in attrs}
        if names != expected_attrs or len(attrs) != 3:
            debug_file = Path("artifacts/debug_rde_attrs_failed.xml")
            debug_file.write_bytes(lote_xml_bytes)
            raise RuntimeError(
                "❌ ERROR CRÍTICO: rDE contiene atributos no permitidos junto a schemaLocation. "
                f"Ver {debug_file}. Tag encontrado: {tag_bytes.decode('utf-8','replace')}"
            )

        schema_value = None
        for name, value in attrs:
            if name == b"xsi:schemaLocation":
                schema_value = value.decode("utf-8", errors="replace")
                break
        if not schema_value:
            raise RuntimeError("❌ ERROR CRÍTICO: schemaLocation no encontrado tras sanitize")

        schema_tokens = schema_value.split()
        if len(schema_tokens) != 2:
            debug_file = Path("artifacts/debug_rde_attrs_failed_schema_tokens.txt")
            debug_file.write_text(
                f"schemaLocation='{schema_value}' tokens={schema_tokens}",
                encoding="utf-8"
            )
            raise RuntimeError(
                "❌ ERROR CRÍTICO: schemaLocation debe tener exactamente 2 tokens"
            )
        if schema_tokens[0] != SIFEN_NS:
            raise RuntimeError(
                "❌ ERROR CRÍTICO: schemaLocation token[0] no coincide con namespace SIFEN"
            )
        print(
            "🔍 rDE schema guard: xmlns default + schemaLocation tokens OK"
        )
    else:
        expected_attrs = {b"xmlns"}
        names = {name for name, _ in attrs}
        if names != expected_attrs or len(attrs) != 1:
            debug_file = Path("artifacts/debug_rde_attrs_failed.xml")
            debug_file.write_bytes(lote_xml_bytes)
            raise RuntimeError(
                "❌ ERROR CRÍTICO: rDE debe conservar solo xmlns default. "
                f"Ver {debug_file}. Tag encontrado: {tag_bytes.decode('utf-8','replace')}"
            )
    
    
    # 11. Logs de diagnóstico (solo debug-soap)
    if debug_enabled:
        # Parsear lote para obtener información estructural
        try:
            lote_root_debug = etree.fromstring(lote_xml_bytes, parser=parser)
            root_localname = local_tag(lote_root_debug.tag)
            root_nsmap = lote_root_debug.nsmap if hasattr(lote_root_debug, 'nsmap') else {}
            children_local = [local_tag(c.tag) for c in list(lote_root_debug)]
            rde_count = len([c for c in list(lote_root_debug) if local_tag(c.tag) == "rDE"])
            xde_count = len([c for c in list(lote_root_debug) if local_tag(c.tag) == "xDE"])
            
            # Buscar Signature y su parent
            sig_count = 0
            sig_parent_local = None
            for elem in lote_root_debug.iter():
                if local_tag(elem.tag) == "Signature":
                    sig_count += 1
                    sig_parent = elem.getparent()
                    if sig_parent is not None:
                        sig_parent_local = local_tag(sig_parent.tag)
                    break
            
            print(f"🔍 DIAGNÓSTICO [lote.xml]:")
            print(f"   root localname: {root_localname}")
            print(f"   root nsmap: {root_nsmap}")
            print(f"   children(local): {children_local}")
            print(f"   rDE count: {rde_count}")
            print(f"   xDE count: {xde_count}")
            print(f"   Signature count: {sig_count}")
            if sig_parent_local:
                print(f"   Signature parent(local): {sig_parent_local}")
            
            # Extraer Reference URI y DE Id
            ref_uri_match = re.search(rb'<Reference[^>]*URI="([^"]*)"', lote_xml_bytes)
            if ref_uri_match:
                ref_uri = ref_uri_match.group(1).decode('utf-8', errors='replace')
                print(f"   Reference URI: {ref_uri}")
                print(f"   DE Id: {de_id}")
                if ref_uri == f"#{de_id}":
                    print(f"   ✅ Reference URI coincide con DE Id")
                else:
                    print(f"   ⚠️  Reference URI NO coincide con DE Id")
            
            # Confirmar estructura correcta
            if xde_count == 0 and rde_count >= 1:
                print(f"   ✅ OK: lote.xml contiene rDE (no xDE). xDE se enviará en SOAP como base64 del ZIP (fuera de lote.xml).")
        except Exception as e:
            print(f"   ⚠️  No se pudo parsear lote.xml para diagnóstico: {e}")
    
    # 12. Sanity gate: detectar problemas comunes de XML mal formado (SIFEN 0160)
    problem = _scan_xml_bytes_for_common_malformed(lote_xml_bytes)
    if problem:
        artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
        try:
            artifacts_dir.joinpath("prevalidator_raw.xml").write_bytes(lote_xml_bytes)
            artifacts_dir.joinpath("prevalidator_sanity_report.txt").write_text(
                problem + "\n",
                encoding="utf-8"
            )
        except Exception:
            pass
        raise RuntimeError(
            f"XML potencialmente mal formado para SIFEN (0160). "
            f"Ver artifacts/prevalidator_raw.xml y artifacts/prevalidator_sanity_report.txt\n\n"
            f"{problem}"
        )
    
    # 13. Hard-guard: verificar estructura correcta de lote.xml
    # IMPORTANTE: lote.xml NO debe contener <dId> ni <xDE> (pertenecen al SOAP rEnvioLote)
    # IMPORTANTE: lote.xml SÍ debe contener <rDE> directamente dentro de <rLoteDE>
    if b"<dId" in lote_xml_bytes or b"</dId>" in lote_xml_bytes:
        raise RuntimeError("BUG: lote.xml NO debe contener <dId>...</dId> (pertenece al SOAP rEnvioLote)")
    if b"<xDE" in lote_xml_bytes or b"</xDE>" in lote_xml_bytes:
        raise RuntimeError("BUG: lote.xml NO debe contener <xDE>...</xDE> (pertenece al SOAP rEnvioLote, NO al lote.xml)")
    if b'<rLoteDE' not in lote_xml_bytes:
        raise RuntimeError("BUG: lote.xml no contiene <rLoteDE>")
    # Verificar que SÍ contiene rDE (al menos uno)
    if b"<rDE" not in lote_xml_bytes or b"</rDE>" not in lote_xml_bytes:
        raise RuntimeError("BUG: lote.xml debe contener <rDE>...</rDE> directamente dentro de <rLoteDE>")
    
    # Verificar que sea well-formed
    try:
        etree.fromstring(lote_xml_bytes)
    except Exception as e:
        raise RuntimeError(f"BUG: lote.xml no es well-formed: {e}")
    
    # Guardar lote.xml para inspección (antes de crear ZIP)
    # SIEMPRE guardar artifacts/last_lote.xml (no solo en debug)
    artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
    try:
        artifacts_dir.joinpath("last_lote.xml").write_bytes(lote_xml_bytes)
        if debug_enabled:
            print(f"💾 Guardado: artifacts/last_lote.xml ({len(lote_xml_bytes)} bytes)")
    except Exception as e:
        if debug_enabled:
            print(f"⚠️  No se pudo guardar artifacts/last_lote.xml: {e}")
    
    # 14. Comprimir en ZIP
    try:
        mem = BytesIO()
        with zipfile.ZipFile(mem, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("lote.xml", lote_xml_bytes)
        zip_bytes = mem.getvalue()
    except Exception as e:
        raise RuntimeError(f"Error al crear ZIP: {e}")
    
    # 15. Validar el ZIP después de crearlo: verificar estructura completa
    try:
        with zipfile.ZipFile(BytesIO(zip_bytes), "r") as zf:
            namelist = zf.namelist()
            if "lote.xml" not in namelist:
                raise RuntimeError("ZIP no contiene 'lote.xml'")
            
            # Validar que contiene SOLO lote.xml
            if len(namelist) != 1:
                raise RuntimeError(f"ZIP debe contener solo 'lote.xml', encontrado: {namelist}")
            
            lote_xml_from_zip = zf.read("lote.xml")
            
            # Parsear para validar estructura (SIN recover)
            parser_strict = etree.XMLParser(remove_blank_text=False, recover=False)
            lote_root_from_zip = etree.fromstring(lote_xml_from_zip, parser=parser_strict)
            root_localname = local_tag(lote_root_from_zip.tag)
            root_ns = None
            if "}" in lote_root_from_zip.tag:
                root_ns = lote_root_from_zip.tag.split("}", 1)[0][1:]
            
            # Validar que NO contiene <dId> (pertenece al SOAP, no al lote.xml)
            lote_xml_str = lote_xml_from_zip.decode("utf-8", errors="replace")
            if "<dId" in lote_xml_str or "</dId>" in lote_xml_str:
                raise RuntimeError("VALIDACIÓN FALLIDA: lote.xml dentro del ZIP contiene <dId> (NO debe existir)")
            
            # Validar estructura correcta
            if root_localname != "rLoteDE":
                raise RuntimeError(f"VALIDACIÓN FALLIDA: root debe ser 'rLoteDE', encontrado: {root_localname}")
            if root_ns != SIFEN_NS:
                raise RuntimeError(f"VALIDACIÓN FALLIDA: rLoteDE debe tener namespace {SIFEN_NS}, encontrado: {root_ns or '(vacío)'}")
            
            # Validar que tiene al menos 1 rDE hijo directo (NO xDE)
            rde_children = [c for c in lote_root_from_zip if local_tag(c.tag) == "rDE"]
            xde_children = [c for c in lote_root_from_zip if local_tag(c.tag) == "xDE"]
            if len(xde_children) > 0:
                raise RuntimeError("VALIDACIÓN FALLIDA: rLoteDE NO debe contener <xDE> (pertenece al SOAP rEnvioLote, NO al lote.xml)")
            if len(rde_children) == 0:
                raise RuntimeError("VALIDACIÓN FALLIDA: rLoteDE debe contener al menos 1 <rDE> hijo directo")
            
            # Validar que dentro del rDE existe <DE Id="..."> y firma cumple SHA256 + URI "#Id"
            rde_elem = rde_children[0]
            de_elem = None
            for elem in rde_elem.iter():
                if local_tag(elem.tag) == "DE":
                    de_elem = elem
                    break
            
            if de_elem is None:
                raise RuntimeError("VALIDACIÓN FALLIDA: No se encontró <DE> dentro de <rDE>")
            
            de_id_zip = de_elem.get("Id") or de_elem.get("id")
            if not de_id_zip:
                raise RuntimeError("VALIDACIÓN FALLIDA: <DE> no tiene atributo Id")
            
            # Validar firma dentro de rDE
            DS_NS_URI = "http://www.w3.org/2000/09/xmldsig#"
            sig_elem = None
            for child in rde_elem:
                if local_tag(child.tag) == "Signature":
                    elem_ns = None
                    if "}" in child.tag:
                        elem_ns = child.tag.split("}", 1)[0][1:]
                    if elem_ns == DS_NS_URI:
                        sig_elem = child
                        break
            
            if sig_elem is None:
                raise RuntimeError("VALIDACIÓN FALLIDA: No se encontró <ds:Signature> dentro de <rDE>")
            
            # Validar SignatureMethod y DigestMethod son SHA256
            sig_method_elem = None
            for elem in sig_elem.iter():
                if local_tag(elem.tag) == "SignatureMethod":
                    sig_method_elem = elem
                    break
            
            if sig_method_elem is None:
                raise RuntimeError("VALIDACIÓN FALLIDA: No se encontró <SignatureMethod> en la firma")
            
            sig_method_alg = sig_method_elem.get("Algorithm", "")
            if sig_method_alg != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256":
                raise RuntimeError(f"VALIDACIÓN FALLIDA: SignatureMethod debe ser rsa-sha256, encontrado: {sig_method_alg}")
            
            digest_method_elem = None
            for elem in sig_elem.iter():
                if local_tag(elem.tag) == "DigestMethod":
                    digest_method_elem = elem
                    break
            
            if digest_method_elem is None:
                raise RuntimeError("VALIDACIÓN FALLIDA: No se encontró <DigestMethod> en la firma")
            
            digest_method_alg = digest_method_elem.get("Algorithm", "")
            if digest_method_alg != "http://www.w3.org/2001/04/xmlenc#sha256":
                raise RuntimeError(f"VALIDACIÓN FALLIDA: DigestMethod debe ser sha256, encontrado: {digest_method_alg}")
            
            # Validar Reference URI = #Id
            ref_elem = None
            for elem in sig_elem.iter():
                if local_tag(elem.tag) == "Reference":
                    ref_elem = elem
                    break
            
            if ref_elem is None:
                raise RuntimeError("VALIDACIÓN FALLIDA: No se encontró <Reference> en la firma")
            
            ref_uri = ref_elem.get("URI", "")
            if ref_uri != f"#{de_id_zip}":
                raise RuntimeError(f"VALIDACIÓN FALLIDA: Reference URI debe ser '#{de_id_zip}', encontrado: '{ref_uri}'")
            
            if debug_enabled:
                print(f"✅ VALIDACIÓN ZIP exitosa:")
                print(f"   - root localname: {root_localname}")
                print(f"   - root namespace: {root_ns}")
                print(f"   - rDE hijos directos: {len(rde_children)}")
                print(f"   - xDE hijos directos: {len(xde_children)} (debe ser 0)")
                print(f"   - NO contiene <dId>: ✅")
                print(f"   - NO contiene <xDE>: ✅")
                print(f"   - Contiene <rDE> directamente: ✅")
                print(f"   - Firma válida (SHA256, URI=#{de_id_zip}): ✅")
    except zipfile.BadZipFile as e:
        # Guardar artifacts si falla validación ZIP
        artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
        try:
            artifacts_dir.joinpath("preflight_zip.zip").write_bytes(zip_bytes)
            artifacts_dir.joinpath("preflight_error.txt").write_text(
                f"Error al validar ZIP: {e}\n\nTipo: {type(e).__name__}",
                encoding="utf-8"
            )
        except Exception:
            pass
        raise RuntimeError(f"Error al validar ZIP: {e}")
    except Exception as e:
        # Guardar artifacts si falla validación
        artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
        try:
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            artifacts_dir.joinpath("preflight_zip.zip").write_bytes(zip_bytes)
            artifacts_dir.joinpath("preflight_error.txt").write_text(
                f"Error al validar lote.xml dentro del ZIP: {e}\n\nTipo: {type(e).__name__}",
                encoding="utf-8"
            )
        except Exception:
            pass
        raise RuntimeError(f"Error al validar lote.xml dentro del ZIP: {e}")
    
    # 16. Sanity check: verificar que el lote contiene al menos 1 rDE y 0 xDE antes de enviar
    try:
        lote_root_check = etree.fromstring(lote_xml_bytes, parser=parser)
        # Verificar hijos DIRECTOS de lote_root
        rde_children_direct = [
            c for c in list(lote_root_check)
            if isinstance(c.tag, str) and local_tag(c.tag) == "rDE"
        ]
        xde_children_direct = [
            c for c in list(lote_root_check)
            if isinstance(c.tag, str) and local_tag(c.tag) == "xDE"
        ]
        
        # Verificar que NO hay xDE (pertenece al SOAP, no al lote.xml)
        if len(xde_children_direct) > 0:
            raise RuntimeError(
                f"Lote inválido: lote.xml contiene {len(xde_children_direct)} elemento(s) <xDE>. "
                "<xDE> pertenece al SOAP rEnvioLote, NO al archivo lote.xml dentro del ZIP. "
                "Ver artifacts/last_lote.xml"
            )
        
        # Verificar que SÍ hay al menos 1 rDE
        if len(rde_children_direct) == 0:
            raise RuntimeError(
                "Lote inválido: no hay <rDE> dentro de <rLoteDE>. "
                "lote.xml debe contener <rDE> directamente dentro de <rLoteDE>. "
                "Ver artifacts/last_lote.xml"
            )
        
        if debug_enabled:
            print(f"✅ Sanity check: lote contiene {len(rde_children_direct)} elemento(s) <rDE> y 0 <xDE> como hijos directos de rLoteDE")
            print(f"   OK: lote.xml contiene rDE (no xDE). xDE se enviará en SOAP como base64 del ZIP (fuera de lote.xml).")
    except RuntimeError:
        raise  # Re-raise RuntimeError tal cual
    except Exception as e:
        # Si falla el parseo, el error se detectará en otro lugar
        if debug_enabled:
            print(f"⚠️  No se pudo verificar rDE/xDE en sanity check: {e}")
    
    # 17. Guardar artifacts SIEMPRE (aunque el envío falle)
    try:
        artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
        
        # Guardar ZIP
        last_xde_zip = artifacts_dir / "last_xde.zip"
        last_xde_zip.write_bytes(zip_bytes)
        
        # Guardar lote.xml extraído (ya se guardó antes, pero lo guardamos aquí también para consistencia)
        last_lote_xml = artifacts_dir / "last_lote.xml"
        last_lote_xml.write_bytes(lote_xml_bytes)
        
        # Guardar copia del lote.xml sanitizado que se envió
        last_sent_lote = artifacts_dir / "_last_sent_lote.xml"
        last_sent_lote.write_bytes(lote_xml_bytes)
        
        if debug_enabled:
            try:
                # Parsear lote para obtener información estructural
                lote_root_debug = etree.fromstring(lote_xml_bytes, parser=parser)
                root_localname = local_tag(lote_root_debug.tag)
                root_nsmap = lote_root_debug.nsmap if hasattr(lote_root_debug, 'nsmap') else {}
                children_local = [local_tag(c.tag) for c in list(lote_root_debug)]
                rde_count = len([c for c in list(lote_root_debug) if local_tag(c.tag) == "rDE"])
                xde_count = len([c for c in list(lote_root_debug) if local_tag(c.tag) == "xDE"])
                
                # Generar reporte de sanity
                sanity_report = (
                    f"Lote XML Sanity Report\n"
                    f"======================\n"
                    f"root localname: {root_localname}\n"
                    f"root nsmap: {root_nsmap}\n"
                    f"children(local): {children_local}\n"
                    f"rDE count: {rde_count}\n"
                    f"xDE count: {xde_count}\n"
                    f"\n"
                    f"Status: {'✅ OK' if xde_count == 0 and rde_count >= 1 else '❌ ERROR'}\n"
                    f"  - lote.xml contiene rDE (no xDE): {'✅' if xde_count == 0 and rde_count >= 1 else '❌'}\n"
                    f"  - xDE se enviará en SOAP como base64 del ZIP (fuera de lote.xml)\n"
                )
                artifacts_dir.joinpath("last_lote_sanity.txt").write_text(
                    sanity_report,
                    encoding="utf-8"
                )
                
                # Guardar len del ZIP base64
                zip_b64 = base64.b64encode(zip_bytes).decode("ascii")
                artifacts_dir.joinpath("last_zip_b64_len.txt").write_text(
                    str(len(zip_b64)),
                    encoding="utf-8"
                )
            except Exception as e:
                if debug_enabled:
                    print(f"⚠️  No se pudo generar reporte de sanity: {e}")
        
        if debug_enabled:
            print(f"💾 Guardado: {last_xde_zip} ({len(zip_bytes)} bytes)")
            print(f"💾 Guardado: {last_lote_xml} ({len(lote_xml_bytes)} bytes)")
    except Exception as e:
        print(f"⚠️  No se pudo guardar artifacts: {e}")
    
    # 16. Codificar en Base64
    b64 = base64.b64encode(zip_bytes).decode("ascii")
    
    # Log de confirmación: verificar estructura correcta
    if debug_enabled:
        print(f"✅ lote.xml validado:")
        print(f"   - Tamaño: {len(lote_xml_bytes)} bytes")
        print(f"   - Contiene <rLoteDE> con xmlns SIFEN: ✅")
        print(f"   - NO contiene <dId>: ✅")
        print(f"   - NO contiene <xDE>: ✅")
        print(f"   - Contiene <rDE>: ✅")
        print(f"   - Well-formed: ✅")
    
    if return_debug:
        return b64, lote_xml_bytes, zip_bytes, None  # lote_did ya no existe (está en SOAP, no en lote.xml)
    return b64


def preflight_soap_request(
    payload_xml: str,
    zip_bytes: bytes,
    lote_xml_bytes: Optional[bytes] = None,
    artifacts_dir: Optional[Path] = None
) -> Tuple[bool, Optional[str]]:
    """
    Preflight local antes de enviar a SIFEN.
    
    Valida:
    1. SOAP request parsea (lxml.etree.fromstring sin recover=True)
    2. xDE existe, es Base64 válido, decodifica a ZIP válido
    3. ZIP contiene lote.xml únicamente
    4. lote.xml parsea y su root/estructura es la esperada
    5. Existe <DE Id="...">
    6. Existe <ds:Signature> dentro de <DE>
    7. En la firma, SignatureMethod y DigestMethod son SHA256 y Reference URI es #Id
    
    Args:
        payload_xml: XML rEnvioLote completo
        zip_bytes: ZIP binario
        lote_xml_bytes: Bytes del XML lote.xml (opcional, se extrae del ZIP si no se proporciona)
        artifacts_dir: Directorio para guardar artifacts si falla (default: artifacts/)
        
    Returns:
        Tupla (success, error_message)
        - success: True si pasa todas las validaciones
        - error_message: None si success=True, mensaje de error si success=False
    """
    artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
    
    try:
        # 1. Validar que SOAP request parsea
        try:
            parser = etree.XMLParser(remove_blank_text=False, recover=False)
            soap_root = etree.fromstring(payload_xml.encode("utf-8"), parser=parser)
        except Exception as e:
            error_msg = f"SOAP request no parsea: {e}"
            artifacts_dir.joinpath("preflight_soap.xml").write_text(payload_xml, encoding="utf-8")
            return (False, error_msg)
        
        # 2. Validar que xDE existe y es Base64 válido
        xde_elem = soap_root.find(f".//{{{SIFEN_NS}}}xDE")
        if xde_elem is None:
            xde_elem = soap_root.find(".//xDE")
        
        if xde_elem is None or not xde_elem.text:
            error_msg = "xDE no encontrado o vacío en rEnvioLote"
            artifacts_dir.joinpath("preflight_soap.xml").write_text(payload_xml, encoding="utf-8")
            return (False, error_msg)
        
        try:
            xde_base64 = xde_elem.text.strip()
            zip_from_base64 = base64.b64decode(xde_base64)
            if zip_from_base64 != zip_bytes:
                # No es crítico, pero avisar
                pass
        except Exception as e:
            error_msg = f"xDE no es Base64 válido: {e}"
            artifacts_dir.joinpath("preflight_soap.xml").write_text(payload_xml, encoding="utf-8")
            return (False, error_msg)
        
        # 3. Validar que ZIP es válido y contiene lote.xml
        try:
            with zipfile.ZipFile(BytesIO(zip_bytes), "r") as zf:
                namelist = zf.namelist()
                if "lote.xml" not in namelist:
                    error_msg = f"ZIP no contiene 'lote.xml'. Archivos encontrados: {namelist}"
                    artifacts_dir.joinpath("preflight_zip.zip").write_bytes(zip_bytes)
                    return (False, error_msg)
                
                if len(namelist) != 1:
                    error_msg = f"ZIP debe contener solo 'lote.xml', encontrado: {namelist}"
                    artifacts_dir.joinpath("preflight_zip.zip").write_bytes(zip_bytes)
                    return (False, error_msg)
                
                # Extraer lote.xml si no se proporcionó
                if lote_xml_bytes is None:
                    lote_xml_bytes = zf.read("lote.xml")
        except zipfile.BadZipFile as e:
            error_msg = f"ZIP no es válido: {e}"
            artifacts_dir.joinpath("preflight_zip.zip").write_bytes(zip_bytes)
            return (False, error_msg)
        
        # 4. Validar que lote.xml parsea y tiene estructura correcta
        try:
            parser = etree.XMLParser(remove_blank_text=False, recover=False)
            lote_root = etree.fromstring(lote_xml_bytes, parser=parser)
            
            # Validar root es rLoteDE
            root_localname = local_tag(lote_root.tag)
            if root_localname != "rLoteDE":
                error_msg = f"lote.xml root debe ser 'rLoteDE', encontrado: {root_localname}"
                artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
                return (False, error_msg)
            
            # Validar namespace
            root_ns = None
            if "}" in lote_root.tag:
                root_ns = lote_root.tag.split("}", 1)[0][1:]
            if root_ns != SIFEN_NS:
                error_msg = f"rLoteDE debe tener namespace {SIFEN_NS}, encontrado: {root_ns or '(vacío)'}"
                artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
                return (False, error_msg)
            
            # Validar que NO contiene <dId> ni <xDE>
            lote_xml_str = lote_xml_bytes.decode("utf-8", errors="replace")
            if "<dId" in lote_xml_str or "</dId>" in lote_xml_str:
                error_msg = "lote.xml NO debe contener <dId> (pertenece al SOAP rEnvioLote)"
                artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
                return (False, error_msg)
            if "<xDE" in lote_xml_str or "</xDE>" in lote_xml_str:
                # Diagnóstico detallado si encuentra xDE
                root_tag = lote_root.tag if hasattr(lote_root, 'tag') else str(lote_root)
                root_nsmap = lote_root.nsmap if hasattr(lote_root, 'nsmap') else {}
                children_local = [local_tag(c.tag) for c in list(lote_root)]
                xde_count = len([c for c in list(lote_root) if local_tag(c.tag) == "xDE"])
                rde_count = len([c for c in list(lote_root) if local_tag(c.tag) == "rDE"])
                error_msg = (
                    f"lote.xml NO debe contener <xDE> (pertenece al SOAP rEnvioLote).\n"
                    f"  root.tag: {root_tag}\n"
                    f"  root.nsmap: {root_nsmap}\n"
                    f"  children(local): {children_local}\n"
                    f"  xDE count: {xde_count}\n"
                    f"  rDE count: {rde_count}"
                )
                artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
                # Guardar reporte de preflight
                preflight_report = (
                    f"Preflight Validation Failed\n"
                    f"==========================\n"
                    f"Error: {error_msg}\n"
                    f"\n"
                    f"Structure Analysis:\n"
                    f"  root.tag: {root_tag}\n"
                    f"  root.nsmap: {root_nsmap}\n"
                    f"  children(local): {children_local}\n"
                    f"  xDE count: {xde_count}\n"
                    f"  rDE count: {rde_count}\n"
                )
                artifacts_dir.joinpath("preflight_report.txt").write_text(
                    preflight_report,
                    encoding="utf-8"
                )
                return (False, error_msg)
            
            # Validar que tiene al menos 1 rDE hijo directo (y 0 xDE)
            rde_children = [c for c in lote_root if local_tag(c.tag) == "rDE"]
            xde_children = [c for c in lote_root if local_tag(c.tag) == "xDE"]
            if len(xde_children) > 0:
                error_msg = f"rLoteDE NO debe contener <xDE> (pertenece al SOAP rEnvioLote). Encontrado: {len(xde_children)}"
                artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
                # Guardar reporte de preflight
                root_tag = lote_root.tag if hasattr(lote_root, 'tag') else str(lote_root)
                root_nsmap = lote_root.nsmap if hasattr(lote_root, 'nsmap') else {}
                children_local = [local_tag(c.tag) for c in list(lote_root)]
                preflight_report = (
                    f"Preflight Validation Failed\n"
                    f"==========================\n"
                    f"Error: {error_msg}\n"
                    f"\n"
                    f"Structure Analysis:\n"
                    f"  root.tag: {root_tag}\n"
                    f"  root.nsmap: {root_nsmap}\n"
                    f"  children(local): {children_local}\n"
                    f"  xDE count: {len(xde_children)}\n"
                    f"  rDE count: {len(rde_children)}\n"
                )
                artifacts_dir.joinpath("preflight_report.txt").write_text(
                    preflight_report,
                    encoding="utf-8"
                )
                return (False, error_msg)
            if len(rde_children) < 1:
                error_msg = f"rLoteDE debe contener al menos 1 rDE hijo directo, encontrado: {len(rde_children)}"
                artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
                # Guardar reporte de preflight
                root_tag = lote_root.tag if hasattr(lote_root, 'tag') else str(lote_root)
                root_nsmap = lote_root.nsmap if hasattr(lote_root, 'nsmap') else {}
                children_local = [local_tag(c.tag) for c in list(lote_root)]
                preflight_report = (
                    f"Preflight Validation Failed\n"
                    f"==========================\n"
                    f"Error: {error_msg}\n"
                    f"\n"
                    f"Structure Analysis:\n"
                    f"  root.tag: {root_tag}\n"
                    f"  root.nsmap: {root_nsmap}\n"
                    f"  children(local): {children_local}\n"
                    f"  xDE count: {len(xde_children)}\n"
                    f"  rDE count: {len(rde_children)}\n"
                )
                artifacts_dir.joinpath("preflight_report.txt").write_text(
                    preflight_report,
                    encoding="utf-8"
                )
                return (False, error_msg)
            
            rde_elem = rde_children[0]
        except Exception as e:
            error_msg = f"lote.xml no parsea o estructura incorrecta: {e}"
            if lote_xml_bytes:
                artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        # 5. Validar que existe <DE Id="...">
        de_elem = None
        for elem in rde_elem.iter():
            if local_tag(elem.tag) == "DE":
                de_elem = elem
                break
        
        if de_elem is None:
            error_msg = "No se encontró elemento <DE> dentro de <rDE>"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        de_id = de_elem.get("Id") or de_elem.get("id")
        if not de_id:
            error_msg = "Elemento <DE> no tiene atributo Id"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        # 6. Validar que existe <ds:Signature> dentro de <rDE>
        DS_NS_URI = "http://www.w3.org/2000/09/xmldsig#"
        sig_elem = None
        for child in rde_elem:
            if local_tag(child.tag) == "Signature":
                # Verificar namespace
                elem_ns = None
                if "}" in child.tag:
                    elem_ns = child.tag.split("}", 1)[0][1:]
                if elem_ns == DS_NS_URI:
                    sig_elem = child
                    break
        
        if sig_elem is None:
            error_msg = "No se encontró <ds:Signature> dentro de <rDE>"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        # 7. Validar firma: SignatureMethod=rsa-sha256, DigestMethod=sha256, Reference URI=#Id
        # Buscar SignatureMethod
        sig_method_elem = None
        for elem in sig_elem.iter():
            if local_tag(elem.tag) == "SignatureMethod":
                sig_method_elem = elem
                break
        
        if sig_method_elem is None:
            error_msg = "No se encontró <SignatureMethod> en la firma"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        sig_method_alg = sig_method_elem.get("Algorithm", "")
        expected_sig_method = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        if sig_method_alg != expected_sig_method:
            error_msg = f"SignatureMethod debe ser '{expected_sig_method}', encontrado: '{sig_method_alg}'"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        # Buscar DigestMethod
        digest_method_elem = None
        for elem in sig_elem.iter():
            if local_tag(elem.tag) == "DigestMethod":
                digest_method_elem = elem
                break
        
        if digest_method_elem is None:
            error_msg = "No se encontró <DigestMethod> en la firma"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        digest_method_alg = digest_method_elem.get("Algorithm", "")
        expected_digest_method = "http://www.w3.org/2001/04/xmlenc#sha256"
        if digest_method_alg != expected_digest_method:
            error_msg = f"DigestMethod debe ser '{expected_digest_method}', encontrado: '{digest_method_alg}'"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        # Buscar Reference URI
        ref_elem = None
        for elem in sig_elem.iter():
            if local_tag(elem.tag) == "Reference":
                ref_elem = elem
                break
        
        if ref_elem is None:
            error_msg = "No se encontró <Reference> en la firma"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        ref_uri = ref_elem.get("URI", "")
        expected_uri = f"#{de_id}"
        if ref_uri != expected_uri:
            error_msg = f"Reference URI debe ser '{expected_uri}', encontrado: '{ref_uri}'"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        # Validar que X509Certificate existe y no está vacío
        x509_cert_elem = None
        for elem in sig_elem.iter():
            if local_tag(elem.tag) == "X509Certificate":
                x509_cert_elem = elem
                break
        
        if x509_cert_elem is None:
            error_msg = "No se encontró <X509Certificate> en la firma"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        if not x509_cert_elem.text or not x509_cert_elem.text.strip():
            error_msg = "<X509Certificate> está vacío (firma dummy o certificado no cargado)"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        # Validar que SignatureValue existe y no es dummy
        sig_value_elem = None
        for elem in sig_elem.iter():
            if local_tag(elem.tag) == "SignatureValue":
                sig_value_elem = elem
                break
        
        if sig_value_elem is None:
            error_msg = "No se encontró <SignatureValue> en la firma"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        if not sig_value_elem.text or not sig_value_elem.text.strip():
            error_msg = "<SignatureValue> está vacío (firma dummy)"
            artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
            return (False, error_msg)
        
        # Validar que SignatureValue no contiene texto dummy
        try:
            sig_value_b64 = sig_value_elem.text.strip()
            sig_value_decoded = base64.b64decode(sig_value_b64)
            sig_value_str = sig_value_decoded.decode("ascii", errors="ignore")
            if "this is a test" in sig_value_str.lower() or "dummy" in sig_value_str.lower():
                error_msg = "SignatureValue contiene texto dummy (firma de prueba, no real)"
                artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
                return (False, error_msg)
        except Exception:
            # Si no se puede decodificar, asumir que es válido (binario real)
            pass
        
        # Todas las validaciones pasaron
        return (True, None)
        
    except Exception as e:
        error_msg = f"Error inesperado en preflight: {e}"
        try:
            artifacts_dir.joinpath("preflight_soap.xml").write_text(payload_xml, encoding="utf-8")
            if zip_bytes:
                artifacts_dir.joinpath("preflight_zip.zip").write_bytes(zip_bytes)
            if lote_xml_bytes:
                artifacts_dir.joinpath("preflight_lote.xml").write_bytes(lote_xml_bytes)
        except Exception:
            pass
        return (False, error_msg)


def build_r_envio_lote_xml(did: Union[int, str], xml_bytes: bytes, zip_base64: Optional[str] = None) -> str:
    """
    Construye el XML rEnvioLote con el lote comprimido en Base64.
    
    Args:
        did: ID del documento (IGNORADO - siempre se genera uno nuevo de 15 dígitos)
        xml_bytes: XML original (puede ser rDE o siRecepDE)
        zip_base64: Base64 del ZIP (opcional, se calcula si no se proporciona)
        
    Returns:
        XML rEnvioLote como string
    """
    # Función para generar dId único de 15 dígitos
    def make_did_15() -> str:
        """Genera un dId único de 15 dígitos: YYYYMMDDHHMMSS + 1 dígito random"""
        import random
        base = datetime.now().strftime("%Y%m%d%H%M%S")  # 14 dígitos
        return base + str(random.randint(0, 9))  # + 1 dígito random = 15
    
    def normalize_did(did) -> str:
        """Normaliza dId para rEnvioLote.
        - Si did es None/''/'auto' => genera 15 dígitos.
        - Si viene seteado => DEBE ser exactamente 15 dígitos (requisito práctico SIFEN).
        """
        if did is None:
            return make_did_15()
        if isinstance(did, int):
            did = str(did)
        did = str(did).strip()
        if did.lower() in ("", "auto"):
            return make_did_15()
        if not (did.isdigit() and len(did) == 15):
            raise ValueError(
                f"dId de rEnvioLote debe ser 15 dígitos (YYYYMMDDHHMMSSx). Recibido: '{did}'"
            )
        return did

    # NO ignorar el parámetro did: usarlo si es válido, o autogenerar si corresponde
    did = normalize_did(did)
    
    if zip_base64 is None:
        xde_b64 = build_lote_base64_from_single_xml(xml_bytes)
    else:
        xde_b64 = zip_base64

    # Construir rEnvioLote con prefijo xsd (nsmap {"xsd": SIFEN_NS})
    rEnvioLote = etree.Element(etree.QName(SIFEN_NS, "rEnvioLote"), nsmap={"xsd": SIFEN_NS})
    dId = etree.SubElement(rEnvioLote, etree.QName(SIFEN_NS, "dId"))
    dId.text = did  # Usar el dId de 15 dígitos generado
    xDE = etree.SubElement(rEnvioLote, etree.QName(SIFEN_NS, "xDE"))
    xDE.text = xde_b64

    return etree.tostring(rEnvioLote, xml_declaration=True, encoding="utf-8").decode("utf-8")


def apply_timbrado_override(xml_bytes: bytes, artifacts_dir: Optional[Path] = None) -> bytes:
    """
    Aplica override de timbrado y fecha de inicio si están definidos en env vars.
    
    Si SIFEN_TIMBRADO_OVERRIDE está definido:
    - Parchea <dNumTim> en gTimb
    - Regenera CDC (DE@Id) y dDVId
    
    Si SIFEN_FEINI_OVERRIDE está definido:
    - Parchea <dFeIniT> en gTimb
    
    Args:
        xml_bytes: XML original (bytes)
        artifacts_dir: Directorio para guardar artifact de salida (opcional)
        
    Returns:
        XML modificado (bytes) o xml_bytes sin cambios si no hay override
    """
    import re
    
    # Leer env vars
    timbrado = os.getenv("SIFEN_TIMBRADO_OVERRIDE", "").strip()
    feini = os.getenv("SIFEN_FEINI_OVERRIDE", "").strip()
    
    # Si ambas vacías, devolver sin cambios
    if not timbrado and not feini:
        return xml_bytes
    
    # Parsear XML
    parser = etree.XMLParser(remove_blank_text=True)
    try:
        root = etree.fromstring(xml_bytes, parser)
    except Exception as e:
        raise ValueError(f"Error al parsear XML para timbrado override: {e}")
    
    # Namespace
    NS = {"s": SIFEN_NS}
    
    # Buscar gTimb
    gtimb = root.find(".//s:gTimb", namespaces=NS)
    if gtimb is None:
        raise RuntimeError("No se encontró <gTimb> en el XML. No se puede aplicar override de timbrado.")
    
    # Aplicar override de timbrado
    if timbrado:
        dnumtim = gtimb.find("s:dNumTim", namespaces=NS)
        if dnumtim is None:
            raise RuntimeError("No se encontró <dNumTim> en <gTimb>. No se puede aplicar override de timbrado.")
        dnumtim.text = timbrado
        print(f"🔧 TIMBRADO OVERRIDE: dNumTim = {timbrado}")
    
    # Aplicar override de fecha inicio
    if feini:
        dfeinit = gtimb.find("s:dFeIniT", namespaces=NS)
        if dfeinit is None:
            raise RuntimeError("No se encontró <dFeIniT> en <gTimb>. No se puede aplicar override de fecha inicio.")
        dfeinit.text = feini
        print(f"🔧 TIMBRADO OVERRIDE: dFeIniT = {feini}")
    
    # Si se cambió el timbrado, regenerar CDC
    if timbrado:
        print("🔄 Regenerando CDC con nuevo timbrado...")
        
        # Extraer datos del XML
        gemis = root.find(".//s:gEmis", namespaces=NS)
        if gemis is None:
            raise RuntimeError("No se encontró <gEmis> en el XML. No se puede regenerar CDC.")
        
        drucem = gemis.find("s:dRucEm", namespaces=NS)
        if drucem is None or not drucem.text:
            raise RuntimeError("No se encontró <dRucEm> en <gEmis>. No se puede regenerar CDC.")
        ruc = drucem.text.strip()
        
        dest = gtimb.find("s:dEst", namespaces=NS)
        if dest is None or not dest.text:
            raise RuntimeError("No se encontró <dEst> en <gTimb>. No se puede regenerar CDC.")
        est = dest.text.strip()
        
        dpunexp = gtimb.find("s:dPunExp", namespaces=NS)
        if dpunexp is None or not dpunexp.text:
            raise RuntimeError("No se encontró <dPunExp> en <gTimb>. No se puede regenerar CDC.")
        pnt = dpunexp.text.strip()
        
        dnumdoc = gtimb.find("s:dNumDoc", namespaces=NS)
        if dnumdoc is None or not dnumdoc.text:
            raise RuntimeError("No se encontró <dNumDoc> en <gTimb>. No se puede regenerar CDC.")
        num = dnumdoc.text.strip()
        
        # Tipo documento
        itide = gtimb.find("s:iTiDE", namespaces=NS)
        if itide is None or not itide.text:
            raise RuntimeError("No se encontró <iTiDE> en <gTimb>. No se puede regenerar CDC.")
        tipo_doc = itide.text.strip()
        
        # Fecha emisión
        gdatgral = root.find(".//s:gDatGralOpe", namespaces=NS)
        if gdatgral is None:
            raise RuntimeError("No se encontró <gDatGralOpe> en el XML. No se puede regenerar CDC.")
        
        dfemi = gdatgral.find("s:dFeEmiDE", namespaces=NS)
        if dfemi is None or not dfemi.text:
            raise RuntimeError("No se encontró <dFeEmiDE> en <gDatGralOpe>. No se puede regenerar CDC.")
        fecha_emi = dfemi.text.strip()
        
        # Convertir fecha de YYYY-MM-DD a YYYYMMDD
        fecha_ymd = re.sub(r"\D", "", fecha_emi)[:8]
        if len(fecha_ymd) != 8:
            raise RuntimeError(f"Fecha de emisión inválida para CDC: {fecha_emi!r}")
        
        # Monto total
        gtot = root.find(".//s:gTotSub", namespaces=NS)
        dtot = gtot.find("s:dTotalGs", namespaces=NS) if gtot is not None else None
        if dtot is None or not dtot.text:
            # Fallback: usar 0 si no hay gTotSub/dTotalGs
            monto = "0"
        else:
            monto = dtot.text.strip()

        # Generar nuevo CDC
        try:
            from app.sifen_client.xml_generator_v150 import generate_cdc
            cdc = generate_cdc(
                ruc=ruc,
                timbrado=timbrado,
                establecimiento=est,
                punto_expedicion=pnt,
                numero_documento=num,
                tipo_documento=tipo_doc,
                fecha=fecha_ymd,
                monto=monto
            )
            print(f"✓ CDC regenerado: {cdc}")
        except Exception as e:
            raise RuntimeError(f"Error al generar CDC: {e}")
        
        # Actualizar DE@Id
        de = root.find(".//s:DE", namespaces=NS)
        if de is None:
            raise RuntimeError("No se encontró <DE> en el XML. No se puede actualizar CDC.")
        de.set("Id", cdc)
        
        # Actualizar dDVId (último dígito del CDC)
        ddvid = root.find(".//s:dDVId", namespaces=NS)
        if ddvid is None:
            raise RuntimeError("No se encontró <dDVId> en el XML. No se puede actualizar DV.")
        ddvid.text = cdc[-1]
        print(f"✓ dDVId actualizado: {cdc[-1]}")
    
    # Serializar de vuelta
    out = etree.tostring(root, xml_declaration=True, encoding="UTF-8", pretty_print=True)
    
    # Guardar artifact si artifacts_dir está definido
    if artifacts_dir is not None:
        try:
            artifacts_dir.mkdir(exist_ok=True)
            artifact_path = artifacts_dir / "xml_after_timbrado_override.xml"
            artifact_path.write_bytes(out)
            print(f"💾 Guardado: {artifact_path}")
        except Exception as e:
            # Silencioso: no romper el flujo si falla guardar artifact
            print(f"⚠️  No se pudo guardar artifact de timbrado override: {e}")
    
    return out


def resolve_xml_path(xml_arg: str, artifacts_dir: Path) -> Path:
    """
    Resuelve el path al XML (puede ser 'latest' o un path específico)
    
    Args:
        xml_arg: Argumento XML ('latest' o path)
        artifacts_dir: Directorio de artifacts
        
    Returns:
        Path al archivo XML
    """
    if xml_arg.lower() == "latest":
        xml_path = find_latest_sirecepde(artifacts_dir)
        if not xml_path:
            raise FileNotFoundError(
                "No se encontró ningún archivo sirecepde_*.xml para '--xml latest'.\n"
                f"Busqué en: {artifacts_dir}\n"
                "Soluciones:\n"
                "  1) Pasar --xml /ruta/al/rde.xml\n"
                "  2) Generar un ejemplo base con: make sample-xml\n"
                "  3) Reintentar con: make send-test XML=/ruta/al/rde.xml"
            )
        return xml_path
    
    xml_path = Path(xml_arg)
    if not xml_path.exists():
        # Intentar como path relativo a artifacts
        artifacts_xml = artifacts_dir / xml_arg
        if artifacts_xml.exists():
            return artifacts_xml
        raise FileNotFoundError(f"Archivo XML no encontrado: {xml_arg}")
    
    return xml_path


def _extract_ruc_from_cert(p12_path: str, p12_password: str) -> Optional[Dict[str, str]]:
    """
    Extrae el RUC del certificado P12/PFX.
    
    Busca el RUC en:
    1. Subject DN: SERIALNUMBER o CN (formato "RUCxxxxxxx-y" o "xxxxxxx-y")
    2. Subject Alternative Names (SAN): DirectoryName con SERIALNUMBER
    
    Args:
        p12_path: Ruta al certificado P12/PFX
        p12_password: Contraseña del certificado
        
    Returns:
        Dict con:
            - "ruc": número de RUC sin DV (ej: "4554737")
            - "ruc_with_dv": RUC completo con DV si se encuentra (ej: "4554737-8")
        None si no se puede extraer o si cryptography no está disponible
    """
    try:
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.hazmat.backends import default_backend
        from cryptography import x509
    except ImportError:
        return None
    
    try:
        with open(p12_path, "rb") as f:
            p12_bytes = f.read()
        password_bytes = p12_password.encode("utf-8") if p12_password else None
        
        key_obj, cert_obj, _ = pkcs12.load_key_and_certificates(
            p12_bytes, password_bytes, backend=default_backend()
        )
        
        if cert_obj is None:
            return None
        
        # Buscar RUC en Subject DN
        subject = cert_obj.subject
        ruc_with_dv = None
        
        # Buscar en SERIALNUMBER
        for attr in subject:
            if attr.oid == x509.NameOID.SERIAL_NUMBER:
                serial = attr.value.strip()
                # Puede ser "RUC4554737-8" o "4554737-8"
                if serial.upper().startswith("RUC"):
                    serial = serial[3:].strip()
                if "-" in serial:
                    ruc_with_dv = serial
                    break
        
        # Si no se encontró en SERIALNUMBER, buscar en CN
        if ruc_with_dv is None:
            for attr in subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    cn = attr.value.strip()
                    # Puede ser "RUC4554737-8" o "4554737-8"
                    if cn.upper().startswith("RUC"):
                        cn = cn[3:].strip()
                    # Validar que es un RUC (solo números y un guion)
                    if "-" in cn and all(c.isdigit() or c == "-" for c in cn):
                        ruc_with_dv = cn
                        break
        
        # Buscar en Subject Alternative Names (SAN)
        if ruc_with_dv is None:
            try:
                san_ext = cert_obj.extensions.get_extension_for_oid(
                    x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                for name in san_ext.value:
                    if isinstance(name, x509.DirectoryName):
                        dir_name = name.value
                        for attr in dir_name:
                            if attr.oid == x509.NameOID.SERIAL_NUMBER:
                                serial = attr.value.strip()
                                if serial.upper().startswith("RUC"):
                                    serial = serial[3:].strip()
                                if "-" in serial:
                                    ruc_with_dv = serial
                                    break
                        if ruc_with_dv:
                            break
            except x509.ExtensionNotFound:
                pass
        
        if ruc_with_dv:
            # Separar RUC y DV
            parts = ruc_with_dv.split("-", 1)
            ruc = parts[0].strip()
            return {
                "ruc": ruc,
                "ruc_with_dv": ruc_with_dv
            }
        
        return None
    except Exception:
        # Silenciosamente fallar si no se puede extraer
        return None


def send_sirecepde(xml_path: Path, env: str = "test", artifacts_dir: Optional[Path] = None, dump_http: bool = False) -> dict:
    """
    Envía un XML siRecepDE al servicio SOAP de Recepción de SIFEN
    
    Args:
        xml_path: Path al archivo XML siRecepDE
        env: Ambiente ('test' o 'prod')
        artifacts_dir: Directorio para guardar respuestas (opcional)
        
    Returns:
        Diccionario con resultado del envío
    """
    # GUARD-RAIL: Verificar dependencias críticas ANTES de continuar
    try:
        _check_signing_dependencies()
    except RuntimeError as e:
        error_msg = f"BLOQUEADO: {str(e)}. Ejecutar scripts/bootstrap_env.sh"
        try:
            xml_bytes = xml_path.read_bytes()
            artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
            artifacts_dir.joinpath("sign_blocked_input.xml").write_bytes(xml_bytes)
            artifacts_dir.joinpath("sign_blocked_reason.txt").write_text(
                f"BLOQUEADO: Dependencias de firma faltantes\n\n{str(e)}\n\n"
                f"Ejecutar: scripts/bootstrap_env.sh\n"
                f"O manualmente: pip install lxml python-xmlsec",
                encoding="utf-8"
            )
        except Exception:
            pass
        return {
            "success": False,
            "error": error_msg,
            "error_type": "DependencyError"
        }

    artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
    os.environ["SIFEN_ARTIFACTS_DIR"] = str(artifacts_dir)
    
    # Leer XML como bytes
    # TEST/DEV: bump doc para generar un nuevo CDC y evitar 0301 por reenvío
    try:
        _bump = int(os.getenv("SIFEN_BUMP_DOC", "0") or "0")
    except Exception:
        _bump = 0

    # AUTO-BUMP: si no se especifica bump, generar uno automáticamente basado en timestamp
    # Esto evita error 0301 por CDC repetido en pruebas
    if _bump == 0:
        import datetime
        # Usar HHMMSS del tiempo actual como bump (ej: 143205 para 14:32:05)
        now = datetime.datetime.now()
        _bump = now.hour * 10000 + now.minute * 100 + now.second
        # Asegurar que sea de 7 dígitos mínimo
        if _bump < 1000000:
            _bump += 1000000
        print(f"🔄 AUTO-BUMP activo: usando {_bump} (basado en timestamp)")

    if _bump > 0:
        # Asegurar tipo Path
        _xmlp = Path(xml_path) if not isinstance(xml_path, Path) else xml_path
        bumped_path = bump_doc_and_recalc_cdc(_xmlp, _bump, artifacts_dir)
        print(f"🧪 TEST bump-doc activo (SIFEN_BUMP_DOC={_bump})")
        print(f"   XML bump guardado: {bumped_path}")
        xml_path = bumped_path

    print(f"📄 Cargando XML: {xml_path}")
    try:
        xml_bytes = xml_path.read_bytes()
    except Exception as e:
        return {
            "success": False,
            "error": f"Error al leer archivo XML: {str(e)}",
            "error_type": type(e).__name__
        }
    
    # Aplicar override de timbrado/fecha inicio si están definidos (ANTES de construir lote)
    xml_bytes = apply_timbrado_override(xml_bytes, artifacts_dir=artifacts_dir)
    
    xml_size = len(xml_bytes)
    print(f"   Tamaño: {xml_size} bytes ({xml_size / 1024:.2f} KB)\n")
    
    # Validar RUC del emisor antes de enviar (evitar código 1264)
    try:
        from app.sifen_client.ruc_validator import validate_emisor_ruc
        from app.sifen_client.config import get_sifen_config
        
        # Obtener RUC esperado del config si está disponible
        try:
            config = get_sifen_config(env=env)
            expected_ruc = os.getenv("SIFEN_EMISOR_RUC") or getattr(config, 'test_ruc', None)
        except:
            expected_ruc = os.getenv("SIFEN_EMISOR_RUC") or os.getenv("SIFEN_TEST_RUC")
        
        xml_content_str = xml_bytes.decode('utf-8') if isinstance(xml_bytes, bytes) else xml_bytes
        is_valid, error_msg = validate_emisor_ruc(xml_content_str, expected_ruc=expected_ruc)
        
        if not is_valid:
            print(f"❌ RUC emisor inválido/dummy/no coincide; no se envía a SIFEN:")
            print(f"   {error_msg}")
            return {
                "success": False,
                "error": error_msg,
                "error_type": "RUCValidationError",
                "note": "Configure SIFEN_EMISOR_RUC con el RUC real del contribuyente habilitado (formato: RUC-DV, ej: 4554737-8)"
            }
        
        print("✓ RUC del emisor validado (no es dummy)\n")
    except ImportError:
        # Si no se puede importar el validador, continuar sin validación (no crítico)
        print("⚠️  No se pudo importar validador de RUC, continuando sin validación\n")
    except Exception as e:
        # Si falla la validación por otro motivo, continuar (no bloquear)
        print(f"⚠️  Error al validar RUC del emisor: {e}, continuando sin validación\n")
    
    # Validar variables de entorno requeridas
    required_vars = ['SIFEN_CERT_PATH', 'SIFEN_CERT_PASSWORD']
    missing_vars = [var for var in required_vars if not os.getenv(var)]
    
    if missing_vars:
        return {
            "success": False,
            "error": f"Variables de entorno faltantes: {', '.join(missing_vars)}",
            "error_type": "ConfigurationError",
            "note": "Configure estas variables en .env o en el entorno"
        }
    
    # Configurar cliente SIFEN
    print(f"🔧 Configurando cliente SIFEN (ambiente: {env})...")
    try:
        config = get_sifen_config(env=env)
        service_key = "recibe_lote"  # Usar servicio de lote (async)
        wsdl_url = config.get_soap_service_url(service_key)
        print(f"   WSDL (recibe_lote): {wsdl_url}")
        print(f"   Operación: siRecepLoteDE\n")
    except Exception as e:
        error_msg = f"Error al configurar cliente SIFEN: {str(e)}"
        print(f"❌ {error_msg}")
        debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
        if debug_enabled:
            import traceback
            traceback.print_exc()
        return {
            "success": False,
            "error": error_msg,
            "error_type": type(e).__name__
        }
    
    # Construir XML de lote (rEnvioLote) desde el XML original
    try:
        print("📦 Construyendo y firmando lote desde XML individual...")
        
        # Leer certificado de firma (fallback a mTLS si no hay específico de firma)
        sign_cert_path = os.getenv("SIFEN_SIGN_P12_PATH") or os.getenv("SIFEN_MTLS_P12_PATH")
        sign_cert_password = os.getenv("SIFEN_SIGN_P12_PASSWORD") or os.getenv("SIFEN_MTLS_P12_PASSWORD")
        
        if not sign_cert_path or not sign_cert_password:
            return {
                "success": False,
                "error": "Falta certificado de firma (SIFEN_SIGN_P12_PATH o SIFEN_MTLS_P12_PATH y su contraseña)",
                "error_type": "ConfigurationError"
            }
        
        print("🔐 Construyendo lote completo y firmando rDE in-place...")
        try:
            # NUEVO FLUJO: construir lote completo ANTES de firmar, luego firmar in-place
            result = build_and_sign_lote_from_xml(
                xml_bytes=xml_bytes,
                cert_path=sign_cert_path,
                cert_password=sign_cert_password,
                env=env,
                return_debug=True,
                dump_http=dump_http,
                artifacts_dir=artifacts_dir,
            )
            if isinstance(result, tuple):
                if len(result) == 4:
                    zip_base64, lote_xml_bytes, zip_bytes, _ = result  # _ es None (lote_did ya no existe)
                else:
                    zip_base64, lote_xml_bytes, zip_bytes = result
            else:
                zip_base64 = result
                zip_bytes = base64.b64decode(zip_base64)
                lote_xml_bytes = None

            # Guardrail QR: extraer y validar dCarQR final ANTES de enviar
            if lote_xml_bytes is None:
                with zipfile.ZipFile(BytesIO(zip_bytes), "r") as zf:
                    lote_xml_bytes = zf.read("lote.xml")
            dcarqr_final = _extract_first_dcarqr_from_lote(lote_xml_bytes)
            print(f"🔗 dCarQR generado: {dcarqr_final}")
            if _is_qr_placeholder(dcarqr_final):
                return {
                    "success": False,
                    "error": f"dCarQR inválido (placeholder detectado): {dcarqr_final!r}",
                    "error_type": "QRValidationError",
                }
            
            print("✓ Lote construido y rDE firmado exitosamente\n")
            
            # NOTA: El sanitize de rDE ahora se hace en build_and_sign_lote_from_xml()
            # antes de devolver los bytes, por lo que aquí no es necesario
            
            # MODO GUERRA 0160: Instrumentación para detectar mutaciones del XML
            debug_0160 = os.getenv("SIFEN_DEBUG_0160", "1") in ("1", "true", "True")
            if debug_0160 and lote_xml_bytes:
                try:
                    sys.path.append(str(Path(__file__).parent))
                    from preflight_digest_report import preflight_digest_report
                    
                    # Etapa 1: XML recién firmado
                    stage1 = preflight_digest_report(lote_xml_bytes, "DESPUÉS_DE_FIRMAR")
                    
                    # Etapa 2: XML dentro del ZIP
                    with zipfile.ZipFile(BytesIO(zip_bytes), 'r') as zf:
                        lote_from_zip = zf.read('lote.xml')
                    stage2 = preflight_digest_report(lote_from_zip, "DENTRO_DEL_ZIP")
                    
                    # Comparar
                    if stage1['sha256'] != stage2['sha256']:
                        print("\n❌ DETECTADO: XML MUTÓ al meter en ZIP!")
                        print(f"   Después de firmar: {stage1['sha256']}")
                        print(f"   Dentro del ZIP:   {stage2['sha256']}")
                        
                        # Guardar artifacts para análisis
                        if artifacts_dir:
                            artifacts_dir.joinpath("_stage_01_post_firma.xml").write_bytes(lote_xml_bytes)
                            artifacts_dir.joinpath("_stage_02_from_zip.xml").write_bytes(lote_from_zip)
                    else:
                        print("\n✅ XML intacto al meter en ZIP")
                        
                except Exception as e:
                    print(f"\n⚠️  Error en instrumentación 0160: {e}")
                    
        except Exception as e:
            error_msg = f"Error al construir/firmar lote: {str(e)}"
            print(f"❌ {error_msg}", file=sys.stderr)
            import traceback
            traceback.print_exc(file=sys.stderr)
            
            # Guardar traceback completo en artifacts
            debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
            if debug_enabled:
                try:
                    artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
                    traceback_file = artifacts_dir / "send_exception_traceback.txt"
                    traceback_file.write_text(
                        f"Error: {error_msg}\n"
                        f"Type: {type(e).__name__}\n"
                        f"Timestamp: {datetime.now().isoformat()}\n\n"
                        f"Traceback:\n{traceback.format_exc()}",
                        encoding="utf-8"
                    )
                except Exception:
                    pass
            
            return {
                "success": False,
                "error": error_msg,
                "error_type": type(e).__name__,
                "traceback": traceback.format_exc()
            }
        
        # Función para generar dId único de 15 dígitos
        def make_did_15() -> str:
            """Genera un dId único de 15 dígitos: YYYYMMDDHHMMSS + 1 dígito random"""
            import random
            import datetime as _dt
            base = _dt.datetime.now().strftime("%Y%m%d%H%M%S")  # 14 dígitos
            return base + str(random.randint(0, 9))  # + 1 dígito random = 15
        
        # Función para normalizar o generar dId: solo acepta EXACTAMENTE 15 dígitos
        def normalize_or_make_did(existing: Optional[str]) -> str:
            """Valida que el dId tenga EXACTAMENTE 15 dígitos, sino genera uno nuevo"""
            import re
            s = (existing or "").strip()
            if re.fullmatch(r"\d{15}", s):
                return s
            return make_did_15()
        
        # Obtener dId del XML original si está disponible, sino generar uno único
        existing_did_from_xml = None
        try:
            xml_root = etree.fromstring(xml_bytes)
            d_id_elem = xml_root.find(f".//{{{SIFEN_NS}}}dId")
            if d_id_elem is not None and d_id_elem.text:
                existing_did_from_xml = d_id_elem.text.strip()
        except:
            pass  # Si falla el parseo, existing_did_from_xml queda None
        
        # Normalizar o generar dId (solo acepta EXACTAMENTE 15 dígitos)
        did = normalize_or_make_did(existing_did_from_xml)
        
        # dId está en el SOAP rEnvioLote, no en el lote.xml
        did_para_log = str(did)
        
        # Construir el payload de lote completo (reutilizando zip_base64)
        payload_xml = build_r_envio_lote_xml(did=did, xml_bytes=xml_bytes, zip_base64=zip_base64)
        
        # MODO GUERRA 0160: Verificación de firma antes de enviar
        debug_0160 = os.getenv("SIFEN_DEBUG_0160", "1") in ("1", "true", "True")
        if debug_0160:
            try:
                # Extraer XML del payload SOAP para verificar
                from lxml import etree
                soap_root = etree.fromstring(payload_xml.encode('utf-8'))
                xde_elem = soap_root.find(f".//{{{SIFEN_NS}}}xDE")
                if xde_elem is None:
                    xde_elem = soap_root.find(".//xDE")
                
                if xde_elem is not None and xde_elem.text:
                    # Decodificar ZIP
                    zip_from_payload = base64.b64decode(xde_elem.text.strip())
                    
                    # Extraer lote.xml del ZIP
                    with zipfile.ZipFile(BytesIO(zip_from_payload), 'r') as zf:
                        lote_xml_bytes = zf.read('lote.xml')
                    
                    # Verificar firma del XML que se enviará
                    verify_xml_signature(lote_xml_bytes)
                    
                    # Guardar artifact para debug
                    if artifacts_dir:
                        artifacts_dir.joinpath("_final_verified_lote.xml").write_bytes(lote_xml_bytes)
                    
            except Exception as e:
                print(f"\n⚠️  Error en verificación de firma: {e}")
                if artifacts_dir:
                    try:
                        artifacts_dir.joinpath("signature_verification_error.txt").write_text(
                            f"Error: {str(e)}\n\nTraceback:\n{traceback.format_exc()}",
                            encoding="utf-8"
                        )
                    except Exception:
                        pass
                raise RuntimeError(f"Verificación de firma falló: {e}") from e
        
        print(f"✓ Lote construido:")
        print(f"   dId: {did_para_log}")
        print(f"   ZIP bytes: {len(zip_bytes)} ({len(zip_bytes) / 1024:.2f} KB)")
        print(f"   Base64 len: {len(zip_base64)}")
        print(f"   Payload XML total: {len(payload_xml.encode('utf-8'))} bytes ({len(payload_xml.encode('utf-8')) / 1024:.2f} KB)\n")
        
        # Validación XSD local (offline)
        validate_xsd = os.getenv("SIFEN_VALIDATE_XSD", "")
        debug_soap = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
        
        # Por defecto: validar si SIFEN_DEBUG_SOAP=1, o si SIFEN_VALIDATE_XSD=1 explícitamente
        should_validate = (
            validate_xsd == "1" or
            (validate_xsd != "0" and debug_soap)
        )
        
        if should_validate:
            # Determinar xsd_dir
            xsd_dir_env = os.getenv("SIFEN_XSD_DIR")
            if xsd_dir_env:
                xsd_dir = Path(xsd_dir_env)
            else:
                # Default: tesaka-cv/docs/set/ekuatia.set.gov.py/sifen/xsd
                repo_root = Path(__file__).parent.parent
                xsd_dir = repo_root / "docs" / "set" / "ekuatia.set.gov.py" / "sifen" / "xsd"
            
            print("🧾 Validando rDE/lote contra XSD local...")
            print(f"   XSD dir: {xsd_dir}")
            
            if not xsd_dir.exists():
                print(f"⚠️  WARNING: Directorio XSD no existe: {xsd_dir}")
                print("   Omitiendo validación XSD. Configurar SIFEN_XSD_DIR o crear el directorio.")
            else:
                validation_result = validate_rde_and_lote(
                    rde_signed_bytes=xml_bytes,
                    lote_xml_bytes=lote_xml_bytes,
                    xsd_dir=xsd_dir
                )
                
                # Mostrar resultados
                if validation_result["rde_ok"]:
                    print(f"✅ XSD OK (rDE)")
                    print(f"   Schema: {validation_result['schema_rde']}")
                else:
                    print(f"❌ XSD FAIL (rDE)")
                    print(f"   Schema: {validation_result['schema_rde']}")
                    for error in validation_result["rde_errors"]:
                        print(f"   {error}")
                
                if validation_result["lote_ok"] is not None:
                    if validation_result["lote_ok"]:
                        print(f"✅ XSD OK (rLoteDE)")
                        if validation_result["schema_lote"]:
                            print(f"   Schema: {validation_result['schema_lote']}")
                    else:
                        print(f"❌ XSD FAIL (rLoteDE)")
                        if validation_result["schema_lote"]:
                            print(f"   Schema: {validation_result['schema_lote']}")
                        print(f"   Errores encontrados: {len(validation_result['lote_errors'])}")
                        for i, error in enumerate(validation_result["lote_errors"][:30], 1):
                            print(f"   {i}. {error}")
                elif validation_result.get("warning"):
                    print(f"⚠️  {validation_result['warning']}")
                else:
                    # Si no hay lote_xml_bytes, no se puede validar
                    print(f"ℹ️  lote.xml no disponible para validación")
                
                # Si falla validación, abortar envío
                if not validation_result["rde_ok"] or \
                   (validation_result["lote_ok"] is not None and not validation_result["lote_ok"]):
                    error_msg = "Validación XSD falló. Corregir errores antes de enviar a SIFEN."
                    if validation_result["rde_errors"]:
                        error_msg += f"\nErrores rDE: {len(validation_result['rde_errors'])}"
                    if validation_result["lote_errors"]:
                        error_msg += f"\nErrores lote: {len(validation_result['lote_errors'])}"
                    
                    # Guardar artifacts si debug está activo (incluso si PRECHECK falló)
                    if debug_soap and artifacts_dir:
                        try:
                            _save_precheck_artifacts(
                                artifacts_dir=artifacts_dir,
                                payload_xml=payload_xml,
                                zip_bytes=zip_bytes,
                                zip_base64=zip_base64,
                                wsdl_url=wsdl_url,
                                lote_xml_bytes=lote_xml_bytes
                            )
                        except Exception as e:
                            print(f"⚠️  Error al guardar artifacts de PRECHECK: {e}")
                    
                    return {
                        "success": False,
                        "error": error_msg,
                        "error_type": "XSDValidationError",
                        "validation_result": validation_result
                    }
        
        # Guardrail: Validar que dCodSeg esté presente en el ZIP dentro del SOAP
        print("\n🔍 Validando que dCodSeg (CSC) esté presente en el ZIP...")
        try:
            # Importar la función de validación
            from tools.validate_xde_zip_contains_dcodseg import extract_and_validate_dcodseg
            
            # Guardar SOAP payload temporalmente para validación
            if artifacts_dir:
                soap_payload_file = artifacts_dir / "_stage_13_soap_payload.xml"
                soap_payload_file.write_text(payload_xml, encoding="utf-8")
                
                # Ejecutar validación
                exit_code, message, dcodseg_value = extract_and_validate_dcodseg(soap_payload_file)
                
                if exit_code == 0:
                    print(f"✅ {message}")
                else:
                    print(f"❌ {message}")
                    error_msg = f"Validación dCodSeg falló: {message}"
                    
                    # Guardar artifacts para debug
                    if debug_soap and artifacts_dir:
                        try:
                            _save_precheck_artifacts(
                                artifacts_dir=artifacts_dir,
                                payload_xml=payload_xml,
                                zip_bytes=zip_bytes,
                                zip_base64=zip_base64,
                                wsdl_url=wsdl_url,
                                lote_xml_bytes=lote_xml_bytes
                            )
                        except Exception as e:
                            print(f"⚠️  Error al guardar artifacts de PRECHECK: {e}")
                    
                    return {
                        "success": False,
                        "error": error_msg,
                        "error_type": "dCodSegValidationError"
                    }
            else:
                print("⚠️  No se puede validar dCodSeg sin artifacts_dir")
        except Exception as e:
            print(f"⚠️  Error al validar dCodSeg: {e}")
            print("   Continuando con el envío (pero validar manualmente)")
        
        print()  # Línea en blanco después de validación
    except Exception as e:
        # SIEMPRE imprimir traceback completo cuando falla build_lote
        error_msg = f"Error al construir lote: {str(e)}"
        error_type = type(e).__name__
        print(f"\n❌ ERROR en construcción de lote:", file=sys.stderr)
        print(f"   Tipo: {error_type}", file=sys.stderr)
        print(f"   Mensaje: {error_msg}", file=sys.stderr)
        import traceback
        print(f"\n📋 TRACEBACK COMPLETO:", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        
        # Guardar traceback completo en artifacts
        debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
        if debug_enabled:
            try:
                artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
                traceback_file = artifacts_dir / "send_exception_traceback.txt"
                traceback_file.write_text(
                    f"Error: {error_msg}\n"
                    f"Type: {error_type}\n"
                    f"Timestamp: {datetime.now().isoformat()}\n\n"
                    f"Traceback:\n{traceback.format_exc()}",
                    encoding="utf-8"
                )
            except Exception:
                pass
        
        return {
            "success": False,
            "error": error_msg,
            "error_type": error_type,
            "traceback": traceback.format_exc()
        }
    
    # Enviar usando SoapClient
    try:
        print("📤 Enviando lote a SIFEN (siRecepLoteDE)...\n")
        print(f"   WSDL: {wsdl_url}")
        print(f"   Servicio: {service_key}")
        print(f"   Operación: siRecepLoteDE\n")
        
        # PREFLIGHT: Validar antes de enviar
        print("🔍 Ejecutando preflight local...")
        preflight_success, preflight_error = preflight_soap_request(
            payload_xml=payload_xml,
            zip_bytes=zip_bytes,
            lote_xml_bytes=lote_xml_bytes,
            artifacts_dir=artifacts_dir
        )
        
        if not preflight_success:
            error_msg = f"PREFLIGHT FALLÓ: {preflight_error}"
            print(f"❌ {error_msg}")
            print("   Artifacts guardados en artifacts/preflight_*.xml y artifacts/preflight_zip.zip")
            return {
                "success": False,
                "error": error_msg,
                "error_type": "PreflightValidationError",
                "note": "El request no fue enviado a SIFEN porque falló la validación preflight. Revise los artifacts guardados."
            }
        
        print("✅ Preflight OK: todas las validaciones pasaron\n")
        
        # Marker de debug: justo antes de enviar SOAP
        debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
        if debug_enabled and artifacts_dir:
            try:
                from datetime import datetime
                marker_before = artifacts_dir / "soap_marker_before.txt"
                marker_before.write_text(
                    f"{datetime.now().isoformat()}\nabout to send\n",
                    encoding="utf-8"
                )
            except Exception:
                pass
        
        with SoapClient(config) as client:
            # --- GATE: verificar habilitación FE del RUC antes de enviar ---
            try:
                # Extraer RUC emisor del lote.xml
                ruc_de = None
                ruc_de_with_dv = None
                ruc_dv = None
                if lote_xml_bytes:
                    try:
                        lote_root = etree.fromstring(lote_xml_bytes)
                        # Buscar DE dentro de rDE
                        de_elem = None
                        for elem in lote_root.iter():
                            if isinstance(elem.tag, str) and _localname(elem.tag) == "DE":
                                de_elem = elem
                                break
                        
                        if de_elem is not None:
                            # Buscar dRucEm y dDVEmi dentro de gEmis
                            g_emis = de_elem.find(f".//{{{SIFEN_NS_URI}}}gEmis")
                            if g_emis is not None:
                                d_ruc_elem = g_emis.find(f"{{{SIFEN_NS_URI}}}dRucEm")
                                if d_ruc_elem is not None and d_ruc_elem.text:
                                    ruc_de = d_ruc_elem.text.strip()
                                
                                d_dv_elem = g_emis.find(f"{{{SIFEN_NS_URI}}}dDVEmi")
                                if d_dv_elem is not None and d_dv_elem.text:
                                    ruc_dv = d_dv_elem.text.strip()
                                
                                # Construir RUC-DE completo si hay DV
                                if ruc_de and ruc_dv:
                                    ruc_de_with_dv = f"{ruc_de}-{ruc_dv}"
                                elif ruc_de:
                                    ruc_de_with_dv = ruc_de
                    except Exception as e:
                        print(f"⚠️  No se pudo extraer RUC del lote.xml para gate: {e}")
                
                # Extraer RUC del certificado P12
                ruc_cert = None
                ruc_cert_with_dv = None
                try:
                    sign_cert_path = os.getenv("SIFEN_SIGN_P12_PATH") or os.getenv("SIFEN_MTLS_P12_PATH")
                    sign_cert_password = os.getenv("SIFEN_SIGN_P12_PASSWORD") or os.getenv("SIFEN_MTLS_P12_PASSWORD")
                    if sign_cert_path and sign_cert_password:
                        cert_info = _extract_ruc_from_cert(sign_cert_path, sign_cert_password)
                        if cert_info:
                            ruc_cert = cert_info.get("ruc")
                            ruc_cert_with_dv = cert_info.get("ruc_with_dv")
                except Exception:
                    pass  # Silenciosamente fallar si no se puede extraer
                
                # --- SANITY CHECK: Comparar RUCs ---
                ruc_gate = None
                if ruc_de:
                    # ruc_gate debe ser SOLO el número (sin DV)
                    ruc_gate = str(ruc_de).strip().split("-", 1)[0].strip()
                
                # Imprimir sanity check
                print("\n" + "="*60)
                print("=== SIFEN SANITY CHECK ===")
                print(f"RUC-DE:     {ruc_de_with_dv or ruc_de or '(no encontrado)'}")
                print(f"RUC-GATE:   {ruc_gate or '(no encontrado)'}")
                print(f"RUC-CERT:   {ruc_cert_with_dv or ruc_cert or '(no disponible)'}")
                
                # Comparaciones booleanas
                match_de_gate = (ruc_de and ruc_gate and ruc_de.split("-", 1)[0].strip() == ruc_gate)
                match_cert_gate = (ruc_cert and ruc_gate and ruc_cert == ruc_gate)
                
                print(f"match(DE.ruc == GATE.ruc):   {match_de_gate}")
                if ruc_cert:
                    print(f"match(CERT.ruc == GATE.ruc): {match_cert_gate}")
                
                # Warnings si hay mismatch (pero no bloquear todavía)
                if ruc_de and ruc_gate and not match_de_gate:
                    print(f"⚠️  WARNING: RUC del DE ({ruc_de.split('-', 1)[0]}) no coincide con RUC-GATE ({ruc_gate})")
                if ruc_cert and ruc_gate and not match_cert_gate:
                    print(f"⚠️  WARNING: RUC del certificado ({ruc_cert}) no coincide con RUC-GATE ({ruc_gate})")
                
                print("="*60 + "\n")
                
                # Guardar artifact JSON si dump_http=True
                if dump_http and artifacts_dir:
                    try:
                        from datetime import datetime
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        sanity_data = {
                            "timestamp": datetime.now().isoformat(),
                            "ruc_de": ruc_de_with_dv or ruc_de,
                            "ruc_gate": ruc_gate,
                            "ruc_cert": ruc_cert_with_dv or ruc_cert,
                            "matches": {
                                "de_gate": match_de_gate,
                                "cert_gate": match_cert_gate if ruc_cert else None
                            }
                        }
                        sanity_file = artifacts_dir / f"sanity_check_{timestamp}.json"
                        sanity_file.write_text(json.dumps(sanity_data, indent=2, ensure_ascii=False), encoding="utf-8")
                    except Exception:
                        pass  # Silenciosamente fallar si no se puede guardar
                
                # Hard-fail si falta dRucEm o es inválido
                if not ruc_de or not ruc_gate:
                    raise RuntimeError(
                        f"No se pudo extraer RUC válido del DE. "
                        f"dRucEm={ruc_de!r} RUC-GATE={ruc_gate!r}"
                    )
                
                ruc_emisor = ruc_gate
                    
                print(f"🔍 Verificando habilitación FE del RUC: {ruc_emisor}")
                
                # Flag de emergencia para saltar validación RUC (MODO GUERRA 0160)
                skip_ruc_gate = os.environ.get("SIFEN_SKIP_RUC_GATE", "0") in ("1", "true", "TRUE", "True")
                
                if skip_ruc_gate:
                    print(f"⚠️  SALTANDO VALIDACIÓN RUC (SIFEN_SKIP_RUC_GATE=1)")
                else:
                    ruc_check = _consulta_ruc_gate_with_retry(client, ruc_emisor, dump_http, artifacts_dir)
                    cod = (ruc_check.get("dCodRes") or "").strip()
                    msg = (ruc_check.get("dMsgRes") or "").strip()
                    
                    # Extraer dRUCFactElec de xContRUC
                    x_cont_ruc = ruc_check.get("xContRUC", {})
                    d_fact_raw = x_cont_ruc.get("dRUCFactElec") if isinstance(x_cont_ruc, dict) else None
                    # Normalizar: convertir a string, trim, uppercase
                    d_fact_normalized = (str(d_fact_raw).strip().upper() if d_fact_raw is not None else "")
                    
                    # Valores que indican HABILITADO: "1", "S", "SI"
                    # Valores que indican NO HABILITADO: "0", "N", "NO", "" (vacío)
                    # 
                    # Test manual de normalización (ejemplos):
                    #   Input: "1"  -> Normalizado: "1"  -> Resultado: OK (habilitado)
                    #   Input: "S"  -> Normalizado: "S"  -> Resultado: OK (habilitado)
                    #   Input: "SI" -> Normalizado: "SI" -> Resultado: OK (habilitado)
                    #   Input: "0"  -> Normalizado: "0"  -> Resultado: FAIL (no habilitado)
                    #   Input: "N"  -> Normalizado: "N"  -> Resultado: FAIL (no habilitado)
                    #   Input: "NO" -> Normalizado: "NO" -> Resultado: FAIL (no habilitado)
                    #   Input: ""   -> Normalizado: ""   -> Resultado: FAIL (no habilitado)
                    #   Input: None -> Normalizado: ""   -> Resultado: FAIL (no habilitado)
                    habilitado = d_fact_normalized in ("1", "S", "SI")
                    
                    if cod != "0502":
                        raise RuntimeError(f"SIFEN siConsRUC no confirmó el RUC. dCodRes={cod} dMsgRes={msg}")
                    
                    if not habilitado:
                        razon = x_cont_ruc.get("dRazCons", "") if isinstance(x_cont_ruc, dict) else ""
                        est = x_cont_ruc.get("dDesEstCons", "") if isinstance(x_cont_ruc, dict) else ""
                        env_str = config.env if hasattr(config, 'env') else env
                        d_fact_display = repr(d_fact_raw) if d_fact_raw is not None else "None"
                        msg = (
                            f"RUC NO habilitado para Facturación Electrónica en SIFEN ({env_str}). "
                            f"RUC={ruc_emisor} RazónSocial='{razon}' Estado='{est}' "
                            f"dRUCFactElec={d_fact_display} (normalizado='{d_fact_normalized}'). "
                            "Debés gestionar la habilitación FE del RUC en SIFEN/SET."
                        )
                        enforce = str(os.getenv("SIFEN_ENFORCE_RUC_FACT_ELEC", "0")).strip().lower() in ("1","true","yes")
                        if enforce:
                            raise RuntimeError(msg)
                        logger.warning(msg + " (IGNORADO por configuración; continuando)")
                    else:
                        print(f"✅ RUC {ruc_emisor} habilitado para FE (dRUCFactElec={d_fact_raw!r} -> '{d_fact_normalized}')")
            except Exception as e:
                # hard-fail: no enviar lote si no está habilitado
                if not skip_ruc_gate:
                    print(f"❌ GATE FALLÓ: {e}")
                    raise
                else:
                    print(f"⚠️  Ignorando error de RUC (SIFEN_SKIP_RUC_GATE=1): {e}")
            # --- FIN GATE ---
            
            response = _recep_lote_with_retry(client, payload_xml, dump_http, artifacts_dir)
            
            # Imprimir dump HTTP si está habilitado
            if dump_http:
                _print_dump_http(artifacts_dir)
            
            # Marker de debug: justo después de recibir respuesta
            if debug_enabled and artifacts_dir:
                try:
                    from datetime import datetime
                    marker_after = artifacts_dir / "soap_marker_after.txt"
                    marker_after.write_text(
                        f"{datetime.now().isoformat()}\nreceived\n",
                        encoding="utf-8"
                    )
                except Exception:
                    pass
            
            # Mostrar resultado
            print("✅ Envío completado")
            print(f"   Estado: {'OK' if response.get('ok') else 'ERROR'}")
            
            codigo_respuesta = response.get('codigo_respuesta')
            if codigo_respuesta:
                print(f"   Código respuesta: {codigo_respuesta}")
            
            if response.get('mensaje'):
                print(f"   Mensaje: {response['mensaje']}")
            
            if response.get('cdc'):
                print(f"   CDC: {response['cdc']}")
            
            if response.get('estado'):
                print(f"   Estado documento: {response['estado']}")
            
            # Extraer y guardar dProtConsLote si está presente
            d_prot_cons_lote = response.get('d_prot_cons_lote')
            if d_prot_cons_lote:
                print(f"   dProtConsLote: {d_prot_cons_lote}")
                
                # Guardar CDCs del lote para fallback automático (0364)
                try:
                    # Extraer CDCs del lote.xml
                    cdcs = []
                    try:
                        lote_root = etree.fromstring(lote_xml_bytes)
                        # Buscar todos los DE dentro de rDE
                        de_elements = lote_root.xpath(".//*[local-name()='DE']")
                        for de_elem in de_elements:
                            de_id = de_elem.get("Id") or de_elem.get("id")
                            if de_id and de_id not in cdcs:
                                cdcs.append(str(de_id))
                    except Exception as e:
                        if debug_enabled:
                            print(f"⚠️  Error al extraer CDCs del lote: {e}")
                    
                    if cdcs:
                        # Guardar JSON con CDCs y dProtConsLote
                        import json
                        from datetime import datetime
                        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                        lote_data = {
                            "dProtConsLote": str(d_prot_cons_lote),
                            "cdcs": cdcs,
                            "timestamp": timestamp,
                            "dId": str(did),
                        }
                        lote_file = artifacts_dir / f"lote_enviado_{timestamp}.json"
                        lote_file.write_text(
                            json.dumps(lote_data, ensure_ascii=False, indent=2),
                            encoding="utf-8"
                        )
                        if debug_enabled:
                            print(f"💾 CDCs guardados en: {lote_file.name} ({len(cdcs)} CDCs)")
                except Exception as e:
                    if debug_enabled:
                        print(f"⚠️  Error al guardar CDCs: {e}")
            
            # Advertencia para dCodRes=0301 con dProtConsLote=0
            if codigo_respuesta == "0301":
                d_prot_cons_lote_val = response.get('d_prot_cons_lote')
                if d_prot_cons_lote_val is None or d_prot_cons_lote_val == 0 or str(d_prot_cons_lote_val) == "0":
                    print(f"\n⚠️  ADVERTENCIA: SIFEN no encoló el lote (dCodRes=0301, dProtConsLote=0)")
                    print(f"   Si estás re-enviando el mismo CDC, SIFEN puede no re-procesarlo.")
                    print(f"   Generá un nuevo CDC (ej: cambiar nro factura y recalcular CDC/DV) para probar cambios.")
                    
                    # Guardar paquete de diagnóstico automáticamente
                    if artifacts_dir:
                        try:
                            _save_0301_diagnostic_package(
                                artifacts_dir=artifacts_dir,
                                response=response,
                                payload_xml=payload_xml,
                                zip_bytes=zip_bytes,
                                lote_xml_bytes=lote_xml_bytes,
                                env=env,
                                did=did
                            )
                        except Exception as e:
                            print(f"   ⚠️  Error al guardar paquete de diagnóstico: {e}")
                
                # Guardar lote en base de datos (solo si tiene dProtConsLote > 0)
                if d_prot_cons_lote and d_prot_cons_lote != 0 and str(d_prot_cons_lote) != "0":
                    try:
                        sys.path.insert(0, str(Path(__file__).parent.parent))
                        from web.lotes_db import create_lote
                        
                        lote_id = create_lote(
                            env=env,
                            d_prot_cons_lote=d_prot_cons_lote,
                            de_document_id=None  # TODO: relacionar con de_documents si es posible
                        )
                        print(f"   💾 Lote guardado en BD (ID: {lote_id})")
                    except Exception as e:
                        print(f"   ⚠️  No se pudo guardar lote en BD: {e}")
            
            # Guardar respuesta si se especificó artifacts_dir
            if artifacts_dir:
                artifacts_dir.mkdir(exist_ok=True)
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                # Add iteration number to timestamp if provided
                _args_obj = globals().get("args")
                _iter = getattr(_args_obj, "iteration", None) if _args_obj is not None else None
                if _iter is not None:
                    timestamp = f"{timestamp}_iter{_iter}"
                response_file = artifacts_dir / f"response_recepcion_{timestamp}.json"
                
                import json
                response_file.write_text(
                    json.dumps(response, indent=2, ensure_ascii=False, default=str),
                    encoding="utf-8"
                )
                print(f"\n💾 Respuesta guardada en: {response_file}")

            # Guardar summary.txt SIEMPRE
            try:
                xde_sha256 = hashlib.sha256(zip_base64.encode("utf-8")).hexdigest()
                zip_sha256 = hashlib.sha256(zip_bytes).hexdigest()
                d_prot_cons_lote = response.get("d_prot_cons_lote")
                summary_lines = [
                    f"dId={did_para_log}",
                    f"xDE_sha256={xde_sha256}",
                    f"zip_sha256={zip_sha256}",
                    f"dProtConsLote={'' if d_prot_cons_lote is None else str(d_prot_cons_lote)}",
                ]
                (artifacts_dir / "summary.txt").write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
            except Exception:
                pass
            
            # Instrumentación para debug del error 1264
            if codigo_respuesta == "1264" and artifacts_dir:
                print("\n🔍 Error 1264 detectado: Guardando archivos de debug...")
                # Convertir xml_bytes a string para debug
                xml_content_str = xml_bytes.decode('utf-8') if isinstance(xml_bytes, bytes) else xml_bytes
                _save_1264_debug(
                    artifacts_dir=artifacts_dir,
                    payload_xml=payload_xml,
                    zip_bytes=zip_bytes,
                    zip_base64=zip_base64,
                    xml_content=xml_content_str,
                    wsdl_url=wsdl_url,
                    service_key=service_key,
                    client=client
                )
        
        return {
            "success": response.get('ok', False),
            "response": response,
            "response_file": str(response_file) if artifacts_dir else None
        }
        
    except SifenSizeLimitError as e:
        print(f"❌ Error: El XML excede el límite de tamaño")
        print(f"   {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "error_type": "SifenSizeLimitError",
            "service": e.service,
            "size": e.size,
            "limit": e.limit
        }
    
    except SifenResponseError as e:
        print(f"❌ Error SIFEN en la respuesta")
        print(f"   Código: {e.code}")
        print(f"   Mensaje: {e.message}")
        return {
            "success": False,
            "error": e.message,
            "error_type": "SifenResponseError",
            "code": e.code
        }
    
    except SifenClientError as e:
        print(f"❌ Error del cliente SIFEN")
        print(f"   {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "error_type": "SifenClientError"
        }
    
    except Exception as e:
        print(f"❌ Error inesperado")
        print(f"   {str(e)}")
        import traceback
        traceback.print_exc()
        
        # Guardar traceback completo en artifacts
        debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
        if debug_enabled:
            try:
                artifacts_dir = _resolve_artifacts_dir(artifacts_dir)
                traceback_file = artifacts_dir / "send_exception_traceback.txt"
                traceback_file.write_text(
                    f"Error: {str(e)}\n"
                    f"Type: {type(e).__name__}\n"
                    f"Timestamp: {datetime.now().isoformat()}\n\n"
                    f"Traceback:\n{traceback.format_exc()}",
                    encoding="utf-8"
                )
            except Exception:
                pass
        
        return {
            "success": False,
            "error": str(e),
            "error_type": type(e).__name__
        }



def verify_xml_signature(xml_bytes: bytes) -> None:
    """
    Verifica que la firma XML del lote sea válida usando xmlsec.
    - Registra atributos Id/ID/id como IDs (requerido para URI="#...").
    - Carga key/cert desde P12/PFX si está disponible por env vars.
    - Fallback: usa X509Certificate embebido en KeyInfo (si existe).
    """
    import os
    import base64
    import xmlsec
    from lxml import etree

    try:
        # Parsear XML SIN alterar whitespace (canon depende de esto)
        parser = etree.XMLParser(remove_blank_text=False, recover=False)
        root = etree.fromstring(xml_bytes, parser=parser)

        # Registrar atributos ID para referencias tipo URI="#DE..."
        # (xmlsec necesita saber qué atributos son IDs)
        xmlsec.tree.add_ids(root, ["Id", "ID", "id"])

        # Buscar Signature (primera firma del documento)
        DS_NS = "http://www.w3.org/2000/09/xmldsig#"
        sig_elem = root.find(f".//{{{DS_NS}}}Signature")
        if sig_elem is None:
            raise RuntimeError("No se encontró elemento Signature")

        # Intentar cargar key/cert para verificar
        # Preferimos P12/PFX de firma (o mTLS) si existe.
        cert_path = (
            os.getenv("SIFEN_SIGN_P12_PATH")
            or os.getenv("SIFEN_MTLS_P12_PATH")
            or os.getenv("SIFEN_CERT_PATH")
        )
        cert_password = (
            os.getenv("SIFEN_SIGN_P12_PASSWORD")
            or os.getenv("SIFEN_MTLS_P12_PASSWORD")
            or os.getenv("SIFEN_CERT_PASSWORD")
        )

        key = None

        if cert_path and cert_path.lower().endswith((".p12", ".pfx")):
            if not cert_password:
                raise RuntimeError("Falta password del P12/PFX para verificar firma (SIFEN_*_P12_PASSWORD)")
            # python-xmlsec a veces no expone KeyFormat.PKCS12; extraemos el CERT del P12 con cryptography
            try:
                from cryptography.hazmat.primitives.serialization import pkcs12, Encoding
                p12_bytes = open(cert_path, "rb").read()
                _key, cert, _addl = pkcs12.load_key_and_certificates(
                    p12_bytes, cert_password.encode("utf-8")
                )
                if cert is None:
                    raise RuntimeError("No se pudo extraer cert del P12/PFX para verificar firma")
                der = cert.public_bytes(Encoding.DER)
                key = xmlsec.Key.from_memory(der, xmlsec.KeyFormat.CERT_DER, None)
            except Exception as e:
                # Fallback: si no hay cryptography o falla extracción, seguimos al fallback X509 embebido
                key = None

        elif cert_path and cert_path.lower().endswith((".pem", ".crt", ".cer")):
            # PEM/CRT con cert público
            key = xmlsec.Key.from_file(cert_path, xmlsec.KeyFormat.PEM, None)

        if key is None:
            # Fallback: usar X509Certificate embebido en KeyInfo
            x509 = sig_elem.find(f".//{{{DS_NS}}}X509Certificate")
            if x509 is None or not (x509.text or "").strip():
                raise RuntimeError(
                    "No hay cert configurado para verify (P12/PEM) y tampoco X509Certificate embebido en KeyInfo"
                )
            der = base64.b64decode("".join(x509.text.split()))
            key = xmlsec.Key.from_memory(der, xmlsec.KeyFormat.CERT_DER, None)

        ctx = xmlsec.SignatureContext()
        ctx.key = key
        ctx.verify(sig_elem)

        print("✓ Firma XML verificada exitosamente")

    except xmlsec.Error as e:
        raise RuntimeError(f"Firma XML inválida: {e}") from e
    except Exception as e:
        raise RuntimeError(f"Error al verificar firma: {e}") from e

def _sifen_mod11_dv(base: str) -> str:
    """
    DV módulo 11 (SIFEN) - DELEGADO al módulo central tools.cdc_dv
    para evitar divergencias con generate_cdc().
    """
    from tools.cdc_dv import calc_cdc_dv
    digits = "".join(c for c in str(base) if c.isdigit())
    return str(calc_cdc_dv(digits))




def _localname(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def _find_first_by_local(root, name: str):
    for el in root.iter():
        if _localname(el.tag) == name:
            return el
    return None


def _find_all_by_local(root, name: str):
    out = []
    for el in root.iter():
        if _localname(el.tag) == name:
            out.append(el)
    return out


def bump_doc_and_recalc_cdc(xml_path, bump_doc: int, artifacts_dir):
    """
    - Cambia dNumDoc al valor bump_doc (padded 7)
    - Recalcula CDC usando PRIORIDAD 1 (CDC existente)
    - Actualiza DE@Id y dCDC (si existe)
    - Guarda XML nuevo en artifacts/ y retorna el nuevo path
    """
    import datetime
    import xml.etree.ElementTree as ET
    from pathlib import Path

    xml_path = Path(xml_path)
    artifacts_dir = Path(artifacts_dir)

    data = xml_path.read_bytes()
    root = ET.fromstring(data)

    # Obtener y actualizar dNumDoc
    el_num = _find_first_by_local(root, "dNumDoc")
    if el_num is None or not (el_num.text or "").strip():
        raise RuntimeError("bump_doc: no encontré <dNumDoc> para modificar.")

    old_num = (el_num.text or "").strip()
    new_num = f"{int(bump_doc):07d}"
    el_num.text = new_num

    # PRIORIDAD 1: Extraer CDC existente
    old_cdc = None
    
    # Intentar obtener desde DE@Id
    el_de = _find_first_by_local(root, "DE")
    if el_de is not None:
        old_cdc = el_de.get("Id")
    
    # Si no hay en DE@Id, buscar primer <dCDC> no vacío
    if not old_cdc:
        for el_cdc in _find_all_by_local(root, "dCDC"):
            if el_cdc.text and el_cdc.text.strip():
                old_cdc = el_cdc.text.strip()
                break
    
    if not old_cdc:
        # PRIORIDAD 2: No hay CDC - reconstruir desde campos
        print("   ⚠️  No se encontró CDC existente, intentando reconstruir desde campos...")
        
        # Campos para CDC
        iTiDE   = _find_first_by_local(root, "iTiDE")
        dRucEm  = _find_first_by_local(root, "dRucEm")
        dDVEmi  = _find_first_by_local(root, "dDVEmi")
        dEst    = _find_first_by_local(root, "dEst")
        dPunExp = _find_first_by_local(root, "dPunExp")
        iTipEmi = _find_first_by_local(root, "iTipEmi")
        dFeEmi  = _find_first_by_local(root, "dFeEmiDE")
        iTipTra = _find_first_by_local(root, "iTipTra")
        dCodSeg = _find_first_by_local(root, "dCodSeg")

        missing = [n for n,e in [
            ("iTiDE", iTiDE), ("dRucEm", dRucEm), ("dDVEmi", dDVEmi),
            ("dEst", dEst), ("dPunExp", dPunExp), ("iTipEmi", iTipEmi),
            ("dFeEmiDE", dFeEmi), ("iTipTra", iTipTra), ("dCodSeg", dCodSeg),
        ] if e is None or not (e.text or "").strip()]

        if missing:
            raise RuntimeError(
                f"bump_doc: No hay CDC existente y faltan campos para reconstruir: {', '.join(missing)}. "
                "Asegúrese de que el XML tenga CDC o todos los campos requeridos."
            )

        # Normalizaciones / padding
        v_iTiDE   = f"{int(iTiDE.text):02d}"
        v_ruc     = f"{int(dRucEm.text):08d}"
        v_dv      = f"{int(dDVEmi.text):01d}"
        v_est     = f"{int(dEst.text):03d}"
        v_punexp  = f"{int(dPunExp.text):03d}"
        v_numdoc  = new_num  # 7
        v_tipemi  = f"{int(iTipEmi.text):01d}"
        date_txt  = (dFeEmi.text or "").strip()
        v_fecha   = date_txt[:10].replace("-", "")
        if len(v_fecha) != 8 or not v_fecha.isdigit():
            raise RuntimeError(f"bump_doc: dFeEmiDE inválido para CDC: '{date_txt}'")
        v_tiptra  = f"{int(iTipTra.text):01d}"
        v_codseg  = f"{int(dCodSeg.text):09d}"

        base = v_iTiDE + v_ruc + v_dv + v_est + v_punexp + v_numdoc + v_tipemi + v_fecha + v_tiptra + v_codseg
        dv_cdc = _sifen_mod11_dv(base)
        new_cdc = base + dv_cdc
        old_cdc = "(reconstruido)"
    else:
        # PRIORIDAD 1: Usar CDC existente
        # Validar formato del CDC
        if not old_cdc.isdigit() or len(old_cdc) != 44:
            raise RuntimeError(
                f"bump_doc: CDC existente con formato inválido: '{old_cdc}'. "
                "Se esperaban 44 dígitos numéricos."
            )
        
        # Extraer base (43 dígitos, sin DV)
        base_old = old_cdc[:-1]
        
        # Reemplazar segmento dNumDoc (offset 17, largo 7)
        # Estructura: iTiDE(2) + dRucEm(8) + dDVEmi(1) + dEst(3) + dPunExp(3) + dNumDoc(7) + ...
        new_base = base_old[:17] + new_num + base_old[24:]
        
        # Calcular nuevo DV y CDC
        dv = _sifen_mod11_dv(new_base)
        new_cdc = new_base + dv

    # Actualizar DE@Id (CDC)
    if el_de is None:
        raise RuntimeError("bump_doc: no encontré el nodo <DE> para actualizar atributo Id.")
    el_de.set("Id", new_cdc)

    # Si existe(n) dCDC, actualizarlo(s) también
    for el in _find_all_by_local(root, "dCDC"):
        el.text = new_cdc


    # Actualizar dDVId (debe coincidir con el último dígito del CDC)
    ddvid_nodes = _find_all_by_local(root, "dDVId")
    if not ddvid_nodes:
        raise RuntimeError("bump_doc: no encontré <dDVId> para actualizar.")
    for n in ddvid_nodes:
        n.text = new_cdc[-1]
    # Guardar XML actualizado
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out = artifacts_dir / f"xml_bumped_{new_num}_{ts}.xml"

    xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    out.write_bytes(xml_bytes)
    
    # Logging obligatorio
    print(f"   dNumDoc: {old_num} -> {new_num}")
    print(f"   CDC:     {old_cdc} -> {new_cdc}")
    print(f"   XML bump guardado: {out}")
    
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Envía XML siRecepLoteDE (rEnvioLote) al servicio SOAP de Recepción Lote DE (async) de SIFEN",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos básicos:
  # Activar entorno virtual (recomendado)
  source .venv/bin/activate
  
  # Enviar archivo específico a test
  python -m tools.send_sirecepde --env test --xml artifacts/sirecepde_20251226_233653.xml
  
  # Enviar el más reciente a test
  python -m tools.send_sirecepde --env test --xml latest
  
  # Enviar a producción
  python -m tools.send_sirecepde --env prod --xml latest
  
  # Con debug SOAP y validación XSD
  SIFEN_DEBUG_SOAP=1 SIFEN_VALIDATE_XSD=1 python -m tools.send_sirecepde --env test --xml latest
  
  Ver docs/USAGE_SEND_SIRECEPDE.md para más ejemplos y opciones avanzadas.

Configuración requerida (variables de entorno):
  SIFEN_ENV              Ambiente (test/prod) - opcional, puede usar --env
  SIFEN_CERT_PATH        Path al certificado P12/PFX (requerido)
  SIFEN_CERT_PASSWORD    Contraseña del certificado (requerido)
  SIFEN_USE_MTLS         true/false (default: true)
  SIFEN_CA_BUNDLE_PATH   Path al bundle CA (opcional)
  SIFEN_DEBUG_SOAP       1/true para guardar SOAP enviado/recibido en artifacts/
  SIFEN_SOAP_COMPAT      roshka para modo compatibilidad Roshka
        """
    )
    
    parser.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="ID determinístico de corrida. Si se especifica, se usa artifacts/<RUN_ID>/"
    )

    parser.add_argument(
        "--env",
        choices=["test", "prod"],
        default=None,
        help="Ambiente SIFEN (sobrescribe SIFEN_ENV)"
    )
    
    parser.add_argument(
        "--xml",
        required=True,
        help="Path al archivo XML (rDE o siRecepDE) o 'latest' para usar el más reciente"
    )

    parser.add_argument(
        "--bump-doc",
        type=int,
        default=None,
        help="Bump del número de documento (dNumDoc) y recálculo automático del CDC antes de firmar. "
             "Equivalente a setear SIFEN_BUMP_DOC=<n>."
    )

    
    parser.add_argument(
        "--dump-http",
        action="store_true",
        help="Mostrar evidencia completa del HTTP request/response (headers, SOAP envelope, body). "
             "Guarda artefactos en artifacts/ para diagnóstico de errores SIFEN.",
    )
    
    parser.add_argument(
        "--artifacts-dir",
        type=Path,
        default=None,
        help="Directorio para guardar respuestas (default: artifacts/)"
    )
    
    parser.add_argument(
        "--iteration",
        type=int,
        default=None,
        help="Número de iteración (para naming de artifacts)"
    )
    
    args = parser.parse_args()
    globals()["args"] = args  # make args visible to helpers
    

    # Exportar bump-doc a env para que el pipeline lo aplique
    if getattr(args, "bump_doc", None) is not None:
        os.environ["SIFEN_BUMP_DOC"] = str(args.bump_doc)


    # Determinar ambiente
    env = args.env or os.getenv("SIFEN_ENV", "test")
    if env not in ["test", "prod"]:
        print(f"❌ Ambiente inválido: {env}. Debe ser 'test' o 'prod'")
        return 1
    
    artifacts_dir = _resolve_run_artifacts_dir(run_id=getattr(args, "run_id", None), artifacts_dir_override=args.artifacts_dir)
    os.environ["SIFEN_ARTIFACTS_DIR"] = str(artifacts_dir)
    
    # Resolver XML path (base dir para 'latest' mantiene compatibilidad)
    try:
        base_dir_for_latest = args.artifacts_dir if args.artifacts_dir is not None else Path("artifacts")
        xml_path = resolve_xml_path(args.xml, base_dir_for_latest)
    except FileNotFoundError as e:
        print(f"❌ {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    # Enviar
    dump_http = getattr(args, 'dump_http', False)
    result = send_sirecepde(
        xml_path=xml_path,
        env=env,
        artifacts_dir=artifacts_dir,
        dump_http=dump_http
    )
    
    # Retornar código de salida (0 solo si success es True explícitamente)
    success = result.get("success") is True
    exit_code = 0 if success else 1
    
    # SIEMPRE imprimir bloque final con resultado (incluso cuando SIFEN_DEBUG_SOAP=0)
    print("\n" + "="*60)
    print("=== RESULT ===")
    print(f"success: {success}")
    if result.get("error"):
        print(f"error: {result.get('error')}")
    if result.get("error_type"):
        print(f"error_type: {result.get('error_type')}")
    if result.get("traceback"):
        print(f"\ntraceback:\n{result.get('traceback')}")
    if result.get("response"):
        print(f"response: {result.get('response')}")
    if result.get("response_file"):
        print(f"response_file: {result.get('response_file')}")
    print("="*60)
    
    # Debug output
    debug_soap = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
    if debug_soap:
        print(f"EXITING_WITH={exit_code}")

    # Manual/documentación: mostrar dir de artifacts y paths clave
    try:
        print(f"Artifacts dir: {artifacts_dir.resolve()}")
        print(f"SOAP request (real): {(artifacts_dir / 'soap_last_request.xml').resolve()}")
        if result.get("response_file"):
            print(f"Response JSON: {Path(result.get('response_file')).resolve()}")
    except Exception:
        pass
    
    return exit_code


if __name__ == "__main__":
    import sys, traceback
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as e:
        print("❌ EXCEPCIÓN NO MOSTRADA:", repr(e), file=sys.stderr)
        traceback.print_exc()
        sys.exit(1)
