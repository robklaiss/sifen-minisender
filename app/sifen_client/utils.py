"""
Utilidades para SIFEN
"""
from typing import Optional, Union
from pathlib import Path
from datetime import date, datetime
from zoneinfo import ZoneInfo
import re

_SIFEN_TZ = ZoneInfo("America/Asuncion")
_SIFEN_TS_FMT = "%Y-%m-%dT%H:%M:%S"
_SIFEN_DATE_FMT = "%Y-%m-%d"
_SIFEN_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")
_SIFEN_TS_SPACE_RE = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$")
_SIFEN_TS_OFFSET_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$")
_SIFEN_TS_HOUR_ONLY_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}$")


def _parse_datetime_like(value: str) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None

    if " " in text and "T" not in text:
        text = text.replace(" ", "T", 1)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"

    try:
        return datetime.fromisoformat(text)
    except Exception:
        pass

    try:
        if len(text) >= 10:
            d = date.fromisoformat(text[:10])
            return datetime(d.year, d.month, d.day)
    except Exception:
        return None
    return None


def _parse_sifen_timestamp_str(value: str) -> datetime:
    raw = value
    text = value.strip()
    if not text:
        raise ValueError(f"Timestamp SIFEN inválido: {raw!r}")
    if _SIFEN_TS_HOUR_ONLY_RE.fullmatch(text):
        raise ValueError(f"Timestamp SIFEN incompleto: {raw!r}")

    if _SIFEN_TS_RE.fullmatch(text):
        parsed = datetime.fromisoformat(text)
    elif _SIFEN_TS_SPACE_RE.fullmatch(text):
        parsed = datetime.fromisoformat(text.replace(" ", "T", 1))
    elif _SIFEN_TS_OFFSET_RE.fullmatch(text):
        parsed = datetime.fromisoformat(text)
    else:
        raise ValueError(f"Timestamp SIFEN inválido: {raw!r}")

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=_SIFEN_TZ)
    return parsed.astimezone(_SIFEN_TZ)


def _normalize_sifen_dt(dt: Optional[Union[datetime, date, str]] = None) -> datetime:
    if dt is None:
        local_dt = datetime.now(_SIFEN_TZ)
    elif isinstance(dt, str):
        parsed = _parse_datetime_like(dt)
        if parsed is None:
            raise ValueError(f"Fecha/hora inválida para SIFEN: {dt!r}")
        dt = parsed
        if dt.tzinfo is None:
            local_dt = dt.replace(tzinfo=_SIFEN_TZ)
        else:
            local_dt = dt.astimezone(_SIFEN_TZ)
    elif isinstance(dt, date) and not isinstance(dt, datetime):
        local_dt = datetime(dt.year, dt.month, dt.day, tzinfo=_SIFEN_TZ)
    elif dt.tzinfo is None:
        local_dt = dt.replace(tzinfo=_SIFEN_TZ)
    else:
        local_dt = dt.astimezone(_SIFEN_TZ)

    return local_dt.replace(microsecond=0)


def sifen_timestamp(dt: Optional[Union[datetime, date, str]] = None) -> str:
    """
    Timestamp SIFEN con offset: YYYY-MM-DDTHH:MM:SS-03:00 en America/Asuncion.
    """
    if isinstance(dt, str):
        local_dt = _parse_sifen_timestamp_str(dt)
    else:
        local_dt = _normalize_sifen_dt(dt)

    local_dt = local_dt.replace(microsecond=0).astimezone(_SIFEN_TZ)
    result = local_dt.isoformat(timespec="seconds")
    if not _SIFEN_TS_OFFSET_RE.fullmatch(result):
        raise ValueError(f"Timestamp SIFEN inválido: {result!r}")
    return result


def sifen_timestamp_no_offset(dt: Optional[Union[datetime, date, str]] = None) -> str:
    """
    Timestamp SIFEN sin offset: YYYY-MM-DDTHH:MM:SS en America/Asuncion.
    """
    if isinstance(dt, str):
        local_dt = _parse_sifen_timestamp_str(dt)
    else:
        local_dt = _normalize_sifen_dt(dt)

    local_dt = local_dt.replace(microsecond=0).astimezone(_SIFEN_TZ)
    result = local_dt.strftime(_SIFEN_TS_FMT)
    if not _SIFEN_TS_RE.fullmatch(result):
        raise ValueError(f"Timestamp SIFEN inválido: {result!r}")
    return result


def sifen_date(dt: Optional[Union[datetime, date, str]] = None) -> str:
    """
    Fecha SIFEN (YYYY-MM-DD) en America/Asuncion.
    """
    local_dt = _normalize_sifen_dt(dt)
    return local_dt.strftime(_SIFEN_DATE_FMT)


def validate_certificate_path(cert_path: Path) -> bool:
    """
    Valida que el certificado existe y es accesible
    
    Args:
        cert_path: Ruta al certificado
        
    Returns:
        True si es válido
    """
    if not cert_path.exists():
        return False
    
    # Verificar que sea un archivo (no directorio)
    if not cert_path.is_file():
        return False
    
    # Verificar extensión común de certificados
    valid_extensions = ['.p12', '.pfx', '.pem', '.crt', '.cer']
    if cert_path.suffix.lower() not in valid_extensions:
        # No es un error crítico, pero puede ser una advertencia
        pass
    
    return True


def format_xml_prettily(xml_content: str) -> str:
    """
    Formatea XML de manera legible (indentado)
    
    Args:
        xml_content: XML sin formato
        
    Returns:
        XML formateado
    """
    try:
        import xml.dom.minidom
        dom = xml.dom.minidom.parseString(xml_content)
        return dom.toprettyxml(indent="  ")
    except:
        return xml_content
