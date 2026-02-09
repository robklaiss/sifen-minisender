"""
Modelos de datos para SIFEN
"""
from dataclasses import dataclass
from typing import Optional, Dict, Any, List
from datetime import datetime


@dataclass
class DocumentoElectronico:
    """Modelo base para Documento Electrónico SIFEN"""
    # TODO: Completar con campos reales según esquema XSD oficial
    pass


@dataclass
class SifenResponse:
    """Modelo para respuesta de servicios SIFEN"""
    ok: bool
    status_code: Optional[int] = None
    response: Optional[str] = None
    error: Optional[str] = None
    data: Optional[Dict[str, Any]] = None
    timestamp: Optional[datetime] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


@dataclass
class PrevalidationResult:
    """Resultado de prevalidación"""
    valid: bool
    errors: List[str]
    warnings: List[str]
    response: Optional[str] = None


@dataclass
class DocumentoEstado:
    """Estado de un documento electrónico"""
    identificador: str
    estado: str  # aceptado, rechazado, pendiente, etc.
    fecha_procesamiento: Optional[datetime] = None
    detalles: Optional[Dict[str, Any]] = None

