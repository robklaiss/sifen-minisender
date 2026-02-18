"""
Excepciones personalizadas para el cliente SIFEN
"""
from typing import Optional


class SifenException(Exception):
    """Excepción base para errores SIFEN"""
    def __init__(self, message: str, code: Optional[str] = None):
        self.message = message
        self.code = code
        super().__init__(self.message)


class SifenClientError(SifenException):
    """Error del cliente SIFEN"""
    pass


class SifenValidationError(SifenException):
    """Error de validación (tamaño, formato, etc.)"""
    pass


class SifenSignatureError(SifenException):
    """Error en la firma digital"""
    pass


class SifenQRError(SifenException):
    """Error en la generación de QR"""
    pass


class SifenSizeLimitError(SifenValidationError):
    """Error cuando se excede el límite de tamaño"""
    def __init__(self, service: str, size: int, limit: int, code: str):
        self.service = service
        self.size = size
        self.limit = limit
        self.code = code
        message = f"Servicio {service}: tamaño {size} bytes excede límite de {limit} bytes (código: {code})"
        super().__init__(message, code)


class SifenResponseError(SifenException):
    """Error en la respuesta de SIFEN"""
    def __init__(self, message: str, code: str, http_status: Optional[int] = None):
        self.http_status = http_status
        super().__init__(message, code)

