"""
Generador de Código QR para SIFEN

Según especificación del Manual Técnico SIFEN V150:
1. Concatenar datos del documento
2. Concatenar CSC (solo para hash)
3. Generar hash SHA-256
4. Construir URL final (SIN CSC)
5. Escapar para XML (& -> &amp;)
"""
import os
import hashlib
import logging
from typing import Optional
from urllib.parse import quote

logger = logging.getLogger(__name__)


class QRGeneratorError(Exception):
    """Excepción para errores en la generación de QR"""
    pass


class QRGenerator:
    """
    Generador de URL QR para documentos SIFEN
    
    Reglas críticas:
    - CSC NUNCA se incluye en la URL final
    - CSC solo se usa para generar el hash
    - URL debe escaparse para XML (& -> &amp;)
    """
    
    # URLs base según ambiente
    QR_URL_BASE = {
        'TEST': 'https://www.ekuatia.set.gov.py/consultas-test/qr?',
        'PROD': 'https://www.ekuatia.set.gov.py/consultas/qr?'
    }
    
    def __init__(
        self,
        csc: Optional[str] = None,
        csc_id: Optional[str] = None,
        environment: str = 'TEST'
    ):
        """
        Inicializa el generador de QR
        
        Args:
            csc: Código Secreto del Contribuyente (32 caracteres alfanuméricos)
            csc_id: ID del CSC (4 dígitos, ej: "0001")
            environment: Ambiente ('TEST' o 'PROD')
        """
        # Cargar desde variables de entorno si no se proporcionan
        self.csc = csc or os.getenv("SIFEN_CSC")
        self.csc_id = csc_id or os.getenv("SIFEN_CSC_ID", "0001")
        self.environment = environment.upper() or os.getenv("SIFEN_ENV", "TEST").upper()
        
        if not self.csc:
            raise QRGeneratorError("CSC no especificado. Configure SIFEN_CSC o pase csc")
        
        if len(self.csc) != 32:
            logger.warning(f"CSC debe tener 32 caracteres. Longitud actual: {len(self.csc)}")
        
        if len(self.csc_id) != 4:
            logger.warning(f"CSC ID debe tener 4 dígitos. Valor actual: {self.csc_id}")
        
        if self.environment not in ['TEST', 'PROD']:
            raise QRGeneratorError(f"Ambiente inválido: {self.environment}. Debe ser 'TEST' o 'PROD'")
        
        self.qr_url_base = self.QR_URL_BASE[self.environment]
    
    def generate(
        self,
        d_id: str,
        d_fe_emi: str,
        d_ruc_em: str,
        d_est: str,
        d_pun_exp: str,
        d_num_doc: str,
        d_tipo_doc: str,
        d_tipo_cont: str,
        d_tipo_emi: str,
        d_cod_gen: str = "",
        d_den_suc: str = "",
        d_dv_emi: str = ""
    ) -> dict:
        """
        Genera la URL QR según los pasos del Manual Técnico
        
        Args:
            d_id: Identificador del documento
            d_fe_emi: Fecha de emisión (formato: YYYYMMDD)
            d_ruc_em: RUC del emisor (sin DV)
            d_est: Establecimiento
            d_pun_exp: Punto de expedición
            d_num_doc: Número de documento
            d_tipo_doc: Tipo de documento
            d_tipo_cont: Tipo de contingencia
            d_tipo_emi: Tipo de emisión
            d_cod_gen: Código de generación (opcional)
            d_den_suc: Denominación de sucursal (opcional)
            d_dv_emi: Dígito verificador del emisor (opcional)
        
        Returns:
            Diccionario con:
            - url: URL QR completa (sin escape XML)
            - url_xml: URL QR escapada para XML (& -> &amp;)
            - hash: Hash SHA-256 generado
            - datos: Datos concatenados (sin CSC)
        """
        try:
            # Paso 1: Concatenar datos del documento
            datos = (
                str(d_id) +
                str(d_fe_emi) +
                str(d_ruc_em) +
                str(d_est) +
                str(d_pun_exp) +
                str(d_num_doc) +
                str(d_tipo_doc) +
                str(d_tipo_cont) +
                str(d_tipo_emi) +
                str(d_cod_gen) +
                str(d_den_suc) +
                str(d_dv_emi)
            )
            
            # Paso 2: Concatenar CSC (SOLO para generar hash)
            datos_con_csc = datos + self.csc
            
            # Paso 3: Generar hash SHA-256
            hash_obj = hashlib.sha256(datos_con_csc.encode('utf-8'))
            hash_hex = hash_obj.hexdigest().upper()
            
            # Paso 4: Construir URL final (SIN CSC)
            # Formato: URL_BASE + datos + &cHashQR=hash
            url_params = f"{datos}&cHashQR={hash_hex}"
            url_final = self.qr_url_base + url_params
            
            # Paso 5: Escapar para XML
            url_xml = url_final.replace('&', '&amp;')
            
            logger.info(f"QR generado exitosamente para documento {d_id}")
            # NO loggear CSC ni datos sensibles
            
            return {
                'url': url_final,
                'url_xml': url_xml,
                'hash': hash_hex,
                'datos': datos,  # Datos sin CSC (seguro para logs)
                'csc_id': self.csc_id  # ID del CSC (no es secreto)
            }
        
        except Exception as e:
            raise QRGeneratorError(f"Error al generar QR: {str(e)}")
    
    def sanitize_for_logging(self, url: str) -> str:
        """
        Sanitiza una URL para logging (remueve cualquier referencia a CSC)
        
        Args:
            url: URL a sanitizar
            
        Returns:
            URL sanitizada
        """
        # Ya no debería haber CSC en la URL, pero por seguridad:
        if self.csc and self.csc in url:
            logger.warning("CSC detectado en URL durante sanitización - esto no debería ocurrir")
            url = url.replace(self.csc, "[CSC_REMOVED]")
        
        return url
    
    @staticmethod
    def escape_xml(url: str) -> str:
        """
        Escapa una URL para uso en XML
        
        Args:
            url: URL a escapar
            
        Returns:
            URL escapada (& -> &amp;)
        """
        return url.replace('&', '&amp;')
    
    @staticmethod
    def unescape_xml(url: str) -> str:
        """
        Desescapa una URL desde XML
        
        Args:
            url: URL escapada
            
        Returns:
            URL sin escape (&amp; -> &)
        """
        return url.replace('&amp;', '&')

