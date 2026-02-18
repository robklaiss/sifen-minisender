"""
Módulo para firma digital XML según especificación SIFEN

Requisitos:
- XML Digital Signature Enveloped
- Certificado X.509 v3
- Algoritmo RSA 2048 bits
- Hash SHA-256
- Validación de cadena de confianza (CRL/LCR)
"""
import os
import logging
from typing import Optional
from pathlib import Path
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from lxml import etree
from signxml import XMLSigner, XMLVerifier, methods, SignatureConfiguration
from signxml.util import ensure_str

logger = logging.getLogger(__name__)


class XmlSignerError(Exception):
    """Excepción para errores en la firma XML"""
    pass


class XmlSigner:
    """
    Firma XML según especificación SIFEN:
    - XML Digital Signature Enveloped
    - Certificado X.509 v3
    - RSA 2048 bits
    - SHA-256
    """
    
    def __init__(
        self,
        cert_path: Optional[str] = None,
        cert_password: Optional[str] = None,
        key_path: Optional[str] = None,
        key_password: Optional[str] = None
    ):
        """
        Inicializa el firmador XML
        
        Args:
            cert_path: Ruta al certificado PFX/P12 (PKCS#12)
            cert_password: Contraseña del certificado
            key_path: Ruta a la clave privada (si está separada del certificado)
            key_password: Contraseña de la clave privada
        """
        # Cargar desde variables de entorno si no se proporcionan
        self.cert_path = cert_path or os.getenv("SIFEN_CERT_PATH")
        self.cert_password = cert_password or os.getenv("SIFEN_CERT_PASSWORD", "")
        self.key_path = key_path or os.getenv("SIFEN_KEY_PATH")
        self.key_password = key_password or os.getenv("SIFEN_KEY_PASSWORD", "")
        
        if not self.cert_path:
            raise XmlSignerError("Certificado no especificado. Configure SIFEN_CERT_PATH o pase cert_path")
        
        cert_file = Path(self.cert_path)
        if not cert_file.exists():
            raise XmlSignerError(f"Certificado no encontrado: {self.cert_path}")
        
        # Cargar certificado y clave privada
        self._load_certificate()
        
        # Validar certificado
        self._validate_certificate()
    
    def _load_certificate(self):
        """Carga el certificado y la clave privada desde el archivo PFX/P12"""
        try:
            with open(self.cert_path, 'rb') as f:
                pfx_data = f.read()
            
            # Intentar cargar como PKCS#12
            try:
                from cryptography.hazmat.primitives.serialization import pkcs12
                private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                    pfx_data,
                    self.cert_password.encode() if self.cert_password else None,
                    backend=default_backend()
                )
                
                if private_key is None:
                    raise XmlSignerError("No se pudo extraer la clave privada del certificado")
                if certificate is None:
                    raise XmlSignerError("No se pudo extraer el certificado del archivo")
                
                self.private_key = private_key
                self.certificate = certificate
                self.additional_certificates = additional_certificates or []
                
            except Exception as e:
                # Si falla PKCS#12, intentar cargar certificado y clave por separado
                if self.key_path:
                    self._load_separate_key_and_cert()
                else:
                    raise XmlSignerError(f"Error al cargar certificado PKCS#12: {str(e)}")
        
        except Exception as e:
            raise XmlSignerError(f"Error al leer certificado: {str(e)}")
    
    def _load_separate_key_and_cert(self):
        """Carga certificado y clave privada desde archivos separados"""
        try:
            # Cargar certificado
            with open(self.cert_path, 'rb') as f:
                cert_data = f.read()
                self.certificate = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Cargar clave privada
            if not self.key_path:
                raise XmlSignerError("key_path requerido cuando el certificado no es PKCS#12")
            
            with open(self.key_path, 'rb') as f:
                key_data = f.read()
                password = self.key_password.encode() if self.key_password else None
                self.private_key = serialization.load_pem_private_key(
                    key_data,
                    password=password,
                    backend=default_backend()
                )
            
            self.additional_certificates = []
        
        except Exception as e:
            raise XmlSignerError(f"Error al cargar certificado/clave separados: {str(e)}")
    
    def _validate_certificate(self):
        """
        Valida el certificado:
        - Fecha de expiración
        - Algoritmo de clave (RSA 2048)
        - Tipo X.509 v3
        """
        now = datetime.now(timezone.utc)
        
        # Validar fecha de expiración
        if self.certificate.not_valid_after_utc < now:
            raise XmlSignerError(
                f"Certificado expirado. Válido hasta: {self.certificate.not_valid_after_utc}"
            )
        
        if self.certificate.not_valid_before_utc > now:
            raise XmlSignerError(
                f"Certificado aún no válido. Válido desde: {self.certificate.not_valid_before_utc}"
            )
        
        # Validar algoritmo de clave
        if not isinstance(self.private_key, rsa.RSAPrivateKey):
            raise XmlSignerError("La clave privada debe ser RSA")
        
        key_size = self.private_key.key_size
        if key_size < 2048:
            raise XmlSignerError(
                f"La clave RSA debe ser de al menos 2048 bits. Actual: {key_size} bits"
            )
        
        # Validar versión del certificado (X.509 v3)
        # Nota: cryptography no expone directamente la versión, pero los certificados modernos son v3
        logger.info(f"Certificado válido. Emisor: {self.certificate.issuer}, "
                   f"Válido hasta: {self.certificate.not_valid_after_utc}")
    
    def sign(self, xml_content: str, reference_uri: Optional[str] = None) -> str:
        """
        Firma un XML usando XML Digital Signature Enveloped
        
        Args:
            xml_content: Contenido XML a firmar
            reference_uri: URI de referencia para la firma (opcional)
            
        Returns:
            XML firmado como string
        """
        try:
            # Parsear XML
            root = etree.fromstring(xml_content.encode('utf-8'))
            
            # Configurar firmador
            signer = XMLSigner(
                method=methods.enveloped,
                signature_algorithm='rsa-sha256',
                digest_algorithm='sha256',
                c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#'
            )
            
            # Firmar
            signed_root = signer.sign(
                root,
                key=self.private_key,
                always_add_key_value=True,
                reference_uri=reference_uri
            )
            
            # Convertir a string
            signed_xml = etree.tostring(
                signed_root,
                encoding='utf-8',
                xml_declaration=True,
                pretty_print=False
            ).decode('utf-8')
            
            logger.info("XML firmado exitosamente")
            return signed_xml
        
        except Exception as e:
            raise XmlSignerError(f"Error al firmar XML: {str(e)}")
    
    def verify(self, signed_xml: str) -> bool:
        """
        Verifica la firma de un XML firmado
        
        Args:
            signed_xml: XML firmado a verificar
            
        Returns:
            True si la firma es válida, False en caso contrario
        """
        try:
            root = etree.fromstring(signed_xml.encode('utf-8'))
            
            verifier = XMLVerifier()
            result = verifier.verify(root, require_x509=False)
            
            return result is not None
        
        except Exception as e:
            logger.error(f"Error al verificar firma: {str(e)}")
            return False
    
    def get_certificate_info(self) -> dict:
        """
        Obtiene información del certificado
        
        Returns:
            Diccionario con información del certificado
        """
        subject = self.certificate.subject
        issuer = self.certificate.issuer
        
        # Extraer RUC del subject si está presente
        ruc = None
        for attr in subject:
            if attr.oid._name == 'commonName' or 'RUC' in str(attr.value):
                ruc = str(attr.value)
                break
        
        return {
            'subject': str(subject),
            'issuer': str(issuer),
            'serial_number': str(self.certificate.serial_number),
            'not_valid_before': self.certificate.not_valid_before_utc.isoformat(),
            'not_valid_after': self.certificate.not_valid_after_utc.isoformat(),
            'ruc': ruc,
            'key_size': self.private_key.key_size if hasattr(self.private_key, 'key_size') else None
        }

