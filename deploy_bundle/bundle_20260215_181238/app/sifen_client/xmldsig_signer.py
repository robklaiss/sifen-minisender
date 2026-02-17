"""
Firma XMLDSig para Documentos Electrónicos SIFEN

Implementa firma digital XMLDSig Enveloped según especificación SIFEN:
- Enveloped signature dentro del mismo <DE>
- Reference URI="#<Id del DE>"
- Canonicalization: Exclusive XML Canonicalization (exc-c14n)
- Digest: SHA-256
- SignatureMethod: RSA-SHA256
- Transforms: enveloped-signature + exc-c14n
- X509Certificate en KeyInfo
"""

import logging
import base64
from pathlib import Path
from typing import Optional, Any

# Import lxml.etree - el linter puede no reconocerlo, pero funciona correctamente
try:
    import lxml.etree as etree  # noqa: F401
except ImportError:
    etree = None  # type: ignore

try:
    from signxml.signer import XMLSigner  # noqa: F401
    from signxml.verifier import XMLVerifier  # noqa: F401
    import signxml
    from cryptography.hazmat.backends import default_backend

    SIGNXML_AVAILABLE = True
except ImportError:
    SIGNXML_AVAILABLE = False
    XMLSigner = None  # type: ignore
    XMLVerifier = None  # type: ignore
    signxml = None  # type: ignore

from .pkcs12_utils import p12_to_temp_pem_files, cleanup_pem_files, PKCS12Error
from .exceptions import SifenClientError

logger = logging.getLogger(__name__)

# Namespaces
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"


class XMLDSigError(SifenClientError):
    """Excepción para errores en firma XMLDSig"""

    pass


def _extract_de_id(xml_root: Any) -> Optional[str]:  # type: ignore
    """Extrae el atributo Id del elemento DE."""
    if etree is None:
        raise XMLDSigError("lxml no está disponible")
    # Buscar DE (puede estar en rDE o directamente)
    de_elem = None
    
    # Buscar directamente DE
    for elem in xml_root.iter():  # type: ignore
        local_name = etree.QName(elem).localname  # type: ignore
        if local_name == "DE":
            de_elem = elem
            break

    if de_elem is None:
        return None

    # Obtener Id (puede ser atributo Id o id)
    de_id = de_elem.get("Id") or de_elem.get("id")
    return de_id


def _validate_no_dummy_signature(xml_str: str) -> None:
    """Valida que no haya firmas dummy en el XML."""
    try:
        if etree is None:
            return
        # Buscar SignatureValue
        if "<ds:SignatureValue>" in xml_str or "<SignatureValue>" in xml_str:
            # Parsear y extraer SignatureValue
            root = etree.fromstring(xml_str.encode("utf-8"))  # type: ignore

            # Buscar SignatureValue en namespace DS
            ns = {"ds": DS_NS}
            sig_values = root.xpath("//ds:SignatureValue", namespaces=ns)

            for sig_val_elem in sig_values:
                if sig_val_elem.text:
                    try:
                        # Decodificar base64
                        decoded = base64.b64decode(sig_val_elem.text.strip())
                        decoded_str = decoded.decode("ascii", errors="ignore")

                        # Verificar si es texto dummy
                        if (
                            "this is a test" in decoded_str.lower()
                            or "dummy" in decoded_str.lower()
                        ):
                            raise XMLDSigError(
                                "Se detectó firma dummy en el XML. "
                                "El SignatureValue contiene texto de prueba. "
                                "Debe usar un certificado real para firmar."
                            )
                    except Exception:
                        # Si no se puede decodificar,
                        # asumir que es válido (binario real)
                        pass
    except Exception as e:
        # Si falla la validación, solo loggear warning (no abortar)
        logger.warning(f"No se pudo validar firma dummy: {e}")


def sign_de_xml(xml_str: str, p12_path: str, p12_password: str) -> str:
    """
    Firma un XML DE con XMLDSig según especificación SIFEN.

    Args:
        xml_str: XML del DE (puede incluir rDE wrapper)
        p12_path: Ruta al certificado P12/PFX
        p12_password: Contraseña del certificado P12

    Returns:
        XML firmado con ds:Signature

    Raises:
        XMLDSigError: Si falta signxml, certificado, o falla la firma
    """
    if not SIGNXML_AVAILABLE:
        raise XMLDSigError(
            "signxml no está instalado. Instale con: pip install signxml"
        )

    p12_path_obj = Path(p12_path)
    if not p12_path_obj.exists():
        raise XMLDSigError(f"Certificado P12 no encontrado: {p12_path}")

    if etree is None:
        raise XMLDSigError("lxml no está disponible")
    # Parsear XML
    try:
        xml_root = etree.fromstring(xml_str.encode("utf-8"))  # type: ignore
    except Exception as e:
        raise XMLDSigError(f"Error al parsear XML: {e}")

    # Extraer Id del DE
    de_id = _extract_de_id(xml_root)
    if not de_id:
        raise XMLDSigError("No se encontró atributo Id en el elemento DE")

    logger.info(f"Firmando DE con Id={de_id}")

    # Convertir P12 a PEM temporales
    cert_pem_path = None
    key_pem_path = None
    try:
        cert_pem_path, key_pem_path = p12_to_temp_pem_files(p12_path, p12_password)

        # Leer certificado y clave
        with open(cert_pem_path, "rb") as f:
            cert_pem = f.read()

        with open(key_pem_path, "rb") as f:
            key_pem = f.read()

        # Cargar certificado y clave privada
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
        private_key = serialization.load_pem_private_key(
            key_pem, None, default_backend()
        )

        # Encontrar el elemento DE a firmar
        de_elem = None
        for elem in xml_root.iter():  # type: ignore
            local_name = etree.QName(elem).localname  # type: ignore
            if local_name == "DE":
                de_elem = elem
                break

        if de_elem is None:
            raise XMLDSigError("No se encontró elemento DE en el XML")

        # Eliminar firma dummy existente si existe
        # Buscar ds:Signature dentro del DE
        ds_ns = "http://www.w3.org/2000/09/xmldsig#"
        ns = {"ds": ds_ns}
        existing_signatures = de_elem.xpath(".//ds:Signature", namespaces=ns)
        for sig in existing_signatures:
            parent = sig.getparent()
            if parent is not None:
                parent.remove(sig)
                logger.info("Firma dummy existente eliminada antes de firmar")

        # Firmar usando signxml
        # signxml requiere que el elemento tenga el atributo Id como ID válido
        # Asegurar que el atributo Id esté marcado como ID
        de_elem.set("Id", de_id)

        # Registrar el atributo Id como ID válido para XML
        # Esto es necesario para que la referencia URI funcione
        # signxml usa el atributo Id automáticamente si está presente

        # Crear signer con configuración SIFEN v150
        # IMPORTANTE: SIFEN v150 requiere RSA-SHA256 y SHA-256 (NO rsa-sha1/sha1)
        if signxml is None or signxml.methods is None:
            raise XMLDSigError("signxml no está disponible correctamente")
        signer = XMLSigner(  # type: ignore
            method=signxml.methods.enveloped,  # Enveloped signature
            signature_algorithm="rsa-sha256",  # RSA-SHA256 (SIFEN v150)
            digest_algorithm="sha256",  # SHA-256 (SIFEN v150)
            c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#",  # exc-c14n (SIFEN v150)
        )

        # Firmar el elemento DE
        # reference_uri debe apuntar al Id del DE (formato: #Id)
        # signxml agrega ds:Signature como hijo del elemento firmado
        # Los transforms se configuran automáticamente:
        # enveloped-signature + exc-c14n
        # id_attribute="Id" le dice a signxml que use el atributo "Id" como ID
        signed_de = signer.sign(  # type: ignore
            de_elem,
            key=private_key,  # type: ignore[arg-type]
            cert=cert,  # type: ignore[arg-type]
            reference_uri=f"#{de_id}",
            id_attribute="Id",  # Atributo que contiene el ID
            always_add_key_value=False,
        )

        # Reemplazar el DE original con el firmado
        # El DE firmado ahora tiene ds:Signature como hijo
        parent = de_elem.getparent()
        if parent is not None:
            # Reemplazar en el parent
            parent.remove(de_elem)
            parent.append(signed_de)
        else:
            # Si DE es root, usar signed_de como nuevo root
            xml_root = signed_de

        # Serializar XML firmado
        signed_xml = etree.tostring(
            xml_root, xml_declaration=True, encoding="UTF-8", pretty_print=False
        ).decode("utf-8")

        # Validar que no haya firmas dummy
        _validate_no_dummy_signature(signed_xml)

        logger.info("DE firmado exitosamente con XMLDSig")
        return signed_xml

    except PKCS12Error as e:
        raise XMLDSigError(f"Error al convertir certificado P12: {e}") from e
    except Exception as e:
        raise XMLDSigError(f"Error al firmar XML: {e}") from e
    finally:
        # Limpiar archivos PEM temporales
        if cert_pem_path and key_pem_path:
            cleanup_pem_files(cert_pem_path, key_pem_path)
