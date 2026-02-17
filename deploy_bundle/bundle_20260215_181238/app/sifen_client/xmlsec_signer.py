"""
Firma XMLDSig para Documentos Electrónicos SIFEN usando python-xmlsec

Implementa firma digital XMLDSig Enveloped según especificación SIFEN v150:
- Enveloped signature dentro del mismo <DE>
- Reference URI="#<Id del DE>"
- Canonicalization: Exclusive XML Canonicalization (exc-c14n)
- Digest: SHA-1 (según ejemplos Roshka)
- SignatureMethod: RSA-SHA1 (según ejemplos Roshka)
- Transforms: enveloped-signature + exc-c14n
- X509Certificate en KeyInfo
"""

import logging
import os
from pathlib import Path
from typing import Optional, Any

# Import lxml.etree - el linter puede no reconocerlo, pero funciona correctamente
try:
    import lxml.etree as etree  # noqa: F401
except ImportError:
    etree = None  # type: ignore

try:
    import xmlsec

    XMLSEC_AVAILABLE = True
except ImportError:
    XMLSEC_AVAILABLE = False
    xmlsec = None

try:
    from cryptography.hazmat.primitives.serialization import (
        pkcs12,
        Encoding,
    )
    from cryptography.hazmat.backends import default_backend

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    pkcs12 = None

from .pkcs12_utils import p12_to_temp_pem_files, cleanup_pem_files, PKCS12Error
from .exceptions import SifenClientError

logger = logging.getLogger(__name__)

# Namespaces
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"  # Alias para claridad
SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"
XMLNS_NS = "http://www.w3.org/2000/xmlns/"  # Namespace para atributos xmlns


class XMLSecError(SifenClientError):
    """Excepción para errores en firma XMLDSig con xmlsec"""

    pass


def _force_signature_default_namespace(sig: Any) -> Any:  # type: ignore
    """
    Convierte <ds:Signature> o <Signature ns0:...> a:
      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#"> ... </Signature>
    preservando todos los hijos.
    """
    if etree is None:
        raise XMLSecError("lxml no está disponible")
    # ya está ok si no tiene prefijo y tiene default ns a DS_NS
    if (
        (sig.prefix is None)
        and (sig.nsmap.get(None) == DS_NS)
        and (sig.tag == f"{{{DS_NS}}}Signature")
    ):
        return sig

    parent = sig.getparent()
    if parent is None:
        raise RuntimeError(
            "Signature no tiene parent, no se puede normalizar namespace"
        )

    # construir Signature con default xmlns (sin prefijo)
    sig2 = etree.Element(f"{{{DS_NS}}}Signature", nsmap={None: DS_NS})  # type: ignore

    # mover hijos (SignedInfo, SignatureValue, KeyInfo, etc.)
    for child in list(sig):
        sig.remove(child)
        sig2.append(child)

    # preservar tail
    sig2.tail = sig.tail

    # reemplazar en el mismo lugar
    idx = parent.index(sig)
    parent.remove(sig)
    parent.insert(idx, sig2)
    return sig2


def _force_signature_default_ns(sig_node: Any) -> Any:  # type: ignore
    """
    Reemplaza <ds:Signature> por <Signature xmlns="DSIG_NS"> preservando hijos.
    """
    if etree is None:
        raise XMLSecError("lxml no está disponible")
    parent = sig_node.getparent()
    if parent is None:
        return sig_node

    # Crear Signature con namespace default (sin prefijo)
    new_sig = etree.Element(f"{{{DSIG_NS}}}Signature", nsmap={None: DSIG_NS})  # type: ignore
    new_sig.text = sig_node.text
    new_sig.tail = sig_node.tail

    # Mover hijos
    for ch in list(sig_node):
        sig_node.remove(ch)
        new_sig.append(ch)

    # Reemplazar en el padre manteniendo posición
    idx = parent.index(sig_node)
    parent.remove(sig_node)
    parent.insert(idx, new_sig)
    return new_sig


def _force_dsig_default_namespace(sig: Any) -> Any:  # type: ignore
    """
    Convierte <ds:Signature ...> a:
      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#"> ... </Signature>
    sin cambiar contenido (solo cómo serializa el namespace).
    """
    if etree is None:
        raise XMLSecError("lxml no está disponible")
    parent = sig.getparent()

    sig2 = etree.Element(f"{{{DSIG_NS}}}Signature", nsmap={None: DSIG_NS})  # type: ignore

    # copiar atributos si hubiera
    for k, v in sig.attrib.items():
        sig2.set(k, v)

    # copiar text y tail
    sig2.text = sig.text
    sig2.tail = sig.tail

    # mover hijos
    for child in list(sig):
        sig.remove(child)
        sig2.append(child)

    if parent is not None:
        parent.replace(sig, sig2)

    return sig2


def force_signature_default_ns(sig: Any) -> Any:  # type: ignore
    """
    Función robusta para forzar que Signature quede en DEFAULT namespace (sin prefijo).
    Convierte <ds:Signature> o cualquier Signature con prefijo a:
      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
    preservando todos los hijos, atributos, .text y .tail.

    Esta función:
    1) Encuentra la Signature por namespace-uri y local-name (no por prefijo)
    2) Crea un nodo nuevo con default namespace DS
    3) Copia atributos y conserva text/tail
    4) Mueve todos los hijos (mover, no copiar)
    5) Reemplaza el nodo en el padre manteniendo la posición
    """
    if etree is None:
        raise XMLSecError("lxml no está disponible")
    parent = sig.getparent()
    if parent is None:
        raise XMLSecError("Signature no tiene parent, no se puede normalizar namespace")

    # Crear nuevo nodo <Signature xmlns="DS_NS"> sin prefijo
    # Usar nsmap={None: DS_NS} para forzar default namespace
    new_sig = etree.Element(etree.QName(DS_NS, "Signature"), nsmap={None: DS_NS})  # type: ignore

    # Copiar atributos
    for k, v in sig.attrib.items():
        new_sig.set(k, v)

    # Conservar text/tail
    new_sig.text = sig.text
    new_sig.tail = sig.tail

    # Mover todos los hijos (mover, no copiar)
    # Esto preserva SignedInfo, SignatureValue, KeyInfo, etc.
    for child in list(sig):
        sig.remove(child)
        new_sig.append(child)

    # Reemplazar el nodo en el padre manteniendo la posición
    # Usar list(parent) para obtener índice correcto
    children_list = list(parent)
    try:
        idx = children_list.index(sig)
    except ValueError:
        # Si no se encuentra en la lista, usar append
        idx = len(children_list)

    parent.remove(sig)
    parent.insert(idx, new_sig)

    return new_sig


def _force_signature_default_ds_namespace(sig: Any) -> Any:  # type: ignore
    """
    Convierte <ds:Signature ...> en <Signature xmlns="DS_NS"> preservando hijos/attrs.
    IMPORTANTE: en lxml el "prefijo" no está en el tag, depende del nsmap al serializar.
    """
    if etree is None:
        raise XMLSecError("lxml no está disponible")
    parent = sig.getparent()
    if parent is None:
        return sig

    # Nuevo nodo Signature con default namespace = DS_NS
    new_sig = etree.Element(etree.QName(DS_NS, "Signature"), nsmap={None: DS_NS})  # type: ignore

    # Copiar atributos si existieran
    for k, v in sig.attrib.items():
        new_sig.set(k, v)

    # Mover hijos (preserva SignedInfo/KeyInfo/etc ya armados por xmlsec)
    for child in list(sig):
        sig.remove(child)
        new_sig.append(child)

    # Reemplazar en el parent manteniendo posición
    idx = parent.index(sig)
    parent.remove(sig)
    parent.insert(idx, new_sig)
    return new_sig


def _extract_de_id(xml_root: Any) -> Optional[str]:  # type: ignore
    """Extrae el atributo Id del elemento DE."""
    if etree is None:
        raise XMLSecError("lxml no está disponible")
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


def _strip_xmlns_prefix(tree, prefix: str) -> None:
    """
    Elimina el atributo xmlns:<prefix> de todos los elementos del árbol XML.

    Doc SIFEN: "no se podrá utilizar prefijos de namespace" - eliminar xmlns:ds del root y todo el doc
    La única declaración del namespace ds debe estar en <Signature xmlns="...">, NO en el root.

    Args:
        tree: Árbol XML (lxml.etree._ElementTree)
        prefix: Prefijo a eliminar (ej: "ds")
    """
    XMLNS_NS = "http://www.w3.org/2000/xmlns/"
    attr = f"{{{XMLNS_NS}}}{prefix}"
    root = tree.getroot()
    for el in root.iter():
        if attr in el.attrib:
            del el.attrib[attr]


def sign_de_with_p12(xml_bytes: bytes, p12_path: str, p12_password: str) -> bytes:
    """
    Firma un XML DE con XMLDSig usando python-xmlsec según especificación SIFEN v150.

    Args:
        xml_bytes: XML del DE/rEnviDe como bytes
        p12_path: Ruta al certificado P12/PFX
        p12_password: Contraseña del certificado P12

    Returns:
        XML firmado como bytes

    Raises:
        XMLSecError: Si falta xmlsec, certificado, o falla la firma
    """
    if not XMLSEC_AVAILABLE:
        raise XMLSecError(
            "python-xmlsec no está instalado. Instale con: pip install python-xmlsec"
        )

    if not CRYPTOGRAPHY_AVAILABLE:
        raise XMLSecError(
            "cryptography no está instalado. Instale con: pip install cryptography"
        )

    p12_path_obj = Path(p12_path)
    if not p12_path_obj.exists():
        raise XMLSecError(f"Certificado P12 no encontrado: {p12_path}")

    if etree is None:
        raise XMLSecError("lxml no está disponible")
    # 1) Parsear XML con parser que no elimine espacios en blanco
    try:
        parser = etree.XMLParser(remove_blank_text=False)  # type: ignore
        root = etree.fromstring(xml_bytes, parser=parser)  # type: ignore
    except Exception as e:
        raise XMLSecError(f"Error al parsear XML: {e}")

    # Obtener tree completo
    tree = root.getroottree()

    # 1.1) ANTES de firmar, eliminar del árbol cualquier declaración de prefijo "ds" heredada
    # Doc SIFEN: "no se podrá utilizar prefijos de namespace" - limpiar ANTES de ctx.sign()
    # Si el elemento raíz (o cualquier ancestro relevante) tiene nsmap con 'ds': DS_NS, eliminarlo
    def remove_ds_prefix_from_tree(elem: Any) -> None:  # type: ignore
        """Elimina el prefijo 'ds' del nsmap de un elemento y sus ancestros relevantes"""
        # Limpiar nsmap del elemento actual si tiene prefijo 'ds'
        if elem.nsmap and "ds" in elem.nsmap:
            # No podemos modificar nsmap directamente, pero podemos limpiar namespaces
            # El cleanup_namespaces se hará después, pero aquí marcamos para limpiar
            pass
        # Recursivamente limpiar hijos
        for child in elem:
            remove_ds_prefix_from_tree(child)

    # Limpiar namespaces del árbol completo para eliminar prefijos "ds" heredados
    etree.cleanup_namespaces(tree)  # type: ignore  # type: ignore

    # 2) Encontrar el <DE> correcto por XPath con namespace SIFEN o sin namespace fallback
    ds_ns = "http://www.w3.org/2000/09/xmldsig#"
    ns = {"ds": ds_ns, "sifen": SIFEN_NS}

    # Buscar DE con namespace SIFEN
    de = None
    de_list = root.xpath("//sifen:DE", namespaces=ns)
    if de_list:
        de = de_list[0]
    else:
        # Fallback: buscar sin namespace
        de_list = root.xpath("//DE")
        if de_list:
            de = de_list[0]

    if de is None:
        raise XMLSecError("No se encontró elemento DE en el XML")

    # Obtener de_id y validar que exista
    de_id = de.get("Id") or de.get("id")
    if not de_id:
        raise XMLSecError("El elemento DE no tiene atributo Id")

    logger.info(f"Firmando DE con Id={de_id}")

    # 3) Asegurar wrapper <rDE> dentro de <xDE> y que <DE> esté dentro de <rDE>
    parent = de.getparent()
    if parent is None:
        raise XMLSecError("DE no tiene parent (no existe rDE/xDE?)")

    # Verificar si el parent es rDE (local name)
    def get_local_name(tag: str) -> str:
        """Extrae el nombre local de un tag (sin namespace)"""
        if "}" in tag:
            return tag.split("}")[1]
        return tag

    parent_local = get_local_name(parent.tag)

    # Namespace XSI para schemaLocation
    XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"

    # Si el parent NO es rDE, buscar rDE o crearlo
    rde = None
    if parent_local == "rDE":
        rde = parent
        logger.debug("DE ya está dentro de rDE")
    else:
        # Buscar rDE en el árbol (puede estar en el root o dentro de xDE)
        rde_list = root.xpath("//sifen:rDE", namespaces=ns)
        if not rde_list:
            rde_list = root.xpath("//rDE")

        if rde_list:
            rde = rde_list[0]
            logger.debug("rDE encontrado en el árbol")
        else:
            # Si no existe rDE, crearlo y mover DE dentro
            # El parent actual puede ser xDE o el root
            # rDE debe tener xmlns:xsi y xsi:schemaLocation
            rde = etree.Element(  # type: ignore
                f"{{{SIFEN_NS}}}rDE", nsmap={None: SIFEN_NS, "xsi": XSI_NS}
            )
            rde.set(
                f"{{{XSI_NS}}}schemaLocation",
                "http://ekuatia.set.gov.py/sifen/xsd/siRecepDE_v150.xsd",
            )

            # Remover DE del parent actual
            parent.remove(de)

            # Mover DE dentro de rDE
            rde.append(de)

            # Insertar rDE en el parent original
            parent.append(rde)

            logger.info(
                "Creado wrapper rDE alrededor de DE con xmlns:xsi y xsi:schemaLocation"
            )

    # Asegurar que DE esté dentro de rDE
    if de.getparent() is not rde:
        # DE no está en rDE, moverlo
        old_parent = de.getparent()
        if old_parent is not None:
            old_parent.remove(de)
        rde.append(de)
        logger.info("DE movido dentro de rDE")

    # Asegurar que rDE tenga xmlns:xsi y xsi:schemaLocation
    if not rde.get(f"{{{XSI_NS}}}schemaLocation"):
        rde.set(
            f"{{{XSI_NS}}}schemaLocation",
            "http://ekuatia.set.gov.py/sifen/xsd/siRecepDE_v150.xsd",
        )
        # Asegurar que xsi esté en nsmap
        if "xsi" not in (rde.nsmap or {}):
            # Actualizar nsmap (lxml no permite modificar nsmap directamente, pero podemos recrear)
            current_nsmap = rde.nsmap.copy() if rde.nsmap else {}
            current_nsmap["xsi"] = XSI_NS
            # Nota: lxml maneja nsmap automáticamente al serializar si los atributos están presentes

    # BORRAR firmas existentes dentro de rDE (cualquier nodo Signature en DS namespace)
    for old in rde.xpath(
        f".//*[local-name()='Signature' and namespace-uri()='{ds_ns}']"
    ):
        old_parent = old.getparent()
        if old_parent is not None:
            old_parent.remove(old)
            logger.info("Firma existente eliminada antes de firmar")

    # Eliminar xmlns:ds de todo el árbol antes de crear la firma
    # Doc SIFEN: "no se podrá utilizar prefijos de namespace" - la única declaración debe estar en <Signature>
    _strip_xmlns_prefix(tree, "ds")  # ✅ mata xmlns:ds del root y de todo el doc
    etree.cleanup_namespaces(tree)  # type: ignore  # type: ignore  # ✅ limpia lo que queda

    # Registrar el atributo Id como ID (IMPORTANTÍSIMO para Reference URI)
    if xmlsec is None:
        raise XMLSecError("xmlsec no está disponible")
    xmlsec.tree.add_ids(tree, ["Id"])  # type: ignore

    # 4) Construir explícitamente el árbol de firma usando lxml con default namespace
    # Doc SIFEN: "no se podrá utilizar prefijos de namespace" - construir SIN prefijo desde el inicio
    # Enfoque: NO usar xmlsec.template.create (fuerza prefijo ds), construir manualmente con lxml
    # Doc SIFEN: "la declaración namespace de la firma digital debe realizarse en la etiqueta <Signature>"
    try:
        # Crear nodo Signature con default namespace (nsmap={None: DS_NS})
        # Esto asegura que serialice como "<Signature xmlns="http://www.w3.org/2000/09/xmldsig#">"
        sig = etree.Element(etree.QName(DS_NS, "Signature"), nsmap={None: DS_NS})  # type: ignore

        # Construir SignedInfo
        signed_info = etree.SubElement(sig, etree.QName(DS_NS, "SignedInfo"))  # type: ignore

        # CanonicalizationMethod: xml-exc-c14n (según ejemplo Roshka)
        canon_method = etree.SubElement(  # type: ignore
            signed_info, etree.QName(DS_NS, "CanonicalizationMethod")  # type: ignore
        )
        canon_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

        # SignatureMethod: rsa-sha256 (xmldsig-more) según doc SIFEN v150
        sig_method = etree.SubElement(  # type: ignore
            signed_info, etree.QName(DS_NS, "SignatureMethod")  # type: ignore
        )
        sig_method.set("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

        # Reference con URI="#<Id>"
        ref = etree.SubElement(signed_info, etree.QName(DS_NS, "Reference"))  # type: ignore
        ref.set("URI", f"#{de_id}")

        # Transforms: enveloped-signature + xml-exc-c14n
        transforms = etree.SubElement(ref, etree.QName(DS_NS, "Transforms"))  # type: ignore
        transform1 = etree.SubElement(transforms, etree.QName(DS_NS, "Transform"))  # type: ignore
        transform1.set(
            "Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
        )
        transform2 = etree.SubElement(transforms, etree.QName(DS_NS, "Transform"))  # type: ignore
        transform2.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

        # DigestMethod: sha256 según doc SIFEN v150
        digest_method = etree.SubElement(ref, etree.QName(DS_NS, "DigestMethod"))  # type: ignore
        digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")

        # DigestValue (se calculará al firmar)
        etree.SubElement(ref, etree.QName(DS_NS, "DigestValue"))  # type: ignore

        # SignatureValue (se calculará al firmar)
        etree.SubElement(sig, etree.QName(DS_NS, "SignatureValue"))  # type: ignore

        # KeyInfo / X509Data / X509Certificate
        key_info = etree.SubElement(sig, etree.QName(DS_NS, "KeyInfo"))  # type: ignore
        x509_data = etree.SubElement(key_info, etree.QName(DS_NS, "X509Data"))  # type: ignore
        x509_cert = etree.SubElement(x509_data, etree.QName(DS_NS, "X509Certificate"))  # type: ignore
        # El certificado se agregará al firmar

        logger.debug(
            "Árbol de firma construido manualmente con default namespace (sin prefijo ds:)"
        )
    except Exception as e:
        raise XMLSecError(f"Error al construir árbol de firma: {e}")

    # Insertar signature como hermano de DE dentro de rDE, justo después de </DE>
    # Doc SIFEN: Signature debe ir como HERMANO de DE dentro de rDE, inmediatamente después de </DE>
    # Encontrar índice de DE dentro de rDE e insertar después (parent.insert(idx_de+1, sig))
    try:
        idx = list(rde).index(de)
        rde.insert(idx + 1, sig)
        logger.debug(f"Firma insertada como hermano de DE en rDE (índice {idx + 1})")
    except (ValueError, IndexError) as e:
        # Fallback: append al final de rDE
        rde.append(sig)
        logger.warning(
            f"No se pudo insertar firma después de DE, se agregó al final: {e}"
        )

    # 8) Cargar key/cert desde PEM (ya existen temporales desde P12) y firmar
    cert_pem_path = None
    key_pem_path = None
    ctx = None
    try:
        cert_pem_path, key_pem_path = p12_to_temp_pem_files(p12_path, p12_password)

        if xmlsec is None:
            raise XMLSecError("xmlsec no está disponible")
        # Cargar key+cert desde PEM
        key = xmlsec.Key.from_file(key_pem_path, xmlsec.KeyFormat.PEM)  # type: ignore
        key.load_cert_from_file(cert_pem_path, xmlsec.KeyFormat.PEM)  # type: ignore

        # Cargar certificado principal desde P12 para agregarlo al X509Certificate
        cert_obj = None
        try:
            with open(p12_path, "rb") as f:
                p12_bytes = f.read()
            password_bytes = p12_password.encode("utf-8") if p12_password else None
            if pkcs12 is None:
                raise XMLSecError("cryptography no está disponible")
            key_obj, cert_obj, addl_certs = pkcs12.load_key_and_certificates(  # type: ignore
                p12_bytes, password_bytes, backend=default_backend()
            )
            # Cargar certificados adicionales si existen
            if addl_certs:
                for addl_cert in addl_certs:
                    try:
                        addl_cert_pem = addl_cert.public_bytes(Encoding.PEM)
                        key.load_cert_from_memory(
                            addl_cert_pem,
                            xmlsec.KeyFormat.PEM,  # type: ignore
                        )
                    except Exception as e:
                        logger.warning(f"No se pudo cargar certificado adicional: {e}")
        except ValueError:
            # Si cryptography falla, continuar sin certificados adicionales
            logger.debug(
                "No se pudieron cargar certificados del P12 con cryptography, usando xmlsec key"
            )

        # Agregar certificado al X509Certificate en el template manual (antes de firmar)
        # xmlsec calculará DigestValue y SignatureValue automáticamente al firmar
        if cert_obj:
            cert_pem = cert_obj.public_bytes(Encoding.PEM)
            # Extraer solo el contenido base64 (sin headers PEM)
            cert_lines = cert_pem.decode("utf-8").split("\n")
            cert_b64 = "".join(
                line.strip()
                for line in cert_lines
                if line.strip() and not line.strip().startswith("-----")
            )
            x509_cert.text = cert_b64
            logger.debug("Certificado X509 agregado al template manual")
        else:
            # Fallback: intentar obtener certificado desde xmlsec key
            # Nota: xmlsec puede tener el certificado cargado, pero no hay API directa para extraerlo
            logger.warning(
                "No se pudo obtener certificado desde P12, X509Certificate puede quedar vacío"
            )

        # Crear contexto de firma
        ctx = xmlsec.SignatureContext()  # type: ignore
        ctx.key = key

        # IMPORTANTÍSIMO: Registrar Ids antes de firmar (ya lo hicimos arriba, pero asegurar)
        xmlsec.tree.add_ids(tree, ["Id"])  # type: ignore

        # Firmar el template construido manualmente
        # xmlsec calculará DigestValue y SignatureValue automáticamente
        ctx.sign(sig)
        logger.info(
            "DE firmado exitosamente con XMLDSig (RSA-SHA256/SHA-256) usando template manual"
        )

    except PKCS12Error as e:
        raise XMLSecError(f"Error al convertir certificado P12: {e}") from e
    except Exception as e:
        raise XMLSecError(f"Error al cargar certificado o firmar: {e}") from e
    finally:
        # Limpiar archivos PEM temporales
        if cert_pem_path and key_pem_path:
            cleanup_pem_files(cert_pem_path, key_pem_path)

    # 6) POST-PROCESADO: Asegurar que no haya prefijos "ds" y que el root no declare xmlns:ds
    # Doc SIFEN: "no se podrá utilizar prefijos de namespace" - limpiar cualquier prefijo residual
    # Doc SIFEN: "la declaración namespace de la firma digital debe realizarse en la etiqueta <Signature>"
    # La única declaración del namespace ds debe estar en <Signature xmlns="...">, NO en el root
    DS_NS_URI = "http://www.w3.org/2000/09/xmldsig#"

    # Limpiar namespaces para eliminar prefijos heredados y asegurar que root no tenga xmlns:ds
    etree.cleanup_namespaces(tree)  # type: ignore

    # Verificar que el root no tenga xmlns:ds declarado
    # Si cleanup_namespaces no lo eliminó, el post-check lo detectará y fallará
    root_nsmap_after = root.nsmap if hasattr(root, "nsmap") and root.nsmap else {}
    if root_nsmap_after and "ds" in root_nsmap_after:
        logger.warning(
            "Root aún tiene xmlns:ds después de cleanup_namespaces, el post-check fallará"
        )

    # Verificar que Signature tenga default namespace (ya debería tenerlo por construcción manual)
    sig_found = None
    sig_candidates = rde.xpath(
        f'.//*[namespace-uri()="{DS_NS_URI}" and local-name()="Signature"]'
    )
    if sig_candidates:
        sig_found = sig_candidates[0]
    else:
        sig_candidates = root.xpath(
            f'//*[namespace-uri()="{DS_NS_URI}" and local-name()="Signature"]'
        )
        if sig_candidates:
            sig_found = sig_candidates[0]

    if sig_found is None:
        raise XMLSecError(
            "Post-procesado falló: no se encontró Signature firmada después de ctx.sign()"
        )

    # Verificar nsmap de Signature - debe tener default namespace y NO tener prefijo ds
    sig_nsmap = (
        sig_found.nsmap if hasattr(sig_found, "nsmap") and sig_found.nsmap else {}
    )
    if sig_nsmap.get(None) != DS_NS or "ds" in sig_nsmap:
        logger.debug(
            "Post-procesado: Signature no tiene default namespace correcto, reconstruyendo"
        )
        # Reconstruir el nodo Signature con default namespace
        parent_sig = sig_found.getparent()
        if parent_sig is None:
            raise XMLSecError("Post-procesado falló: Signature no tiene parent")

        # Crear nuevo nodo Signature con default namespace
        new_sig = etree.Element(etree.QName(DS_NS, "Signature"), nsmap={None: DS_NS})  # type: ignore

        # Copiar atributos
        for k, v in sig_found.attrib.items():
            new_sig.set(k, v)

        # Conservar text/tail
        new_sig.text = sig_found.text
        new_sig.tail = sig_found.tail

        # Mover hijos (mover, no copiar) - preserva SignedInfo, SignatureValue, KeyInfo, etc.
        for child in list(sig_found):
            sig_found.remove(child)
            new_sig.append(child)

        # Reemplazar en el parent misma posición
        idx = list(parent_sig).index(sig_found)
        parent_sig.remove(sig_found)
        parent_sig.insert(idx, new_sig)

        sig_found = new_sig

        # Limpiar namespaces otra vez después de reconstruir
        etree.cleanup_namespaces(tree)  # type: ignore

    # Serializar el documento COMPLETO
    try:
        out = etree.tostring(tree, encoding="utf-8", xml_declaration=True)  # type: ignore
    except Exception as e:
        raise XMLSecError(f"Error al serializar XML firmado: {e}") from e

    # 8) POST-CHECK ESTRICTO antes de devolver - revisar XML SERIALIZADO (bytes), no solo el árbol
    # Doc SIFEN: "no se podrá utilizar prefijos de namespace" - validar en bytes finales
    DS_NS_URI = "http://www.w3.org/2000/09/xmldsig#"
    SIFEN_NS_URI = "http://ekuatia.set.gov.py/sifen/xsd"

    # 8.1) Validar que NO exista "<ds:" ni "xmlns:ds" en el texto serializado
    # Doc SIFEN: prohibido "ds:" y prohibido "xmlns:ds="
    if b"<ds:" in out:
        raise XMLSecError(
            "Post-check falló: todavía existe '<ds:' en el XML serializado (Doc SIFEN: no se podrá utilizar prefijos)"
        )
    if b"xmlns:ds=" in out:
        raise XMLSecError(
            "Post-check falló: todavía existe 'xmlns:ds=' en el XML serializado (Doc SIFEN: no se podrá utilizar prefijos)"
        )

    # 8.2) Validar que SÍ exista '<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"' en el texto serializado
    # Doc SIFEN: xmlns debe declararse en la etiqueta <Signature> como DEFAULT
    if b'<Signature xmlns="http://www.w3.org/2000/09/xmldsig#"' not in out:
        raise XMLSecError(
            "Post-check falló: no se encontró '<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"' en el XML serializado (Doc SIFEN: xmlns en Signature)"
        )

    # 3) Post-check estructural con lxml
    # tree/root ya existen en tu función
    root2 = tree.getroot()
    
    # Helpers para extraer localname y namespace
    def _localname(tag: str) -> str:
        """Extrae el localname de un tag (sin namespace)"""
        return tag.split("}", 1)[1] if isinstance(tag, str) and tag.startswith("{") else tag
    
    def _ns(tag: str) -> Optional[str]:
        """Extrae el namespace URI de un tag, o None si no tiene namespace"""
        if not isinstance(tag, str) or not tag.startswith("{"):
            return None
        return tag[1:].split("}", 1)[0]

    # 3.1) Ubicar rDE: primero verificar si el root es rDE
    rde_check = None
    if isinstance(root2.tag, str) and _localname(root2.tag) == "rDE":
        rde_check = root2
    else:
        # Buscar rDE en el árbol (namespace-aware primero, luego fallback)
        rde_check = root2.find(f".//{{{SIFEN_NS}}}rDE")
        if rde_check is None:
            # Fallback: buscar por local-name (ignora namespace)
            nodes = root2.xpath("//*[local-name()='rDE']")
            rde_check = nodes[0] if nodes else None
    
    if rde_check is None:
        # Obtener información de debug
        root_tag = root2.tag if hasattr(root2, 'tag') else str(root2)
        root_nsmap = root2.nsmap if hasattr(root2, 'nsmap') else {}
        
        # Obtener primeros 10 tags hijos del root para diagnóstico
        child_tags = []
        for i, child in enumerate(list(root2)[:10]):
            child_localname = _localname(child.tag)
            child_tags.append(f"  [{i}] {child.tag} (local: {child_localname})")
        child_tags_str = "\n".join(child_tags) if child_tags else "  (sin hijos)"
        
        error_msg = (
            f"Post-check falló: no se encontró <rDE> (SIFEN_NS).\n"
            f"  root.tag: {root_tag}\n"
            f"  root.nsmap: {root_nsmap}\n"
            f"  root localname: {_localname(root_tag)}\n"
            f"  Primeros 10 hijos del root:\n{child_tags_str}"
        )
        
        # Guardar artifacts si está habilitado debug
        debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
        if debug_enabled:
            try:
                artifacts_dir = Path("artifacts")
                artifacts_dir.mkdir(parents=True, exist_ok=True)
                artifacts_dir.joinpath("xmlsec_signed_output.xml").write_bytes(out)
            except Exception:
                pass
        
        raise XMLSecError(error_msg)
    
    # Validar namespace del rDE encontrado
    rde_ns = _ns(rde_check.tag)
    if rde_ns is not None and rde_ns != SIFEN_NS:
        raise XMLSecError(
            f"Post-check falló: rDE tiene namespace incorrecto. "
            f"Tag actual: {rde_check.tag!r}, namespace actual: {rde_ns!r}, "
            f"esperado: {SIFEN_NS!r}"
        )

    de2 = rde_check.find(f"./{{{SIFEN_NS}}}DE")
    if de2 is None:
        # por si DE vino sin namespace:
        de2 = rde_check.find("./DE")
    if de2 is None:
        raise XMLSecError("Post-check falló: no se encontró <DE> dentro de <rDE>")

    de_id_check = de2.get("Id")
    if not de_id_check:
        raise XMLSecError("Post-check falló: <DE> no tiene atributo Id")

    # 3.2) Signature debe ser HERMANO de DE y en DS_NS_URI (prefijo NO importa)
    # Validar que el parent directo del Signature sea rDE (namespace SIFEN)
    sig2 = None
    children = list(rde_check)
    for i, ch in enumerate(children):
        if ch is de2 and i + 1 < len(children):
            cand = children[i + 1]
            if cand.tag == f"{{{DS_NS_URI}}}Signature":
                sig2 = cand
            break

    if sig2 is None:
        # fallback: buscar cualquier Signature en DS_NS_URI dentro de rDE
        sig_any = rde_check.find(f".//{{{DS_NS_URI}}}Signature")
        if sig_any is not None:
            raise XMLSecError(
                "Post-check falló: Signature existe pero NO está inmediatamente después de <DE> dentro de <rDE>"
            )
        raise XMLSecError(
            "Post-check falló: no se encontró Signature en DS_NS_URI dentro de <rDE>"
        )

    # Validar que el parent directo del Signature sea rDE (tag endswith "}rDE")
    sig2_parent = sig2.getparent()
    if sig2_parent is None:
        raise XMLSecError("Post-check falló: Signature no tiene parent")
    if not sig2_parent.tag.endswith("}rDE") and sig2_parent.tag != "rDE":
        raise XMLSecError(
            f"Post-check falló: el parent directo del Signature es '{sig2_parent.tag}' (se esperaba rDE)"
        )

    # Validar orden: Signature debe estar después de DE dentro de rDE
    de_idx = -1
    sig_idx = -1
    for i, ch in enumerate(children):
        if ch is de2:
            de_idx = i
        if ch is sig2:
            sig_idx = i
    if de_idx == -1 or sig_idx == -1:
        raise XMLSecError(
            "Post-check falló: no se pudo determinar el orden de DE y Signature"
        )
    if sig_idx <= de_idx:
        raise XMLSecError(
            f"Post-check falló: Signature está en índice {sig_idx}, DE está en {de_idx} (Signature debe estar después de DE)"
        )

    # 8.3) Deben existir SignatureValue, DigestValue, X509Certificate
    if sig2.find(f".//{{{DS_NS_URI}}}SignatureValue") is None:
        raise XMLSecError("Post-check falló: falta SignatureValue")
    if sig2.find(f".//{{{DS_NS_URI}}}DigestValue") is None:
        raise XMLSecError("Post-check falló: falta DigestValue")
    if sig2.find(f".//{{{DS_NS_URI}}}X509Certificate") is None:
        raise XMLSecError("Post-check falló: falta X509Certificate")

    # 8.4) Validar Reference URI="#Id"
    ref = sig2.find(f".//{{{DS_NS_URI}}}Reference")
    uri = ref.get("URI") if ref is not None else None
    if uri != f"#{de_id_check}":
        raise XMLSecError(
            f"Post-check falló: Reference URI esperado '#{de_id_check}', vino '{uri}'"
        )

    logger.info(
        "Post-check estructural OK: rDE/DE/Signature ubicados correctamente, SignatureValue/DigestValue/X509Certificate presentes, Reference URI válido, Signature sin prefijo ds: ni xmlns:ds"
    )
    return out


def sign_event_with_p12(xml_bytes: bytes, p12_path: str, p12_password: str) -> bytes:
    """
    Firma un XML de Evento SIFEN (gGroupGesEve) con XMLDSig usando python-xmlsec.

    Espera un XML que contenga <rEve Id="..."> y firma ese Id.
    Inserta <Signature> como hermano de <rEve> dentro de <rGesEve>.
    """
    if not XMLSEC_AVAILABLE:
        raise XMLSecError(
            "python-xmlsec no está instalado. Instale con: pip install python-xmlsec"
        )

    if not CRYPTOGRAPHY_AVAILABLE:
        raise XMLSecError(
            "cryptography no está instalado. Instale con: pip install cryptography"
        )

    p12_path_obj = Path(p12_path)
    if not p12_path_obj.exists():
        raise XMLSecError(f"Certificado P12 no encontrado: {p12_path}")

    if etree is None:
        raise XMLSecError("lxml no está disponible")

    try:
        parser = etree.XMLParser(remove_blank_text=False)  # type: ignore
        root = etree.fromstring(xml_bytes, parser=parser)  # type: ignore
    except Exception as e:
        raise XMLSecError(f"Error al parsear XML: {e}")

    tree = root.getroottree()

    # limpiar prefijo ds si existe
    etree.cleanup_namespaces(tree)  # type: ignore

    ds_ns = "http://www.w3.org/2000/09/xmldsig#"
    ns = {"ds": ds_ns, "sifen": SIFEN_NS}

    # localizar rEve
    eve = None
    eve_list = root.xpath("//sifen:rEve", namespaces=ns)
    if eve_list:
        eve = eve_list[0]
    else:
        eve_list = root.xpath("//rEve")
        if eve_list:
            eve = eve_list[0]

    if eve is None:
        raise XMLSecError("No se encontró elemento rEve en el XML de evento")

    eve_id = eve.get("Id") or eve.get("id")
    if not eve_id:
        raise XMLSecError("El elemento rEve no tiene atributo Id")

    # borrar firmas previas
    for old in root.xpath(f".//*[local-name()='Signature' and namespace-uri()='{ds_ns}']"):
        old_parent = old.getparent()
        if old_parent is not None:
            old_parent.remove(old)

    # registrar Id
    if xmlsec is None:
        raise XMLSecError("xmlsec no está disponible")
    xmlsec.tree.add_ids(tree, ["Id"])  # type: ignore

    # construir Signature manual sin prefijo
    try:
        sig = etree.Element(etree.QName(DS_NS, "Signature"), nsmap={None: DS_NS})  # type: ignore
        signed_info = etree.SubElement(sig, etree.QName(DS_NS, "SignedInfo"))  # type: ignore
        canon_method = etree.SubElement(signed_info, etree.QName(DS_NS, "CanonicalizationMethod"))  # type: ignore
        canon_method.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

        sig_method = etree.SubElement(signed_info, etree.QName(DS_NS, "SignatureMethod"))  # type: ignore
        sig_method.set("Algorithm", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")

        ref = etree.SubElement(signed_info, etree.QName(DS_NS, "Reference"))  # type: ignore
        ref.set("URI", f"#{eve_id}")

        transforms = etree.SubElement(ref, etree.QName(DS_NS, "Transforms"))  # type: ignore
        transform1 = etree.SubElement(transforms, etree.QName(DS_NS, "Transform"))  # type: ignore
        transform1.set("Algorithm", "http://www.w3.org/2000/09/xmldsig#enveloped-signature")
        transform2 = etree.SubElement(transforms, etree.QName(DS_NS, "Transform"))  # type: ignore
        transform2.set("Algorithm", "http://www.w3.org/2001/10/xml-exc-c14n#")

        digest_method = etree.SubElement(ref, etree.QName(DS_NS, "DigestMethod"))  # type: ignore
        digest_method.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
        etree.SubElement(ref, etree.QName(DS_NS, "DigestValue"))  # type: ignore

        etree.SubElement(sig, etree.QName(DS_NS, "SignatureValue"))  # type: ignore

        key_info = etree.SubElement(sig, etree.QName(DS_NS, "KeyInfo"))  # type: ignore
        x509_data = etree.SubElement(key_info, etree.QName(DS_NS, "X509Data"))  # type: ignore
        x509_cert = etree.SubElement(x509_data, etree.QName(DS_NS, "X509Certificate"))  # type: ignore
    except Exception as e:
        raise XMLSecError(f"Error al construir árbol de firma: {e}")

    # insertar firma como hermano de rEve dentro de rGesEve
    parent = eve.getparent()
    if parent is None:
        raise XMLSecError("rEve no tiene parent")
    try:
        idx = list(parent).index(eve)
        parent.insert(idx + 1, sig)
    except Exception:
        parent.append(sig)

    cert_pem_path = None
    key_pem_path = None
    ctx = None
    try:
        cert_pem_path, key_pem_path = p12_to_temp_pem_files(p12_path, p12_password)

        key = xmlsec.Key.from_file(key_pem_path, xmlsec.KeyFormat.PEM)  # type: ignore
        key.load_cert_from_file(cert_pem_path, xmlsec.KeyFormat.PEM)  # type: ignore

        cert_obj = None
        try:
            with open(p12_path, "rb") as f:
                p12_bytes = f.read()
            password_bytes = p12_password.encode("utf-8") if p12_password else None
            if pkcs12 is None:
                raise XMLSecError("cryptography no está disponible")
            key_obj, cert_obj, addl_certs = pkcs12.load_key_and_certificates(  # type: ignore
                p12_bytes, password_bytes, backend=default_backend()
            )
            if addl_certs:
                for addl_cert in addl_certs:
                    try:
                        addl_cert_pem = addl_cert.public_bytes(Encoding.PEM)
                        key.load_cert_from_memory(addl_cert_pem, xmlsec.KeyFormat.PEM)  # type: ignore
                    except Exception:
                        pass
        except ValueError:
            pass

        if cert_obj:
            cert_pem = cert_obj.public_bytes(Encoding.PEM)
            cert_lines = cert_pem.decode("utf-8").split("\n")
            cert_b64 = "".join(
                line.strip()
                for line in cert_lines
                if line.strip() and not line.strip().startswith("-----")
            )
            x509_cert.text = cert_b64

        ctx = xmlsec.SignatureContext()  # type: ignore
        ctx.key = key
        xmlsec.tree.add_ids(tree, ["Id"])  # type: ignore
        ctx.sign(sig)
    except PKCS12Error as e:
        raise XMLSecError(f"Error al convertir certificado P12: {e}") from e
    except Exception as e:
        raise XMLSecError(f"Error al cargar certificado o firmar: {e}") from e
    finally:
        if cert_pem_path and key_pem_path:
            cleanup_pem_files(cert_pem_path, key_pem_path)

    etree.cleanup_namespaces(tree)  # type: ignore

    out = etree.tostring(root, xml_declaration=True, encoding="UTF-8", pretty_print=False)
    return out
