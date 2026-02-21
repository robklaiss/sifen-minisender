"""
Validador XSD local (offline) para documentos SIFEN.

Valida rDE y rLoteDE contra esquemas XSD locales, resolviendo includes/imports
desde el directorio local en lugar de URLs remotas.
"""
import os
import re
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any

try:
    import lxml.etree as etree
except ImportError:
    raise ImportError("lxml es requerido para validación XSD. Instalar con: pip install lxml")

# Constantes de namespace
SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"
DSIG_NS = "http://www.w3.org/2000/09/xmldsig#"


class SifenLocalResolver(etree.Resolver):
    """Resolver que mapea URLs de SIFEN a archivos locales."""
    
    def __init__(self, xsd_dir: Path):
        """
        Args:
            xsd_dir: Directorio base donde están los XSD locales
        """
        super().__init__()
        self.xsd_dir = Path(xsd_dir).resolve()
    
    def resolve(self, url: str, pubid: str, context) -> Optional[etree._Entity]:
        """
        Resuelve una URL de SIFEN a un archivo local.
        
        Args:
            url: URL del XSD (puede ser https://ekuatia.set.gov.py/sifen/xsd/... o relativo)
            pubid: Public ID (no usado)
            context: Contexto del parser
            
        Returns:
            Entity resuelta o None si no se puede resolver
        """
        # Caso 1: URL absoluta de SIFEN
        if url.startswith("https://ekuatia.set.gov.py/sifen/xsd/") or \
           url.startswith("http://ekuatia.set.gov.py/sifen/xsd/"):
            # Extraer el nombre del archivo (último segmento)
            fname = url.split("/")[-1]
            local_path = self.xsd_dir / fname
            if local_path.exists():
                return self.resolve_filename(str(local_path), context)
        
        # Caso 2: URL relativa
        elif not url.startswith(("http://", "https://")):
            local_path = self.xsd_dir / url
            if local_path.exists():
                return self.resolve_filename(str(local_path), context)
        
        # No se puede resolver localmente
        return None


def _parser_with_resolver(xsd_dir: Path) -> etree.XMLParser:
    """
    Crea un parser XML con el resolver local configurado.
    
    Args:
        xsd_dir: Directorio base de XSD
        
    Returns:
        Parser configurado
    """
    parser = etree.XMLParser(
        remove_blank_text=False,
        load_dtd=False,
        resolve_entities=False,
        no_network=True,
        huge_tree=True
    )
    parser.resolvers.add(SifenLocalResolver(xsd_dir))
    return parser


def load_schema(main_xsd: Path, xsd_dir: Path) -> etree.XMLSchema:
    """
    Carga un esquema XSD desde un archivo, resolviendo includes/imports localmente.
    
    Args:
        main_xsd: Path al archivo XSD principal
        xsd_dir: Directorio base donde están los XSD (para resolver includes)
        
    Returns:
        Esquema XSD cargado y validado
        
    Raises:
        etree.XMLSchemaParseError: Si el XSD es inválido
        FileNotFoundError: Si el archivo no existe
    """
    main_xsd = Path(main_xsd).resolve()
    if not main_xsd.exists():
        raise FileNotFoundError(f"XSD no encontrado: {main_xsd}")
    
    parser = _parser_with_resolver(xsd_dir)
    doc = etree.parse(str(main_xsd), parser)
    return etree.XMLSchema(doc)


def _localname(tag: str) -> str:
    """Devuelve localname de un tag QName."""
    if "}" in tag:
        return tag.rsplit("}", 1)[-1]
    return tag


def _xsd_declares_global_element(xsd_path: Path, element_name: str) -> bool:
    """
    Verifica si un XSD declara un elemento global con nombre exacto.
    Soporta prefijos xs: o xsd:.
    """
    try:
        text = xsd_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return False
    pattern = re.compile(
        rf"<\s*(?:xs|xsd):element\b[^>]*\bname\s*=\s*\"{re.escape(element_name)}\"",
        re.IGNORECASE,
    )
    return bool(pattern.search(text))


def _score_main_xsd_candidate(xsd_path: Path, expected_root: str) -> tuple[int, str]:
    """
    Scoring determinista para elegir XSD principal.
    Prioriza documentos DE v150 y, para rDE, evita variantes problemáticas.
    """
    name = xsd_path.name.lower()
    score = 0

    if "de" in name:
        score += 20
    if "150" in name:
        score += 30
    if expected_root.lower() in name:
        score += 15

    if expected_root == "rDE":
        if name == "sirecepde_v150.xsd":
            score += 120
        elif name.startswith("sirecepde"):
            score += 80
        elif name == "de_v150.xsd":
            score += 50
        if "sireceprde" in name:
            # En algunos bundles esta variante apunta includes no disponibles.
            score -= 30
    elif expected_root == "DE":
        if name == "de_v150.xsd":
            score += 120
        elif name.startswith("de_"):
            score += 60

    # preferencia explícita a nombres que contengan DE + 150
    if "de" in name and "150" in name:
        score += 25

    return score, name


def _select_main_de_xsd_for_xml(xml_text: str, schemas_dir: Path) -> Path:
    """
    Selecciona el XSD raíz más probable para validar el XML de DE.
    - Busca candidatos en schemas_sifen/.
    - Prefiere nombres con DE + 150.
    - Verifica carga real de includes/imports antes de elegir.
    """
    schemas_dir = Path(schemas_dir).resolve()
    if not schemas_dir.exists():
        raise RuntimeError(f"Directorio de esquemas no encontrado: {schemas_dir}")

    parser = _parser_with_resolver(schemas_dir)
    try:
        root = etree.fromstring(xml_text.encode("utf-8"), parser=parser)
    except etree.XMLSyntaxError as exc:
        raise RuntimeError(f"XML inválido para selección de XSD: {exc}") from exc

    root_name = _localname(root.tag)
    expected_root = root_name
    if expected_root not in ("rDE", "DE"):
        if root.xpath(".//*[local-name()='rDE']"):
            expected_root = "rDE"
        elif root.xpath(".//*[local-name()='DE']"):
            expected_root = "DE"
        else:
            raise RuntimeError(
                f"No se encontró root DE/rDE en el XML (root actual: {root_name})."
            )

    xsd_files = list(schemas_dir.glob("*.xsd"))
    if not xsd_files:
        raise RuntimeError(f"No hay archivos XSD en {schemas_dir}")

    candidates = [p for p in xsd_files if _xsd_declares_global_element(p, expected_root)]
    if not candidates:
        raise RuntimeError(
            f"No se encontró XSD que declare elemento global '{expected_root}' en {schemas_dir}. "
            "Faltan XSD en schemas_sifen/."
        )

    ranked = sorted(
        candidates,
        key=lambda p: _score_main_xsd_candidate(p, expected_root),
        reverse=True,
    )

    load_errors = []
    for candidate in ranked:
        try:
            load_schema(candidate, schemas_dir)
            return candidate
        except Exception as exc:
            load_errors.append(f"{candidate.name}: {exc}")

    details = "; ".join(load_errors[:3])
    raise RuntimeError(
        f"No se pudo cargar un XSD raíz válido para '{expected_root}' desde {schemas_dir}. "
        f"Candidatos probados: {details}"
    )


def validate_de_xml_against_xsd(xml_text: str, *, schemas_dir: Path) -> tuple[bool, list[str]]:
    """
    Valida un DE firmado (por ejemplo rde_signed_qr_*.xml) contra XSD v150 locales.
    """
    if not xml_text or not xml_text.strip():
        return False, ["XML vacío."]

    schemas_dir = Path(schemas_dir).resolve()
    if not schemas_dir.exists():
        return False, [f"Directorio de esquemas no encontrado: {schemas_dir}"]

    try:
        main_xsd = _select_main_de_xsd_for_xml(xml_text, schemas_dir)
    except Exception as exc:
        return False, [str(exc)]

    try:
        schema = load_schema(main_xsd, schemas_dir)
    except Exception as exc:
        return False, [f"No se pudo cargar XSD principal {main_xsd.name}: {exc}"]

    ok, errors = validate_xml_bytes(xml_text.encode("utf-8"), schema, schemas_dir)
    return ok, errors


def validate_xml_bytes(
    xml_bytes: bytes,
    schema: etree.XMLSchema,
    xsd_dir: Path
) -> Tuple[bool, List[str]]:
    """
    Valida bytes XML contra un esquema XSD.
    
    Args:
        xml_bytes: Contenido XML a validar
        schema: Esquema XSD cargado
        xsd_dir: Directorio base de XSD (para resolver includes en el XML si aplica)
        
    Returns:
        Tupla (ok, lista_errores)
        - ok: True si válido, False si hay errores
        - lista_errores: Lista de strings con formato "line N: mensaje"
    """
    parser = _parser_with_resolver(xsd_dir)
    try:
        doc = etree.fromstring(xml_bytes, parser)
    except etree.XMLSyntaxError as e:
        return (False, [f"Error de sintaxis XML: {e}"])
    
    ok = schema.validate(doc)
    
    if ok:
        return (True, [])
    
    # Recopilar errores (máximo 30)
    errors = []
    for error in schema.error_log[:30]:
        line_info = f"line {error.line}" if error.line else "line ?"
        col_info = f", col {error.column}" if error.column else ""
        errors.append(f"{line_info}{col_info}: {error.message}")
    
    return (False, errors)


def extract_element_as_doc(
    xml_bytes: bytes,
    localname: str,
    ns: str = SIFEN_NS
) -> bytes:
    """
    Extrae un elemento por localname del XML y lo devuelve como documento standalone.
    
    Args:
        xml_bytes: XML completo (puede tener wrapper)
        localname: Nombre local del elemento a extraer (ej: "rDE")
        ns: Namespace del elemento (default: SIFEN_NS)
        
    Returns:
        Bytes del elemento extraído como documento XML standalone (con XML declaration)
        
    Raises:
        ValueError: Si no se encuentra el elemento
    """
    try:
        root = etree.fromstring(xml_bytes)
    except Exception as e:
        raise ValueError(f"Error al parsear XML: {e}")
    
    def get_localname(tag: str) -> str:
        """Obtiene el localname de un tag (sin namespace)."""
        if "}" in tag:
            return tag.split("}", 1)[-1]
        return tag
    
    # Caso 1: el root es el elemento buscado
    if get_localname(root.tag) == localname:
        element = root
    else:
        # Caso 2: buscar con namespace
        element = root.find(f".//{{{ns}}}{localname}")
        if element is None:
            # Caso 3: buscar por localname sin namespace
            element = root.xpath(f".//*[local-name()='{localname}']")
            if element:
                element = element[0]
            else:
                element = None
    
    if element is None:
        root_local = get_localname(root.tag)
        raise ValueError(
            f"No se encontró elemento '{localname}' en el XML. "
            f"Root encontrado: {root_local}"
        )
    
    # Serializar el elemento como documento standalone
    return etree.tostring(
        element,
        xml_declaration=True,
        encoding="utf-8",
        pretty_print=False
    )


def find_xsd_declaring_global_element(
    xsd_dir: Path,
    element_name: str
) -> Optional[Path]:
    """
    Busca un archivo XSD que declare un elemento global con el nombre dado.
    
    Args:
        xsd_dir: Directorio donde buscar
        element_name: Nombre del elemento (ej: "rDE", "rLoteDE")
        
    Returns:
        Path al archivo XSD encontrado, o None si no se encuentra
    """
    xsd_dir = Path(xsd_dir).resolve()
    if not xsd_dir.exists():
        return None
    
    # Buscar en todos los .xsd
    candidates = []
    for xsd_file in xsd_dir.glob("*.xsd"):
        try:
            content = xsd_file.read_bytes()
            # Buscar patrón: <xs:element name="element_name"
            pattern = f'<xs:element name="{element_name}"'.encode('utf-8')
            if pattern in content:
                candidates.append(xsd_file)
        except Exception:
            continue
    
    if not candidates:
        return None
    
    # Preferir archivos con "siRecep" en el nombre si hay varios
    si_recep_candidates = [c for c in candidates if "siRecep" in c.name.lower()]
    if si_recep_candidates:
        return si_recep_candidates[0]
    
    return candidates[0]


def validate_rde_and_lote(
    rde_signed_bytes: bytes,
    lote_xml_bytes: Optional[bytes],
    xsd_dir: Path
) -> Dict[str, Any]:
    """
    Valida rDE firmado y (opcionalmente) lote.xml contra XSD locales.
    
    Extrae el elemento rDE del XML completo (puede venir envuelto en rEnviDe u otro wrapper)
    y lo valida como documento standalone.
    
    Args:
        rde_signed_bytes: XML del rDE firmado (bytes) - puede tener wrapper como rEnviDe
        lote_xml_bytes: XML del lote.xml (bytes) o None si no se proporciona
        xsd_dir: Directorio base donde están los XSD
        
    Returns:
        Dict con:
        {
            "rde_ok": bool,
            "rde_errors": List[str],
            "lote_ok": Optional[bool],
            "lote_errors": List[str],
            "schema_rde": str (path),
            "schema_lote": Optional[str] (path),
            "warning": Optional[str],
            "root_original": str (localname del root original),
            "extracted_rde_root": str (siempre "rDE")
        }
    """
    xsd_dir = Path(xsd_dir).resolve()
    debug_enabled = os.getenv("SIFEN_DEBUG_SOAP", "0") in ("1", "true", "True")
    
    result = {
        "rde_ok": False,
        "rde_errors": [],
        "lote_ok": None,
        "lote_errors": [],
        "schema_rde": "",
        "schema_lote": None,
        "warning": None,
        "root_original": "",
        "extracted_rde_root": "rDE"
    }
    
    # Detectar root original del XML completo
    try:
        root = etree.fromstring(rde_signed_bytes)
        def get_localname(tag: str) -> str:
            return tag.split("}", 1)[-1] if "}" in tag else tag
        result["root_original"] = get_localname(root.tag)
    except Exception:
        result["root_original"] = "?"
    
    # 1) Extraer rDE del XML completo
    try:
        rde_doc_bytes = extract_element_as_doc(rde_signed_bytes, "rDE", SIFEN_NS)
    except ValueError as e:
        result["rde_errors"] = [f"Error al extraer rDE del XML: {e}"]
        return result
    
    # 2) Buscar XSD que declare elemento global "rDE"
    schema_rde_path = find_xsd_declaring_global_element(xsd_dir, "rDE")
    if schema_rde_path is None:
        # Fallback a siRecepDE_v150.xsd si existe
        schema_rde_path = xsd_dir / "siRecepDE_v150.xsd"
        if not schema_rde_path.exists():
            result["rde_errors"] = [
                f"No se encontró XSD para rDE en {xsd_dir}. "
                "Buscar siRecepDE_v150.xsd o archivo que declare elemento global 'rDE'."
            ]
            return result
    
    result["schema_rde"] = str(schema_rde_path)
    
    # 3) Validar rDE extraído
    try:
        schema_rde = load_schema(schema_rde_path, xsd_dir)
        rde_ok, rde_errors = validate_xml_bytes(rde_doc_bytes, schema_rde, xsd_dir)
        result["rde_ok"] = rde_ok
        result["rde_errors"] = rde_errors
    except Exception as e:
        result["rde_errors"] = [f"Error al cargar/validar XSD rDE: {e}"]
        return result
    
    # 4) Validar lote.xml si se proporciona (validación estructural, no XSD)
    # NOTA: No existe XSD que declare elemento global rLoteDE en el set actual de SIFEN.
    # En su lugar, hacemos validación estructural del lote.xml.
    if lote_xml_bytes is not None:
        try:
            lote_root = etree.fromstring(lote_xml_bytes)
            
            def get_localname(tag: str) -> str:
                return tag.split("}", 1)[-1] if "}" in tag else tag
            
            def get_namespace(tag: str) -> str:
                if "}" in tag and tag.startswith("{"):
                    return tag[1:].split("}", 1)[0]
                return ""
            
            root_local = get_localname(lote_root.tag)
            root_ns = get_namespace(lote_root.tag)
            
            # Validación estructural
            structural_errors = []
            
            # 1. Root debe ser rLoteDE con namespace SIFEN
            if root_local != "rLoteDE":
                structural_errors.append(f"Root debe ser 'rLoteDE', encontrado: {root_local}")
            if root_ns != SIFEN_NS:
                structural_errors.append(f"rLoteDE debe tener namespace {SIFEN_NS}, encontrado: {root_ns or '(vacío)'}")
            
            # 2. Debe contener exactamente 1 rDE
            rde_candidates = []
            for child in lote_root:
                if get_localname(child.tag) == "rDE":
                    rde_candidates.append(child)
            
            if len(rde_candidates) == 0:
                structural_errors.append("rLoteDE debe contener exactamente 1 rDE, encontrado: 0")
            elif len(rde_candidates) > 1:
                structural_errors.append(f"rLoteDE debe contener exactamente 1 rDE, encontrado: {len(rde_candidates)}")
            else:
                rde_elem = rde_candidates[0]
                rde_ns = get_namespace(rde_elem.tag)
                
                # 3. rDE debe tener namespace SIFEN
                if rde_ns != SIFEN_NS:
                    structural_errors.append(f"rDE debe tener namespace {SIFEN_NS}, encontrado: {rde_ns}")
                
                # 4. rDE debe contener Signature y gCamFuFD
                rde_children = [get_localname(c.tag) for c in rde_elem]
                has_signature = "Signature" in rde_children
                has_gcam = "gCamFuFD" in rde_children
                
                if not has_signature:
                    structural_errors.append("rDE debe contener elemento Signature")
                if not has_gcam:
                    structural_errors.append("rDE debe contener elemento gCamFuFD")
            
            if structural_errors:
                result["lote_ok"] = False
                result["lote_errors"] = structural_errors
            else:
                result["lote_ok"] = True
                result["lote_errors"] = []
            
            result["warning"] = "Validación estructural de rLoteDE (no existe XSD global para rLoteDE)"
            result["schema_lote"] = None
            
        except Exception as e:
            result["lote_errors"] = [f"Error al validar estructura de lote.xml: {e}"]
            result["lote_ok"] = False
            result["schema_lote"] = None
    
    # Debug output
    if debug_enabled:
        print(f"   ROOT_ORIGINAL={result['root_original']}")
        print(f"   EXTRACTED_RDE_ROOT={result['extracted_rde_root']}")
        print(f"   RDE_SCHEMA={result['schema_rde']}")
        if result["schema_lote"]:
            print(f"   LOTE_SCHEMA={result['schema_lote']}")
        else:
            print(f"   LOTE_SCHEMA=NONE")
    
    return result
