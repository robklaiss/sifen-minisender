import argparse
import base64
import hashlib
import json
import os
import random
import re
import sys
import time
import zipfile
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Optional, Tuple

import requests
from lxml import etree

SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"
SOAP12_NS = "http://www.w3.org/2003/05/soap-envelope"

DEFAULT_RECIBE_LOTE_ENDPOINTS = {
    "test": "https://sifen-test.set.gov.py/de/ws/async/recibe-lote.wsdl",
    "prod": "https://sifen.set.gov.py/de/ws/async/recibe-lote.wsdl",
}

DEFAULT_CONSULTA_LOTE_WSDL = {
    "test": "https://sifen-test.set.gov.py/de/ws/consultas/consulta-lote.wsdl",
    "prod": "https://sifen.set.gov.py/de/ws/async/consulta-lote.wsdl",
}

WSDL_NS = "http://schemas.xmlsoap.org/wsdl/"
SOAP12_BINDING_NS = "http://schemas.xmlsoap.org/wsdl/soap12/"

_XML_DECL_RE = re.compile(br"^\s*<\?xml[^>]*\?>\s*", re.I)


def _strip_xml_decl(b: bytes) -> bytes:
    return _XML_DECL_RE.sub(b"", b, count=1)


def _require_file(path: str, env_key: str) -> str:
    p = Path(path).expanduser()
    if not p.exists() or not p.is_file():
        raise SystemExit(f"ERROR: {env_key} no existe o no es archivo: {p}")
    return str(p)


def _get_mtls_cert() -> Tuple[str, str]:
    cert_path = (os.getenv("SIFEN_CERT_PATH") or "").strip()
    key_path = (os.getenv("SIFEN_KEY_PATH") or "").strip()
    if not cert_path or not key_path:
        raise SystemExit("ERROR: faltan SIFEN_CERT_PATH y/o SIFEN_KEY_PATH (mTLS PEM)")
    return _require_file(cert_path, "SIFEN_CERT_PATH"), _require_file(key_path, "SIFEN_KEY_PATH")


def _normalize_endpoint(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return u
    if "?" in u:
        u = u.split("?", 1)[0]
    return u


def _get_recibe_lote_endpoint(env: str) -> str:
    direct = (os.getenv("SIFEN_RECIBE_LOTE_ENDPOINT") or "").strip()
    if direct:
        return _normalize_endpoint(direct)

    wsdl = (os.getenv("SIFEN_WSDL_RECIBE_LOTE") or "").strip()
    if wsdl:
        return _normalize_endpoint(wsdl)

    return DEFAULT_RECIBE_LOTE_ENDPOINTS[env]


def _make_did_15() -> str:
    base = datetime.now().strftime("%Y%m%d%H%M%S")
    return base + str(random.randint(0, 9))


def _normalize_did(did: Optional[str]) -> str:
    if did is None:
        return _make_did_15()
    d = (did or "").strip()
    if d.lower() in ("", "auto"):
        return _make_did_15()
    if not (d.isdigit() and len(d) == 15):
        raise SystemExit(f"ERROR: dId debe ser 15 dígitos (YYYYMMDDHHMMSSx). Recibido: {d!r}")
    return d


def _strip_rde_opening_attrs(lote_xml_text: str) -> str:
    def repl(m: re.Match) -> str:
        prefix = m.group("prefix") or ""
        attrs = m.group("attrs") or ""
        attrs = re.sub(r'\s+xmlns:xsi="[^"]*"', "", attrs)
        attrs = re.sub(r'\s+xsi:schemaLocation="[^"]*"', "", attrs)
        return f"<{prefix}rDE{attrs}>"

    return re.sub(
        r"<(?P<prefix>(?:[A-Za-z_][A-Za-z0-9._-]*:)?)rDE\b(?P<attrs>[^>]*)>",
        repl,
        lote_xml_text,
        count=1,
    )


def _build_lote_xml_from_signed_rde_bytes(signed_rde_bytes: bytes) -> bytes:
    inner = _strip_xml_decl(signed_rde_bytes)
    inner_text = inner.decode("utf-8", errors="strict")
    inner_text = _strip_rde_opening_attrs(inner_text)

    lote_text = (
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<rLoteDE xmlns="{SIFEN_NS}">\n'
        f"{inner_text}\n"
        f"</rLoteDE>"
    )
    return lote_text.encode("utf-8")


def _zip_lote_xml(lote_xml_bytes: bytes, zip_mode: str) -> bytes:
    if zip_mode == "stored":
        compression = zipfile.ZIP_STORED
    elif zip_mode == "deflated":
        compression = zipfile.ZIP_DEFLATED
    else:
        raise SystemExit(f"ERROR: zip_mode inválido: {zip_mode!r}")

    mem = BytesIO()
    with zipfile.ZipFile(mem, mode="w", compression=compression) as zf:
        zf.writestr("lote.xml", lote_xml_bytes)
    return mem.getvalue()


def _build_soap_envelope(did: str, xde_base64: str) -> bytes:
    envelope = etree.Element(etree.QName(SOAP12_NS, "Envelope"), nsmap={"soap": SOAP12_NS, "xsd": SIFEN_NS})
    etree.SubElement(envelope, etree.QName(SOAP12_NS, "Header"))
    body = etree.SubElement(envelope, etree.QName(SOAP12_NS, "Body"))

    r_envio_lote = etree.Element(etree.QName(SIFEN_NS, "rEnvioLote"), nsmap={None: SIFEN_NS})
    d_id = etree.SubElement(r_envio_lote, etree.QName(SIFEN_NS, "dId"))
    d_id.text = did
    x_de = etree.SubElement(r_envio_lote, etree.QName(SIFEN_NS, "xDE"))
    x_de.text = xde_base64
    body.append(r_envio_lote)

    return etree.tostring(envelope, xml_declaration=True, encoding="UTF-8", pretty_print=False)


def _localname(tag: str) -> str:
    if tag.startswith("{") and "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _namespace(tag: str) -> Optional[str]:
    if tag.startswith("{") and "}" in tag:
        return tag.split("}", 1)[0][1:]
    return None


def _find_first_by_localname(root, name: str):
    for elem in root.iter():
        if _localname(elem.tag) == name:
            return elem
    return None


def _find_soap_body_first_child(root):
    for elem in root.iter():
        if _localname(elem.tag) == "Body":
            children = list(elem)
            return children[0] if children else None
    return None


def _extract_opening_tag(xml_text: str, localname: str) -> Optional[str]:
    m = re.search(rf"<(?:(?:[A-Za-z_][A-Za-z0-9._-]*):)?{re.escape(localname)}\b[^>]*>", xml_text)
    return m.group(0) if m else None


def _pick_first_existing(artifacts_dir: Path, names: Tuple[str, ...]) -> Optional[Path]:
    for name in names:
        p = artifacts_dir / name
        if p.exists() and p.is_file():
            return p
    return None


def _get_consulta_lote_wsdl_and_endpoint(env: str) -> Tuple[str, str]:
    env_norm = (env or "").strip().lower()
    if env_norm not in ("test", "prod"):
        raise SystemExit(f"ERROR: env inválido para consulta-lote: {env!r} (usar test|prod)")

    if env_norm == "test":
        host = "sifen-test.set.gov.py"
    else:
        host = "sifen.set.gov.py"

    wsdl_url = f"https://{host}/de/ws/consultas/consulta-lote.wsdl?wsdl"
    endpoint_cfg = f"https://{host}/de/ws/consultas/consulta-lote.wsdl"
    return wsdl_url, endpoint_cfg


def _analyze_consulta_lote_wsdl(wsdl_bytes: bytes):
    try:
        root = etree.fromstring(wsdl_bytes)
    except Exception as exc:
        raise RuntimeError(f"ERROR: no se pudo parsear WSDL de consulta-lote: {exc}")

    ns = {"wsdl": WSDL_NS, "soap12": SOAP12_BINDING_NS}

    address_location = None
    addresses = root.xpath("//wsdl:service/wsdl:port/soap12:address", namespaces=ns)
    if addresses:
        address_location = (addresses[0].get("location") or "").strip() or None

    ops = root.xpath("//wsdl:portType/wsdl:operation", namespaces=ns)
    candidates = []
    for op in ops:
        name = (op.get("name") or "").strip()
        if not name:
            continue
        nlow = name.lower()
        if "lote" in nlow and ("result" in nlow or "cons" in nlow):
            candidates.append(op)

    if not candidates:
        raise RuntimeError(
            "ERROR: no se encontró operación de consulta de lote en WSDL (buscando nombre con 'Lote' y 'Result' o 'Cons')"
        )

    op = candidates[0]
    op_name = (op.get("name") or "").strip()

    input_el = op.find(f"{{{WSDL_NS}}}input")
    if input_el is None:
        raise RuntimeError(f"ERROR: operación WSDL {op_name!r} no tiene wsdl:input")
    message_qname = (input_el.get("message") or "").strip()
    if not message_qname:
        raise RuntimeError(f"ERROR: operación WSDL {op_name!r} tiene wsdl:input sin @message")

    if ":" in message_qname:
        _, msg_local = message_qname.split(":", 1)
    else:
        msg_local = message_qname

    msgs = root.xpath(f"//wsdl:message[@name='{msg_local}']", namespaces=ns)
    if not msgs:
        raise RuntimeError(f"ERROR: no se encontró wsdl:message {msg_local!r} en WSDL")
    msg_el = msgs[0]

    part_el = msg_el.find(f"{{{WSDL_NS}}}part")
    if part_el is None:
        raise RuntimeError(f"ERROR: wsdl:message {msg_local!r} no tiene wsdl:part")
    element_qname = (part_el.get("element") or "").strip()
    if not element_qname:
        raise RuntimeError(f"ERROR: wsdl:part de message {msg_local!r} no tiene @element")

    if ":" in element_qname:
        prefix, local = element_qname.split(":", 1)
        ns_uri = msg_el.nsmap.get(prefix)
    else:
        local = element_qname
        ns_uri = msg_el.nsmap.get(None)
    if ns_uri is None:
        ns_uri = SIFEN_NS

    body_ns = ns_uri
    body_local = local

    soap_action = None
    binding_ops = root.xpath("//wsdl:binding/wsdl:operation", namespaces=ns)
    for bop in binding_ops:
        if (bop.get("name") or "").strip() == op_name:
            soap_elems = bop.xpath("./soap12:operation", namespaces=ns)
            if soap_elems:
                soap_action = (soap_elems[0].get("soapAction") or "").strip() or None
            break

    return address_location, body_ns, body_local, soap_action, op_name


def _build_consulta_lote_soap_envelope(body_ns: str, body_localname: str, prot: str) -> bytes:
    ns_for_body = body_ns or SIFEN_NS
    envelope = etree.Element(etree.QName(SOAP12_NS, "Envelope"), nsmap={"soap": SOAP12_NS, "xsd": SIFEN_NS})
    etree.SubElement(envelope, etree.QName(SOAP12_NS, "Header"))
    body = etree.SubElement(envelope, etree.QName(SOAP12_NS, "Body"))
    root = etree.Element(etree.QName(ns_for_body, body_localname), nsmap={"xsd": ns_for_body})
    dprot = etree.SubElement(root, etree.QName(ns_for_body, "dProtConsLote"))
    dprot.text = prot
    body.append(root)
    return etree.tostring(envelope, xml_declaration=True, encoding="UTF-8", pretty_print=False)


def _build_consulta_lote_soap_fallback(prot: str) -> bytes:
    did = _make_did_15()

    envelope = etree.Element(etree.QName(SOAP12_NS, "Envelope"), nsmap={"soap": SOAP12_NS})
    etree.SubElement(envelope, etree.QName(SOAP12_NS, "Header"))
    body = etree.SubElement(envelope, etree.QName(SOAP12_NS, "Body"))

    root = etree.Element(etree.QName(SIFEN_NS, "rEnviConsLoteDe"), nsmap={None: SIFEN_NS})
    d_id = etree.SubElement(root, etree.QName(SIFEN_NS, "dId"))
    d_id.text = did
    dprot = etree.SubElement(root, etree.QName(SIFEN_NS, "dProtConsLote"))
    dprot.text = prot
    body.append(root)

    return etree.tostring(envelope, xml_declaration=True, encoding="UTF-8", pretty_print=False)


def send(
    *,
    env: str,
    signed_rde_xml_path: Path,
    zip_mode: str = "stored",
    did: Optional[str] = None,
    artifacts_root: Optional[Path] = None,
    do_http: bool = True,
) -> Path:
    env_norm = (env or "").strip().lower()
    if env_norm not in ("test", "prod"):
        raise SystemExit(f"ERROR: --env inválido: {env!r} (usar test|prod)")

    if env_norm == "prod":
        if (os.getenv("SIFEN_CONFIRM_PROD") or "").strip() != "YES":
            raise SystemExit("ERROR: --env prod requiere SIFEN_CONFIRM_PROD=YES")

    endpoint = _get_recibe_lote_endpoint(env_norm)
    cert_path: Optional[str]
    key_path: Optional[str]
    if do_http:
        cert_path, key_path = _get_mtls_cert()
    else:
        cert_path, key_path = None, None

    signed_rde_bytes = signed_rde_xml_path.read_bytes()
    lote_xml_bytes = _build_lote_xml_from_signed_rde_bytes(signed_rde_bytes)
    zip_bytes = _zip_lote_xml(lote_xml_bytes, zip_mode=zip_mode)
    zip_b64 = base64.b64encode(zip_bytes).decode("ascii")
    did_final = _normalize_did(did)
    soap_bytes = _build_soap_envelope(did_final, zip_b64)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    root = (artifacts_root or Path(os.getenv("SIFEN_ARTIFACTS_DIR") or os.getenv("SIFEN_ARTIFACTS_PATH") or "artifacts")).expanduser()
    run_dir = root / f"run_{ts}"
    run_dir.mkdir(parents=True, exist_ok=True)

    (run_dir / "lote.xml").write_bytes(lote_xml_bytes)
    (run_dir / "zip_sent.bin").write_bytes(zip_bytes)
    (run_dir / "soap_last_request.xml").write_bytes(soap_bytes)

    meta = {
        "timestamp": ts,
        "env": env_norm,
        "endpoint": endpoint,
        "zip_mode": zip_mode,
        "did": did_final,
        "input_signed_rde_xml": str(signed_rde_xml_path),
        "mtls_cert_path": cert_path,
        "mtls_key_path": key_path,
        "lote_sha256": hashlib.sha256(lote_xml_bytes).hexdigest(),
        "zip_sha256": hashlib.sha256(zip_bytes).hexdigest(),
        "soap_request_sha256": hashlib.sha256(soap_bytes).hexdigest(),
    }

    if not do_http:
        meta["http_skipped"] = True
        (run_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
        return run_dir

    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "Accept": "application/soap+xml, text/xml, */*",
    }

    start = time.time()
    resp = None
    try:
        resp = requests.post(
            endpoint,
            data=soap_bytes,
            headers=headers,
            cert=(cert_path, key_path),
            timeout=(15, 45),
        )
        meta["http_status"] = resp.status_code
        meta["response_headers"] = dict(resp.headers)
        meta["duration_s"] = round(time.time() - start, 6)

        (run_dir / "soap_last_response.xml").write_bytes(resp.content)
        meta["soap_response_sha256"] = hashlib.sha256(resp.content).hexdigest()

        try:
            root_xml = etree.fromstring(resp.content)
            dcod = _find_first_by_localname(root_xml, "dCodRes")
            dmsg = _find_first_by_localname(root_xml, "dMsgRes")
            dprot = _find_first_by_localname(root_xml, "dProtConsLote")
            meta["dCodRes"] = (dcod.text or "").strip() if dcod is not None and dcod.text else None
            meta["dMsgRes"] = (dmsg.text or "").strip() if dmsg is not None and dmsg.text else None
            meta["dProtConsLote"] = (dprot.text or "").strip() if dprot is not None and dprot.text else None
        except Exception:
            pass

    except Exception as exc:
        meta["error"] = str(exc)
        meta["duration_s"] = round(time.time() - start, 6)
        if resp is not None:
            try:
                (run_dir / "soap_last_response.xml").write_bytes(resp.content)
            except Exception:
                pass
        raise
    finally:
        (run_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")

    return run_dir


def inspect(*, artifacts_dir: Path, out_lote: Optional[Path] = None) -> Optional[Path]:
    artifacts_dir = artifacts_dir.expanduser()
    if not artifacts_dir.exists() or not artifacts_dir.is_dir():
        raise SystemExit(f"ERROR: artifacts_dir no existe o no es directorio: {artifacts_dir}")

    request_path = _pick_first_existing(
        artifacts_dir,
        (
            "soap_last_request.xml",
            "soap_last_request_SENT.xml",
            "soap_last_sent.xml",
        ),
    )
    if request_path is None:
        raise SystemExit(f"ERROR: no se encontró request SOAP en {artifacts_dir}")

    req_bytes = request_path.read_bytes()
    try:
        root = etree.fromstring(req_bytes)
    except Exception as exc:
        raise SystemExit(f"ERROR: no se pudo parsear request XML: {request_path} ({exc})")

    body_first = _find_soap_body_first_child(root)
    print("==== REQUEST ====")
    print(f"request_file: {request_path}")
    print(f"request_bytes_len: {len(req_bytes)}")
    if body_first is not None:
        print(f"soap_body_first: {_localname(body_first.tag)} ns={_namespace(body_first.tag)}")

    xde = _find_first_by_localname(root, "xDE")
    if xde is None:
        print("xDE: NOT FOUND")
        return None
    if not (xde.text or "").strip():
        if len(list(xde)) > 0:
            print("xDE: present but not Base64 text (contains nested XML)")
        else:
            print("xDE: EMPTY")
        return None

    raw_xde = xde.text or ""
    cleaned = re.sub(r"\s+", "", raw_xde)
    print(f"xDE_base64_len: {len(cleaned)}")
    print(f"xDE_base64_has_whitespace: {cleaned != raw_xde}")
    print(f"xDE_base64_sha256: {hashlib.sha256(cleaned.encode('utf-8')).hexdigest()}")

    zip_bytes = base64.b64decode(cleaned)
    print(f"zip_bytes_len: {len(zip_bytes)}")
    print(f"zip_sha256: {hashlib.sha256(zip_bytes).hexdigest()}")

    lote_bytes = None
    zip_entries = []
    with zipfile.ZipFile(BytesIO(zip_bytes), mode="r") as zf:
        for zi in zf.infolist():
            zip_entries.append(
                {
                    "name": zi.filename,
                    "size": zi.file_size,
                    "compress_size": zi.compress_size,
                    "compress_type": zi.compress_type,
                }
            )
        if "lote.xml" in zf.namelist():
            lote_bytes = zf.read("lote.xml")
        elif zf.namelist():
            lote_bytes = zf.read(zf.namelist()[0])

    print(f"zip_entries: {zip_entries}")
    if lote_bytes is None:
        print("ZIP: vacío")
        return None

    out_path = out_lote or (artifacts_dir / "lote_extracted.xml")
    out_path.write_bytes(lote_bytes)

    lote_text = lote_bytes.decode("utf-8", errors="replace")
    print("\n==== LOTE.XML (from xDE ZIP) ====")
    print(f"out_lote: {out_path}")
    print(f"lote_bytes_len: {len(lote_bytes)}")
    print(f"lote_sha256: {hashlib.sha256(lote_bytes).hexdigest()}")
    print(f"count('xsi:'): {lote_text.count('xsi:')}")
    print(f"count('schemaLocation'): {lote_text.count('schemaLocation')}")
    print("opening_tags:")
    print(f"  rLoteDE: {_extract_opening_tag(lote_text, 'rLoteDE')}")
    print(f"  rDE: {_extract_opening_tag(lote_text, 'rDE')}")
    print(f"  DE: {_extract_opening_tag(lote_text, 'DE')}")
    print(f"  Signature: {_extract_opening_tag(lote_text, 'Signature')}")

    response_path = _pick_first_existing(
        artifacts_dir,
        (
            "soap_last_response.xml",
            "soap_last_received.xml",
            "soap_last_response_lote.xml",
        ),
    )
    print("\n==== RESPONSE ====")
    if response_path is None:
        print("response_file: NOT FOUND")
        return out_path

    resp_bytes = response_path.read_bytes()
    print(f"response_file: {response_path}")
    print(f"response_bytes_len: {len(resp_bytes)}")
    print(f"response_sha256: {hashlib.sha256(resp_bytes).hexdigest()}")
    try:
        resp_root = etree.fromstring(resp_bytes)
        resp_body_first = _find_soap_body_first_child(resp_root)
        if resp_body_first is not None:
            print(f"soap_body_first: {_localname(resp_body_first.tag)} ns={_namespace(resp_body_first.tag)}")
        dcod = _find_first_by_localname(resp_root, "dCodRes")
        dmsg = _find_first_by_localname(resp_root, "dMsgRes")
        dprot = _find_first_by_localname(resp_root, "dProtConsLote")
        if dcod is not None and (dcod.text or "").strip():
            print(f"dCodRes: {(dcod.text or '').strip()}")
        if dmsg is not None and (dmsg.text or "").strip():
            print(f"dMsgRes: {(dmsg.text or '').strip()}")
        if dprot is not None and (dprot.text or "").strip():
            print(f"dProtConsLote: {(dprot.text or '').strip()}")
    except Exception as exc:
        print(f"parse_error: {exc}")

    return out_path


def consult(
    *,
    env: str,
    prot: str,
    artifacts_dir: Optional[Path] = None,
    do_http: bool = True,
) -> Path:
    env_norm = (env or "").strip().lower()
    if env_norm not in ("test", "prod"):
        raise SystemExit(f"ERROR: --env inválido: {env!r} (usar test|prod)")

    if env_norm == "prod":
        if (os.getenv("SIFEN_CONFIRM_PROD") or "").strip() != "YES":
            raise SystemExit("ERROR: --env prod requiere SIFEN_CONFIRM_PROD=YES")

    prot_value = (prot or "").strip()
    if not prot_value:
        raise SystemExit("ERROR: --prot es requerido y no puede ser vacío")

    wsdl_url, endpoint_cfg = _get_consulta_lote_wsdl_and_endpoint(env_norm)
    wsdl_bytes: bytes = b""
    address_from_wsdl: Optional[str] = None
    body_ns: Optional[str] = None
    body_local: Optional[str] = None
    soap_action: Optional[str] = None
    op_name: Optional[str] = None
    fallback_wsdl = False
    wsdl_error: Optional[str] = None

    # mTLS: preparar cert/key antes de usarlo en GET del WSDL o POST
    cert_path: Optional[str]
    key_path: Optional[str]
    if do_http:
        cert_path, key_path = _get_mtls_cert()
    else:
        cert_path, key_path = None, None

    if do_http:
        try:
            wsdl_resp = requests.get(
                wsdl_url,
                headers={
                    # Algunos endpoints de SIFEN devuelven 200 con body vacío si falta UA/Accept.
                    # Esto imita tu curl exitoso.
                    "User-Agent": "curl/8.7.1",
                    "Accept": "*/*",
                    "Accept-Encoding": "identity",
                },
                timeout=30,
                cert=(cert_path, key_path) if cert_path and key_path else None,
            )
            wsdl_resp.raise_for_status()
            wsdl_bytes = wsdl_resp.content
            address_from_wsdl, body_ns, body_local, soap_action, op_name = _analyze_consulta_lote_wsdl(wsdl_bytes)
        except Exception as exc:
            fallback_wsdl = True
            wsdl_error = str(exc)
            print(f"WARN consult fallback sin WSDL: {wsdl_url!r}: {exc}", file=sys.stderr)

    if fallback_wsdl or not wsdl_bytes:
        soap_bytes = _build_consulta_lote_soap_fallback(prot_value)
    else:
        soap_bytes = _build_consulta_lote_soap_envelope(body_ns, body_local, prot_value)

    endpoint_from_wsdl = address_from_wsdl
    endpoint = endpoint_cfg or endpoint_from_wsdl or _normalize_endpoint(wsdl_url)
    # FIX: nunca postear a un *.wsdl (SIFEN suele resetear). Convertir a endpoint real.
    if endpoint.endswith(".wsdl"):
        endpoint = endpoint[:-5]

    if not endpoint:
        raise SystemExit("ERROR: no se pudo determinar endpoint de consulta-lote")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if artifacts_dir is not None:
        run_dir = artifacts_dir.expanduser()
    else:
        root = Path(os.getenv("SIFEN_ARTIFACTS_DIR") or os.getenv("SIFEN_ARTIFACTS_PATH") or "artifacts").expanduser()
        run_dir = root / f"run_{ts}_consult"
    run_dir.mkdir(parents=True, exist_ok=True)

    (run_dir / "soap_last_request.xml").write_bytes(soap_bytes)
    (run_dir / "wsdl_last.xml").write_bytes(wsdl_bytes)

    meta = {
        "timestamp": ts,
        "env": env_norm,
        "wsdl_url": wsdl_url,
        "endpoint": endpoint,
        "endpoint_from_wsdl": endpoint_from_wsdl,
        "soap_action": soap_action,
        "operation": op_name,
        "prot": prot_value,
        "soap_request_sha256": hashlib.sha256(soap_bytes).hexdigest(),
        "wsdl_sha256": hashlib.sha256(wsdl_bytes).hexdigest(),
        "fallback_wsdl": fallback_wsdl,
    }

    if wsdl_error is not None:
        meta["wsdl_fallback_error"] = wsdl_error
    if not do_http:
        meta["http_skipped"] = True
        (run_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")
        return run_dir

    # ya tenemos cert_path/key_path preparados arriba
    meta["mtls_cert_path"] = cert_path
    meta["mtls_key_path"] = key_path
    headers = {
        "Accept": "application/soap+xml, text/xml, */*",
    }
    # SOAP 1.2: SIEMPRE enviar Content-Type application/soap+xml
    if soap_action is not None:
        if str(soap_action) == "":
            headers["Content-Type"] = "application/soap+xml; charset=utf-8"
        else:
            headers["Content-Type"] = f'application/soap+xml; charset=utf-8; action="{soap_action}"'
    else:
        headers["Content-Type"] = "application/soap+xml; charset=utf-8"

    start = time.time()
    resp = None
    try:
        resp = requests.post(
            endpoint,
            data=soap_bytes,
            headers=headers,
            cert=(cert_path, key_path),
            timeout=60,
        )
        meta["http_status"] = resp.status_code
        meta["response_headers"] = dict(resp.headers)
        meta["duration_s"] = round(time.time() - start, 6)

        (run_dir / "soap_last_response.xml").write_bytes(resp.content)
        meta["response_sha256"] = hashlib.sha256(resp.content).hexdigest()

        try:
            root_xml = etree.fromstring(resp.content)
            dcod = _find_first_by_localname(root_xml, "dCodRes")
            dmsg = _find_first_by_localname(root_xml, "dMsgRes")
            meta["dCodRes"] = (dcod.text or "").strip() if dcod is not None and dcod.text else None
            meta["dMsgRes"] = (dmsg.text or "").strip() if dmsg is not None and dmsg.text else None

            for name in ("dEstRes", "dFecProc", "dNumEnvio", "dNumLote", "dNumRecep"):
                elem = _find_first_by_localname(root_xml, name)
                if elem is not None and elem.text and elem.text.strip():
                    meta[name] = elem.text.strip()
        except Exception:
            pass

    except Exception as exc:
        meta["error"] = str(exc)
        meta["duration_s"] = round(time.time() - start, 6)
        if resp is not None:
            try:
                (run_dir / "soap_last_response.xml").write_bytes(resp.content)
            except Exception:
                pass
        raise
    finally:
        (run_dir / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")

    return run_dir


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="sifen_minisender")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_send = sub.add_parser("send")
    p_send.add_argument("--env", required=True, choices=["test", "prod"])
    p_send.add_argument("--zip", dest="zip_mode", default="stored", choices=["stored", "deflated"])
    p_send.add_argument("--did", default="auto")
    p_send.add_argument("--no-http", action="store_true")
    p_send.add_argument("--artifacts-root", type=Path, default=None)
    p_send.add_argument("signed_rde_xml", type=Path)

    p_inspect = sub.add_parser("inspect")
    p_inspect.add_argument("artifacts_dir", type=Path)
    p_inspect.add_argument("--out-lote", type=Path, default=None)

    p_consult = sub.add_parser("consult")
    p_consult.add_argument("--env", required=True, choices=["test", "prod"])
    p_consult.add_argument("--prot", required=True)
    p_consult.add_argument("--no-http", action="store_true")
    p_consult.add_argument("--artifacts-dir", type=Path, default=None)

    args = parser.parse_args(argv)

    if args.cmd == "send":
        try:
            run_dir = send(
                env=args.env,
                signed_rde_xml_path=args.signed_rde_xml,
                zip_mode=args.zip_mode,
                did=args.did,
                artifacts_root=args.artifacts_root,
                do_http=(not args.no_http),
            )
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

        print(f"artifacts_dir: {run_dir}")
        meta_path = run_dir / "meta.json"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                if meta.get("dCodRes") is not None:
                    print(f"dCodRes: {meta.get('dCodRes')}")
                if meta.get("dMsgRes") is not None:
                    print(f"dMsgRes: {meta.get('dMsgRes')}")
                if meta.get("dProtConsLote") is not None:
                    print(f"dProtConsLote: {meta.get('dProtConsLote')}")
            except Exception:
                pass
        return 0

    if args.cmd == "inspect":
        try:
            inspect(artifacts_dir=args.artifacts_dir, out_lote=args.out_lote)
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.cmd == "consult":
        try:
            run_dir = consult(
                env=args.env,
                prot=args.prot,
                artifacts_dir=args.artifacts_dir,
                do_http=(not args.no_http),
            )
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1

        print(f"artifacts_dir: {run_dir}")
        meta_path = run_dir / "meta.json"
        if meta_path.exists():
            try:
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                if meta.get("dCodRes") is not None:
                    print(f"dCodRes: {meta.get('dCodRes')}")
                if meta.get("dMsgRes") is not None:
                    print(f"dMsgRes: {meta.get('dMsgRes')}")
                for name in ("dEstRes", "dFecProc", "dNumEnvio", "dNumLote", "dNumRecep"):
                    if meta.get(name) is not None:
                        print(f"{name}: {meta.get(name)}")
            except Exception:
                pass
        return 0

    return 2
