import os
import re
import sqlite3
import subprocess
import json
import copy
import hashlib
import smtplib
import ssl
import threading
import time
import sys
import random
import zipfile
from decimal import Decimal, ROUND_HALF_UP
from email.message import EmailMessage
from datetime import datetime, date
from flask import Flask, g, request, redirect, url_for, render_template_string, abort, send_file, jsonify
from pathlib import Path
from typing import Optional
import xml.etree.ElementTree as ET

# requests (HTTP) for eventos
import requests

# Asegurar imports desde repo root (evitar conflicto con webui/app.py)
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) in sys.path:
    sys.path.remove(str(SCRIPT_DIR))
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.pdf.invoice_renderer import render_invoice_pdf
from app.sifen_client.xml_generator_v150 import generate_cdc
from app.sifen_client.xmlsec_signer import sign_de_with_p12, sign_event_with_p12
from app.sifen_client.config import get_sifen_config
from app.sifen_client.soap_client import SoapClient
from app.sifen_client.cdc_utils import calc_dv_mod11

APP_TITLE = "SIFEN WebUI (SQLite)"
DB_PATH = os.environ.get("SIFEN_WEBUI_DB", os.path.join(os.path.dirname(__file__), "data.db"))

app = Flask(__name__)

DOC_TYPE_MAP = {
    "1": "Factura electrónica",
    "4": "Autofactura electrónica",
    "5": "Nota de crédito electrónica",
    "6": "Nota de débito electrónica",
    "7": "Nota de remisión electrónica",
}

DOC_ASOC_TYPE_MAP = {
    "1": "Electrónico",
    "2": "Impreso",
    "3": "Constancia Electrónica",
}

DOC_IMPRESO_TYPE_MAP = {
    "1": "Factura",
    "2": "Nota de crédito",
    "3": "Nota de débito",
    "4": "Nota de remisión",
    "5": "Comprobante de retención",
}

NC_MOTIVO_MAP = {
    "1": "Devolución y Ajuste de precios",
    "2": "Devolución",
    "3": "Descuento",
    "4": "Bonificación",
    "5": "Crédito incobrable",
    "6": "Recupero de costo",
    "7": "Recupero de gasto",
    "8": "Ajuste de precio",
}

REM_MOTIVO_MAP = {
    "1": "Traslado por ventas",
    "2": "Traslado por consignación",
    "3": "Exportación",
    "4": "Traslado por compra",
    "5": "Importación",
    "6": "Traslado por devolución",
    "7": "Traslado entre locales de la empresa",
    "8": "Traslado de bienes por transformación",
    "9": "Traslado de bienes por reparación",
    "10": "Traslado por emisor móvil",
    "11": "Exhibición o demostración",
    "12": "Participación en ferias",
    "13": "Traslado de encomienda",
    "14": "Decomiso",
    "99": "Otro",
}

REM_RESP_MAP = {
    "1": "Emisor de la factura",
    "2": "Poseedor de la factura y bienes",
    "3": "Empresa transportista",
    "4": "Despachante de Aduanas",
    "5": "Agente de transporte o intermediario",
}

AFE_NAT_MAP = {
    "1": "No contribuyente",
    "2": "Extranjero",
}

AFE_ID_MAP = {
    "1": "Cédula paraguaya",
    "2": "Pasaporte",
    "3": "Cédula extranjera",
    "4": "Carnet de residencia",
}

EVENT_MOTIVOS = [
    "Error en datos del cliente",
    "Error en monto/total",
    "Error en RUC/DV",
    "Error en ítems",
    "Error en impuestos",
    "Error en fecha",
    "Documento duplicado",
    "Operación anulada",
    "Cliente desistió",
    "Prueba de conexión",
]

TRANS_TIPO_MAP = {
    "1": "Propio",
    "2": "Tercero",
}

TRANS_MOD_MAP = {
    "1": "Terrestre",
    "2": "Fluvial",
    "3": "Aéreo",
    "4": "Multimodal",
}

RESP_FLETE_MAP = {
    "1": "Emisor de la Factura Electrónica",
    "2": "Receptor de la Factura Electrónica",
    "3": "Tercero",
    "4": "Agente intermediario del transporte",
    "5": "Transporte propio",
}

VEH_TIPO_MAP = {
    "1": "Camion",
    "2": "Camioneta",
    "3": "Furgon",
    "4": "Otro",
}

_GEOREF_CACHE = None

# -------------------------
# Simple in-process queue
# -------------------------
_QUEUE = []
_QUEUE_LOCK = None
_QUEUE_WORKER_STARTED = False
_POLLING = set()
_POLL_LOCK = None
_BACKUP_LOCK = None
_BACKUP_THREAD_STARTED = False
_LOTE_SYNC_THREAD_STARTED = False
_BOOTSTRAP_LOCK = None
_BOOTSTRAPPED = False

# -------------------------
# DB helpers
# -------------------------
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys = ON;")
        con.execute("PRAGMA journal_mode = WAL;")
        con.execute("PRAGMA synchronous = FULL;")
        con.execute("PRAGMA busy_timeout = 5000;")
        g.db = con
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    con = g.pop("db", None)
    if con is not None:
        con.close()

def init_db():
    con = get_db()
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );

CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ruc TEXT,
            email TEXT,
            phone TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sku TEXT,
            name TEXT NOT NULL,
            unit TEXT DEFAULT 'UN',
            price_unit INTEGER DEFAULT 0, -- en guaraníes (entero) para evitar floats
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            issued_at TEXT, -- cuando el usuario "emitió" (puede ser igual a created_at)
            customer_id INTEGER NOT NULL REFERENCES customers(id),
            currency TEXT DEFAULT 'PYG',
            total INTEGER DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'DRAFT',
            sifen_env TEXT,
            doc_type TEXT DEFAULT '1',
            doc_number TEXT,
            doc_extra_json TEXT,
            signed_at TEXT,
            queued_at TEXT,
            sent_at TEXT,
            confirmed_at TEXT,
            sifen_prot_cons_lote TEXT,
            last_lote_code TEXT,
            last_lote_msg TEXT,
            last_sifen_code TEXT,
            last_sifen_msg TEXT,
            last_event_type TEXT,
            last_event_id TEXT,
            last_event_est TEXT,
            last_event_code TEXT,
            last_event_msg TEXT,
            last_event_prot_aut TEXT,
            last_event_at TEXT,
            last_event_artifacts_dir TEXT,
            source_xml_path TEXT,
            last_artifacts_dir TEXT
        );

        CREATE TABLE IF NOT EXISTS invoice_lines (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_id INTEGER NOT NULL REFERENCES invoices(id) ON DELETE CASCADE,
            product_id INTEGER REFERENCES products(id),
            description TEXT NOT NULL,
            qty INTEGER NOT NULL DEFAULT 1,
            price_unit INTEGER NOT NULL DEFAULT 0,
            line_total INTEGER NOT NULL DEFAULT 0
        );

        CREATE INDEX IF NOT EXISTS idx_invoices_created_at ON invoices(created_at);
        CREATE INDEX IF NOT EXISTS idx_invoices_status ON invoices(status);
        CREATE INDEX IF NOT EXISTS idx_customers_name ON customers(name);
        """
    )
        # Migraciones ligeras (SQLite): agregar columnas si faltan
    cols = {row['name'] for row in con.execute("PRAGMA table_info(invoices)")}
    if 'source_xml_path' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN source_xml_path TEXT")
    if 'last_artifacts_dir' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_artifacts_dir TEXT")
    if 'pdf_path' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN pdf_path TEXT")
    if 'email_status' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN email_status TEXT")
    if 'last_sifen_est' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_sifen_est TEXT")
    if 'last_sifen_prot_aut' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_sifen_prot_aut TEXT")
    if 'last_lote_code' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_lote_code TEXT")
    if 'last_lote_msg' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_lote_msg TEXT")
    if 'sifen_env' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN sifen_env TEXT")
    if 'doc_number' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN doc_number TEXT")
    if 'signed_at' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN signed_at TEXT")
    if 'codseg' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN codseg TEXT")
    if 'establishment' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN establishment TEXT")
    if 'point_exp' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN point_exp TEXT")
    if 'doc_type' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN doc_type TEXT DEFAULT '1'")
    if 'doc_extra_json' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN doc_extra_json TEXT")
    if 'last_event_type' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_type TEXT")
    if 'last_event_id' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_id TEXT")
    if 'last_event_est' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_est TEXT")
    if 'last_event_code' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_code TEXT")
    if 'last_event_msg' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_msg TEXT")
    if 'last_event_prot_aut' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_prot_aut TEXT")
    if 'last_event_at' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_at TEXT")
    if 'last_event_artifacts_dir' not in cols:
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_artifacts_dir TEXT")
    con.commit()

def now_iso():
    return datetime.now().isoformat(timespec="seconds")

def _parse_iso_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None

def _ensure_doc_number(con: sqlite3.Connection, inv: sqlite3.Row, invoice_id: int) -> str:
    doc_number = (inv["doc_number"] or "").strip() if "doc_number" in inv.keys() else ""
    if doc_number:
        return doc_number
    est = (inv["establishment"] or "").strip() if "establishment" in inv.keys() else ""
    pun = (inv["point_exp"] or "").strip() if "point_exp" in inv.keys() else ""
    doc_type = (inv["doc_type"] or "").strip() if "doc_type" in inv.keys() else ""
    dnum = _next_doc_number(con, invoice_id, est, pun, doc_type)
    con.execute("UPDATE invoices SET doc_number=? WHERE id=?", (dnum, invoice_id))
    con.commit()
    return dnum

def _ensure_signed_at(con: sqlite3.Connection, inv: sqlite3.Row, invoice_id: int) -> datetime:
    signed_at = (inv["signed_at"] or "").strip() if "signed_at" in inv.keys() else ""
    issued_at = (inv["issued_at"] or "").strip() if "issued_at" in inv.keys() else ""

    dt = _parse_iso_dt(signed_at) or _parse_iso_dt(issued_at)
    if not dt:
        signed_at = now_iso()
        dt = _parse_iso_dt(signed_at)
    if not signed_at:
        signed_at = dt.isoformat(timespec="seconds")
    if not (inv["signed_at"] or "").strip():
        con.execute("UPDATE invoices SET signed_at=? WHERE id=?", (signed_at, invoice_id))
        con.commit()
    return dt

def _ensure_codseg(con: sqlite3.Connection, inv: sqlite3.Row, invoice_id: int) -> str:
    codseg = (inv["codseg"] or "").strip() if "codseg" in inv.keys() else ""
    if codseg and re.fullmatch(r"\d{9}", codseg):
        return codseg
    env_cod = (os.getenv("SIFEN_CODSEG") or "").strip()
    if re.fullmatch(r"\d{9}", env_cod):
        codseg = env_cod
    else:
        codseg = str(random.randint(0, 999999999)).zfill(9)
    con.execute("UPDATE invoices SET codseg=? WHERE id=?", (codseg, invoice_id))
    con.commit()
    return codseg

def _extract_signed_xml_meta(xml_text: str) -> dict:
    cdc = None
    if xml_text:
        m = re.search(r'<DE[^>]+Id="([0-9]{44})"', xml_text)
        if m:
            cdc = m.group(1)
    return {
        "cdc": cdc,
        "dnumdoc": _extract_tag(xml_text, "dNumDoc"),
        "feemi": _extract_tag(xml_text, "dFeEmiDE") or _extract_tag(xml_text, "dFecFirma"),
        "total": _extract_tag(xml_text, "dTotGralOpe"),
        "tot_iva": _extract_tag(xml_text, "dTotIVA"),
    }

def _backfill_doc_info_from_xml(con: sqlite3.Connection, inv: sqlite3.Row, invoice_id: int, xml_text: str) -> dict:
    meta = _extract_signed_xml_meta(xml_text)
    doc_number = (inv["doc_number"] or "").strip() if "doc_number" in inv.keys() else ""
    signed_at = (inv["signed_at"] or "").strip() if "signed_at" in inv.keys() else ""

    if not doc_number and meta.get("dnumdoc"):
        con.execute("UPDATE invoices SET doc_number=? WHERE id=?", (meta["dnumdoc"], invoice_id))
        con.commit()
    if not signed_at and meta.get("feemi"):
        con.execute("UPDATE invoices SET signed_at=? WHERE id=?", (meta["feemi"], invoice_id))
        con.commit()
    return meta

def _fmt_decimal(value: Decimal, places: int = 4) -> str:
    q = Decimal("1." + ("0" * places))
    return str(Decimal(value).quantize(q, rounding=ROUND_HALF_UP))


def _to_decimal(value, default: Optional[Decimal] = Decimal("0")) -> Optional[Decimal]:
    if value is None:
        return default
    if isinstance(value, Decimal):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))
    raw = str(value).strip()
    if not raw:
        return default
    cleaned = re.sub(r"[^\d,.\-]", "", raw)
    if not cleaned or cleaned in ("-", ".", ","):
        return default
    if "," in cleaned and "." in cleaned:
        if cleaned.rfind(",") > cleaned.rfind("."):
            cleaned = cleaned.replace(".", "")
            cleaned = cleaned.replace(",", ".")
        else:
            cleaned = cleaned.replace(",", "")
    elif "," in cleaned:
        cleaned = cleaned.replace(",", ".")
    try:
        return Decimal(cleaned)
    except Exception:
        return default


def _fmt_decimal_places(value: Decimal, places: int) -> str:
    if places <= 0:
        return str(int(Decimal(value).quantize(Decimal("1"), rounding=ROUND_HALF_UP)))
    q = Decimal("1." + ("0" * places))
    return str(Decimal(value).quantize(q, rounding=ROUND_HALF_UP))


def _decimal_places_from_text(text: Optional[str], default: int) -> int:
    if text is None:
        return default
    raw = str(text).strip()
    m = re.match(r"^-?\d+[.,](\d+)$", raw)
    if not m:
        return default
    return len(m.group(1))


def _infer_places_from_xpath(root: ET.Element, xpath: str, ns: dict, default: int) -> int:
    el = root.find(xpath, ns)
    if el is None:
        return default
    return _decimal_places_from_text(el.text, default)


def _line_get(line, key: str, default=None):
    if isinstance(line, dict):
        return line.get(key, default)
    try:
        return line[key]
    except Exception:
        return default


def _safe_get_setting(key: str, default: str = "") -> str:
    try:
        return get_setting(key, default)
    except Exception:
        return default


def _config_value(setting_key: str, env_keys: list[str]) -> tuple[str, str]:
    sval = (_safe_get_setting(setting_key, "") or "").strip()
    if sval:
        return sval, f"settings:{setting_key}"
    for env_key in env_keys:
        ev = (os.getenv(env_key) or "").strip()
        if ev:
            return ev, f"env:{env_key}"
    return "", ""


def _resolve_timb_values(
    *,
    establishment: Optional[str],
    point_exp: Optional[str],
    template_tim: dict,
) -> tuple[dict, list[str]]:
    warnings: list[str] = []

    tim_num, tim_src = _config_value(
        "timbrado_num",
        ["SIFEN_TIMBRADO_NUM", "SIFEN_NUM_TIMBRADO", "SIFEN_DNUMTIM"],
    )
    tim_fe_ini, fe_ini_src = _config_value(
        "timbrado_fe_ini",
        ["SIFEN_TIMBRADO_FE_INI", "SIFEN_DFEINIT"],
    )
    est_setting, _ = _config_value(
        "est",
        ["SIFEN_EST", "SIFEN_ESTABLECIMIENTO", "SIFEN_DEFAULT_EST"],
    )
    pun_setting, _ = _config_value(
        "pun",
        ["SIFEN_PUN", "SIFEN_PUN_EXP", "SIFEN_PUNTO_EXPEDICION", "SIFEN_DEFAULT_PUN"],
    )

    if not tim_src:
        warnings.append("timbrado_num no configurado en settings/env; se usa valor del template.")
    if not fe_ini_src:
        warnings.append("timbrado_fe_ini no configurado en settings/env; se usa valor del template.")

    est_arg = _zfill_digits(establishment, 3)
    pun_arg = _zfill_digits(point_exp, 3)
    est = est_arg or _zfill_digits(est_setting, 3) or _zfill_digits(_safe_get_setting("default_establishment", ""), 3)
    pun = pun_arg or _zfill_digits(pun_setting, 3) or _zfill_digits(_safe_get_setting("default_point_exp", ""), 3)

    return {
        "dNumTim": _zfill_digits(tim_num, 8) or (template_tim.get("dNumTim") or ""),
        "dFeIniT": (tim_fe_ini or template_tim.get("dFeIniT") or "").strip(),
        "dEst": est or (template_tim.get("dEst") or ""),
        "dPunExp": pun or (template_tim.get("dPunExp") or ""),
    }, warnings

def normalize_doc_type(value: Optional[str]) -> str:
    raw = re.sub(r"\D", "", (value or "").strip())
    raw = raw.lstrip("0") or "1"
    return raw if raw in DOC_TYPE_MAP else "1"

def doc_type_label(code: Optional[str]) -> str:
    return DOC_TYPE_MAP.get(normalize_doc_type(code), "Factura electrónica")

def _read_json_file(path: Path) -> Optional[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None

def _default_extra_json_for(doc_type: str) -> Optional[dict]:
    repo_root = _repo_root()
    base = repo_root / "json-ejemplos-tipos-de-factura"
    if doc_type == "4":
        data = _read_json_file(base / "ejemplo-autofactura.json") or {}
        # En AFE el documento asociado debe ser Constancia Electrónica (H002=3)
        data["documentoAsociado"] = {
            "tipoDocumentoAsoc": "3",
        }
        return data
    if doc_type in ("5", "6"):
        # usar nota de crédito como base para NC/ND
        return _read_json_file(base / "ejemplo-nota-de-credito.json")
    if doc_type == "7":
        return _read_json_file(base / "data2.1.json (remision)")
    return None

def _parse_extra_json(text: Optional[str], doc_type: str) -> dict:
    if text and text.strip():
        try:
            return json.loads(text)
        except Exception as e:
            raise RuntimeError(f"JSON extra inválido: {e}")
    fallback = _default_extra_json_for(doc_type)
    return fallback or {}

def _get_transport_from_extra(extra_json: dict) -> dict:
    extra_json = extra_json or {}
    transporte = extra_json.get("transporte")
    if isinstance(transporte, list):
        transporte = transporte[0] if transporte else {}
    return transporte or {}

def _parse_price_unit(price_raw: str) -> int:
    if not price_raw:
        return 0
    cleaned = price_raw.replace(".", "").replace(",", "").replace(" ", "")
    if cleaned.isdigit():
        return int(cleaned)
    raise RuntimeError("Precio inválido (solo números, opcional separador de miles)")

def _load_georef_maps() -> dict:
    global _GEOREF_CACHE
    if _GEOREF_CACHE is not None:
        return _GEOREF_CACHE
    path = _repo_root() / "data" / "georef_maps.json"
    if path.exists():
        try:
            _GEOREF_CACHE = json.loads(path.read_text(encoding="utf-8"))
            return _GEOREF_CACHE
        except Exception:
            pass
    _GEOREF_CACHE = {"dep": {}, "dist": {}, "city": {}}
    return _GEOREF_CACHE

def _geo_name(kind: str, code: Optional[str]) -> str:
    if code is None:
        return ""
    code_str = str(code).strip()
    if not code_str:
        return ""
    code_str = re.sub(r"\D", "", code_str)
    if not code_str:
        return ""
    try:
        code_str = str(int(code_str))
    except Exception:
        code_str = code_str.lstrip("0") or code_str
    maps = _load_georef_maps()
    return (maps.get(kind, {}) or {}).get(code_str, "")

def _validate_doc_extra(doc_type: str, extra_json: dict) -> list:
    errors = []
    extra_json = extra_json or {}

    def _is_digits(val: str, length: Optional[int] = None) -> bool:
        if not val or not val.isdigit():
            return False
        return len(val) == length if length else True

    if doc_type in ("4", "5", "6"):
        assoc = extra_json.get("documentoAsociado") or {}
        if not assoc and extra_json.get("cdcAsociado"):
            assoc = {"tipoDocumentoAsoc": "1", "cdcAsociado": extra_json.get("cdcAsociado")}
        if not assoc:
            errors.append("Falta documentoAsociado (obligatorio para AFE/NC/ND).")
        else:
            tip = str(assoc.get("tipoDocumentoAsoc") or assoc.get("iTipDocAso") or "1").strip()
            if tip not in ("1", "2", "3"):
                errors.append("documentoAsociado.tipoDocumentoAsoc inválido (1/2/3).")
            if tip == "1":
                cdc = str(assoc.get("cdcAsociado") or assoc.get("dCdCDERef") or "").strip()
                if not _is_digits(cdc, 44):
                    errors.append("documentoAsociado.cdcAsociado debe ser CDC de 44 dígitos (iTipDocAso=1).")
            if tip == "2":
                tim = _zfill_digits(assoc.get("timbradoAsoc"), 8)
                est = _zfill_digits(assoc.get("establecimientoAsoc"), 3)
                pun = _zfill_digits(assoc.get("puntoAsoc"), 3)
                num = _zfill_digits(assoc.get("numeroAsoc"), 7)
                if not all([tim, est, pun, num]):
                    errors.append("documentoAsociado (iTipDocAso=2) requiere timbrado/establecimiento/punto/numero.")

    if doc_type in ("5", "6"):
        mot = str(extra_json.get("iMotEmi") or extra_json.get("motivo") or extra_json.get("descripcion") or "").strip()
        if mot not in NC_MOTIVO_MAP:
            errors.append("Falta iMotEmi en doc_extra_json (1-8) para Nota de crédito/débito.")

    if doc_type == "4":
        afe = extra_json.get("autofactura") or {}
        if not str(afe.get("documento") or "").strip():
            errors.append("Autofactura: falta autofactura.documento (dNumIDVen).")
        if not str(afe.get("nombre") or "").strip():
            errors.append("Autofactura: falta autofactura.nombre (dNomVen).")
        # En AFE el documento asociado debe ser Constancia Electrónica (H002=3)
        assoc = extra_json.get("documentoAsociado") or {}
        tip = str(assoc.get("tipoDocumentoAsoc") or assoc.get("iTipDocAso") or "").strip()
        if tip and tip != "3":
            errors.append("Autofactura: documentoAsociado.tipoDocumentoAsoc debe ser 3 (Constancia electrónica).")
    if doc_type in ("5", "6"):
        assoc = extra_json.get("documentoAsociado") or {}
        tip = str(assoc.get("tipoDocumentoAsoc") or assoc.get("iTipDocAso") or "").strip()
        if tip == "3":
            errors.append("Nota crédito/débito: documentoAsociado.tipoDocumentoAsoc no puede ser 3 (Constancia electrónica).")

    if doc_type == "7":
        rem = extra_json.get("remision") or {}
        mot = str(rem.get("iMotEmiNR") or rem.get("motivo") or "").strip()
        if mot not in REM_MOTIVO_MAP:
            errors.append("Remisión: falta remision.motivo (1-14/99).")
        resp = str(rem.get("iRespEmiNR") or rem.get("responsableEmi") or "").strip()
        if resp not in REM_RESP_MAP:
            errors.append("Remisión: falta remision.responsableEmi (1-5).")

        transporte = extra_json.get("transporte")
        if transporte and isinstance(transporte, list):
            transporte = transporte[0] if transporte else None
        if not transporte:
            errors.append("Remisión: falta transporte (gTransp obligatorio).")
        else:
            mod = str(transporte.get("iModTrans") or transporte.get("modalidad") or "").strip()
            if mod not in TRANS_MOD_MAP:
                errors.append("Transporte: falta modalidad (iModTrans 1-4).")
            resp_flete = str(transporte.get("iRespFlete") or transporte.get("tipoResponsable") or "").strip()
            if resp_flete not in RESP_FLETE_MAP:
                errors.append("Transporte: falta tipoResponsable (iRespFlete 1-5).")

            salida = transporte.get("salida") or {}
            entrega = transporte.get("entrega") or {}
            for label, loc in [("salida", salida), ("entrega", entrega)]:
                if not str(loc.get("direccion") or "").strip():
                    errors.append(f"Transporte {label}: falta direccion.")
                if not str(loc.get("numCasa") or "").strip():
                    errors.append(f"Transporte {label}: falta numCasa.")
                if not str(loc.get("departamento") or "").strip():
                    errors.append(f"Transporte {label}: falta departamento.")
                if not str(loc.get("ciudad") or "").strip():
                    errors.append(f"Transporte {label}: falta ciudad.")

            veh = transporte.get("vehiculo") or {}
            if not str(veh.get("tipo") or "").strip():
                errors.append("Vehículo: falta tipo.")
            if not str(veh.get("marca") or "").strip():
                errors.append("Vehículo: falta marca.")
            if not str(veh.get("documentoTipo") or "").strip():
                errors.append("Vehículo: falta documentoTipo (dTipIdenVeh).")
            if not str(veh.get("numeroIden") or "").strip():
                errors.append("Vehículo: falta numeroIden / numeroMat.")

            trans = transporte.get("transportista") or {}
            if not str(trans.get("tipo") or "").strip():
                errors.append("Transportista: falta tipo (iNatTrans).")
            if not str(trans.get("nombreTr") or "").strip():
                errors.append("Transportista: falta nombreTr.")
            if not str(trans.get("numeroTr") or "").strip():
                errors.append("Transportista: falta numeroTr.")
            if not str(trans.get("nombreCh") or "").strip():
                errors.append("Transportista: falta nombreCh.")
            if not str(trans.get("numeroCh") or "").strip():
                errors.append("Transportista: falta numeroCh.")

    return errors

def _split_ruc_dv(ruc_raw: Optional[str]) -> tuple[str, str]:
    if not ruc_raw:
        return "", ""
    raw = ruc_raw.strip()
    if "-" in raw:
        ruc, dv = raw.split("-", 1)
        return re.sub(r"\D", "", ruc), re.sub(r"\D", "", dv)[:1]
    digits = re.sub(r"\D", "", raw)
    if not digits:
        return "", ""
    try:
        dv = str(calc_dv_mod11(digits))
    except Exception:
        dv = ""
    return digits, dv

def _default_template_path(doc_type: str = "1") -> str:
    # Prefer versioned templates shipped with the repo/image so Docker/EC2
    # does not depend on local artifacts history.
    default_by_type = {
        "1": _repo_root() / "templates" / "xml" / "rde_factura.xml",
        "4": _repo_root() / "templates" / "xml" / "rde_autofactura.xml",
        "5": _repo_root() / "templates" / "xml" / "rde_nota_credito.xml",
        "6": _repo_root() / "templates" / "xml" / "rde_nota_debito.xml",
        "7": _repo_root() / "templates" / "xml" / "rde_remision.xml",
    }
    cand = default_by_type.get((doc_type or "").strip(), default_by_type["1"])
    if cand.exists():
        return str(cand)
    # Backward-compatible fallback for older deployments.
    legacy = _repo_root() / "artifacts" / "prod_emit_20260206" / "rde_input.xml"
    return str(legacy) if legacy.exists() else ""

def _template_for_doc_type(doc_type: str) -> str:
    key_map = {
        "1": "template_xml_path_factura",
        "4": "template_xml_path_autofactura",
        "5": "template_xml_path_nota_credito",
        "6": "template_xml_path_nota_debito",
        "7": "template_xml_path_remision",
    }
    key = key_map.get(doc_type, "template_xml_path_factura")
    path = (get_setting(key, "") or "").strip()
    if path:
        return path
    fallback = (get_setting("template_xml_path", "") or "").strip()
    return fallback or _default_template_path(doc_type)

def _next_doc_number(con: sqlite3.Connection, invoice_id: int, est: str = "", pun: str = "", doc_type: str = "") -> str:
    est = _zfill_digits(est, 3) or ""
    pun = _zfill_digits(pun, 3) or ""
    doc_type = (doc_type or "").strip()
    if est and pun and doc_type:
        key = f"next_dnumdoc_{est}_{pun}_{doc_type}"
        raw = (get_setting(key, "") or "").strip()
        if raw.isdigit():
            num = int(raw)
        else:
            row = con.execute(
                "SELECT MAX(CAST(doc_number AS INTEGER)) AS maxnum FROM invoices WHERE establishment=? AND point_exp=? AND doc_type=?",
                (est, pun, doc_type),
            ).fetchone()
            maxnum = int(row["maxnum"] or 0)
            num = maxnum + 1
        dnum = str(num).zfill(7)
        set_setting(key, str(num + 1).zfill(7))
        return dnum

    raw = (get_setting("next_dnumdoc", "") or "").strip()
    if raw.isdigit():
        num = int(raw)
        dnum = str(num).zfill(7)
        set_setting("next_dnumdoc", str(num + 1).zfill(7))
        return dnum
    return str(invoice_id).zfill(7)

def _make_event_id() -> str:
    base = datetime.now().strftime("%Y%m%d%H%M%S")
    return (base + str(random.randint(0, 9)))[-10:]

def _make_did_15() -> str:
    base = datetime.now().strftime("%Y%m%d%H%M%S")
    return base + str(random.randint(0, 9))

def _zfill_digits(value: Optional[str], width: int) -> str:
    raw = "" if value is None else str(value)
    digits = re.sub(r"\D", "", raw.strip())
    if not digits:
        return ""
    return digits.zfill(width)

def _extract_cdc_from_xml_path(xml_path: str) -> Optional[str]:
    if not xml_path:
        return None
    p = Path(xml_path)
    if not p.is_absolute():
        p = (_repo_root() / p).resolve()
    if not p.exists():
        return None
    text = p.read_text(encoding="utf-8")
    m = re.search(r'<DE[^>]+Id="([0-9]{44})"', text)
    return m.group(1) if m else None

def _extract_inutil_defaults_from_xml_path(xml_path: str) -> dict:
    defaults = {"dNumTim": "", "dEst": "", "dPunExp": "", "dNumDoc": "", "iTiDE": ""}
    if not xml_path:
        return defaults
    p = Path(xml_path)
    if not p.is_absolute():
        p = (_repo_root() / p).resolve()
    if not p.exists():
        return defaults
    try:
        xml = p.read_text(encoding="utf-8")
        root = ET.fromstring(xml)
        ns = {"s": "http://ekuatia.set.gov.py/sifen/xsd"}
        def _t(path: str) -> str:
            el = root.find(path, ns)
            return (el.text or "").strip() if el is not None and el.text else ""
        defaults["dNumTim"] = _t(".//s:gTimb/s:dNumTim")
        defaults["dEst"] = _t(".//s:gTimb/s:dEst")
        defaults["dPunExp"] = _t(".//s:gTimb/s:dPunExp")
        defaults["dNumDoc"] = _t(".//s:gTimb/s:dNumDoc")
        defaults["iTiDE"] = _t(".//s:gTimb/s:iTiDE")
    except Exception:
        return defaults
    return defaults

def _build_cancel_event_xml(cdc: str, motivo: str, event_id: str) -> bytes:
    ns_uri = "http://ekuatia.set.gov.py/sifen/xsd"
    ET.register_namespace("", ns_uri)
    root = ET.Element(f"{{{ns_uri}}}gGroupGesEve")
    rGesEve = ET.SubElement(root, f"{{{ns_uri}}}rGesEve")
    rEve = ET.SubElement(rGesEve, f"{{{ns_uri}}}rEve")
    rEve.set("Id", event_id)
    dFecFirma = ET.SubElement(rEve, f"{{{ns_uri}}}dFecFirma")
    dFecFirma.text = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    dVerFor = ET.SubElement(rEve, f"{{{ns_uri}}}dVerFor")
    dVerFor.text = "150"
    dTiGDE = ET.SubElement(rEve, f"{{{ns_uri}}}dTiGDE")
    dTiGDE.text = "1"
    gGroupTiEvt = ET.SubElement(rEve, f"{{{ns_uri}}}gGroupTiEvt")
    rGeVeCan = ET.SubElement(gGroupTiEvt, f"{{{ns_uri}}}rGeVeCan")
    cdc_el = ET.SubElement(rGeVeCan, f"{{{ns_uri}}}Id")
    cdc_el.text = cdc
    mot = ET.SubElement(rGeVeCan, f"{{{ns_uri}}}mOtEve")
    mot.text = motivo
    return ET.tostring(root, encoding="utf-8", method="xml")

def _build_inutil_event_xml(
    *,
    timbrado: str,
    est: str,
    punexp: str,
    num_ini: str,
    num_fin: str,
    tipo_doc: str,
    motivo: str,
    event_id: str,
) -> bytes:
    ns_uri = "http://ekuatia.set.gov.py/sifen/xsd"
    ET.register_namespace("", ns_uri)
    root = ET.Element(f"{{{ns_uri}}}gGroupGesEve")
    rGesEve = ET.SubElement(root, f"{{{ns_uri}}}rGesEve")
    rEve = ET.SubElement(rGesEve, f"{{{ns_uri}}}rEve")
    rEve.set("Id", event_id)
    dFecFirma = ET.SubElement(rEve, f"{{{ns_uri}}}dFecFirma")
    dFecFirma.text = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    dVerFor = ET.SubElement(rEve, f"{{{ns_uri}}}dVerFor")
    dVerFor.text = "150"
    dTiGDE = ET.SubElement(rEve, f"{{{ns_uri}}}dTiGDE")
    dTiGDE.text = "2"
    gGroupTiEvt = ET.SubElement(rEve, f"{{{ns_uri}}}gGroupTiEvt")
    rGeVeInu = ET.SubElement(gGroupTiEvt, f"{{{ns_uri}}}rGeVeInu")
    ET.SubElement(rGeVeInu, f"{{{ns_uri}}}dNumTim").text = timbrado
    ET.SubElement(rGeVeInu, f"{{{ns_uri}}}dEst").text = est
    ET.SubElement(rGeVeInu, f"{{{ns_uri}}}dPunExp").text = punexp
    ET.SubElement(rGeVeInu, f"{{{ns_uri}}}dNumIn").text = num_ini
    ET.SubElement(rGeVeInu, f"{{{ns_uri}}}dNumFin").text = num_fin
    ET.SubElement(rGeVeInu, f"{{{ns_uri}}}iTiDE").text = tipo_doc
    ET.SubElement(rGeVeInu, f"{{{ns_uri}}}mOtEve").text = motivo
    return ET.tostring(root, encoding="utf-8", method="xml")

def _send_cancel_event(
    *,
    env: str,
    cdc: str,
    motivo: str,
    event_id: str,
    artifacts_root: Path,
) -> dict:
    cfg = get_sifen_config(env=env)
    wsdl_url = cfg.get_soap_service_url("evento")

    # construir evento
    event_xml = _build_cancel_event_xml(cdc, motivo, event_id)
    p12_path = os.getenv("SIFEN_SIGN_P12_PATH") or os.getenv("SIFEN_P12_PATH") or os.getenv("SIFEN_CERT_PATH")
    p12_password = os.getenv("SIFEN_SIGN_P12_PASSWORD") or os.getenv("SIFEN_P12_PASSWORD") or os.getenv("SIFEN_CERT_PASSWORD")
    if not p12_path or not p12_password:
        raise RuntimeError("Faltan SIFEN_SIGN_P12_PATH/SIFEN_SIGN_P12_PASSWORD (o equivalentes) para firmar evento.")

    signed_event = sign_event_with_p12(event_xml, p12_path, p12_password).decode("utf-8")

    # construir SOAP
    soap_ns = "http://www.w3.org/2003/05/soap-envelope"
    sifen_ns = "http://ekuatia.set.gov.py/sifen/xsd"
    envelope = ET.Element(f"{{{soap_ns}}}Envelope")
    ET.SubElement(envelope, f"{{{soap_ns}}}Header")
    body = ET.SubElement(envelope, f"{{{soap_ns}}}Body")
    root = ET.SubElement(body, f"{{{sifen_ns}}}rEnviEventoDe")
    did = ET.SubElement(root, f"{{{sifen_ns}}}dId")
    did.text = _make_did_15()
    devreg = ET.SubElement(root, f"{{{sifen_ns}}}dEvReg")
    devreg.append(ET.fromstring(signed_event))

    soap_bytes = ET.tostring(envelope, encoding="utf-8", method="xml")

    # POST con mTLS
    cert_path = os.getenv("SIFEN_CERT_PATH") or ""
    key_path = os.getenv("SIFEN_KEY_PATH") or ""
    if not cert_path or not key_path:
        raise RuntimeError("Faltan SIFEN_CERT_PATH/SIFEN_KEY_PATH para mTLS.")

    run_dir = artifacts_root / f"event_cancel_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "event_signed.xml").write_text(signed_event, encoding="utf-8")
    (run_dir / "soap_last_request.xml").write_bytes(soap_bytes)

    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "Accept": "application/soap+xml, text/xml, */*",
    }
    resp = requests.post(wsdl_url, data=soap_bytes, headers=headers, cert=(cert_path, key_path), timeout=(15, 60))
    (run_dir / "soap_last_response.xml").write_bytes(resp.content)

    parsed = _parse_consult_response(resp.content.decode("utf-8", errors="ignore"))
    parsed["http_status"] = resp.status_code
    parsed["artifacts_dir"] = str(run_dir)
    parsed["event_id"] = event_id
    return parsed

def _send_inutil_event(
    *,
    env: str,
    timbrado: str,
    est: str,
    punexp: str,
    num_ini: str,
    num_fin: str,
    tipo_doc: str,
    motivo: str,
    event_id: str,
    artifacts_root: Path,
) -> dict:
    cfg = get_sifen_config(env=env)
    wsdl_url = cfg.get_soap_service_url("evento")

    event_xml = _build_inutil_event_xml(
        timbrado=timbrado,
        est=est,
        punexp=punexp,
        num_ini=num_ini,
        num_fin=num_fin,
        tipo_doc=tipo_doc,
        motivo=motivo,
        event_id=event_id,
    )

    p12_path = os.getenv("SIFEN_SIGN_P12_PATH") or os.getenv("SIFEN_P12_PATH") or os.getenv("SIFEN_CERT_PATH")
    p12_password = os.getenv("SIFEN_SIGN_P12_PASSWORD") or os.getenv("SIFEN_P12_PASSWORD") or os.getenv("SIFEN_CERT_PASSWORD")
    if not p12_path or not p12_password:
        raise RuntimeError("Faltan SIFEN_SIGN_P12_PATH/SIFEN_SIGN_P12_PASSWORD (o equivalentes) para firmar evento.")

    signed_event = sign_event_with_p12(event_xml, p12_path, p12_password).decode("utf-8")

    soap_ns = "http://www.w3.org/2003/05/soap-envelope"
    sifen_ns = "http://ekuatia.set.gov.py/sifen/xsd"
    envelope = ET.Element(f"{{{soap_ns}}}Envelope")
    ET.SubElement(envelope, f"{{{soap_ns}}}Header")
    body = ET.SubElement(envelope, f"{{{soap_ns}}}Body")
    root = ET.SubElement(body, f"{{{sifen_ns}}}rEnviEventoDe")
    did = ET.SubElement(root, f"{{{sifen_ns}}}dId")
    did.text = _make_did_15()
    devreg = ET.SubElement(root, f"{{{sifen_ns}}}dEvReg")
    devreg.append(ET.fromstring(signed_event))

    soap_bytes = ET.tostring(envelope, encoding="utf-8", method="xml")

    cert_path = os.getenv("SIFEN_CERT_PATH") or ""
    key_path = os.getenv("SIFEN_KEY_PATH") or ""
    if not cert_path or not key_path:
        raise RuntimeError("Faltan SIFEN_CERT_PATH/SIFEN_KEY_PATH para mTLS.")

    run_dir = artifacts_root / f"event_inutil_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "event_signed.xml").write_text(signed_event, encoding="utf-8")
    (run_dir / "soap_last_request.xml").write_bytes(soap_bytes)

    headers = {
        "Content-Type": "application/soap+xml; charset=utf-8",
        "Accept": "application/soap+xml, text/xml, */*",
    }
    resp = requests.post(wsdl_url, data=soap_bytes, headers=headers, cert=(cert_path, key_path), timeout=(15, 60))
    (run_dir / "soap_last_response.xml").write_bytes(resp.content)

    parsed = _parse_consult_response(resp.content.decode("utf-8", errors="ignore"))
    parsed["http_status"] = resp.status_code
    parsed["artifacts_dir"] = str(run_dir)
    parsed["event_id"] = event_id
    return parsed

def _update_text(root: ET.Element, xpath: str, value: str, ns: dict) -> None:
    el = root.find(xpath, ns)
    if el is not None:
        el.text = value

def _ensure_child(parent: ET.Element, tag: str) -> ET.Element:
    child = parent.find(tag)
    if child is None:
        child = ET.SubElement(parent, tag)
    return child

def _ensure_child_ns(parent: ET.Element, tag: str, ns_uri: str) -> ET.Element:
    child = parent.find(f"{{{ns_uri}}}{tag}")
    if child is None:
        child = ET.SubElement(parent, f"{{{ns_uri}}}{tag}")
    return child

def _remove_child_ns(parent: ET.Element, tag: str, ns_uri: str) -> None:
    child = parent.find(f"{{{ns_uri}}}{tag}")
    if child is not None:
        parent.remove(child)

def _fill_geo_desc_in(parent: Optional[ET.Element], code_tag: str, desc_tag: str, kind: str, ns_uri: str) -> None:
    if parent is None:
        return
    code_el = parent.find(f"{{{ns_uri}}}{code_tag}")
    if code_el is None or not (code_el.text or "").strip():
        return
    desc_el = parent.find(f"{{{ns_uri}}}{desc_tag}")
    if desc_el is not None and (desc_el.text or "").strip():
        return
    name = _geo_name(kind, code_el.text or "")
    if name:
        _ensure_child_ns(parent, desc_tag, ns_uri).text = name

def _build_invoice_xml_from_template(
    *,
    template_path: str,
    invoice_id: int,
    customer: sqlite3.Row,
    lines: list,
    doc_number: Optional[str] = None,
    doc_type: str = "1",
    extra_json: Optional[dict] = None,
    issue_dt: Optional[datetime] = None,
    codseg: Optional[str] = None,
    establishment: Optional[str] = None,
    point_exp: Optional[str] = None,
) -> dict:
    ns_uri = "http://ekuatia.set.gov.py/sifen/xsd"
    ns = {"s": ns_uri}
    ET.register_namespace("", ns_uri)
    ET.register_namespace("xsi", "http://www.w3.org/2001/XMLSchema-instance")

    xml = Path(template_path).read_text(encoding="utf-8")
    root = ET.fromstring(xml)

    # Documento / fechas
    def _text(path: str) -> str:
        el = root.find(path, ns)
        return (el.text or "").strip() if el is not None and el.text else ""

    template_tim = {
        "dNumTim": _text(".//s:gTimb/s:dNumTim"),
        "dFeIniT": _text(".//s:gTimb/s:dFeIniT"),
        "dEst": _text(".//s:gTimb/s:dEst"),
        "dPunExp": _text(".//s:gTimb/s:dPunExp"),
    }
    tim_values, build_warnings = _resolve_timb_values(
        establishment=establishment,
        point_exp=point_exp,
        template_tim=template_tim,
    )

    dnumdoc = doc_number or str(invoice_id).zfill(7)
    _update_text(root, ".//s:gTimb/s:dNumDoc", dnumdoc, ns)
    if tim_values.get("dNumTim"):
        _update_text(root, ".//s:gTimb/s:dNumTim", tim_values["dNumTim"], ns)
    if tim_values.get("dFeIniT"):
        _update_text(root, ".//s:gTimb/s:dFeIniT", tim_values["dFeIniT"], ns)
    if tim_values.get("dEst"):
        _update_text(root, ".//s:gTimb/s:dEst", tim_values["dEst"], ns)
    if tim_values.get("dPunExp"):
        _update_text(root, ".//s:gTimb/s:dPunExp", tim_values["dPunExp"], ns)
    _update_text(root, ".//s:gTimb/s:iTiDE", doc_type, ns)
    _update_text(root, ".//s:gTimb/s:dDesTiDE", doc_type_label(doc_type), ns)

    now = issue_dt or datetime.now()
    iso = now.strftime("%Y-%m-%dT%H:%M:%S")
    _update_text(root, ".//s:gDatGralOpe/s:dFeEmiDE", iso, ns)
    _update_text(root, ".//s:dFecFirma", iso, ns)

    codseg_digits = re.sub(r"\D", "", str(codseg or "").strip())
    if not re.fullmatch(r"\d{9}", codseg_digits):
        raise RuntimeError("codseg requerido y debe tener exactamente 9 dígitos.")
    de_node = root.find(".//s:DE", ns)
    if de_node is None:
        raise RuntimeError("No se encontró <DE> en el XML base.")
    gopede = de_node.find("s:gOpeDE", ns)
    if gopede is None:
        gopede = _ensure_child_ns(de_node, "gOpeDE", ns_uri)
    _ensure_child_ns(gopede, "dCodSeg", ns_uri).text = codseg_digits

    fe_ini = _text(".//s:gTimb/s:dFeIniT")
    if fe_ini:
        try:
            fe_ini_date = date.fromisoformat(fe_ini[:10])
            if now.date() < fe_ini_date:
                raise RuntimeError(
                    f"Fecha de emisión {now.date().isoformat()} anterior al inicio de timbrado {fe_ini_date.isoformat()}."
                )
        except ValueError:
            raise RuntimeError(f"dFeIniT inválida en XML: {fe_ini!r}")

    # Receptor
    cust_name = (customer["name"] or "").strip()
    cust_ruc_raw = (customer["ruc"] or "").strip()
    cust_ruc, cust_dv = _split_ruc_dv(cust_ruc_raw)
    if cust_name:
        _update_text(root, ".//s:gDatRec/s:dNomRec", cust_name, ns)
    if cust_ruc:
        _update_text(root, ".//s:gDatRec/s:dRucRec", cust_ruc, ns)
    if cust_dv:
        _update_text(root, ".//s:gDatRec/s:dDVRec", cust_dv, ns)

    extra_json = extra_json or {}

    # Ajustes por tipo de documento
    gdtip = root.find(".//s:gDtipDE", ns)
    if gdtip is None:
        raise RuntimeError("No se encontró <gDtipDE> en el XML base.")
    if doc_type != "1":
        _remove_child_ns(gdtip, "gCamFE", ns_uri)
    if doc_type not in ("1", "4"):
        _remove_child_ns(gdtip, "gCamCond", ns_uri)

    # dInfoFisc obligatorio para Remisión
    if doc_type == "7":
        info_fisc = extra_json.get("dInfoFisc") or extra_json.get("infoFisc") or "Traslado de mercaderías"
        gopede = root.find(".//s:gOpeDE", ns)
        if gopede is not None:
            _ensure_child_ns(gopede, "dInfoFisc", ns_uri).text = str(info_fisc)

    # gCamAE (Autofactura)
    if doc_type == "4":
        afe = extra_json.get("autofactura") or {}
        gcam = _ensure_child_ns(gdtip, "gCamAE", ns_uri)
        i_nat = str(afe.get("iNatVen") or afe.get("naturaleza") or "1").strip()
        if i_nat not in ("1", "2"):
            i_nat = "1"
        _ensure_child_ns(gcam, "iNatVen", ns_uri).text = i_nat
        _ensure_child_ns(gcam, "dDesNatVen", ns_uri).text = AFE_NAT_MAP.get(i_nat, "No contribuyente")

        i_tip_id = str(afe.get("iTipIDVen") or afe.get("tipoDocumento") or "1").strip()
        if i_tip_id not in AFE_ID_MAP:
            i_tip_id = "1"
        _ensure_child_ns(gcam, "iTipIDVen", ns_uri).text = i_tip_id
        _ensure_child_ns(gcam, "dDTipIDVen", ns_uri).text = AFE_ID_MAP.get(i_tip_id, "Cédula paraguaya")

        _ensure_child_ns(gcam, "dNumIDVen", ns_uri).text = str(afe.get("documento") or "1")
        _ensure_child_ns(gcam, "dNomVen", ns_uri).text = str(afe.get("nombre") or "Vendedor")

        def _emval(path: str) -> str:
            el = root.find(path, ns)
            return (el.text or "").strip() if el is not None and el.text else ""

        dir_ven = str(afe.get("direccion") or afe.get("direccionVendedor") or _emval(".//s:gEmis/s:dDirEmi") or "Dirección").strip()
        num_cas_ven = str(afe.get("numCasa") or _emval(".//s:gEmis/s:dNumCas") or "0").strip()
        _ensure_child_ns(gcam, "dDirVen", ns_uri).text = dir_ven
        _ensure_child_ns(gcam, "dNumCasVen", ns_uri).text = num_cas_ven

        dep_ven = str(afe.get("departamentoVendedor") or _emval(".//s:gEmis/s:cDepEmi") or "1").strip()
        des_dep_ven = str(afe.get("dDesDepVen") or _emval(".//s:gEmis/s:dDesDepEmi") or "CAPITAL").strip()
        _ensure_child_ns(gcam, "cDepVen", ns_uri).text = dep_ven
        _ensure_child_ns(gcam, "dDesDepVen", ns_uri).text = des_dep_ven

        dis_ven = str(afe.get("distritoVendedor") or "").strip()
        if dis_ven:
            _ensure_child_ns(gcam, "cDisVen", ns_uri).text = dis_ven
            des_dis = str(afe.get("dDesDisVen") or "").strip()
            if des_dis:
                _ensure_child_ns(gcam, "dDesDisVen", ns_uri).text = des_dis

        ciu_ven = str(afe.get("ciudadVendedor") or _emval(".//s:gEmis/s:cCiuEmi") or "1").strip()
        des_ciu_ven = str(afe.get("dDesCiuVen") or _emval(".//s:gEmis/s:dDesCiuEmi") or "ASUNCION (DISTRITO)").strip()
        _ensure_child_ns(gcam, "cCiuVen", ns_uri).text = ciu_ven
        _ensure_child_ns(gcam, "dDesCiuVen", ns_uri).text = des_ciu_ven

        dir_prov = str(afe.get("direccionProv") or afe.get("direccionVendedor") or dir_ven).strip()
        dep_prov = str(afe.get("departamentoProv") or dep_ven).strip()
        des_dep_prov = str(afe.get("dDesDepProv") or des_dep_ven).strip()
        ciu_prov = str(afe.get("ciudadProv") or ciu_ven).strip()
        des_ciu_prov = str(afe.get("dDesCiuProv") or des_ciu_ven).strip()
        _ensure_child_ns(gcam, "dDirProv", ns_uri).text = dir_prov
        _ensure_child_ns(gcam, "cDepProv", ns_uri).text = dep_prov
        _ensure_child_ns(gcam, "dDesDepProv", ns_uri).text = des_dep_prov

        dis_prov = str(afe.get("distritoProv") or "").strip()
        if dis_prov:
            _ensure_child_ns(gcam, "cDisProv", ns_uri).text = dis_prov
            des_dis_p = str(afe.get("dDesDisProv") or "").strip()
            if des_dis_p:
                _ensure_child_ns(gcam, "dDesDisProv", ns_uri).text = des_dis_p

        _ensure_child_ns(gcam, "cCiuProv", ns_uri).text = ciu_prov
        _ensure_child_ns(gcam, "dDesCiuProv", ns_uri).text = des_ciu_prov

    # gCamNCDE (Nota de crédito/débito)
    if doc_type in ("5", "6"):
        gcam = _ensure_child_ns(gdtip, "gCamNCDE", ns_uri)
        mot_raw = extra_json.get("iMotEmi") or extra_json.get("motivo") or extra_json.get("descripcion") or "1"
        mot = str(mot_raw).strip()
        if not mot.isdigit():
            mot = "1"
        _ensure_child_ns(gcam, "iMotEmi", ns_uri).text = mot
        _ensure_child_ns(gcam, "dDesMotEmi", ns_uri).text = NC_MOTIVO_MAP.get(mot, "Devolución")

    # gCamNRE (Remisión)
    if doc_type == "7":
        rem = extra_json.get("remision") or {}
        gcam = _ensure_child_ns(gdtip, "gCamNRE", ns_uri)
        mot = str(rem.get("iMotEmiNR") or rem.get("motivo") or "1").strip()
        if not mot.isdigit():
            mot = "1"
        _ensure_child_ns(gcam, "iMotEmiNR", ns_uri).text = mot
        _ensure_child_ns(gcam, "dDesMotEmiNR", ns_uri).text = REM_MOTIVO_MAP.get(mot, "Otro")

        resp = str(rem.get("iRespEmiNR") or rem.get("responsableEmi") or "1").strip()
        if not resp.isdigit():
            resp = "1"
        _ensure_child_ns(gcam, "iRespEmiNR", ns_uri).text = resp
        _ensure_child_ns(gcam, "dDesRespEmiNR", ns_uri).text = REM_RESP_MAP.get(resp, "Emisor de la factura")

        km = rem.get("kmEstimado")
        if km is not None and str(km).strip() != "":
            _ensure_child_ns(gcam, "dKmR", ns_uri).text = str(int(float(km)))

        fec = rem.get("fechaFactura") or rem.get("dFecEm")
        if fec:
            _ensure_child_ns(gcam, "dFecEm", ns_uri).text = str(fec).split(" ")[0]

    # Completar descripciones geográficas en emisor/receptor/autofactura
    g_emis = root.find(".//s:gEmis", ns)
    _fill_geo_desc_in(g_emis, "cDepEmi", "dDesDepEmi", "dep", ns_uri)
    _fill_geo_desc_in(g_emis, "cDisEmi", "dDesDisEmi", "dist", ns_uri)
    _fill_geo_desc_in(g_emis, "cCiuEmi", "dDesCiuEmi", "city", ns_uri)

    g_rec = root.find(".//s:gDatRec", ns)
    _fill_geo_desc_in(g_rec, "cDepRec", "dDesDepRec", "dep", ns_uri)
    _fill_geo_desc_in(g_rec, "cDisRec", "dDesDisRec", "dist", ns_uri)
    _fill_geo_desc_in(g_rec, "cCiuRec", "dDesCiuRec", "city", ns_uri)

    if doc_type == "4":
        g_ae = root.find(".//s:gDtipDE/s:gCamAE", ns)
        _fill_geo_desc_in(g_ae, "cDepVen", "dDesDepVen", "dep", ns_uri)
        _fill_geo_desc_in(g_ae, "cDisVen", "dDesDisVen", "dist", ns_uri)
        _fill_geo_desc_in(g_ae, "cCiuVen", "dDesCiuVen", "city", ns_uri)
        _fill_geo_desc_in(g_ae, "cDepProv", "dDesDepProv", "dep", ns_uri)
        _fill_geo_desc_in(g_ae, "cDisProv", "dDesDisProv", "dist", ns_uri)
        _fill_geo_desc_in(g_ae, "cCiuProv", "dDesCiuProv", "city", ns_uri)

    # gTransp (Transporte)
    if doc_type in ("4", "5", "6"):
        _remove_child_ns(gdtip, "gTransp", ns_uri)
    else:
        transporte = extra_json.get("transporte")
        if transporte and isinstance(transporte, list):
            transporte = transporte[0] if transporte else None
        if doc_type == "7" and not transporte:
            raise RuntimeError("doc_extra_json.transporte requerido para Remisión (iTiDE=7).")
        if transporte:
            gtransp = _ensure_child_ns(gdtip, "gTransp", ns_uri)
            tip_trans = str(transporte.get("iTipTrans") or transporte.get("tipoTransporte") or "").strip()
            if tip_trans:
                _ensure_child_ns(gtransp, "iTipTrans", ns_uri).text = tip_trans
                _ensure_child_ns(gtransp, "dDesTipTrans", ns_uri).text = TRANS_TIPO_MAP.get(tip_trans, "Tercero")

            mod_trans = str(transporte.get("iModTrans") or transporte.get("modalidad") or "1").strip()
            if mod_trans:
                _ensure_child_ns(gtransp, "iModTrans", ns_uri).text = mod_trans
                _ensure_child_ns(gtransp, "dDesModTrans", ns_uri).text = TRANS_MOD_MAP.get(mod_trans, "Terrestre")

            resp_flete = str(transporte.get("iRespFlete") or transporte.get("tipoResponsable") or "").strip()
            if resp_flete:
                _ensure_child_ns(gtransp, "iRespFlete", ns_uri).text = resp_flete

            ini = transporte.get("iniFechaEstimadaTrans") or transporte.get("dIniTras")
            fin = transporte.get("finFechaEstimadaTrans") or transporte.get("dFinTras")
            if ini:
                _ensure_child_ns(gtransp, "dIniTras", ns_uri).text = str(ini).split(" ")[0]
            if fin:
                _ensure_child_ns(gtransp, "dFinTras", ns_uri).text = str(fin).split(" ")[0]

            def _set_loc(loc: dict, tag: str) -> None:
                if not loc:
                    return
                g = _ensure_child_ns(gtransp, tag, ns_uri)
                if tag == "gCamSal":
                    ddir = "dDirLocSal"
                    dnum = "dNumCasSal"
                    dcomp1 = "dComp1Sal"
                    dcomp2 = "dComp2Sal"
                    cdep = "cDepSal"
                    ddep = "dDesDepSal"
                    cdis = "cDisSal"
                    ddis = "dDesDisSal"
                    cciu = "cCiuSal"
                    dciu = "dDesCiuSal"
                    dtel = "dTelSal"
                else:
                    ddir = "dDirLocEnt"
                    dnum = "dNumCasEnt"
                    dcomp1 = "dComp1Ent"
                    dcomp2 = "dComp2Ent"
                    cdep = "cDepEnt"
                    ddep = "dDesDepEnt"
                    cdis = "cDisEnt"
                    ddis = "dDesDisEnt"
                    cciu = "cCiuEnt"
                    dciu = "dDesCiuEnt"
                    dtel = "dTelEnt"

                _ensure_child_ns(g, ddir, ns_uri).text = str(loc.get("direccion") or loc.get("dir") or "S/D")
                _ensure_child_ns(g, dnum, ns_uri).text = str(loc.get("numCasa") or loc.get("numero") or "0")
                comp1 = loc.get("comp1") or loc.get("complemento1")
                comp2 = loc.get("comp2") or loc.get("complemento2")
                if comp1:
                    _ensure_child_ns(g, dcomp1, ns_uri).text = str(comp1)
                if comp2:
                    _ensure_child_ns(g, dcomp2, ns_uri).text = str(comp2)

                dep = loc.get("departamento")
                dep_code = _zfill_digits(dep, 2) if dep is not None else ""
                if dep_code:
                    _ensure_child_ns(g, cdep, ns_uri).text = dep_code
                    dep_desc = loc.get("departamentoDesc") or _geo_name("dep", dep_code)
                    if dep_desc:
                        _ensure_child_ns(g, ddep, ns_uri).text = dep_desc

                dis = loc.get("distrito")
                dis_code = _zfill_digits(dis, 4) if dis is not None else ""
                if dis_code:
                    _ensure_child_ns(g, cdis, ns_uri).text = dis_code
                    dis_desc = loc.get("distritoDesc") or _geo_name("dist", dis_code)
                    if dis_desc:
                        _ensure_child_ns(g, ddis, ns_uri).text = dis_desc

                ciu = loc.get("ciudad")
                ciu_code = _zfill_digits(ciu, 5) if ciu is not None else ""
                if ciu_code:
                    _ensure_child_ns(g, cciu, ns_uri).text = ciu_code
                    ciu_desc = loc.get("ciudadDesc") or _geo_name("city", ciu_code)
                    if ciu_desc:
                        _ensure_child_ns(g, dciu, ns_uri).text = ciu_desc

                tel = loc.get("telefono")
                if tel:
                    _ensure_child_ns(g, dtel, ns_uri).text = str(tel)

            _set_loc(transporte.get("salida") or {}, "gCamSal")
            _set_loc(transporte.get("entrega") or {}, "gCamEnt")

            veh = transporte.get("vehiculo") or {}
            if veh:
                gveh = _ensure_child_ns(gtransp, "gVehTras", ns_uri)
                vtipo = str(veh.get("tipo") or veh.get("dTiVehTras") or "").strip()
                if vtipo:
                    _ensure_child_ns(gveh, "dTiVehTras", ns_uri).text = VEH_TIPO_MAP.get(vtipo, vtipo)
                marca = veh.get("marca") or veh.get("dMarVeh")
                if marca:
                    _ensure_child_ns(gveh, "dMarVeh", ns_uri).text = str(marca)

                tip_id = str(veh.get("documentoTipo") or veh.get("dTipIdenVeh") or "1").strip()
                _ensure_child_ns(gveh, "dTipIdenVeh", ns_uri).text = tip_id
                nro = veh.get("numeroIden") or veh.get("dNroIDVeh") or veh.get("numeroMat") or veh.get("dNroMatVeh")
                if tip_id == "1" and nro:
                    _ensure_child_ns(gveh, "dNroIDVeh", ns_uri).text = str(nro)
                elif tip_id == "2" and nro:
                    _ensure_child_ns(gveh, "dNroMatVeh", ns_uri).text = str(nro)

                nro_vuelo = veh.get("numeroVuelo") or veh.get("dNroVuelo")
                if mod_trans == "3" and nro_vuelo:
                    _ensure_child_ns(gveh, "dNroVuelo", ns_uri).text = str(nro_vuelo)

            trans = transporte.get("transportista") or {}
            if trans or doc_type == "7":
                gcam = _ensure_child_ns(gtransp, "gCamTrans", ns_uri)
                nat = str(trans.get("tipo") or trans.get("iNatTrans") or "1").strip()
                if nat not in ("1", "2"):
                    nat = "1"
                _ensure_child_ns(gcam, "iNatTrans", ns_uri).text = nat
                _ensure_child_ns(gcam, "dNomTrans", ns_uri).text = str(trans.get("nombreTr") or trans.get("nombre") or "Transportista")

                if nat == "1":
                    ruc_raw = str(trans.get("numeroTr") or trans.get("ruc") or "").strip()
                    ruc, dv = _split_ruc_dv(ruc_raw)
                    if not dv and ruc:
                        try:
                            dv = str(calc_dv_mod11(ruc))
                        except Exception:
                            dv = ""
                    if ruc:
                        _ensure_child_ns(gcam, "dRucTrans", ns_uri).text = ruc
                    if dv:
                        _ensure_child_ns(gcam, "dDVTrans", ns_uri).text = dv
                else:
                    tip_id = str(trans.get("tipoDocumentoTr") or trans.get("iTipIDTrans") or "1").strip()
                    if tip_id not in AFE_ID_MAP:
                        tip_id = "1"
                    _ensure_child_ns(gcam, "iTipIDTrans", ns_uri).text = tip_id
                    _ensure_child_ns(gcam, "dDTipIDTrans", ns_uri).text = AFE_ID_MAP.get(tip_id, "Cédula paraguaya")
                    num_id = trans.get("numeroTr") or trans.get("dNumIDTrans")
                    if num_id:
                        _ensure_child_ns(gcam, "dNumIDTrans", ns_uri).text = str(num_id)

                num_ch = trans.get("numeroCh") or trans.get("dNumIDChof") or "0"
                nom_ch = trans.get("nombreCh") or trans.get("dNomChof") or "Chofer"
                _ensure_child_ns(gcam, "dNumIDChof", ns_uri).text = str(num_ch)
                _ensure_child_ns(gcam, "dNomChof", ns_uri).text = str(nom_ch)

                dom_fisc = trans.get("direccionTr") or trans.get("dDomFisc")
                if dom_fisc:
                    _ensure_child_ns(gcam, "dDomFisc", ns_uri).text = str(dom_fisc)
                dir_ch = trans.get("direccionCh") or trans.get("dDirChof")
                if dir_ch:
                    _ensure_child_ns(gcam, "dDirChof", ns_uri).text = str(dir_ch)

    # Items
    existing_items = gdtip.findall("s:gCamItem", ns)
    if not existing_items:
        raise RuntimeError("No se encontró <gCamItem> en el XML base.")

    base_item = copy.deepcopy(existing_items[0])
    for item in existing_items:
        gdtip.remove(item)

    currency = (_text(".//s:gDatGralOpe/s:gOpeCom/s:cMoneOpe") or "PYG").upper()
    money_places_default = 0 if currency == "PYG" else 2

    qty_places = _infer_places_from_xpath(base_item, "s:dCantProSer", ns, 2)
    unit_places = _infer_places_from_xpath(base_item, "s:gValorItem/s:dPUniProSer", ns, money_places_default)
    item_total_places = _infer_places_from_xpath(base_item, "s:gValorItem/s:dTotBruOpeItem", ns, money_places_default)
    op_item_places = _infer_places_from_xpath(base_item, "s:gValorItem/s:gValorRestaItem/s:dTotOpeItem", ns, item_total_places)
    base_places = _infer_places_from_xpath(base_item, "s:gCamIVA/s:dBasGravIVA", ns, 4)
    iva_places = _infer_places_from_xpath(base_item, "s:gCamIVA/s:dLiqIVAItem", ns, 4)

    total = Decimal("0")
    sub_exe = Decimal("0")
    sub_exo = Decimal("0")
    sub5 = Decimal("0")
    sub10 = Decimal("0")
    base5 = Decimal("0")
    base10 = Decimal("0")
    iva5 = Decimal("0")
    iva10 = Decimal("0")
    items_for_pdf = []

    afec_desc = {
        "1": "Gravado IVA",
        "2": "Exonerado IVA",
        "3": "Exento IVA",
    }

    for idx, line in enumerate(lines, start=1):
        qty = _to_decimal(_line_get(line, "qty", 1), Decimal("1")) or Decimal("1")
        if qty <= 0:
            qty = Decimal("1")
        price_unit = _to_decimal(_line_get(line, "price_unit", 0), Decimal("0")) or Decimal("0")

        line_total = _to_decimal(_line_get(line, "line_total"), None)
        if line_total is None:
            line_total = qty * price_unit
        if line_total < 0:
            raise RuntimeError(f"line_total inválido en línea {idx}: {line_total}")

        iva_rate_raw = _line_get(line, "iva_rate", _line_get(line, "tax_rate", _line_get(line, "iva")))
        iva_rate = _to_decimal(iva_rate_raw, Decimal("10")) or Decimal("10")
        if iva_rate not in (Decimal("0"), Decimal("5"), Decimal("10")):
            iva_rate = Decimal("10")

        afec = str(
            _line_get(line, "afectacion", _line_get(line, "iAfecIVA", ""))
        ).strip()
        if afec not in ("1", "2", "3"):
            afec = "1" if iva_rate in (Decimal("5"), Decimal("10")) else "3"
        if afec != "1":
            iva_rate = Decimal("0")

        if afec == "1" and iva_rate in (Decimal("5"), Decimal("10")):
            factor = Decimal("1") + (iva_rate / Decimal("100"))
            base = (line_total / factor)
            iva = line_total - base
            base = Decimal(_fmt_decimal_places(base, base_places))
            iva = Decimal(_fmt_decimal_places(iva, iva_places))
        else:
            base = Decimal("0")
            iva = Decimal("0")

        total += line_total
        if afec == "1" and iva_rate == Decimal("5"):
            sub5 += line_total
            base5 += base
            iva5 += iva
        elif afec == "1" and iva_rate == Decimal("10"):
            sub10 += line_total
            base10 += base
            iva10 += iva
        elif afec == "2":
            sub_exo += line_total
        else:
            sub_exe += line_total

        item = copy.deepcopy(base_item)
        _update_text(item, "s:dCodInt", f"{idx:03d}", ns)
        _update_text(item, "s:dDesProSer", _line_get(line, "description", "") or "", ns)
        _update_text(item, "s:dCantProSer", _fmt_decimal_places(qty, qty_places), ns)
        _update_text(item, "s:gValorItem/s:dPUniProSer", _fmt_decimal_places(price_unit, unit_places), ns)
        _update_text(item, "s:gValorItem/s:dTotBruOpeItem", _fmt_decimal_places(line_total, item_total_places), ns)
        _update_text(item, "s:gValorItem/s:gValorRestaItem/s:dTotOpeItem", _fmt_decimal_places(line_total, op_item_places), ns)

        gcamiva = item.find("s:gCamIVA", ns)
        if gcamiva is not None:
            _update_text(gcamiva, "s:iAfecIVA", afec, ns)
            _update_text(gcamiva, "s:dDesAfecIVA", afec_desc.get(afec, "Gravado IVA"), ns)
            _update_text(gcamiva, "s:dPropIVA", "100" if afec == "1" else "0", ns)
            _update_text(gcamiva, "s:dTasaIVA", str(int(iva_rate)), ns)
            _update_text(gcamiva, "s:dBasGravIVA", _fmt_decimal_places(base, base_places), ns)
            _update_text(gcamiva, "s:dLiqIVAItem", _fmt_decimal_places(iva, iva_places), ns)
            dbase = gcamiva.find("s:dBasExe", ns)
            dbase_value = line_total if afec in ("2", "3") else Decimal("0")
            dbase_text = _fmt_decimal_places(dbase_value, item_total_places)
            if dbase is None:
                ET.SubElement(gcamiva, f"{{{ns_uri}}}dBasExe").text = dbase_text
            else:
                dbase.text = dbase_text

        gdtip.append(item)

        items_for_pdf.append({
            "descripcion": _line_get(line, "description", ""),
            "cantidad": _fmt_decimal_places(qty, qty_places),
            "precio_unit": _fmt_decimal_places(price_unit, unit_places),
            "iva": str(int(iva_rate)),
            "total": _fmt_decimal_places(line_total, item_total_places),
        })

    iva_total = iva5 + iva10
    total_str = _fmt_decimal_places(total, money_places_default)
    base_total_str = _fmt_decimal_places(base5 + base10, base_places)
    iva_total_str = _fmt_decimal_places(iva_total, iva_places)
    cdc_total_str = _fmt_decimal_places(total, 0)

    _update_text(root, ".//s:gDtipDE/s:gCamCond/s:gPaConEIni/s:dMonTiPag", total_str, ns)

    if doc_type != "7":
        gtot = root.find(".//s:gTotSub", ns)
        if gtot is not None:
            def _gtot_places(tag: str, default_places: int) -> int:
                return _infer_places_from_xpath(root, f".//s:gTotSub/s:{tag}", ns, default_places)

            def _set_gtot(tag: str, value: Decimal, default_places: int) -> None:
                el = _ensure_child_ns(gtot, tag, ns_uri)
                el.text = _fmt_decimal_places(value, _gtot_places(tag, default_places))

            _set_gtot("dSubExe", sub_exe, money_places_default)
            _set_gtot("dSubExo", sub_exo, money_places_default)
            _set_gtot("dSub5", sub5, money_places_default)
            _set_gtot("dSub10", sub10, money_places_default)
            _set_gtot("dTotOpe", total, money_places_default)
            _set_gtot("dTotGralOpe", total, money_places_default)
            _set_gtot("dIVA5", iva5, iva_places)
            _set_gtot("dIVA10", iva10, iva_places)
            _set_gtot("dLiqTotIVA5", Decimal("0"), iva_places)
            _set_gtot("dLiqTotIVA10", Decimal("0"), iva_places)
            _set_gtot("dTotIVA", iva_total, iva_places)
            _set_gtot("dBaseGrav5", base5, base_places)
            _set_gtot("dBaseGrav10", base10, base_places)
            _set_gtot("dTBasGraIVA", (base5 + base10), base_places)

            # PYG: no debe existir dTotalGs
            dtotal = gtot.find("s:dTotalGs", ns)
            if dtotal is not None:
                gtot.remove(dtotal)

            if doc_type == "4":
                # Autofactura: remover campos no permitidos según doc
                for tag in [
                    "dSubExe",
                    "dSubExo",
                    "dSub5",
                    "dSub10",
                    "dIVA5",
                    "dIVA10",
                    "dTotIVA",
                    "dBaseGrav5",
                    "dBaseGrav10",
                    "dTBasGraIVA",
                    "dTotalGs",
                    "dComi",
                    "dIVAComi",
                ]:
                        el = gtot.find(f"s:{tag}", ns)
                        if el is not None:
                            gtot.remove(el)
    else:
        # Remisión: no informar gTotSub
        gtot = root.find(".//s:gTotSub", ns)
        if gtot is not None:
            parent = root.find(".//s:DE", ns)
            if parent is not None:
                try:
                    parent.remove(gtot)
                except Exception:
                    pass

    # CDC
    ruc_em = _text(".//s:gEmis/s:dRucEm")
    dv_em = _text(".//s:gEmis/s:dDVEmi")
    ruc_full = f"{ruc_em}-{dv_em}"
    timbrado = _text(".//s:gTimb/s:dNumTim")
    est = _text(".//s:gTimb/s:dEst")
    pun = _text(".//s:gTimb/s:dPunExp")
    tipo_doc = _text(".//s:gTimb/s:iTiDE")
    fecha = iso[:10].replace("-", "")

    cdc = generate_cdc(
        ruc=ruc_full,
        timbrado=timbrado,
        establecimiento=est,
        punto_expedicion=pun,
        numero_documento=dnumdoc,
        tipo_documento=tipo_doc,
        fecha=fecha,
        monto=f"{int(cdc_total_str):010d}",
        codseg=codseg_digits,
    )

    de = root.find(".//s:DE", ns)
    if de is None:
        raise RuntimeError("No se encontró <DE> para setear CDC.")
    de.set("Id", cdc)
    _update_text(root, ".//s:dDVId", cdc[-1], ns)

    # gCamDEAsoc para AFE/NC/ND
    if doc_type in ("4", "5", "6"):
        assoc = extra_json.get("documentoAsociado") or {}
        if not assoc and extra_json.get("cdcAsociado"):
            assoc = {"tipoDocumentoAsoc": "1", "cdcAsociado": extra_json.get("cdcAsociado")}
        if not assoc:
            raise RuntimeError("Falta documentoAsociado en doc_extra_json (obligatorio para AFE/NC/ND).")
        de_node = root.find(".//s:DE", ns)
        if de_node is None:
            raise RuntimeError("No se encontró <DE> para insertar gCamDEAsoc.")
        gcam = de_node.find("s:gCamDEAsoc", ns)
        if gcam is None:
            gcam = ET.Element(f"{{{ns_uri}}}gCamDEAsoc")
            insert_after = de_node.find("s:gTotSub", ns) or de_node.find("s:gCamGen", ns) or de_node.find("s:gDtipDE", ns)
            if insert_after is not None:
                idx = list(de_node).index(insert_after)
                de_node.insert(idx + 1, gcam)
            else:
                de_node.append(gcam)

        tip_doc_aso = str(assoc.get("tipoDocumentoAsoc") or assoc.get("iTipDocAso") or "1").strip()
        if tip_doc_aso not in ("1", "2", "3"):
            tip_doc_aso = "1"
        _ensure_child_ns(gcam, "iTipDocAso", ns_uri).text = tip_doc_aso
        _ensure_child_ns(gcam, "dDesTipDocAso", ns_uri).text = DOC_ASOC_TYPE_MAP.get(tip_doc_aso, "Electrónico")

        if tip_doc_aso == "1":
            cdc_ref = str(assoc.get("cdcAsociado") or assoc.get("dCdCDERef") or "").strip()
            if not cdc_ref:
                raise RuntimeError("documentoAsociado.cdcAsociado requerido para iTipDocAso=1")
            _ensure_child_ns(gcam, "dCdCDERef", ns_uri).text = cdc_ref
        elif tip_doc_aso == "2":
            tim = _zfill_digits(assoc.get("timbradoAsoc"), 8)
            est = _zfill_digits(assoc.get("establecimientoAsoc"), 3)
            pun = _zfill_digits(assoc.get("puntoAsoc"), 3)
            num = _zfill_digits(assoc.get("numeroAsoc"), 7)
            if not all([tim, est, pun, num]):
                raise RuntimeError("documentoAsociado debe incluir timbrado/establecimiento/punto/numero para iTipDocAso=2")
            _ensure_child_ns(gcam, "dNTimDI", ns_uri).text = tim
            _ensure_child_ns(gcam, "dEstDocAso", ns_uri).text = est
            _ensure_child_ns(gcam, "dPExpDocAso", ns_uri).text = pun
            _ensure_child_ns(gcam, "dNumDocAso", ns_uri).text = num

            tipo_imp = str(assoc.get("tipoDocumentoIm") or assoc.get("tipoDocuemntoIm") or assoc.get("iTipoDocAso") or "").strip()
            if tipo_imp:
                _ensure_child_ns(gcam, "iTipoDocAso", ns_uri).text = tipo_imp
                _ensure_child_ns(gcam, "dDTipoDocAso", ns_uri).text = DOC_IMPRESO_TYPE_MAP.get(tipo_imp, "Factura")
            fec = str(assoc.get("fechaDocIm") or assoc.get("dFecEmiDI") or "").strip()
            if fec:
                _ensure_child_ns(gcam, "dFecEmiDI", ns_uri).text = fec.split(" ")[0]

    out = ET.tostring(root, encoding="utf-8", method="xml")
    return {
        "xml_bytes": out,
        "cdc": cdc,
        "dnumdoc": dnumdoc,
        "feemi": iso,
        "total_str": total_str,
        "base_total_str": base_total_str,
        "iva_total_str": iva_total_str,
        "items_for_pdf": items_for_pdf,
        "warnings": build_warnings,
    }

def _update_qr_in_signed_xml(xml_text: str, csc: str, csc_id: str) -> tuple[str, dict]:
    ns = {"s": "http://ekuatia.set.gov.py/sifen/xsd", "ds": "http://www.w3.org/2000/09/xmldsig#"}
    root = ET.fromstring(xml_text)

    def _t(path: str, default: str = "") -> str:
        el = root.find(path, ns)
        if el is not None and el.text:
            return el.text.strip()
        return default

    cdc = root.find(".//s:DE", ns).attrib.get("Id")
    dfe = _t(".//s:gDatGralOpe/s:dFeEmiDE")
    ruc_rec = root.find(".//s:gDatRec/s:dRucRec", ns)
    dv_rec = root.find(".//s:gDatRec/s:dDVRec", ns)
    if ruc_rec is not None and ruc_rec.text and ruc_rec.text.strip():
        id_rec = re.sub(r"\D", "", ruc_rec.text.strip())
        use_ruc_dv = os.getenv("SIFEN_QR_RUC_WITH_DV", "").strip().lower() in ("1", "true", "yes")
        if use_ruc_dv and dv_rec is not None and dv_rec.text and dv_rec.text.strip():
            dv = re.sub(r"\D", "", dv_rec.text.strip())
            if dv:
                id_rec = f"{id_rec}{dv}"
    else:
        num_id = root.find(".//s:gDatRec/s:dNumIDRec", ns)
        id_rec = num_id.text.strip() if num_id is not None and num_id.text else ""

    ntotal = _t(".//s:gTotSub/s:dTotGralOpe") or _t(".//s:gTotSub/s:dTotOpe") or "0"
    totiva = _t(".//s:gTotSub/s:dTotIVA", "0")
    citems = str(len(root.findall(".//s:gDtipDE/s:gCamItem", ns)))
    sig_digest = _t(".//ds:DigestValue")

    nversion = "150"
    dfe_hex = dfe.encode("utf-8").hex()
    digest_hex = sig_digest.encode("utf-8").hex()
    params = (
        f"nVersion={nversion}"
        f"&Id={cdc}"
        f"&dFeEmiDE={dfe_hex}"
        f"&dRucRec={id_rec}"
        f"&dTotGralOpe={ntotal}"
        f"&dTotIVA={totiva}"
        f"&cItems={citems}"
        f"&DigestValue={digest_hex}"
        f"&IdCSC={csc_id}"
    )
    hash_hex = hashlib.sha256((params + csc).encode("utf-8")).hexdigest()
    base_url = (os.getenv("SIFEN_QR_BASE_URL") or "").strip()
    if not base_url:
        env = (os.getenv("SIFEN_ENV") or "test").strip().lower()
        if env == "prod":
            base_url = "https://www.ekuatia.set.gov.py/consultas/qr"
        else:
            base_url = "https://www.ekuatia.set.gov.py/consultas-test/qr"
    base_url = base_url.rstrip("?")
    qr_url = f"{base_url}?{params}&cHashQR={hash_hex}"
    qr_url_xml = qr_url.replace("&", "&amp;")

    # Reemplazar sin reserializar para no tocar la firma
    new_xml, count = re.subn(r"<dCarQR>.*?</dCarQR>", f"<dCarQR>{qr_url_xml}</dCarQR>", xml_text, flags=re.DOTALL)
    if count != 1:
        raise RuntimeError(f"No se pudo actualizar dCarQR (reemplazos={count})")

    debug = {
        "cdc": cdc,
        "dfe": dfe,
        "dfe_hex": dfe_hex,
        "id_rec": id_rec,
        "dTotGralOpe": ntotal,
        "dTotIVA": totiva,
        "cItems": citems,
        "digest": sig_digest,
        "digest_hex": digest_hex,
        "cHashQR": hash_hex,
        "qr_url": qr_url,
    }
    return new_xml, debug

def _maybe_compute_qr_from_signed_xml(xml_text: str) -> str:
    if not xml_text:
        return ""
    csc = (os.getenv("SIFEN_CSC") or "").strip()
    if not csc:
        return ""
    csc_id = (os.getenv("SIFEN_CSC_ID") or "0001").strip()
    try:
        _, debug = _update_qr_in_signed_xml(xml_text, csc, csc_id)
        return (debug.get("qr_url") or "").strip()
    except Exception:
        return ""

def _build_pdf_payload(
    *,
    invoice: sqlite3.Row,
    items_for_pdf: list,
    response_xml: Optional[str],
    cdc: str,
    dnumdoc: str,
    feemi: str,
    total_str: str,
    iva_total_str: str,
    source_xml_text: Optional[str] = None,
) -> dict:
    cust_ruc = (invoice["customer_ruc"] if "customer_ruc" in invoice.keys() else "") or ""
    ruc_main, ruc_dv = _split_ruc_dv(cust_ruc)
    est = (invoice["establishment"] if "establishment" in invoice.keys() else "") or ""
    pun = (invoice["point_exp"] if "point_exp" in invoice.keys() else "") or ""
    qr_url = ""
    if source_xml_text:
        m = re.search(r"<(?:\\w+:)?dCarQR>(.*?)</(?:\\w+:)?dCarQR>", source_xml_text, flags=re.DOTALL)
        if m:
            qr_url = (m.group(1) or "").strip()
        if (not qr_url) or ("TESTQRCODE" in qr_url.upper()) or ("PLACEHOLDER" in qr_url.upper()):
            computed = _maybe_compute_qr_from_signed_xml(source_xml_text)
            if computed:
                qr_url = computed
    def find_tag(tag: str) -> str:
        if not source_xml_text:
            return ""
        m = re.search(rf"<(?:\\w+:)?{tag}>(.*?)</(?:\\w+:)?{tag}>", source_xml_text, flags=re.DOTALL)
        if not m:
            return ""
        return (m.group(1) or "").strip()

    dir_rec = find_tag("dDirRec")
    num_cas_rec = find_tag("dNumCasRec")
    if dir_rec and num_cas_rec:
        dir_lower = dir_rec.lower()
        if all(token not in dir_lower for token in ("nr", "nro", "n°", "nº")):
            dir_rec = f"{dir_rec} Nr. {num_cas_rec}"
    tel_rec = find_tag("dTelRec")
    cond_venta = find_tag("dDCondOpe")
    remision = find_tag("dNumRem")

    parsed_fields = {
        "CDC": cdc,
        "dNumDoc": dnumdoc,
        "dSerDoc": f"{est}-{pun}" if est and pun else "",
        "dFecEmi": feemi,
        "dTotGralOpe": total_str,
        "dTotOpe": total_str,
        "dIVA10": iva_total_str,
        "dIVA5": "0",
        "dTotIVA": iva_total_str,
        "dNomRec": (invoice["customer_name"] if "customer_name" in invoice.keys() else "") or "",
        "dRucRec": ruc_main,
        "dDVRec": ruc_dv,
        "dEmailRec": (invoice["customer_email"] if "customer_email" in invoice.keys() else "") or "",
        "dDirRec": dir_rec,
        "dTelRec": tel_rec,
        "dDCondOpe": cond_venta,
        "dNumRem": remision,
    }
    return {
        "CDC": cdc,
        "parsed_fields": parsed_fields,
        "items": items_for_pdf,
        "response_xml": response_xml or "",
        "qr_url": qr_url,
    }

def _build_issuer_from_template(template_path: str) -> dict:
    ns = {"s": "http://ekuatia.set.gov.py/sifen/xsd"}
    xml = Path(template_path).read_text(encoding="utf-8")
    root = ET.fromstring(xml)
    def get(tag):
        el = root.find(f".//s:{tag}", ns)
        return (el.text.strip() if el is not None and el.text else "")
    issuer = {
        "razon_social": get("dNomEmi"),
        "ruc": get("dRucEm"),
        "dv": get("dDVEmi"),
        "direccion": get("dDirEmi"),
        "num_casa": get("dNumCas"),
        "ciudad": get("dDesCiuEmi"),
        "departamento": get("dDesDepEmi"),
        "telefono": get("dTelEmi"),
        "email": get("dEmailE"),
        "timbrado": get("dNumTim"),
        "vigencia": get("dFeIniT"),
    }
    return _apply_issuer_overrides(issuer)

def _build_issuer_from_xml_text(xml_text: str) -> dict:
    if not xml_text:
        return {}
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return {}

    def find_local(tag: str) -> str:
        for el in root.iter():
            if el.tag == tag or el.tag.endswith(f"}}{tag}"):
                if el.text and el.text.strip():
                    return el.text.strip()
        return ""

    issuer = {
        "razon_social": find_local("dNomEmi"),
        "ruc": find_local("dRucEm"),
        "dv": find_local("dDVEmi"),
        "direccion": find_local("dDirEmi"),
        "num_casa": find_local("dNumCas"),
        "ciudad": find_local("dDesCiuEmi"),
        "departamento": find_local("dDesDepEmi"),
        "telefono": find_local("dTelEmi"),
        "email": find_local("dEmailE"),
        "timbrado": find_local("dNumTim"),
        "vigencia": find_local("dFeIniT"),
    }
    return _apply_issuer_overrides(issuer)

def _apply_issuer_overrides(issuer: dict) -> dict:
    if not issuer:
        issuer = {}
    name = os.getenv("SIFEN_ISSUER_NAME", "").strip()
    tagline = os.getenv("SIFEN_ISSUER_TAGLINE", "").strip()
    addr = os.getenv("SIFEN_ISSUER_ADDRESS", "").strip()
    phone = os.getenv("SIFEN_ISSUER_PHONE", "").strip()
    email = os.getenv("SIFEN_ISSUER_EMAIL", "").strip()
    city = os.getenv("SIFEN_ISSUER_CITY", "").strip()
    logo_path = os.getenv("SIFEN_ISSUER_LOGO_PATH", "").strip()
    if name:
        issuer["razon_social"] = name
    if tagline:
        issuer["tagline"] = tagline
    if addr:
        issuer["direccion"] = addr
    if phone:
        issuer["telefono"] = phone
    if email:
        issuer["email"] = email
    if city:
        issuer["ciudad"] = city
    if logo_path:
        issuer["logo_path"] = logo_path
    return issuer

def _send_email_with_pdf(to_email: str, subject: str, body: str, pdf_path: Path) -> None:
    host = os.getenv("SMTP_HOST", "").strip()
    port = int(os.getenv("SMTP_PORT", "587") or 587)
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASS", "")
    mail_from = os.getenv("MAIL_FROM", user).strip()

    if not host or not mail_from or not to_email:
        raise RuntimeError("SMTP_HOST/MAIL_FROM/email destino no configurado.")

    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.set_content(body)

    pdf_bytes = Path(pdf_path).read_bytes()
    msg.add_attachment(pdf_bytes, maintype="application", subtype="pdf", filename=Path(pdf_path).name)

    context = ssl.create_default_context()
    if port == 465:
        with smtplib.SMTP_SSL(host, port, context=context, timeout=30) as smtp:
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)

def _queue_init():
    global _QUEUE_LOCK, _QUEUE_WORKER_STARTED
    if _QUEUE_LOCK is None:
        _QUEUE_LOCK = threading.Lock()
    if _QUEUE_WORKER_STARTED:
        return

    def worker():
        while True:
            job = None
            with _QUEUE_LOCK:
                if _QUEUE:
                    job = _QUEUE.pop(0)
            if not job:
                time.sleep(1)
                continue
            try:
                invoice_id, env = job
                with app.app_context():
                    _process_invoice_emit(invoice_id, env, async_mode=True)
            except Exception:
                # silencioso: ya se registra en DB si aplica
                pass

    _QUEUE_WORKER_STARTED = True
    t = threading.Thread(target=worker, daemon=True)
    t.start()

def _enqueue_invoice(invoice_id: int, env: str) -> None:
    _queue_init()
    with _QUEUE_LOCK:
        _QUEUE.append((invoice_id, env))

def _poll_init():
    global _POLL_LOCK
    if _POLL_LOCK is None:
        _POLL_LOCK = threading.Lock()

def _schedule_lote_poll(
    invoice_id: int,
    env: str,
    prot: str,
    rel_signed: Optional[str] = None,
    max_wait_sec: int = 600,
    interval_sec: int = 20,
) -> None:
    if not prot:
        return
    _poll_init()
    with _POLL_LOCK:
        if invoice_id in _POLLING:
            return
        _POLLING.add(invoice_id)

    def worker():
        deadline = time.time() + max_wait_sec
        try:
            while time.time() < deadline:
                with app.app_context():
                    status = _consult_lote_and_update(
                        invoice_id=invoice_id,
                        env=env,
                        prot=prot,
                        rel_signed=rel_signed,
                        attempts=1,
                        sleep_between=0,
                    )
                if status in ("CONFIRMED_OK", "CONFIRMED_REJECTED"):
                    break
                time.sleep(interval_sec)
        finally:
            with _POLL_LOCK:
                _POLLING.discard(invoice_id)

    t = threading.Thread(target=worker, daemon=True)
    t.start()

def _backup_init():
    global _BACKUP_LOCK, _BACKUP_THREAD_STARTED
    if _BACKUP_LOCK is None:
        _BACKUP_LOCK = threading.Lock()
    if _BACKUP_THREAD_STARTED:
        return
    _BACKUP_THREAD_STARTED = True

def _backup_db_once() -> Optional[str]:
    backup_dir = _repo_root() / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    raw_path = backup_dir / f"sifen_webui_{ts}.sqlite"
    zip_path = backup_dir / f"sifen_webui_{ts}.zip"

    with _BACKUP_LOCK:
        src = sqlite3.connect(DB_PATH)
        try:
            src.execute("PRAGMA journal_mode = WAL;")
            src.execute("PRAGMA synchronous = FULL;")
            dest = sqlite3.connect(str(raw_path))
            try:
                src.backup(dest)
            finally:
                dest.close()
        finally:
            src.close()

        with zipfile.ZipFile(zip_path, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.write(raw_path, arcname=raw_path.name)
        try:
            raw_path.unlink()
        except Exception:
            pass

        set_setting("last_backup_at", datetime.now().isoformat(timespec="seconds"))
        set_setting("last_backup_file", str(zip_path))
        return str(zip_path)

def _start_backup_scheduler(interval_sec: int = 900) -> None:
    _backup_init()

    def worker():
        while True:
            try:
                with app.app_context():
                    _backup_db_once()
            except Exception:
                pass
            time.sleep(interval_sec)

    t = threading.Thread(target=worker, daemon=True)
    t.start()


def recompute_invoice_totals(invoice_id: int):
    con = get_db()
    rows = con.execute(
        "SELECT COALESCE(SUM(line_total),0) AS total FROM invoice_lines WHERE invoice_id=?",
        (invoice_id,),
    ).fetchone()
    total = int(rows["total"] or 0)
    con.execute("UPDATE invoices SET total=? WHERE id=?", (total, invoice_id))
    con.commit()


def run_minisender(args, cwd=None, env=None):
    """Ejecuta minisender como subprocess y retorna (code, stdout, stderr)."""
    proc = subprocess.run(
        args,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    return proc.returncode, proc.stdout, proc.stderr

def parse_minisender_response(stdout_text: str):
    """Extrae pares clave:valor del stdout (líneas 'k: v')."""
    out = {}
    for line in (stdout_text or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            v = v.strip()
            if k and v:
                out[k] = v
    return out

def _extract_tag(xml_text: str, tag: str) -> Optional[str]:
    if not xml_text:
        return None
    match = re.search(rf"<(?:[^:>]+:)?{tag}>(.*?)</(?:[^:>]+:)?{tag}>", xml_text, flags=re.DOTALL)
    if match:
        return (match.group(1) or "").strip() or None
    return None

def _parse_consult_response(xml_text: Optional[str]) -> dict:
    if not xml_text:
        return {}
    return {
        "dEstRes": _extract_tag(xml_text, "dEstRes"),
        "dProtAut": _extract_tag(xml_text, "dProtAut"),
        "dCodRes": _extract_tag(xml_text, "dCodRes"),
        "dMsgRes": _extract_tag(xml_text, "dMsgRes"),
        "dCodResLot": _extract_tag(xml_text, "dCodResLot"),
        "dMsgResLot": _extract_tag(xml_text, "dMsgResLot"),
        "dFecProc": _extract_tag(xml_text, "dFecProc"),
    }

def _parse_consult_de_response(xml_text: Optional[str]) -> dict:
    if not xml_text:
        return {}
    return {
        "dCodRes": _extract_tag(xml_text, "dCodRes"),
        "dMsgRes": _extract_tag(xml_text, "dMsgRes"),
        "dProtAut": _extract_tag(xml_text, "dProtAut"),
        "dFecProc": _extract_tag(xml_text, "dFecProc"),
    }

def _refresh_invoice_from_soap(invoice_id: int, xml_text: str, art_dir: Optional[str]) -> None:
    parsed = _parse_consult_response(xml_text)
    dCodResLot = parsed.get("dCodResLot") or ""
    dMsgResLot = parsed.get("dMsgResLot") or ""
    est = parsed.get("dEstRes") or ""
    dProtAut = parsed.get("dProtAut") or ""
    dCodRes = parsed.get("dCodRes") or ""
    dMsgRes = parsed.get("dMsgRes") or ""

    est, dCodRes, dMsgRes = _normalize_consult_fields(
        est, dCodRes, dMsgRes, dCodResLot, dMsgResLot
    )

    con = get_db()
    inv = con.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    if not inv:
        return

    new_status = inv["status"]
    if dCodResLot or dMsgResLot or est:
        new_status = _derive_consult_status(est, dCodResLot, dMsgResLot)
    elif dCodRes == "0422" and dProtAut:
        new_status = "CONFIRMED_OK"

    confirmed_at = None
    if new_status in ("CONFIRMED_OK", "CONFIRMED_REJECTED") and not inv["confirmed_at"]:
        confirmed_at = now_iso()

    con.execute(
        """
        UPDATE invoices SET
            status=?,
            confirmed_at=COALESCE(confirmed_at, ?),
            last_lote_code=COALESCE(?, last_lote_code),
            last_lote_msg=COALESCE(?, last_lote_msg),
            last_sifen_est=COALESCE(?, last_sifen_est),
            last_sifen_prot_aut=COALESCE(?, last_sifen_prot_aut),
            last_sifen_code=COALESCE(?, last_sifen_code),
            last_sifen_msg=COALESCE(?, last_sifen_msg),
            last_artifacts_dir=COALESCE(?, last_artifacts_dir)
        WHERE id=?
        """,
        (
            new_status,
            confirmed_at,
            dCodResLot or None,
            dMsgResLot or None,
            est or None,
            dProtAut or None,
            dCodRes or None,
            dMsgRes or None,
            art_dir or None,
            invoice_id,
        ),
    )
    con.commit()

def _normalize_consult_fields(est: str, dCodRes: str, dMsgRes: str, dCodResLot: str, dMsgResLot: str) -> tuple:
    if not dCodRes and dCodResLot:
        dCodRes = dCodResLot
    if not dMsgRes and dMsgResLot:
        dMsgRes = dMsgResLot
    if not est and dMsgResLot:
        est = dMsgResLot
    return est, dCodRes, dMsgRes

def _derive_consult_status(est: str, dCodResLot: str, dMsgResLot: str) -> str:
    est_lower = (est or "").strip().lower()
    if est_lower.startswith(("acep", "aprob")):
        return "CONFIRMED_OK"
    if est_lower.startswith("rech"):
        return "CONFIRMED_REJECTED"

    lot_text = " ".join([t for t in [dMsgResLot, est] if t]).strip().lower()
    if dCodResLot in {"0365"}:
        return "CONFIRMED_REJECTED"
    if any(tok in lot_text for tok in ("rech", "lote cancel", "cancelad")):
        return "CONFIRMED_REJECTED"

    return "CONFIRMING"

def _consult_lote_and_update(
    invoice_id: int,
    env: str,
    prot: str,
    rel_signed: Optional[str] = None,
    prefer_art_dir: Optional[str] = None,
    attempts: int = 1,
    sleep_between: int = 2,
) -> str:
    repo_root_path = _repo_root()
    venv_py = str(repo_root_path / ".venv" / "bin" / "python")
    env_used = os.environ.copy()
    last_art_dir = normalize_artifacts_dir(prefer_art_dir or "") or ""
    final_status = "CONFIRMING"

    for idx in range(max(1, attempts)):
        args = [
            venv_py, "-m", "sifen_minisender", "consult",
            "--env", env,
            "--prot", prot,
        ]
        code, out, err = run_minisender(args, cwd=str(repo_root_path), env=env_used)
        parsed = parse_minisender_response(out)
        art_dir_raw = detect_artifacts_dir(parsed, out, env_used)
        last_art_dir = normalize_artifacts_dir(art_dir_raw) or last_art_dir

        response_xml = None
        parsed_xml = {}
        if last_art_dir:
            resp_path = Path(last_art_dir) / "soap_last_response.xml"
            if resp_path.exists():
                response_xml = resp_path.read_text(encoding="utf-8")
                parsed_xml = _parse_consult_response(response_xml)

        est = parsed_xml.get("dEstRes") or parsed.get("dEstRes") or ""
        prot_aut = parsed_xml.get("dProtAut") or parsed.get("dProtAut") or ""
        dCodRes = parsed_xml.get("dCodRes") or parsed.get("dCodRes") or ""
        dMsgRes = parsed_xml.get("dMsgRes") or parsed.get("dMsgRes") or ""
        dCodResLot = parsed_xml.get("dCodResLot") or parsed.get("dCodResLot") or ""
        dMsgResLot = parsed_xml.get("dMsgResLot") or parsed.get("dMsgResLot") or ""
        if not est and dMsgResLot:
            est = dMsgResLot

        est, dCodRes, dMsgRes = _normalize_consult_fields(
            est, dCodRes, dMsgRes, dCodResLot, dMsgResLot
        )
        new_status = _derive_consult_status(est, dCodResLot, dMsgResLot)
        final_status = new_status

        confirmed_at = now_iso() if new_status in ("CONFIRMED_OK", "CONFIRMED_REJECTED") else None

        con = get_db()
        con.execute(
            "UPDATE invoices SET status=?, confirmed_at=COALESCE(confirmed_at,?), last_sifen_code=?, last_sifen_msg=?, last_sifen_est=?, last_sifen_prot_aut=?, last_lote_code=?, last_lote_msg=?, last_artifacts_dir=COALESCE(?, last_artifacts_dir), source_xml_path=COALESCE(?, source_xml_path) WHERE id=?",
            (
                new_status,
                confirmed_at,
                dCodRes or None,
                (dMsgRes or "") + (f" | dEstRes={est}" if est else ""),
                est or None,
                prot_aut or None,
                dCodResLot or None,
                dMsgResLot or None,
                last_art_dir or None,
                rel_signed or None,
                invoice_id,
            ),
        )
        con.commit()

        if code != 0:
            con.execute(
                "UPDATE invoices SET last_sifen_msg=? WHERE id=?",
                ((dMsgRes or "") + f" | minisender_exit={code} | stderr={err[-500:]}", invoice_id),
            )
            con.commit()

        if new_status in ("CONFIRMED_OK", "CONFIRMED_REJECTED"):
            break
        if idx < attempts - 1:
            time.sleep(sleep_between)

    return final_status

def _consult_cdc_and_update(invoice_id: int, env: str, cdc: str) -> str:
    init_db()
    con = get_db()
    inv = con.execute("SELECT status FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    if not inv:
        return "MISSING"

    client = None
    try:
        cfg = get_sifen_config(env=env)
        client = SoapClient(cfg)
        result = client.consulta_de_por_cdc_raw(cdc, dump_http=False)
    except Exception as e:
        con.execute(
            "UPDATE invoices SET last_sifen_msg=? WHERE id=?",
            (f"ERROR consulta CDC: {e}", invoice_id),
        )
        con.commit()
        return inv["status"]
    finally:
        try:
            if client:
                client.close()
        except Exception:
            pass

    raw_xml = result.get("raw_xml") or ""
    parsed = _parse_consult_de_response(raw_xml)
    dCodRes = parsed.get("dCodRes") or ""
    dMsgRes = (parsed.get("dMsgRes") or "").strip()
    prot_aut = parsed.get("dProtAut") or ""
    http_status = result.get("http_status")
    if http_status:
        dMsgRes = (dMsgRes + f" | http={http_status}").strip()

    est = ""
    new_status = inv["status"]
    if dCodRes == "0422":
        est = "CDC encontrado"
        if new_status not in ("CONFIRMED_OK", "CONFIRMED_REJECTED"):
            new_status = "CONFIRMED_OK"
    confirmed_at = now_iso() if new_status == "CONFIRMED_OK" else None

    con.execute(
        """
        UPDATE invoices SET
            status=?,
            confirmed_at=COALESCE(confirmed_at, ?),
            last_sifen_code=?,
            last_sifen_msg=?,
            last_sifen_prot_aut=COALESCE(?, last_sifen_prot_aut),
            last_sifen_est=COALESCE(?, last_sifen_est)
        WHERE id=?
        """,
        (new_status, confirmed_at, dCodRes or None, dMsgRes or None, prot_aut or None, est or None, invoice_id),
    )
    con.commit()
    return new_status

def _sync_pending_lotes(batch_size: int = 15) -> None:
    init_db()
    con = get_db()
    rows = con.execute(
        """
        SELECT id, status, sifen_env, sifen_prot_cons_lote, source_xml_path, last_artifacts_dir
        FROM invoices
        WHERE status IN ('QUEUED','SENT','CONFIRMING')
        ORDER BY id DESC
        LIMIT ?
        """,
        (batch_size,),
    ).fetchall()

    default_env = get_setting("default_env", "prod") or "prod"
    for row in rows:
        env = (row["sifen_env"] or default_env).strip().lower()
        if env not in ("test", "prod"):
            env = "prod"
        prot = (row["sifen_prot_cons_lote"] or "").strip()
        if prot:
            _consult_lote_and_update(
                invoice_id=row["id"],
                env=env,
                prot=prot,
                rel_signed=row["source_xml_path"] or None,
                prefer_art_dir=row["last_artifacts_dir"] or None,
                attempts=1,
                sleep_between=0,
            )
            continue
        cdc = _extract_cdc_from_xml_path(row["source_xml_path"] or "")
        if cdc:
            _consult_cdc_and_update(row["id"], env, cdc)

def _start_lote_sync_scheduler(interval_sec: int = 120) -> None:
    global _LOTE_SYNC_THREAD_STARTED
    if _LOTE_SYNC_THREAD_STARTED:
        return
    _LOTE_SYNC_THREAD_STARTED = True

    def worker():
        while True:
            try:
                with app.app_context():
                    _sync_pending_lotes()
            except Exception:
                pass
            time.sleep(interval_sec)

    t = threading.Thread(target=worker, daemon=True)
    t.start()

def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]

def detect_artifacts_dir(parsed: dict, stdout_text: str, env: Optional[dict]) -> str:
    for key in ("Artifacts dir", "Artifacts dir:", "artifacts_dir", "artifacts_dir:"):
        val = (parsed.get(key) or "").strip()
        if val:
            return val
    if stdout_text:
        match = re.search(r"Artifacts dir:\s*(.+)", stdout_text)
        if match:
            return match.group(1).strip()
    env_val = ""
    if env:
        env_val = env.get("SIFEN_ARTIFACTS_DIR", "") or ""
    if not env_val:
        env_val = os.environ.get("SIFEN_ARTIFACTS_DIR", "") or ""
    return env_val.strip()

def normalize_artifacts_dir(art_dir: str) -> Optional[str]:
    if not art_dir:
        return None
    p = Path(art_dir.strip())
    if not p.is_absolute():
        p = (_repo_root() / p).resolve()
    return str(p)

def resolve_existing_xml_path(xml_path: str) -> Optional[str]:
    if not xml_path:
        return None
    p = Path(xml_path.strip())
    if not p.is_absolute():
        p = (_repo_root() / p).resolve()
    if not p.exists() or not p.is_file():
        return None
    try:
        repo_root = _repo_root().resolve()
        resolved = p.resolve()
        if resolved == repo_root or repo_root in resolved.parents:
            return str(resolved.relative_to(repo_root))
    except Exception:
        pass
    return str(p)

def list_recent_artifacts_dirs(artifacts_root: Path) -> list:
    if not artifacts_root.exists():
        return []
    preferred = []
    others = []
    for p in artifacts_root.iterdir():
        if not p.is_dir():
            continue
        name = p.name.lower()
        if name == "pdf" or name.startswith("_wsdl_"):
            continue
        if name.startswith(("run_", "send_", "consulta_", "diag")) or "artifacts" in name:
            preferred.append(p)
        else:
            others.append(p)
    candidates = preferred or others
    candidates.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    return candidates

def resolve_source_xml_path(art_dir: str) -> Optional[str]:
    if not art_dir:
        return None
    try:
        base = Path(art_dir.strip())
        if not base.is_absolute():
            base = (_repo_root() / base).resolve()
        if not base.exists():
            return None

        def normalize_path(p: Path) -> str:
            try:
                repo_root = _repo_root().resolve()
                resolved = p.resolve()
                if resolved == repo_root or repo_root in resolved.parents:
                    return str(resolved.relative_to(repo_root))
            except Exception:
                pass
            return str(p)

        if base.is_file():
            xml_files = [base] if base.suffix.lower() == ".xml" else []
        else:
            xml_files = [p for p in base.rglob("*.xml") if p.is_file()]

        def choose_best(paths):
            if not paths:
                return None
            def sort_key(p: Path):
                try:
                    st = p.stat()
                    return (st.st_mtime, st.st_size)
                except Exception:
                    return (0, 0)
            return max(paths, key=sort_key)

        exact_matches = [p for p in xml_files if p.name == "DE_TAL_CUAL_TRANSMITIDO.xml"]
        best = choose_best(exact_matches)
        if best:
            return normalize_path(best)

        cands = [p for p in xml_files if "tal_cual" in p.name.lower() and "transmit" in p.name.lower()]
        best = choose_best(cands)
        if best:
            return normalize_path(best)

        include = ("signed", "firmad", "rde", "de")
        exclude = ("response", "request", "soap", "reject", "rechazo")
        cands = []
        for p in xml_files:
            name = p.name.lower()
            if any(bad in name for bad in exclude):
                continue
            if any(tok in name for tok in include):
                cands.append(p)
        best = choose_best(cands)
        return normalize_path(best) if best else None
    except Exception:
        return None

# -------------------------
# UI helpers
# -------------------------
def badge(status: str) -> str:
    m = {
        "DRAFT": "secondary",
        "READY": "info",
        "QUEUED": "warning",
        "SENT": "primary",
        "CONFIRMING": "warning",
        "CONFIRMED_OK": "success",
        "CONFIRMED_REJECTED": "danger",
        "CANCELLED_OK": "success",
        "CANCELLED_REJECTED": "danger",
        "INUTIL_OK": "success",
        "INUTIL_REJECTED": "danger",
    }
    cls = m.get(status, "dark")
    return f'<span class="badge bg-{cls}">{status}</span>'

BASE_HTML = """
<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{title}}</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body { padding: 24px; }
    .brand-logo { height: 48px; width: auto; display: block; }
    .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .nowrap { white-space: nowrap; }
    .backup-toast {
      position: fixed;
      right: 20px;
      bottom: 20px;
      background: #198754;
      color: #fff;
      padding: 10px 14px;
      border-radius: 8px;
      box-shadow: 0 6px 16px rgba(0,0,0,0.2);
      opacity: 0;
      transform: translateY(6px);
      transition: opacity 0.2s ease, transform 0.2s ease;
      pointer-events: none;
      z-index: 9999;
      max-width: 520px;
      font-size: 14px;
    }
    .backup-toast.show {
      opacity: 1;
      transform: translateY(0);
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="d-flex justify-content-between align-items-center mb-3">
      <div class="d-flex align-items-center gap-3">
        <img src="{{ url_for('issuer_logo') }}" alt="Industria Feris" class="brand-logo" onerror="this.style.display='none'">
        <div>
          <h3 class="mb-0">Industria Feris - Facturación</h3>
        </div>
      </div>
      <div class="d-flex gap-2">
        <a class="btn btn-outline-secondary" href="{{ url_for('invoices') }}" title="Inicio" aria-label="Inicio">
          <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 16 16" aria-hidden="true">
            <path d="M8.354 1.146a.5.5 0 0 0-.708 0l-6 6A.5.5 0 0 0 2 7.5V14a1 1 0 0 0 1 1h4a.5.5 0 0 0 .5-.5V10h1v4.5a.5.5 0 0 0 .5.5h4a1 1 0 0 0 1-1V7.5a.5.5 0 0 0 .146-.354.5.5 0 0 0-.146-.353l-6-6z"/>
          </svg>
        </a>
        <a class="btn btn-outline-secondary" href="{{ url_for('customers') }}">Clientes</a>
        <a class="btn btn-outline-secondary" href="{{ url_for('products') }}">Productos</a>
        <a class="btn btn-primary" href="{{ url_for('invoice_new') }}">Documento nuevo</a>
      </div>
    </div>

    {{ body|safe }}

  </div>
  <div id="backup-toast" class="backup-toast"></div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    (function () {
      const toast = document.getElementById("backup-toast");
      if (!toast) return;
      const key = "sifen_last_backup_at";
      let lastSeen = localStorage.getItem(key) || "";

      function showToast(msg) {
        toast.textContent = msg;
        toast.classList.add("show");
        setTimeout(() => toast.classList.remove("show"), 6000);
      }

      async function check() {
        try {
          const res = await fetch("/backup/status", { cache: "no-store" });
          if (!res.ok) return;
          const data = await res.json();
          if (!data || !data.last_backup_at) return;
          if (data.last_backup_at !== lastSeen) {
            lastSeen = data.last_backup_at;
            localStorage.setItem(key, lastSeen);
            const file = (data.last_backup_file || "").split("/").pop();
            const msg = "Respaldo OK " + data.last_backup_at + (file ? " (" + file + ")" : "");
            showToast(msg);
          }
        } catch (e) {}
      }

      check();
      setInterval(check, 15000);
    })();
  </script>
</body>
</html>
"""

# -------------------------
# Routes
# -------------------------
def _ensure_bootstrap():
    global _BOOTSTRAP_LOCK, _BOOTSTRAPPED
    if _BOOTSTRAP_LOCK is None:
        _BOOTSTRAP_LOCK = threading.Lock()
    with _BOOTSTRAP_LOCK:
        if _BOOTSTRAPPED:
            return
        _BOOTSTRAPPED = True
    _start_backup_scheduler(interval_sec=15 * 60)
    _start_lote_sync_scheduler(interval_sec=120)

@app.before_request
def _bootstrap_background_jobs():
    _ensure_bootstrap()

def get_setting(key: str, default: str = "") -> str:
    init_db()
    con = get_db()
    row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return (row["value"] if row and row["value"] is not None else default) or default

def set_setting(key: str, value: str) -> None:
    init_db()
    con = get_db()
    con.execute(
        "INSERT INTO settings(key,value) VALUES(?,?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )
    con.commit()

def _diagnostics_artifacts_dir() -> Path:
    root = _repo_root() / "artifacts" / "diagnostics"
    root.mkdir(parents=True, exist_ok=True)
    return root

def _read_last_diagnostics() -> dict:
    path = (get_setting("diagnostics_last_path", "") or "").strip()
    if not path:
        return {}
    p = Path(path)
    if not p.is_absolute():
        p = (_repo_root() / p).resolve()
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return {}

def _find_default_cdc_and_prot() -> tuple[str, str]:
    con = get_db()
    row = con.execute(
        "SELECT id, source_xml_path, sifen_prot_cons_lote FROM invoices "
        "WHERE source_xml_path IS NOT NULL OR sifen_prot_cons_lote IS NOT NULL "
        "ORDER BY id DESC LIMIT 1"
    ).fetchone()
    if not row:
        return "", ""
    cdc = ""
    if row["source_xml_path"]:
        cdc = _extract_cdc_from_xml_path(row["source_xml_path"]) or ""
    prot = row["sifen_prot_cons_lote"] or ""
    return cdc, prot

def _diagnostics_dry_run() -> dict:
    results = {}
    diag_warnings: list[str] = []
    sample_customer = {"name": "Cliente Prueba", "ruc": "7524653-8"}
    lines = [
        {"description": "Servicio", "qty": Decimal("1.5"), "price_unit": Decimal("100"), "line_total": Decimal("150"), "iva_rate": 10},
        {"description": "Servicio 5%", "qty": Decimal("1"), "price_unit": Decimal("50"), "line_total": Decimal("50"), "iva_rate": 5},
    ]

    p12_path = os.getenv("SIFEN_SIGN_P12_PATH") or os.getenv("SIFEN_P12_PATH") or os.getenv("SIFEN_CERT_PATH")
    p12_password = os.getenv("SIFEN_SIGN_P12_PASSWORD") or os.getenv("SIFEN_P12_PASSWORD") or os.getenv("SIFEN_CERT_PASSWORD")
    csc = (os.getenv("SIFEN_CSC") or "").strip()
    csc_id = (os.getenv("SIFEN_CSC_ID") or "0001").strip()
    tim_num, _ = _config_value("timbrado_num", ["SIFEN_TIMBRADO_NUM", "SIFEN_NUM_TIMBRADO", "SIFEN_DNUMTIM"])
    tim_fe_ini, _ = _config_value("timbrado_fe_ini", ["SIFEN_TIMBRADO_FE_INI", "SIFEN_DFEINIT"])
    if not tim_num:
        diag_warnings.append("timbrado_num no configurado en settings/env; se usará el valor del template.")
    if not tim_fe_ini:
        diag_warnings.append("timbrado_fe_ini no configurado en settings/env; se usará el valor del template.")

    if not (p12_path and p12_password and csc):
        return {
            "error": "Faltan credenciales SIFEN_SIGN_P12_PATH/SIFEN_SIGN_P12_PASSWORD/SIFEN_CSC",
            "warnings": diag_warnings,
        }

    for doc_type in ["1", "4", "5", "6", "7"]:
        label = doc_type_label(doc_type)
        try:
            extra = _default_extra_json_for(doc_type) or {}
            if doc_type == "4":
                extra["documentoAsociado"] = {"tipoDocumentoAsoc": "3"}
                extra.setdefault("autofactura", {})
                extra["autofactura"].setdefault("documento", "123456")
                extra["autofactura"].setdefault("nombre", "Vendedor")
            if doc_type in ("5", "6"):
                extra["documentoAsociado"] = {
                    "tipoDocumentoAsoc": "1",
                    "cdcAsociado": "0" * 44,
                }
                extra["iMotEmi"] = extra.get("iMotEmi") or "1"

            errors = _validate_doc_extra(doc_type, extra)
            if errors:
                results[label] = {"ok": False, "error": " | ".join(errors)}
                continue

            template_path = _template_for_doc_type(doc_type)
            if not template_path or not Path(template_path).exists():
                results[label] = {"ok": False, "error": f"Plantilla no encontrada: {template_path}"}
                continue

            build = _build_invoice_xml_from_template(
                template_path=template_path,
                invoice_id=999000 + int(doc_type),
                customer=sample_customer,
                lines=lines,
                doc_number="0000001",
                doc_type=doc_type,
                extra_json=extra,
                issue_dt=datetime.now(),
                codseg="123456789",
                establishment="001",
                point_exp="001",
            )
            build2 = _build_invoice_xml_from_template(
                template_path=template_path,
                invoice_id=999100 + int(doc_type),
                customer=sample_customer,
                lines=lines,
                doc_number="0000002",
                doc_type=doc_type,
                extra_json=extra,
                issue_dt=datetime.now(),
                codseg="123456789",
                establishment="001",
                point_exp="001",
            )
            signed = sign_de_with_p12(build["xml_bytes"], p12_path, p12_password)
            signed_qr_text, _ = _update_qr_in_signed_xml(signed.decode("utf-8"), csc, csc_id)
            has_qr = "<dCarQR>" in signed_qr_text and "TESTQRCODE" not in signed_qr_text

            xml_txt = build["xml_bytes"].decode("utf-8", errors="ignore")
            qty_ok = "<dCantProSer>1.5" in xml_txt
            cdc_changes = build["cdc"] != build2["cdc"]
            tim_set = (_safe_get_setting("timbrado_num", "") or "").strip()
            fe_set = (_safe_get_setting("timbrado_fe_ini", "") or "").strip()
            tim_override_ok = True
            if tim_set:
                tim_override_ok = f"<dNumTim>{_zfill_digits(tim_set, 8)}</dNumTim>" in xml_txt
            if tim_override_ok and fe_set:
                tim_override_ok = f"<dFeIniT>{fe_set}</dFeIniT>" in xml_txt

            results[label] = {
                "ok": bool(has_qr and qty_ok and cdc_changes and tim_override_ok),
                "cdc_tail": build["cdc"][-6:],
                "qr_ok": has_qr,
                "qty_decimal_ok": qty_ok,
                "cdc_changes_between_runs": cdc_changes,
                "timbrado_override_ok": tim_override_ok,
                "warnings": build.get("warnings", []),
            }
        except Exception as exc:
            results[label] = {"ok": False, "error": str(exc), "warnings": diag_warnings}
    if diag_warnings:
        results["_warnings"] = diag_warnings
    return results

def _diagnostics_consult_lote(env: str, prot: str) -> dict:
    repo_root = _repo_root()
    venv_py = str(repo_root / ".venv" / "bin" / "python")
    args = [venv_py, "-m", "sifen_minisender", "consult", "--env", env, "--prot", prot]
    env_used = os.environ.copy()
    if env == "prod":
        env_used["SIFEN_CONFIRM_PROD"] = "YES"
    code, out, err = run_minisender(args, cwd=str(repo_root), env=env_used)
    parsed = parse_minisender_response(out)

    # Si no vino dCodRes/dMsgRes por stdout, intentar parsear el response XML
    artifacts_dir = (parsed.get("artifacts_dir") or "").strip()
    if artifacts_dir:
        resp_path = Path(artifacts_dir) / "soap_last_response.xml"
        if resp_path.exists():
            parsed_xml = _parse_consult_response(resp_path.read_text(encoding="utf-8"))
            for k in ("dCodRes", "dMsgRes", "dEstRes", "dCodResLot", "dMsgResLot"):
                if parsed_xml.get(k) and k not in parsed:
                    parsed[k] = parsed_xml.get(k)

    return {
        "exit_code": code,
        "parsed": parsed,
        "stdout_tail": (out or "")[-2000:],
        "stderr_tail": (err or "")[-2000:],
    }

def _diagnostics_consult_ruc(env: str, ruc: str) -> dict:
    cfg = get_sifen_config(env=env)
    client = SoapClient(cfg)
    try:
        resp = client.consulta_ruc_raw(ruc)
        xml = resp.get("response_xml") or ""
        return {
            "d_cod_res": resp.get("d_cod_res"),
            "mensaje": resp.get("mensaje"),
            "http_status": resp.get("http_status"),
            "has_body": bool(xml and xml.strip()),
        }
    finally:
        client.close()

def _diagnostics_consult_cdc(env: str, cdc: str) -> dict:
    cfg = get_sifen_config(env=env)
    client = SoapClient(cfg)
    try:
        resp = client.consulta_de_por_cdc_raw(cdc, dump_http=False)
        xml = resp.get("response_xml") or ""
        return {
            "d_cod_res": resp.get("d_cod_res"),
            "mensaje": resp.get("mensaje"),
            "http_status": resp.get("http_status"),
            "has_body": bool(xml and xml.strip()),
        }
    finally:
        client.close()

@app.route("/backup/status")
def backup_status():
    return {
        "last_backup_at": get_setting("last_backup_at", ""),
        "last_backup_file": get_setting("last_backup_file", ""),
    }


def autodetect_signed_rde_path() -> str:
    """Devuelve el signed_rde.xml más reciente desde ../tesaka-if/artifacts si existe."""
    try:
        repo_root = Path(__file__).resolve().parents[1]   # .../sifen-minisender
        tesaka_if = (repo_root.parent / "tesaka-if").resolve()
        artifacts = tesaka_if / "artifacts"
        if not artifacts.exists():
            return ""
        cands = list(artifacts.glob("run_*/signed_rde.xml"))
        if not cands:
            cands = list(artifacts.rglob("signed_rde.xml"))
        if not cands:
            return ""
        best = max(cands, key=lambda x: x.stat().st_mtime)
        return str(best)
    except Exception:
        return ""

@app.route("/settings", methods=["GET", "POST"])
def settings_page():
    if request.method == "POST":
        default_path = (request.form.get("default_signed_xml_path") or "").strip()
        template_path = (request.form.get("template_xml_path") or "").strip()
        template_factura = (request.form.get("template_xml_path_factura") or "").strip()
        template_autof = (request.form.get("template_xml_path_autofactura") or "").strip()
        template_nc = (request.form.get("template_xml_path_nota_credito") or "").strip()
        template_nd = (request.form.get("template_xml_path_nota_debito") or "").strip()
        template_rem = (request.form.get("template_xml_path_remision") or "").strip()
        next_dnumdoc = (request.form.get("next_dnumdoc") or "").strip()
        default_est = (request.form.get("default_establishment") or "").strip()
        default_pun = (request.form.get("default_point_exp") or "").strip()
        available_pun = (request.form.get("available_point_exp") or "").strip()
        default_env = (request.form.get("default_env") or "").strip().lower()
        timbrado_num = (request.form.get("timbrado_num") or "").strip()
        timbrado_fe_ini = (request.form.get("timbrado_fe_ini") or "").strip()
        est_cfg = (request.form.get("est") or "").strip()
        pun_cfg = (request.form.get("pun") or "").strip()
        set_setting("default_signed_xml_path", default_path)
        set_setting("template_xml_path", template_path)
        set_setting("template_xml_path_factura", template_factura)
        set_setting("template_xml_path_autofactura", template_autof)
        set_setting("template_xml_path_nota_credito", template_nc)
        set_setting("template_xml_path_nota_debito", template_nd)
        set_setting("template_xml_path_remision", template_rem)
        set_setting("next_dnumdoc", next_dnumdoc)
        if default_est:
            set_setting("default_establishment", default_est)
        if default_pun:
            set_setting("default_point_exp", default_pun)
        if available_pun:
            set_setting("available_point_exp", available_pun)
        if default_env in ("test", "prod"):
            set_setting("default_env", default_env)
        set_setting("timbrado_num", _zfill_digits(timbrado_num, 8))
        set_setting("timbrado_fe_ini", timbrado_fe_ini)
        set_setting("est", _zfill_digits(est_cfg, 3))
        set_setting("pun", _zfill_digits(pun_cfg, 3))
        return redirect(url_for("settings_page"))

    default_path = get_setting("default_signed_xml_path", "")
    template_path = get_setting("template_xml_path", "") or _default_template_path()
    template_factura = get_setting("template_xml_path_factura", "")
    template_autof = get_setting("template_xml_path_autofactura", "")
    template_nc = get_setting("template_xml_path_nota_credito", "")
    template_nd = get_setting("template_xml_path_nota_debito", "")
    template_rem = get_setting("template_xml_path_remision", "")
    next_dnumdoc = get_setting("next_dnumdoc", "")
    default_est = get_setting("default_establishment", "001")
    default_pun = get_setting("default_point_exp", "001")
    available_pun = get_setting("available_point_exp", "001,002,003")
    default_env = get_setting("default_env", "prod") or "prod"
    timbrado_num = get_setting("timbrado_num", "")
    timbrado_fe_ini = get_setting("timbrado_fe_ini", "")
    est_cfg = get_setting("est", "")
    pun_cfg = get_setting("pun", "")

    if not default_path:

        default_path = autodetect_signed_rde_path()

    return render_template_string("""
    <!doctype html>
    <html><head>
      <meta charset="utf-8">
      <title>Settings</title>
      <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
      <style>.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace;}</style>
    </head>
    <body class="p-4">
      <div class="container" style="max-width: 980px;">
        <h3>Settings</h3>
        <p class="text-muted">Configura plantillas base para emitir y el XML firmado por defecto si no hay uno específico.</p>
        <form method="post" class="card p-3">
          <label class="form-label">default_signed_xml_path</label>
          <input class="form-control mono" name="default_signed_xml_path" value="{{ default_path }}" placeholder="/Users/.../signed_rde.xml">
          <label class="form-label mt-3">template_xml_path (rDE base sin firma)</label>
          <input class="form-control mono" name="template_xml_path" value="{{ template_path }}" placeholder="/Users/.../rde_input.xml">
          <label class="form-label mt-3">template_xml_path_factura (iTiDE=1)</label>
          <input class="form-control mono" name="template_xml_path_factura" value="{{ template_factura }}" placeholder="/Users/.../rde_factura.xml">
          <label class="form-label mt-3">template_xml_path_autofactura (iTiDE=4)</label>
          <input class="form-control mono" name="template_xml_path_autofactura" value="{{ template_autof }}" placeholder="/Users/.../rde_autofactura.xml">
          <label class="form-label mt-3">template_xml_path_nota_credito (iTiDE=5)</label>
          <input class="form-control mono" name="template_xml_path_nota_credito" value="{{ template_nc }}" placeholder="/Users/.../rde_nota_credito.xml">
          <label class="form-label mt-3">template_xml_path_nota_debito (iTiDE=6)</label>
          <input class="form-control mono" name="template_xml_path_nota_debito" value="{{ template_nd }}" placeholder="/Users/.../rde_nota_debito.xml">
          <label class="form-label mt-3">template_xml_path_remision (iTiDE=7)</label>
          <input class="form-control mono" name="template_xml_path_remision" value="{{ template_rem }}" placeholder="/Users/.../rde_remision.xml">
          <label class="form-label mt-3">next_dnumdoc (7 dígitos)</label>
          <input class="form-control mono" name="next_dnumdoc" value="{{ next_dnumdoc }}" placeholder="0000024">
          <label class="form-label mt-3">default_establishment (3 dígitos)</label>
          <input class="form-control mono" name="default_establishment" value="{{ default_est }}" placeholder="001">
          <label class="form-label mt-3">default_point_exp (3 dígitos)</label>
          <input class="form-control mono" name="default_point_exp" value="{{ default_pun }}" placeholder="001">
          <label class="form-label mt-3">available_point_exp (coma separada)</label>
          <input class="form-control mono" name="available_point_exp" value="{{ available_pun }}" placeholder="001,002,003">
          <label class="form-label mt-3">timbrado_num (sobrescribe template)</label>
          <input class="form-control mono" name="timbrado_num" value="{{ timbrado_num }}" placeholder="18578288">
          <label class="form-label mt-3">timbrado_fe_ini (YYYY-MM-DD, sobrescribe template)</label>
          <input class="form-control mono" name="timbrado_fe_ini" value="{{ timbrado_fe_ini }}" placeholder="2026-01-14">
          <label class="form-label mt-3">est (3 dígitos, opcional)</label>
          <input class="form-control mono" name="est" value="{{ est_cfg }}" placeholder="001">
          <label class="form-label mt-3">pun (3 dígitos, opcional)</label>
          <input class="form-control mono" name="pun" value="{{ pun_cfg }}" placeholder="001">
          <label class="form-label mt-3">default_env (test/prod)</label>
          <input class="form-control mono" name="default_env" value="{{ default_env }}" placeholder="prod">
          <button class="btn btn-primary mt-3" type="submit">Guardar</button>
        </form>
        <div class="mt-3">
          <a href="{{ url_for('invoices') }}">← Volver</a>
          <span class="ms-2">|</span>
          <a href="{{ url_for('diagnostics_page') }}">Diagnósticos</a>
        </div>
      </div>
    </body></html>
    """,
        default_path=default_path,
        template_path=template_path,
        template_factura=template_factura,
        template_autof=template_autof,
        template_nc=template_nc,
        template_nd=template_nd,
        template_rem=template_rem,
        next_dnumdoc=next_dnumdoc,
        default_est=default_est,
        default_pun=default_pun,
        available_pun=available_pun,
        timbrado_num=timbrado_num,
        timbrado_fe_ini=timbrado_fe_ini,
        est_cfg=est_cfg,
        pun_cfg=pun_cfg,
        default_env=default_env,
    )

@app.route("/assets/issuer-logo")
def issuer_logo():
    path = (os.getenv("SIFEN_ISSUER_LOGO_PATH") or "").strip()
    if not path:
        path = str(_repo_root() / "temp" / "industria-feris-isotipo.jpg")
    p = Path(path)
    if not p.is_absolute():
        p = (_repo_root() / p).resolve()
    if not p.exists():
        abort(404)
    resp = send_file(p, mimetype="image/jpeg", as_attachment=False)
    resp.headers["Cache-Control"] = "public, max-age=3600"
    return resp

@app.route("/diagnostics", methods=["GET"])
def diagnostics_page():
    init_db()
    last = _read_last_diagnostics()
    default_cdc, default_prot = _find_default_cdc_and_prot()
    default_ruc = re.sub(r"\\D", "", (os.getenv("SIFEN_EMISOR_RUC") or "")) or "45547378"

    last_json = json.dumps(last, indent=2, ensure_ascii=False) if last else ""
    if len(last_json) > 12000:
        last_json = last_json[:12000] + "\n... (recortado)\n"

    body = render_template_string(
        """
        <div class="card">
          <div class="card-body">
            <h5>Diagnósticos (sin emisión)</h5>
            <p class="text-muted">Pruebas de armado/firma/QR y consultas a endpoints. No envía DE.</p>
            <form method="post" action="{{ url_for('diagnostics_run') }}" class="row g-3">
              <div class="col-12">
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" name="do_dry_run" id="do_dry_run" checked>
                  <label class="form-check-label" for="do_dry_run">Dry-run tipos de documento (XML + firma + QR)</label>
                </div>
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" name="do_consult_ruc" id="do_consult_ruc" checked>
                  <label class="form-check-label" for="do_consult_ruc">Consulta RUC</label>
                </div>
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" name="do_consult_cdc" id="do_consult_cdc" checked>
                  <label class="form-check-label" for="do_consult_cdc">Consulta DE por CDC</label>
                </div>
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" name="do_consult_lote" id="do_consult_lote" checked>
                  <label class="form-check-label" for="do_consult_lote">Consulta Lote (sifen_minisender consult)</label>
                </div>
              </div>

              <div class="col-md-3">
                <label class="form-label">Ambiente</label>
                <select class="form-select" name="env">
                  <option value="prod">prod</option>
                  <option value="test">test</option>
                  <option value="both">test + prod</option>
                </select>
              </div>
              <div class="col-md-3">
                <label class="form-label">RUC (solo dígitos)</label>
                <input class="form-control mono" name="ruc" value="{{ default_ruc }}">
              </div>
              <div class="col-md-3">
                <label class="form-label">CDC (44 dígitos)</label>
                <input class="form-control mono" name="cdc" value="{{ default_cdc }}">
              </div>
              <div class="col-md-3">
                <label class="form-label">Prot. consulta lote</label>
                <input class="form-control mono" name="prot" value="{{ default_prot }}">
              </div>

              <div class="col-12">
                <button class="btn btn-primary" type="submit">Ejecutar diagnósticos</button>
                <a class="btn btn-outline-secondary" href="{{ url_for('settings_page') }}">Volver a settings</a>
              </div>
            </form>

            {% if last_json %}
              <hr>
              <h6>Último resultado</h6>
              <pre class="mono" style="white-space: pre-wrap;">{{ last_json }}</pre>
            {% endif %}
          </div>
        </div>
        """,
        default_cdc=default_cdc,
        default_prot=default_prot,
        default_ruc=default_ruc,
        last_json=last_json,
    )
    return render_template_string(BASE_HTML, title="Diagnósticos", db_path=DB_PATH, body=body)

@app.route("/diagnostics/run", methods=["POST"])
def diagnostics_run():
    init_db()
    env_choice = (request.form.get("env") or "prod").strip().lower()
    envs = ["test", "prod"] if env_choice == "both" else [env_choice]
    ruc = re.sub(r"\\D", "", (request.form.get("ruc") or ""))
    cdc = re.sub(r"\\D", "", (request.form.get("cdc") or ""))
    prot = re.sub(r"\\D", "", (request.form.get("prot") or ""))

    result = {
        "started_at": now_iso(),
        "envs": envs,
        "inputs": {"ruc": ruc, "cdc": cdc, "prot": prot},
        "dry_run": None,
        "consult_ruc": {},
        "consult_cdc": {},
        "consult_lote": {},
    }

    if request.form.get("do_dry_run"):
        result["dry_run"] = _diagnostics_dry_run()

    for env in envs:
        if request.form.get("do_consult_ruc") and ruc:
            try:
                result["consult_ruc"][env] = _diagnostics_consult_ruc(env, ruc)
            except Exception as exc:
                result["consult_ruc"][env] = {"error": str(exc)}
        if request.form.get("do_consult_cdc") and cdc and len(cdc) == 44:
            try:
                result["consult_cdc"][env] = _diagnostics_consult_cdc(env, cdc)
            except Exception as exc:
                result["consult_cdc"][env] = {"error": str(exc)}
        if request.form.get("do_consult_lote") and prot:
            try:
                result["consult_lote"][env] = _diagnostics_consult_lote(env, prot)
            except Exception as exc:
                result["consult_lote"][env] = {"error": str(exc)}

    out_dir = _diagnostics_artifacts_dir()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"diagnostics_{ts}.json"
    out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    set_setting("diagnostics_last_path", str(out_path))

    return redirect(url_for("diagnostics_page"))

@app.route("/")
def index():
    return redirect(url_for("invoices"))

@app.route("/invoices")
def invoices():
    init_db()

    q = (request.args.get("q") or "").strip()
    customer_id = (request.args.get("customer_id") or "").strip()
    page = int(request.args.get("page") or "1")
    per_page = 15
    offset = (page - 1) * per_page

    con = get_db()

    customers = con.execute("SELECT id, name FROM customers ORDER BY name ASC").fetchall()

    where = []
    params = []

    if q:
        where.append("(c.name LIKE ? OR c.ruc LIKE ? OR i.id LIKE ? OR i.sifen_prot_cons_lote LIKE ?)")
        like = f"%{q}%"
        params += [like, like, like, like]

    if customer_id:
        where.append("i.customer_id = ?")
        params.append(customer_id)

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    total_row = con.execute(
        f"""
        SELECT COUNT(*) AS n
        FROM invoices i
        JOIN customers c ON c.id=i.customer_id
        {where_sql}
        """,
        params,
    ).fetchone()
    total = int(total_row["n"])
    pending_row = con.execute(
        """
        SELECT COUNT(*) AS n
        FROM invoices
        WHERE status IN ('QUEUED','SENT','CONFIRMING')
          AND sifen_prot_cons_lote IS NOT NULL
          AND sifen_prot_cons_lote != ''
        """
    ).fetchone()
    pending_total = int(pending_row["n"])

    rows = con.execute(
        f"""
        SELECT
          i.*,
          c.name AS customer_name,
          c.ruc AS customer_ruc
        FROM invoices i
        JOIN customers c ON c.id=i.customer_id
        {where_sql}
        ORDER BY i.id DESC
        LIMIT ? OFFSET ?
        """,
        params + [per_page, offset],
    ).fetchall()

    def yn(v): return "✅" if v else "—"

    # pagination calc
    pages = max(1, (total + per_page - 1) // per_page)

    body = render_template_string(
        """
        <form class="row g-2 mb-3" method="get" action="{{ url_for('invoices') }}">
          <div class="col-sm-6 col-md-6">
            <input class="form-control" name="q" placeholder="Buscar por cliente, RUC, ID, protocolo..." value="{{q}}">
          </div>
          <div class="col-sm-4 col-md-4">
            <select class="form-select" name="customer_id">
              <option value="">Todos los clientes</option>
              {% for c in customers %}
                <option value="{{c.id}}" {% if customer_id==c.id|string %}selected{% endif %}>{{c.name}}</option>
              {% endfor %}
            </select>
          </div>
          <div class="col-sm-2 col-md-2 d-grid">
            <button class="btn btn-outline-primary" type="submit">Filtrar</button>
          </div>
        </form>

        <div class="card">
          <div class="card-body">
            <div class="d-flex justify-content-between align-items-center mb-2">
              <div class="text-muted">
                Total: <b>{{total}}</b>
                <span class="ms-2">Sin confirmar: <b>{{pending_total}}</b></span>
              </div>
              <div class="text-muted">Página <b>{{page}}</b> / {{pages}}</div>
            </div>

            <div class="table-responsive">
              <table class="table table-sm align-middle">
                <thead>
                  <tr>
                    <th class="nowrap">ID</th>
                    <th>Cliente</th>
                    <th class="nowrap">RUC</th>
                    <th class="nowrap">Tipo</th>
                    <th class="nowrap">Total</th>
                    <th class="nowrap">Estado</th>
                    <th class="nowrap">Encolado</th>
                    <th class="nowrap">Confirmado</th>
                    <th class="nowrap">Prot. lote</th>
                    <th class="nowrap">Acciones</th>
                  </tr>
                </thead>
                <tbody>
                  {% for r in rows %}
                    <tr>
                      <td class="mono">{{r.id}}</td>
                      <td>{{r.customer_name}}</td>
                      <td class="mono">{{r.customer_ruc or "—"}}</td>
                      <td>{{ doc_type_label(r.doc_type) }}</td>
                      <td class="mono">{{"{:,}".format(r.total).replace(",", ".")}} {{r.currency}}</td>
                      <td>
                        {{ badge(r.status)|safe }}
                        {% if r.status in ("QUEUED","SENT","CONFIRMING") and r.sifen_prot_cons_lote %}
                          <div class="small text-warning">Sin confirmar</div>
                        {% endif %}
                      </td>
                      <td class="nowrap">{{ yn(r.queued_at or r.sent_at) }}</td>
                      <td class="nowrap">
                        {% if r.status == "CONFIRMED_OK" %}✅{% elif r.status=="CONFIRMED_REJECTED" %}❌{% else %}—{% endif %}
                      </td>
                      <td class="mono">{{ r.sifen_prot_cons_lote or "—" }}</td>
                      <td class="nowrap">
                        <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('invoice_detail', invoice_id=r.id) }}">Ver</a>
                      </td>
                    </tr>
                  {% endfor %}
                  {% if not rows %}
                    <tr><td colspan="10" class="text-muted">Sin resultados.</td></tr>
                  {% endif %}
                </tbody>
              </table>
            </div>

            <nav class="d-flex justify-content-between">
              <div>
                {% if page > 1 %}
                  <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('invoices', q=q, customer_id=customer_id, page=page-1) }}">← Anterior</a>
                {% endif %}
              </div>
              <div>
                {% if page < pages %}
                  <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('invoices', q=q, customer_id=customer_id, page=page+1) }}">Siguiente →</a>
                {% endif %}
              </div>
            </nav>

          </div>
        </div>
        """,
        rows=rows,
        customers=customers,
        q=q,
        customer_id=customer_id,
        total=total,
        pending_total=pending_total,
        page=page,
        pages=pages,
        yn=yn,
        badge=badge,
        doc_type_label=doc_type_label,
    )

    return render_template_string(BASE_HTML, title=APP_TITLE, db_path=DB_PATH, body=body)

@app.route("/invoice/new", methods=["GET", "POST"])
def invoice_new():
    init_db()
    con = get_db()

    # Seed mínimo si DB está vacía (para que puedas ver algo ya)
    if con.execute("SELECT COUNT(*) n FROM customers").fetchone()["n"] == 0:
        con.execute("INSERT INTO customers (name, ruc, created_at) VALUES (?,?,?)", ("Cliente Demo S.A.", "80012345-6", now_iso()))
        con.commit()

    customers = con.execute("SELECT id, name, ruc FROM customers ORDER BY name ASC").fetchall()
    products = con.execute("SELECT id, sku, name, unit, price_unit FROM products ORDER BY name ASC").fetchall()
    default_est = get_setting("default_establishment", "001")
    default_pun = get_setting("default_point_exp", "001")
    available_pun = [p.strip() for p in (get_setting("available_point_exp", "001,002,003") or "").split(",") if p.strip()]
    if not available_pun:
        available_pun = [default_pun or "001"]

    if request.method == "POST":
        customer_id = int(request.form.get("customer_id") or "0")
        if not customer_id:
            abort(400, "customer_id requerido")
        doc_type = normalize_doc_type(request.form.get("doc_type"))

        issued_at = now_iso()
        est = _zfill_digits(request.form.get("establishment") or default_est, 3)
        pun = _zfill_digits(request.form.get("point_exp") or default_pun, 3)
        cur = con.execute(
            "INSERT INTO invoices (created_at, issued_at, customer_id, status, doc_type, establishment, point_exp) VALUES (?,?,?,?,?,?,?)",
            (now_iso(), issued_at, customer_id, "DRAFT", doc_type, est, pun),
        )
        invoice_id = cur.lastrowid

        def _parse_int(value: Optional[str], default: int) -> int:
            try:
                raw = (value or "").strip()
                return int(raw) if raw else default
            except Exception:
                return default

        descs = request.form.getlist("description")
        qtys = request.form.getlist("qty")
        prices = request.form.getlist("price_unit")
        product_ids = request.form.getlist("product_id")

        inserted = 0
        max_len = max(len(descs), len(qtys), len(prices))
        for idx in range(max_len):
            desc = (descs[idx] if idx < len(descs) else "").strip()
            if not desc:
                continue
            qty = _parse_int(qtys[idx] if idx < len(qtys) else None, 1)
            price_unit = _parse_int(prices[idx] if idx < len(prices) else None, 0)
            prod_id_raw = (product_ids[idx] if idx < len(product_ids) else "").strip()
            prod_id = int(prod_id_raw) if prod_id_raw.isdigit() else None
            line_total = qty * price_unit
            con.execute(
                "INSERT INTO invoice_lines (invoice_id, product_id, description, qty, price_unit, line_total) VALUES (?,?,?,?,?,?)",
                (invoice_id, prod_id, desc, qty, price_unit, line_total),
            )
            inserted += 1

        if inserted == 0:
            desc = "Servicio"
            qty = 1
            price_unit = 0
            line_total = qty * price_unit
            con.execute(
                "INSERT INTO invoice_lines (invoice_id, product_id, description, qty, price_unit, line_total) VALUES (?,?,?,?,?,?)",
                (invoice_id, None, desc, qty, price_unit, line_total),
            )
        con.commit()
        recompute_invoice_totals(invoice_id)

        return redirect(url_for("invoice_detail", invoice_id=invoice_id))

    body = render_template_string(
        """
        <div class="card">
          <div class="card-body">
            <h5>Nuevo documento (mínimo viable)</h5>
            <form method="post" class="row g-3">
              <div class="col-md-6">
                <label class="form-label">Cliente</label>
                <select class="form-select" name="customer_id" id="customer-select" required>
                  {% for c in customers %}
                    <option value="{{c.id}}">{{c.name}} ({{c.ruc or "sin RUC"}})</option>
                  {% endfor %}
                </select>
                <button class="btn btn-sm btn-outline-primary mt-2" type="button" data-bs-toggle="modal" data-bs-target="#customerModal">+ Agregar cliente nuevo</button>
              </div>
              <div class="col-md-6">
                <label class="form-label">Tipo de documento</label>
                <select class="form-select" name="doc_type" required>
                  <option value="1">Factura electrónica</option>
                  <option value="4">Autofactura electrónica</option>
                  <option value="5">Nota de crédito electrónica</option>
                  <option value="6">Nota de débito electrónica</option>
                  <option value="7">Nota de remisión electrónica</option>
                </select>
              </div>
              <div class="col-12"></div>
              <div class="col-md-3">
                <label class="form-label">Establecimiento</label>
                <input class="form-control mono" name="establishment" value="{{ default_est }}" required>
              </div>
              <div class="col-md-3">
                <label class="form-label">Punto de expedición</label>
                <select class="form-select mono" name="point_exp" required>
                  {% for p in available_pun %}
                    <option value="{{p}}" {% if p==default_pun %}selected{% endif %}>{{p}}</option>
                  {% endfor %}
                </select>
              </div>

              <div class="col-12"><hr></div>

              <div id="items-container">
                <div class="row g-3 item-row align-items-end">
                  <div class="col-md-5">
                    <label class="form-label">Descripción</label>
                    {% if products %}
                      <select class="form-select product-select" name="description" required>
                        <option value="" selected>Seleccionar producto/servicio...</option>
                        {% for p in products %}
                          <option value="{{p.name}}" data-id="{{p.id}}" data-price="{{p.price_unit}}">{{p.name}}{% if p.sku %} ({{p.sku}}){% endif %}</option>
                        {% endfor %}
                      </select>
                    {% else %}
                      <input class="form-control" name="description" value="Servicio" required>
                    {% endif %}
                    <input type="hidden" name="product_id" value="">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Cantidad</label>
                    <input class="form-control" name="qty" type="number" value="1" required>
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">Precio unitario (PYG)</label>
                    <input class="form-control" name="price_unit" type="number" value="0" required>
                  </div>
                  <div class="col-md-2">
                    <label class="form-label d-block">&nbsp;</label>
                    <button class="btn btn-outline-danger w-100 remove-item" type="button" aria-label="Eliminar ítem" title="Eliminar ítem">
                      <span aria-hidden="true">🗑️</span>
                    </button>
                  </div>
                </div>
              </div>
              <div class="col-12">
                <button class="btn btn-sm btn-outline-secondary" type="button" id="add-item">+ Agregar ítem</button>
                <button class="btn btn-sm btn-outline-primary ms-2" type="button" data-bs-toggle="modal" data-bs-target="#productModal">+ Agregar producto nuevo</button>
              </div>

              <div class="col-12 d-flex gap-2">
                <button class="btn btn-primary" type="submit">Crear factura</button>
                <a class="btn btn-outline-secondary" href="{{ url_for('invoices') }}">Cancelar</a>
              </div>
            </form>
            <div class="text-muted small mt-3">
              Tip: podés agregar varias líneas con el botón “Agregar ítem”.
            </div>

            <div class="modal fade" id="customerModal" tabindex="-1" aria-hidden="true">
              <div class="modal-dialog">
                <div class="modal-content">
                  <form id="quick-customer-form">
                    <div class="modal-header">
                      <h5 class="modal-title">Agregar cliente</h5>
                      <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                      <div class="mb-2">
                        <label class="form-label">Nombre *</label>
                        <input class="form-control" name="name" required>
                      </div>
                      <div class="mb-2">
                        <label class="form-label">RUC</label>
                        <input class="form-control mono" name="ruc" placeholder="4554737-8">
                      </div>
                      <div class="mb-2">
                        <label class="form-label">Email</label>
                        <input class="form-control" name="email" type="email">
                      </div>
                      <div class="mb-2">
                        <label class="form-label">Teléfono</label>
                        <input class="form-control" name="phone">
                      </div>
                      <div class="text-danger small d-none" id="quick-customer-error"></div>
                    </div>
                    <div class="modal-footer">
                      <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancelar</button>
                      <button type="submit" class="btn btn-primary">Guardar</button>
                    </div>
                  </form>
                </div>
              </div>
            </div>

            <div class="modal fade" id="productModal" tabindex="-1" aria-hidden="true">
              <div class="modal-dialog">
                <div class="modal-content">
                  <form id="quick-product-form">
                    <div class="modal-header">
                      <h5 class="modal-title">Agregar producto/servicio</h5>
                      <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                      <div class="mb-2">
                        <label class="form-label">Nombre *</label>
                        <input class="form-control" name="name" required>
                      </div>
                      <div class="mb-2">
                        <label class="form-label">SKU</label>
                        <input class="form-control" name="sku">
                      </div>
                      <div class="mb-2">
                        <label class="form-label">Unidad</label>
                        <input class="form-control" name="unit" value="UN">
                      </div>
                      <div class="mb-2">
                        <label class="form-label">Precio Unit. (PYG)</label>
                        <input class="form-control mono" name="price_unit" placeholder="1.234.567">
                      </div>
                      <div class="text-danger small d-none" id="quick-product-error"></div>
                    </div>
                    <div class="modal-footer">
                      <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancelar</button>
                      <button type="submit" class="btn btn-primary">Guardar</button>
                    </div>
                  </form>
                </div>
              </div>
            </div>

            <script>
              (function () {
                const container = document.getElementById("items-container");
                const addBtn = document.getElementById("add-item");
                if (!container || !addBtn) return;
                addBtn.addEventListener("click", function () {
                  const rows = container.querySelectorAll(".item-row");
                  if (!rows.length) return;
                  const clone = rows[rows.length - 1].cloneNode(true);
                  clone.querySelectorAll("input").forEach((inp) => {
                    if (inp.name === "description") inp.value = "";
                    if (inp.name === "qty") inp.value = "1";
                    if (inp.name === "price_unit") inp.value = "0";
                    if (inp.name === "product_id") inp.value = "";
                  });
                  clone.querySelectorAll("select").forEach((sel) => {
                    if (sel.name === "description") sel.value = "";
                  });
                  container.appendChild(clone);
                });
                container.addEventListener("click", function (ev) {
                  const btn = ev.target.closest(".remove-item");
                  if (!btn) return;
                  const row = btn.closest(".item-row");
                  if (!row) return;
                  const rows = container.querySelectorAll(".item-row");
                  if (rows.length <= 1) {
                    row.querySelectorAll("input").forEach((inp) => {
                      if (inp.name === "description") inp.value = "";
                      if (inp.name === "qty") inp.value = "1";
                      if (inp.name === "price_unit") inp.value = "0";
                      if (inp.name === "product_id") inp.value = "";
                    });
                    row.querySelectorAll("select").forEach((sel) => {
                      if (sel.name === "description") sel.value = "";
                    });
                    return;
                  }
                  row.remove();
                });

                container.addEventListener("change", function (ev) {
                  const sel = ev.target.closest(".product-select");
                  if (!sel) return;
                  const row = sel.closest(".item-row");
                  if (!row) return;
                  const opt = sel.selectedOptions[0];
                  if (!opt) return;
                  const price = opt.getAttribute("data-price") || "";
                  const pid = opt.getAttribute("data-id") || "";
                  const priceInput = row.querySelector('input[name="price_unit"]');
                  const pidInput = row.querySelector('input[name="product_id"]');
                  if (priceInput && price) priceInput.value = price;
                  if (pidInput) pidInput.value = pid;
                });

                const quickForm = document.getElementById("quick-product-form");
                const errBox = document.getElementById("quick-product-error");
                if (quickForm) {
                  quickForm.addEventListener("submit", async function (ev) {
                    ev.preventDefault();
                    if (errBox) { errBox.classList.add("d-none"); errBox.textContent = ""; }
                    const data = new FormData(quickForm);
                    const payload = {
                      name: data.get("name"),
                      sku: data.get("sku"),
                      unit: data.get("unit"),
                      price_unit: data.get("price_unit"),
                    };
                    try {
                      const res = await fetch("{{ url_for('product_quick_add') }}", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(payload),
                      });
                      const out = await res.json();
                      if (!res.ok) {
                        throw new Error(out.error || "Error al crear producto");
                      }
                      const optionLabel = out.sku ? `${out.name} (${out.sku})` : out.name;
                      document.querySelectorAll(".product-select").forEach((sel) => {
                        const opt = document.createElement("option");
                        opt.value = out.name;
                        opt.textContent = optionLabel;
                        opt.setAttribute("data-id", out.id);
                        opt.setAttribute("data-price", out.price_unit);
                        sel.appendChild(opt);
                      });
                      const rows = container.querySelectorAll(".item-row");
                      const row = rows[rows.length - 1];
                      const sel = row ? row.querySelector(".product-select") : null;
                      if (sel) {
                        sel.value = out.name;
                        sel.dispatchEvent(new Event("change"));
                      }
                      quickForm.reset();
                      if (out.unit) quickForm.querySelector('input[name="unit"]').value = out.unit;
                      const modalEl = document.getElementById("productModal");
                      if (modalEl) {
                        const modal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
                        modal.hide();
                      }
                    } catch (e) {
                      if (errBox) {
                        errBox.textContent = e.message || "Error";
                        errBox.classList.remove("d-none");
                      }
                    }
                  });
                }

                const quickCustomerForm = document.getElementById("quick-customer-form");
                const customerErr = document.getElementById("quick-customer-error");
                const customerSelect = document.getElementById("customer-select");
                if (quickCustomerForm && customerSelect) {
                  quickCustomerForm.addEventListener("submit", async function (ev) {
                    ev.preventDefault();
                    if (customerErr) { customerErr.classList.add("d-none"); customerErr.textContent = ""; }
                    const data = new FormData(quickCustomerForm);
                    const payload = {
                      name: data.get("name"),
                      ruc: data.get("ruc"),
                      email: data.get("email"),
                      phone: data.get("phone"),
                    };
                    try {
                      const res = await fetch("{{ url_for('customer_quick_add') }}", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify(payload),
                      });
                      const out = await res.json();
                      if (!res.ok) {
                        throw new Error(out.error || "Error al crear cliente");
                      }
                      const label = out.ruc ? `${out.name} (${out.ruc})` : out.name;
                      const opt = document.createElement("option");
                      opt.value = out.id;
                      opt.textContent = label;
                      customerSelect.appendChild(opt);
                      customerSelect.value = String(out.id);
                      quickCustomerForm.reset();
                      const modalEl = document.getElementById("customerModal");
                      if (modalEl) {
                        const modal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
                        modal.hide();
                      }
                    } catch (e) {
                      if (customerErr) {
                        customerErr.textContent = e.message || "Error";
                        customerErr.classList.remove("d-none");
                      }
                    }
                  });
                }
              })();
            </script>
          </div>
        </div>
        """,
        customers=customers,
        default_est=default_est,
        default_pun=default_pun,
        available_pun=available_pun,
        products=products,
    )
    return render_template_string(BASE_HTML, title="Factura nueva", db_path=DB_PATH, body=body)

@app.route("/invoice/<int:invoice_id>")
def invoice_detail(invoice_id: int):
    init_db()
    con = get_db()

    inv = con.execute(
        """
        SELECT i.*, c.name AS customer_name, c.ruc AS customer_ruc, c.email AS customer_email
        FROM invoices i JOIN customers c ON c.id=i.customer_id
        WHERE i.id=?
        """,
        (invoice_id,),
    ).fetchone()
    if not inv:
        abort(404)

    lines = con.execute(
        "SELECT * FROM invoice_lines WHERE invoice_id=? ORDER BY id ASC",
        (invoice_id,),
    ).fetchall()

    doc_type = normalize_doc_type(inv["doc_type"])
    cdc = _extract_cdc_from_xml_path(inv["source_xml_path"] or "")
    inutil_defaults = _extract_inutil_defaults_from_xml_path(inv["source_xml_path"] or "")
    extra_prefill = inv["doc_extra_json"]
    if not extra_prefill:
        fallback = _default_extra_json_for(doc_type)
        if fallback:
            extra_prefill = json.dumps(fallback, indent=2, ensure_ascii=False)
    try:
        extra_parsed = _parse_extra_json(inv["doc_extra_json"], doc_type)
    except Exception:
        extra_parsed = _default_extra_json_for(doc_type) or {}
    transport = _get_transport_from_extra(extra_parsed)
    t_sal = transport.get("salida") or {}
    t_ent = transport.get("entrega") or {}
    t_veh = transport.get("vehiculo") or {}
    t_trn = transport.get("transportista") or {}

    body = render_template_string(
        """
        <div class="d-flex justify-content-between align-items-center mb-3">
          <div>
            <h4 class="mb-0">Documento #{{inv.id}}</h4>
            <div class="text-muted">
              {{inv.customer_name}} — <span class="mono">{{inv.customer_ruc or "—"}}</span><br>
              Tipo: <b>{{ doc_type_label(inv.doc_type) }}</b> (<span class="mono">iTiDE={{ inv.doc_type or "1" }}</span>)
              <br>Est/Pun: <span class="mono">{{ (inv.establishment or "001") }}-{{ (inv.point_exp or "001") }}</span>
            </div>
          </div>
          <div>
            <a class="btn btn-outline-secondary" href="{{ url_for('invoices') }}">Volver</a>
          </div>
        </div>

        <div class="row g-3">
          <div class="col-lg-6">
            <div class="card">
              <div class="card-body">
                <h6>Estado</h6>
                <div class="mb-2">{{ badge(inv.status)|safe }}</div>
                {% if inv.last_lote_code or inv.last_sifen_code or inv.last_sifen_est %}
                <div class="mt-2">
                  {% if inv.last_lote_code == "0361" %}
                    <div class="alert alert-warning py-2 mb-2">
                      Lote en procesamiento. Reintentaremos automáticamente.
                      {% if inv.last_lote_msg %}<div class="small mt-1">{{ inv.last_lote_msg }}</div>{% endif %}
                    </div>
                  {% elif inv.last_lote_code == "0362" %}
                    <div class="alert alert-info py-2 mb-2">
                      Lote procesado. Resultado del DE:
                      <b>{{ inv.last_sifen_est or "—" }}</b>
                      {% if inv.last_sifen_msg %}<div class="small mt-1">{{ inv.last_sifen_msg }}</div>{% endif %}
                    </div>
                  {% elif inv.last_lote_code == "0365" %}
                    <div class="alert alert-danger py-2 mb-2">
                      Lote cancelado (SIFEN rechazó todos los DE del lote).
                      {% if inv.last_lote_msg %}<div class="small mt-1">{{ inv.last_lote_msg }}</div>{% endif %}
                    </div>
                  {% elif inv.status == "CONFIRMED_REJECTED" %}
                    <div class="alert alert-danger py-2 mb-2">
                      Documento rechazado por SIFEN.
                      {% if inv.last_sifen_msg %}<div class="small mt-1">{{ inv.last_sifen_msg }}</div>{% endif %}
                    </div>
                  {% endif %}
                </div>
                {% endif %}
                <div class="small text-muted">
                  Creada: <span class="mono">{{inv.created_at}}</span><br>
                  Emitida: <span class="mono">{{inv.issued_at or "—"}}</span><br>
                  Encolada: <span class="mono">{{inv.queued_at or "—"}}</span><br>
                  Enviada: <span class="mono">{{inv.sent_at or "—"}}</span><br>
                  Confirmada: <span class="mono">{{inv.confirmed_at or "—"}}</span>
                  {% if inv.last_sifen_est %} — <b>{{inv.last_sifen_est}}</b>{% endif %}<br>
                </div>
                <hr>
                <div class="small">
                  Prot. consulta lote: <span class="mono">{{inv.sifen_prot_cons_lote or "—"}}</span><br>
                  Código lote: <span class="mono">{{inv.last_lote_code or "—"}}</span><br>
                  Mensaje lote: {{inv.last_lote_msg or "—"}}<br>
                  Prot. autorización: <span class="mono">{{inv.last_sifen_prot_aut or "—"}}</span><br>
                  Estado SIFEN: <span class="mono">{{inv.last_sifen_est or "—"}}</span><br>
                  Último código: <span class="mono">{{inv.last_sifen_code or "—"}}</span><br>
                  Último mensaje: {{inv.last_sifen_msg or "—"}}
                </div>
                <form method="post" action="{{ url_for('invoice_resync', invoice_id=inv.id) }}" class="d-flex gap-2 flex-wrap align-items-center mt-2">
                  <select class="form-select form-select-sm" name="env" style="max-width: 140px;">
                    <option value="prod" {% if default_env=="prod" %}selected{% endif %}>PROD</option>
                    <option value="test" {% if default_env=="test" %}selected{% endif %}>TEST</option>
                  </select>
                  <button class="btn btn-sm btn-outline-primary" type="submit">Re-sincronizar con SIFEN</button>
                </form>
                <form method="post" action="{{ url_for('invoice_consult_cdc', invoice_id=inv.id) }}" class="d-flex gap-2 flex-wrap align-items-center mt-2">
                  <select class="form-select form-select-sm" name="env" style="max-width: 140px;">
                    <option value="prod" {% if default_env=="prod" %}selected{% endif %}>PROD</option>
                    <option value="test" {% if default_env=="test" %}selected{% endif %}>TEST</option>
                  </select>
                  <button class="btn btn-sm btn-outline-primary" type="submit">Consultar DE (CDC)</button>
                </form>
                <form method="post" action="{{ url_for('invoice_refresh_soap', invoice_id=inv.id) }}" class="mt-2">
                  <button class="btn btn-sm btn-outline-secondary" type="submit">Actualizar desde último SOAP</button>
                </form>
              
                <hr>
                <h6>Emisión integrada</h6>
                <div class="small text-muted mb-2">
                  Email cliente: <span class="mono">{{ inv.customer_email or "—" }}</span>
                </div>
                <div class="small text-muted mb-2">
                  Tipo: <b>{{ doc_type_label(inv.doc_type) }}</b> — si no es Factura, configurá la plantilla específica en /settings.
                </div>
                <form method="post" action="{{ url_for('invoice_set_extra', invoice_id=inv.id) }}" class="mb-2">
                  <label class="form-label small text-muted">doc_extra_json (pegar JSON de ejemplo si aplica)</label>
                  <textarea class="form-control form-control-sm mono" name="doc_extra_json" rows="8" placeholder="{}">{{ extra_prefill or "" }}</textarea>
                  <button class="btn btn-sm btn-outline-secondary mt-2" type="submit">Guardar JSON extra</button>
                </form>
                {% if inv.doc_type == "7" %}
                <div class="card mt-3">
                  <div class="card-body">
                    <h6>Transporte (Remisión)</h6>
                    <form method="post" action="{{ url_for('invoice_set_transporte', invoice_id=inv.id) }}">
                      <div class="row g-2">
                        <div class="col-md-4">
                          <label class="form-label small">Tipo transporte (iTipTrans)</label>
                          <select class="form-select form-select-sm" name="tr_tipo" required>
                            {% for k,v in trans_tipo.items() %}
                              <option value="{{k}}" {% if transport.get('tipoTransporte')|string == k %}selected{% endif %}>{{k}} - {{v}}</option>
                            {% endfor %}
                          </select>
                        </div>
                        <div class="col-md-4">
                          <label class="form-label small">Modalidad (iModTrans)</label>
                          <select class="form-select form-select-sm" name="tr_modalidad" required>
                            {% for k,v in trans_mod.items() %}
                              <option value="{{k}}" {% if transport.get('modalidad')|string == k %}selected{% endif %}>{{k}} - {{v}}</option>
                            {% endfor %}
                          </select>
                        </div>
                        <div class="col-md-4">
                          <label class="form-label small">Responsable flete (iRespFlete)</label>
                          <select class="form-select form-select-sm" name="tr_resp" required>
                            {% for k,v in resp_flete.items() %}
                              <option value="{{k}}" {% if transport.get('tipoResponsable')|string == k %}selected{% endif %}>{{k}} - {{v}}</option>
                            {% endfor %}
                          </select>
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Inicio traslado</label>
                          <input class="form-control form-control-sm" name="tr_ini" value="{{ transport.get('iniFechaEstimadaTrans','') }}">
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Fin traslado</label>
                          <input class="form-control form-control-sm" name="tr_fin" value="{{ transport.get('finFechaEstimadaTrans','') }}">
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Cond. negociación</label>
                          <input class="form-control form-control-sm" name="tr_cond" value="{{ transport.get('condNeg','') }}">
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Nro. manifiesto</label>
                          <input class="form-control form-control-sm" name="tr_manif" value="{{ transport.get('numManif','') }}">
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Despacho import.</label>
                          <input class="form-control form-control-sm" name="tr_desp" value="{{ transport.get('despachoImp','') }}">
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">País destino</label>
                          <input class="form-control form-control-sm" name="tr_pais" value="{{ transport.get('paisDest','') }}">
                        </div>
                        <div class="col-md-6">
                          <label class="form-label small">Desc país destino</label>
                          <input class="form-control form-control-sm" name="tr_pais_desc" value="{{ transport.get('paisDestDesc','') }}">
                        </div>
                      </div>

                      <hr>
                      <h6 class="mt-2">Salida</h6>
                      <div class="row g-2">
                        <div class="col-md-6">
                          <label class="form-label small">Dirección</label>
                          <input class="form-control form-control-sm" name="sal_dir" value="{{ t_sal.get('direccion','') }}" required>
                        </div>
                        <div class="col-md-2">
                          <label class="form-label small">Nro casa</label>
                          <input class="form-control form-control-sm" name="sal_num" value="{{ t_sal.get('numCasa','') }}" required>
                        </div>
                        <div class="col-md-2">
                          <label class="form-label small">Dep</label>
                          <input class="form-control form-control-sm" name="sal_dep" value="{{ t_sal.get('departamento','') }}" required>
                        </div>
                        <div class="col-md-2">
                          <label class="form-label small">Dist</label>
                          <input class="form-control form-control-sm" name="sal_dist" value="{{ t_sal.get('distrito','') }}">
                        </div>
                        <div class="col-md-2">
                          <label class="form-label small">Ciudad</label>
                          <input class="form-control form-control-sm" name="sal_ciu" value="{{ t_sal.get('ciudad','') }}" required>
                        </div>
                        <div class="col-md-4">
                          <label class="form-label small">Teléfono</label>
                          <input class="form-control form-control-sm" name="sal_tel" value="{{ t_sal.get('telefono','') }}">
                        </div>
                        <div class="col-md-4">
                          <label class="form-label small">Comp. 1</label>
                          <input class="form-control form-control-sm" name="sal_comp1" value="{{ t_sal.get('comp1','') }}">
                        </div>
                        <div class="col-md-4">
                          <label class="form-label small">Comp. 2</label>
                          <input class="form-control form-control-sm" name="sal_comp2" value="{{ t_sal.get('comp2','') }}">
                        </div>
                      </div>

                      <hr>
                      <h6 class="mt-2">Entrega</h6>
                      <div class="row g-2">
                        <div class="col-md-6">
                          <label class="form-label small">Dirección</label>
                          <input class="form-control form-control-sm" name="ent_dir" value="{{ t_ent.get('direccion','') }}" required>
                        </div>
                        <div class="col-md-2">
                          <label class="form-label small">Nro casa</label>
                          <input class="form-control form-control-sm" name="ent_num" value="{{ t_ent.get('numCasa','') }}" required>
                        </div>
                        <div class="col-md-2">
                          <label class="form-label small">Dep</label>
                          <input class="form-control form-control-sm" name="ent_dep" value="{{ t_ent.get('departamento','') }}" required>
                        </div>
                        <div class="col-md-2">
                          <label class="form-label small">Dist</label>
                          <input class="form-control form-control-sm" name="ent_dist" value="{{ t_ent.get('distrito','') }}">
                        </div>
                        <div class="col-md-2">
                          <label class="form-label small">Ciudad</label>
                          <input class="form-control form-control-sm" name="ent_ciu" value="{{ t_ent.get('ciudad','') }}" required>
                        </div>
                        <div class="col-md-4">
                          <label class="form-label small">Teléfono</label>
                          <input class="form-control form-control-sm" name="ent_tel" value="{{ t_ent.get('telefono','') }}">
                        </div>
                        <div class="col-md-4">
                          <label class="form-label small">Comp. 1</label>
                          <input class="form-control form-control-sm" name="ent_comp1" value="{{ t_ent.get('comp1','') }}">
                        </div>
                        <div class="col-md-4">
                          <label class="form-label small">Comp. 2</label>
                          <input class="form-control form-control-sm" name="ent_comp2" value="{{ t_ent.get('comp2','') }}">
                        </div>
                      </div>

                      <hr>
                      <h6 class="mt-2">Vehículo</h6>
                      <div class="row g-2">
                        <div class="col-md-3">
                          <label class="form-label small">Tipo</label>
                          <input class="form-control form-control-sm" name="veh_tipo" value="{{ t_veh.get('tipo','') }}" required>
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Marca</label>
                          <input class="form-control form-control-sm" name="veh_marca" value="{{ t_veh.get('marca','') }}" required>
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Tipo doc vehículo</label>
                          <select class="form-select form-select-sm" name="veh_doc_tipo" required>
                            <option value="1" {% if t_veh.get('documentoTipo')|string == "1" %}selected{% endif %}>1 - Identificación</option>
                            <option value="2" {% if t_veh.get('documentoTipo')|string == "2" %}selected{% endif %}>2 - Matrícula</option>
                          </select>
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Nro id/matrícula</label>
                          <input class="form-control form-control-sm" name="veh_num" value="{{ t_veh.get('numeroIden', t_veh.get('numeroMat','')) }}" required>
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Datos adicionales</label>
                          <input class="form-control form-control-sm" name="veh_adic" value="{{ t_veh.get('adic','') }}">
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Nro vuelo</label>
                          <input class="form-control form-control-sm" name="veh_vuelo" value="{{ t_veh.get('numeroVuelo','') }}">
                        </div>
                      </div>

                      <hr>
                      <h6 class="mt-2">Transportista</h6>
                      <div class="row g-2">
                        <div class="col-md-3">
                          <label class="form-label small">Naturaleza</label>
                          <select class="form-select form-select-sm" name="trn_nat" required>
                            <option value="1" {% if t_trn.get('tipo')|string == "1" %}selected{% endif %}>1 - Contribuyente</option>
                            <option value="2" {% if t_trn.get('tipo')|string == "2" %}selected{% endif %}>2 - No contribuyente</option>
                          </select>
                        </div>
                        <div class="col-md-5">
                          <label class="form-label small">Nombre/Razón social</label>
                          <input class="form-control form-control-sm" name="trn_nom" value="{{ t_trn.get('nombreTr','') }}" required>
                        </div>
                        <div class="col-md-4">
                          <label class="form-label small">RUC / Doc ID</label>
                          <input class="form-control form-control-sm" name="trn_num" value="{{ t_trn.get('numeroTr','') }}" required>
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Tipo doc (no contrib.)</label>
                          <select class="form-select form-select-sm" name="trn_doc_tipo">
                            <option value="">—</option>
                            <option value="1" {% if t_trn.get('tipoDocumentoTr')|string == "1" %}selected{% endif %}>1 - Cédula</option>
                            <option value="2" {% if t_trn.get('tipoDocumentoTr')|string == "2" %}selected{% endif %}>2 - Pasaporte</option>
                            <option value="3" {% if t_trn.get('tipoDocumentoTr')|string == "3" %}selected{% endif %}>3 - Cédula extranjera</option>
                            <option value="4" {% if t_trn.get('tipoDocumentoTr')|string == "4" %}selected{% endif %}>4 - Carnet residencia</option>
                          </select>
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Nacionalidad</label>
                          <input class="form-control form-control-sm" name="trn_nac" value="{{ t_trn.get('nacionalidad','') }}">
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Chofer doc</label>
                          <input class="form-control form-control-sm" name="trn_ch_doc" value="{{ t_trn.get('numeroCh','') }}" required>
                        </div>
                        <div class="col-md-3">
                          <label class="form-label small">Chofer nombre</label>
                          <input class="form-control form-control-sm" name="trn_ch_nom" value="{{ t_trn.get('nombreCh','') }}" required>
                        </div>
                        <div class="col-md-6">
                          <label class="form-label small">Domicilio fiscal</label>
                          <input class="form-control form-control-sm" name="trn_dom" value="{{ t_trn.get('direccionTr','') }}">
                        </div>
                        <div class="col-md-6">
                          <label class="form-label small">Dirección chofer</label>
                          <input class="form-control form-control-sm" name="trn_dir_ch" value="{{ t_trn.get('direccionCh','') }}">
                        </div>
                      </div>
                      <button class="btn btn-sm btn-outline-primary mt-3" type="submit">Guardar transporte</button>
                    </form>
                    <div class="small text-muted mt-2">
                      Nota: departamento/ciudad se completan con la planilla geográfica. Distrito es opcional.
                    </div>
                  </div>
                </div>
                {% endif %}
                <form method="post" action="{{ url_for('invoice_emit', invoice_id=inv.id) }}" class="d-flex gap-2 flex-wrap align-items-center">
                  <select class="form-select form-select-sm" name="env" style="max-width: 140px;">
                    <option value="prod" {% if default_env=="prod" %}selected{% endif %}>PROD</option>
                    <option value="test" {% if default_env=="test" %}selected{% endif %}>TEST</option>
                  </select>
                  <div class="form-check form-check-inline">
                    <input class="form-check-input" type="checkbox" name="confirm_emit" value="YES" id="confirm-emit-{{inv.id}}">
                    <label class="form-check-label small" for="confirm-emit-{{inv.id}}">Confirmo emisión PROD</label>
                  </div>
                  <button class="btn btn-sm btn-success" type="submit">Emitir ahora</button>
                </form>
                <form method="post" action="{{ url_for('invoice_enqueue', invoice_id=inv.id) }}" class="d-flex gap-2 flex-wrap align-items-center mt-2">
                  <select class="form-select form-select-sm" name="env" style="max-width: 140px;">
                    <option value="prod" {% if default_env=="prod" %}selected{% endif %}>PROD</option>
                    <option value="test" {% if default_env=="test" %}selected{% endif %}>TEST</option>
                  </select>
                  <div class="form-check form-check-inline">
                    <input class="form-check-input" type="checkbox" name="confirm_emit" value="YES" id="confirm-queue-{{inv.id}}">
                    <label class="form-check-label small" for="confirm-queue-{{inv.id}}">Confirmo emisión PROD</label>
                  </div>
                  <button class="btn btn-sm btn-outline-success" type="submit">Encolar</button>
                </form>
                <div class="text-muted small mt-2">
                  Requiere: `SIFEN_SIGN_P12_PATH`, `SIFEN_SIGN_P12_PASSWORD`, `SIFEN_CSC` y SMTP (`SMTP_HOST`, `SMTP_USER`, `SMTP_PASS`, `MAIL_FROM`).
                </div>

                <hr>
                <h6>Eventos SIFEN (Cancelación / Inutilización)</h6>
                <div class="small text-muted mb-1">
                  CDC: <span class="mono">{{ cdc or "—" }}</span>
                </div>
                <div class="small mb-2">
                  Último evento: <span class="mono">{{ inv.last_event_type or "—" }}</span><br>
                  Evento ID: <span class="mono">{{ inv.last_event_id or "—" }}</span><br>
                  Fecha evento: <span class="mono">{{ inv.last_event_at or "—" }}</span><br>
                  Estado evento: <span class="mono">{{ inv.last_event_est or "—" }}</span><br>
                  Prot. evento: <span class="mono">{{ inv.last_event_prot_aut or "—" }}</span><br>
                  Código evento: <span class="mono">{{ inv.last_event_code or "—" }}</span><br>
                  Mensaje evento: {{ inv.last_event_msg or "—" }}<br>
                  Artifacts evento: <span class="mono">{{ inv.last_event_artifacts_dir or "—" }}</span>
                </div>

                <form method="post" action="{{ url_for('invoice_cancel', invoice_id=inv.id) }}" class="d-flex gap-2 flex-wrap align-items-center">
                  <select class="form-select form-select-sm" name="env" style="max-width: 140px;">
                    <option value="prod" {% if default_env=="prod" %}selected{% endif %}>PROD</option>
                    <option value="test" {% if default_env=="test" %}selected{% endif %}>TEST</option>
                  </select>
                  <div class="form-check form-check-inline">
                    <input class="form-check-input" type="checkbox" name="confirm_emit" value="YES" id="confirm-cancel-{{inv.id}}">
                    <label class="form-check-label small" for="confirm-cancel-{{inv.id}}">Confirmo evento PROD</label>
                  </div>
                  <select class="form-select form-select-sm" name="motivo_preset" style="max-width: 240px;">
                    <option value="">Motivo sugerido…</option>
                    {% for m in event_motivos %}
                      <option value="{{ m }}">{{ m }}</option>
                    {% endfor %}
                  </select>
                  <input class="form-control form-control-sm" name="motivo" style="min-width: 260px;" placeholder="Motivo cancelación (5-500)">
                  <button class="btn btn-sm btn-danger" type="submit">Cancelar</button>
                </form>

                <form method="post" action="{{ url_for('invoice_inutil', invoice_id=inv.id) }}" class="mt-2">
                  <div class="row g-2 align-items-end">
                    <div class="col-6 col-md-3">
                      <label class="form-label small">Timbrado</label>
                      <input class="form-control form-control-sm mono" name="dNumTim" value="{{ inutil_defaults.get('dNumTim','') }}" placeholder="18578288" required>
                    </div>
                    <div class="col-3 col-md-2">
                      <label class="form-label small">Est</label>
                      <input class="form-control form-control-sm mono" name="dEst" value="{{ inutil_defaults.get('dEst','') }}" placeholder="001" required>
                    </div>
                    <div class="col-3 col-md-2">
                      <label class="form-label small">Pto Exp</label>
                      <input class="form-control form-control-sm mono" name="dPunExp" value="{{ inutil_defaults.get('dPunExp','') }}" placeholder="001" required>
                    </div>
                    <div class="col-6 col-md-2">
                      <label class="form-label small">N° Ini</label>
                      <input class="form-control form-control-sm mono" name="dNumIn" value="{{ inutil_defaults.get('dNumDoc','') }}" placeholder="0000001" required>
                    </div>
                    <div class="col-6 col-md-2">
                      <label class="form-label small">N° Fin</label>
                      <input class="form-control form-control-sm mono" name="dNumFin" value="{{ inutil_defaults.get('dNumDoc','') }}" placeholder="0000001" required>
                    </div>
                    <div class="col-4 col-md-1">
                      <label class="form-label small">TiDE</label>
                      <input class="form-control form-control-sm mono" name="iTiDE" value="{{ inutil_defaults.get('iTiDE','1') }}" placeholder="1" required>
                    </div>
                  </div>
                  <div class="row g-2 align-items-end mt-1">
                    <div class="col-12 col-md-6">
                      <label class="form-label small">Motivo inutilización (5-500)</label>
                      <input class="form-control form-control-sm" name="motivo" placeholder="Motivo inutilización">
                    </div>
                    <div class="col-12 col-md-6">
                      <label class="form-label small">Motivo sugerido</label>
                      <select class="form-select form-select-sm" name="motivo_preset">
                        <option value="">Seleccionar…</option>
                        {% for m in event_motivos %}
                          <option value="{{ m }}">{{ m }}</option>
                        {% endfor %}
                      </select>
                    </div>
                    <div class="col-6 col-md-2">
                      <label class="form-label small">Ambiente</label>
                      <select class="form-select form-select-sm" name="env">
                        <option value="prod" {% if default_env=="prod" %}selected{% endif %}>PROD</option>
                        <option value="test" {% if default_env=="test" %}selected{% endif %}>TEST</option>
                      </select>
                    </div>
                    <div class="col-6 col-md-2">
                      <div class="form-check mt-3">
                        <input class="form-check-input" type="checkbox" name="confirm_emit" value="YES" id="confirm-inutil-{{inv.id}}">
                        <label class="form-check-label small" for="confirm-inutil-{{inv.id}}">Confirmo evento PROD</label>
                      </div>
                    </div>
                    <div class="col-12 col-md-2">
                      <button class="btn btn-sm btn-outline-danger w-100" type="submit">Inutilizar</button>
                    </div>
                  </div>
                </form>

                <hr>
                <h6>Integración minisender (MVP)</h6>
                <form method="post" action="{{ url_for('invoice_set_xml', invoice_id=inv.id) }}" class="mb-2">
                  <label class="form-label small text-muted">source_xml_path (XML firmado)</label>
                  <input class="form-control form-control-sm mono" name="source_xml_path" value="{{ inv.source_xml_path or '' }}" placeholder="/path/a/signed_rde.xml">
                  <button class="btn btn-sm btn-outline-secondary mt-2" type="submit">Guardar XML path</button>
                </form>
                {% if inv.source_xml_path %}
                  <div class="text-muted small mb-2">source_xml_path: <span class="mono">{{ inv.source_xml_path }}</span></div>
                {% endif %}

                <div class="d-flex gap-2 flex-wrap">
                  <form method="post" action="{{ url_for('invoice_send_test', invoice_id=inv.id) }}">
                    <button class="btn btn-sm btn-primary" type="submit">Enviar a SIFEN (TEST)</button>
                  </form>
                  <form method="post" action="{{ url_for('invoice_consult_test', invoice_id=inv.id) }}">
                    <button class="btn btn-sm btn-outline-primary" type="submit">Consultar estado (TEST)</button>
                  </form>
                </div>
                <form method="post" action="{{ url_for('invoice_consult_cdc', invoice_id=inv.id) }}" class="d-flex gap-2 flex-wrap align-items-center mt-2">
                  <select class="form-select form-select-sm" name="env" style="max-width: 140px;">
                    <option value="prod" {% if default_env=="prod" %}selected{% endif %}>PROD</option>
                    <option value="test" {% if default_env=="test" %}selected{% endif %}>TEST</option>
                  </select>
                  <button class="btn btn-sm btn-outline-primary" type="submit">Consultar DE (CDC)</button>
                </form>
                <div class="text-muted small mt-1">
                  Usa el CDC del XML firmado (source_xml_path).
                </div>
                <div class="mt-2">
                  <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('invoice_preview_pdf', invoice_id=inv.id) }}" target="_blank">Ver PDF (preview)</a>
                </div>

                <div class="text-muted small mt-2">
                  last_artifacts_dir: <span class="mono">{{ inv.last_artifacts_dir or "—" }}</span>
                </div>
                <div class="text-muted small mt-2">
                  pdf_path: <span class="mono">{{ inv.pdf_path or "—" }}</span><br>
                  email_status: <span class="mono">{{ inv.email_status or "—" }}</span>
                </div>
                {% if inv.customer_email %}
                <form method="post" action="{{ url_for('invoice_send_email', invoice_id=inv.id) }}" class="mt-2">
                  <button class="btn btn-sm btn-outline-secondary" type="submit">Reenviar email</button>
                </form>
                {% endif %}
</div>
            </div>
          </div>

          <div class="col-lg-6">
            <div class="card">
              <div class="card-body">
                <h6>Totales</h6>
                <div class="display-6 mono">{{ "{:,}".format(inv.total).replace(",", ".") }} {{inv.currency}}</div>
              </div>
            </div>
            <div class="card mt-3">
              <div class="card-body">
                <h6>Factura (SIFEN)</h6>
                {% if inv.status == "CONFIRMED_OK" %}
                  <iframe src="{{ url_for('invoice_preview_pdf', invoice_id=inv.id) }}" style="width: 100%; height: 640px; border: 1px solid #e0e0e0; border-radius: 6px;"></iframe>
                  <div class="mt-2 small">
                    <a href="{{ url_for('invoice_preview_pdf', invoice_id=inv.id) }}" target="_blank">Abrir PDF en nueva pestaña</a>
                  </div>
                {% else %}
                  <div class="p-3 rounded" style="background:#f2f2f2; color:#666;">
                    Factura todavía no confirmada en la SIFEN.
                  </div>
                {% endif %}
              </div>
            </div>
          </div>

          <div class="col-12">
            <div class="card">
              <div class="card-body">
                <h6>Detalle</h6>
                <div class="table-responsive">
                  <table class="table table-sm">
                    <thead>
                      <tr>
                        <th>Descripción</th>
                        <th class="nowrap">Cant</th>
                        <th class="nowrap">P. Unit</th>
                        <th class="nowrap">Total</th>
                      </tr>
                    </thead>
                    <tbody>
                      {% for l in lines %}
                        <tr>
                          <td>{{l.description}}</td>
                          <td class="mono">{{l.qty}}</td>
                          <td class="mono">{{ "{:,}".format(l.price_unit).replace(",", ".") }}</td>
                          <td class="mono">{{ "{:,}".format(l.line_total).replace(",", ".") }}</td>
                        </tr>
                      {% endfor %}
                    </tbody>
                  </table>
                </div>
                <div class="text-muted small">
                  Próximo: agregar botón “Encolar”, y cuando tengamos minisender integrado, guardar artifacts por factura/job.
                </div>
              </div>
            </div>
          </div>
        </div>
        """,
        inv=inv,
        lines=lines,
        badge=badge,
        doc_type_label=doc_type_label,
        cdc=cdc,
        inutil_defaults=inutil_defaults,
        extra_prefill=extra_prefill,
        transport=transport,
        t_sal=t_sal,
        t_ent=t_ent,
        t_veh=t_veh,
        t_trn=t_trn,
        trans_tipo=TRANS_TIPO_MAP,
        trans_mod=TRANS_MOD_MAP,
        resp_flete=RESP_FLETE_MAP,
        event_motivos=EVENT_MOTIVOS,
        default_env=get_setting("default_env", "prod") or "prod",
    )
    return render_template_string(BASE_HTML, title=f"Documento #{invoice_id}", db_path=DB_PATH, body=body)


@app.route("/invoice/<int:invoice_id>/set_xml", methods=["POST"])
def invoice_set_xml(invoice_id: int):
    init_db()
    con = get_db()
    xml_path = (request.form.get("source_xml_path") or "").strip()
    con.execute("UPDATE invoices SET source_xml_path=? WHERE id=?", (xml_path, invoice_id))
    con.commit()
    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

@app.route("/invoice/<int:invoice_id>/set_extra", methods=["POST"])
def invoice_set_extra(invoice_id: int):
    init_db()
    con = get_db()
    extra = (request.form.get("doc_extra_json") or "").strip()
    con.execute("UPDATE invoices SET doc_extra_json=? WHERE id=?", (extra, invoice_id))
    con.commit()
    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

@app.route("/invoice/<int:invoice_id>/set_transporte", methods=["POST"])
def invoice_set_transporte(invoice_id: int):
    init_db()
    con = get_db()
    inv = con.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    if not inv:
        abort(404)
    doc_type = normalize_doc_type(inv["doc_type"])
    if doc_type != "7":
        abort(400, "Transporte solo aplica a Remisión (iTiDE=7).")
    try:
        extra = _parse_extra_json(inv["doc_extra_json"], doc_type)
    except Exception:
        extra = _default_extra_json_for(doc_type) or {}

    def g(name: str) -> str:
        return (request.form.get(name) or "").strip()

    def set_if(d: dict, key: str, val: str) -> None:
        if val != "":
            d[key] = val

    transport = {}
    set_if(transport, "tipoTransporte", g("tr_tipo"))
    set_if(transport, "modalidad", g("tr_modalidad"))
    set_if(transport, "tipoResponsable", g("tr_resp"))
    set_if(transport, "iniFechaEstimadaTrans", g("tr_ini"))
    set_if(transport, "finFechaEstimadaTrans", g("tr_fin"))
    set_if(transport, "condNeg", g("tr_cond"))
    set_if(transport, "numManif", g("tr_manif"))
    set_if(transport, "despachoImp", g("tr_desp"))
    set_if(transport, "paisDest", g("tr_pais"))
    set_if(transport, "paisDestDesc", g("tr_pais_desc"))

    salida = {}
    set_if(salida, "direccion", g("sal_dir"))
    set_if(salida, "numCasa", g("sal_num"))
    set_if(salida, "departamento", g("sal_dep"))
    set_if(salida, "distrito", g("sal_dist"))
    set_if(salida, "ciudad", g("sal_ciu"))
    set_if(salida, "telefono", g("sal_tel"))
    set_if(salida, "comp1", g("sal_comp1"))
    set_if(salida, "comp2", g("sal_comp2"))
    if salida:
        transport["salida"] = salida

    entrega = {}
    set_if(entrega, "direccion", g("ent_dir"))
    set_if(entrega, "numCasa", g("ent_num"))
    set_if(entrega, "departamento", g("ent_dep"))
    set_if(entrega, "distrito", g("ent_dist"))
    set_if(entrega, "ciudad", g("ent_ciu"))
    set_if(entrega, "telefono", g("ent_tel"))
    set_if(entrega, "comp1", g("ent_comp1"))
    set_if(entrega, "comp2", g("ent_comp2"))
    if entrega:
        transport["entrega"] = entrega

    veh = {}
    set_if(veh, "tipo", g("veh_tipo"))
    set_if(veh, "marca", g("veh_marca"))
    set_if(veh, "documentoTipo", g("veh_doc_tipo"))
    set_if(veh, "numeroIden", g("veh_num"))
    set_if(veh, "adic", g("veh_adic"))
    set_if(veh, "numeroVuelo", g("veh_vuelo"))
    if veh:
        transport["vehiculo"] = veh

    trn = {}
    set_if(trn, "tipo", g("trn_nat"))
    set_if(trn, "nombreTr", g("trn_nom"))
    set_if(trn, "numeroTr", g("trn_num"))
    set_if(trn, "tipoDocumentoTr", g("trn_doc_tipo"))
    set_if(trn, "nacionalidad", g("trn_nac"))
    set_if(trn, "numeroCh", g("trn_ch_doc"))
    set_if(trn, "nombreCh", g("trn_ch_nom"))
    set_if(trn, "direccionTr", g("trn_dom"))
    set_if(trn, "direccionCh", g("trn_dir_ch"))
    if trn:
        transport["transportista"] = trn

    extra = extra or {}
    extra["transporte"] = [transport]
    con.execute("UPDATE invoices SET doc_extra_json=? WHERE id=?", (json.dumps(extra, ensure_ascii=False, indent=2), invoice_id))
    con.commit()
    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

@app.route("/invoice/<int:invoice_id>/emit", methods=["POST"])
def invoice_emit(invoice_id: int):
    env = (request.form.get("env") or get_setting("default_env", "prod") or "prod").strip().lower()
    if env not in ("test", "prod"):
        abort(400, "env inválido (usar test|prod)")
    confirm = (request.form.get("confirm_emit") or "").strip().upper()
    if env == "prod" and confirm != "YES":
        abort(400, "Confirmación requerida para PROD (marcá la casilla).")

    return _process_invoice_emit(invoice_id, env, async_mode=False)

@app.route("/invoice/<int:invoice_id>/enqueue", methods=["POST"])
def invoice_enqueue(invoice_id: int):
    init_db()
    env = (request.form.get("env") or get_setting("default_env", "prod") or "prod").strip().lower()
    if env not in ("test", "prod"):
        abort(400, "env inválido (usar test|prod)")
    confirm = (request.form.get("confirm_emit") or "").strip().upper()
    if env == "prod" and confirm != "YES":
        abort(400, "Confirmación requerida para PROD (marcá la casilla).")
    con = get_db()
    con.execute(
        "UPDATE invoices SET status=?, queued_at=?, sifen_env=? WHERE id=?",
        ("QUEUED", now_iso(), env, invoice_id),
    )
    con.commit()
    _enqueue_invoice(invoice_id, env)
    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

@app.route("/invoice/<int:invoice_id>/cancel", methods=["POST"])
def invoice_cancel(invoice_id: int):
    init_db()
    con = get_db()
    env = (request.form.get("env") or get_setting("default_env", "prod") or "prod").strip().lower()
    if env not in ("test", "prod"):
        abort(400, "env inválido (usar test|prod)")
    confirm = (request.form.get("confirm_emit") or "").strip().upper()
    if env == "prod" and confirm != "YES":
        abort(400, "Confirmación requerida para PROD (marcá la casilla).")

    motivo = (request.form.get("motivo") or "").strip()
    motivo_preset = (request.form.get("motivo_preset") or "").strip()
    if not motivo and motivo_preset:
        motivo = motivo_preset
    if len(motivo) < 5 or len(motivo) > 500:
        abort(400, "Motivo debe tener entre 5 y 500 caracteres.")

    inv = con.execute(
        """
        SELECT i.*, c.name AS customer_name, c.ruc AS customer_ruc, c.email AS customer_email
        FROM invoices i JOIN customers c ON c.id=i.customer_id
        WHERE i.id=?
        """,
        (invoice_id,),
    ).fetchone()
    if not inv:
        abort(404)

    cdc = _extract_cdc_from_xml_path(inv["source_xml_path"] or "")
    if not cdc:
        abort(400, "No se pudo obtener CDC desde source_xml_path. Guardá el XML firmado primero.")

    event_id = _make_event_id()
    try:
        parsed = _send_cancel_event(
            env=env,
            cdc=cdc,
            motivo=motivo,
            event_id=event_id,
            artifacts_root=_repo_root() / "artifacts",
        )
    except Exception as e:
        con.execute(
            "UPDATE invoices SET last_event_type=?, last_event_msg=?, last_event_at=? WHERE id=?",
            ("cancel", f"ERROR: {e}", now_iso(), invoice_id),
        )
        con.commit()
        abort(400, str(e))

    est = parsed.get("dEstRes") or ""
    code = parsed.get("dCodRes") or ""
    msg = (parsed.get("dMsgRes") or "").strip()
    prot_aut = parsed.get("dProtAut") or ""
    http_status = parsed.get("http_status")
    if http_status:
        msg = (msg + f" | http={http_status}").strip()

    new_status = inv["status"]
    if est.lower().startswith("aprob"):
        new_status = "CANCELLED_OK"
    elif est.lower().startswith("rech"):
        new_status = "CANCELLED_REJECTED"

    con.execute(
        """
        UPDATE invoices SET
            status=?,
            last_event_type=?,
            last_event_id=?,
            last_event_est=?,
            last_event_code=?,
            last_event_msg=?,
            last_event_prot_aut=?,
            last_event_at=?,
            last_event_artifacts_dir=?
        WHERE id=?
        """,
        (
            new_status,
            "cancel",
            event_id,
            est or None,
            code or None,
            msg or None,
            prot_aut or None,
            now_iso(),
            parsed.get("artifacts_dir") or None,
            invoice_id,
        ),
    )
    con.commit()
    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

@app.route("/invoice/<int:invoice_id>/inutil", methods=["POST"])
def invoice_inutil(invoice_id: int):
    init_db()
    con = get_db()
    env = (request.form.get("env") or get_setting("default_env", "prod") or "prod").strip().lower()
    if env not in ("test", "prod"):
        abort(400, "env inválido (usar test|prod)")
    confirm = (request.form.get("confirm_emit") or "").strip().upper()
    if env == "prod" and confirm != "YES":
        abort(400, "Confirmación requerida para PROD (marcá la casilla).")

    motivo = (request.form.get("motivo") or "").strip()
    motivo_preset = (request.form.get("motivo_preset") or "").strip()
    if not motivo and motivo_preset:
        motivo = motivo_preset
    if len(motivo) < 5 or len(motivo) > 500:
        abort(400, "Motivo debe tener entre 5 y 500 caracteres.")

    timbrado = _zfill_digits(request.form.get("dNumTim"), 8)
    est = _zfill_digits(request.form.get("dEst"), 3)
    punexp = _zfill_digits(request.form.get("dPunExp"), 3)
    num_ini = _zfill_digits(request.form.get("dNumIn"), 7)
    num_fin = _zfill_digits(request.form.get("dNumFin"), 7)
    tipo_doc = _zfill_digits(request.form.get("iTiDE"), 2).lstrip("0") or "1"

    if not all([timbrado, est, punexp, num_ini, num_fin, tipo_doc]):
        abort(400, "Datos incompletos para inutilización (timbrado/est/punexp/rango/tipo).")

    inv = con.execute(
        """
        SELECT i.*, c.name AS customer_name, c.ruc AS customer_ruc, c.email AS customer_email
        FROM invoices i JOIN customers c ON c.id=i.customer_id
        WHERE i.id=?
        """,
        (invoice_id,),
    ).fetchone()
    if not inv:
        abort(404)

    event_id = _make_event_id()
    try:
        parsed = _send_inutil_event(
            env=env,
            timbrado=timbrado,
            est=est,
            punexp=punexp,
            num_ini=num_ini,
            num_fin=num_fin,
            tipo_doc=tipo_doc,
            motivo=motivo,
            event_id=event_id,
            artifacts_root=_repo_root() / "artifacts",
        )
    except Exception as e:
        con.execute(
            "UPDATE invoices SET last_event_type=?, last_event_msg=?, last_event_at=? WHERE id=?",
            ("inutil", f"ERROR: {e}", now_iso(), invoice_id),
        )
        con.commit()
        abort(400, str(e))

    est_res = parsed.get("dEstRes") or ""
    code = parsed.get("dCodRes") or ""
    msg = (parsed.get("dMsgRes") or "").strip()
    prot_aut = parsed.get("dProtAut") or ""
    http_status = parsed.get("http_status")
    if http_status:
        msg = (msg + f" | http={http_status}").strip()

    new_status = inv["status"]
    if est_res.lower().startswith("aprob"):
        new_status = "INUTIL_OK"
    elif est_res.lower().startswith("rech"):
        new_status = "INUTIL_REJECTED"

    con.execute(
        """
        UPDATE invoices SET
            status=?,
            last_event_type=?,
            last_event_id=?,
            last_event_est=?,
            last_event_code=?,
            last_event_msg=?,
            last_event_prot_aut=?,
            last_event_at=?,
            last_event_artifacts_dir=?
        WHERE id=?
        """,
        (
            new_status,
            "inutil",
            event_id,
            est_res or None,
            code or None,
            msg or None,
            prot_aut or None,
            now_iso(),
            parsed.get("artifacts_dir") or None,
            invoice_id,
        ),
    )
    con.commit()
    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

def _process_invoice_emit(invoice_id: int, env: str, async_mode: bool) -> str:
    init_db()
    con = get_db()

    inv = con.execute(
        """
        SELECT i.*, c.name AS customer_name, c.ruc AS customer_ruc, c.email AS customer_email
        FROM invoices i JOIN customers c ON c.id=i.customer_id
        WHERE i.id=?
        """,
        (invoice_id,),
    ).fetchone()
    if not inv:
        abort(404)

    con.execute("UPDATE invoices SET sifen_env=? WHERE id=?", (env, invoice_id))
    con.commit()

    # si ya fue procesado por SIFEN, no reenviar
    if inv["status"] in ("CONFIRMED_OK", "CONFIRMED_REJECTED"):
        abort(400, "Este documento ya fue procesado por SIFEN. Creá una nueva factura para emitir otro.")

    doc_type = normalize_doc_type(inv["doc_type"])
    try:
        extra_json = _parse_extra_json(inv["doc_extra_json"], doc_type)
    except Exception as e:
        abort(400, str(e))
    errors = _validate_doc_extra(doc_type, extra_json)
    if errors:
        abort(400, "Errores de validación:\n- " + "\n- ".join(errors))
    template_path = _template_for_doc_type(doc_type)
    if not template_path or not Path(template_path).exists():
        abort(400, f"Plantilla no configurada para {doc_type_label(doc_type)}. Configurala en /settings.")

    # Si ya existe XML firmado, reutilizarlo para no cambiar CDC
    rel_signed = resolve_existing_xml_path(inv["source_xml_path"] or "")
    signed_qr_text = None
    build = None
    issue_dt = None
    if rel_signed:
        signed_path = Path(rel_signed)
        if not signed_path.is_absolute():
            signed_path = _repo_root() / signed_path
    else:
        signed_path = None

    if signed_path and signed_path.exists():
        signed_qr_text = signed_path.read_text(encoding="utf-8")
        meta = _backfill_doc_info_from_xml(con, inv, invoice_id, signed_qr_text)
        issue_dt = _parse_iso_dt(meta.get("feemi")) or _ensure_signed_at(con, inv, invoice_id)

        lines = con.execute(
            "SELECT * FROM invoice_lines WHERE invoice_id=? ORDER BY id ASC",
            (invoice_id,),
        ).fetchall()
        items_for_pdf = []
        for line in lines:
            items_for_pdf.append({
                "descripcion": line["description"],
                "cantidad": line["qty"],
                "precio_unit": line["price_unit"],
                "iva": "10",
                "total": line["line_total"],
            })
        build = {
            "items_for_pdf": items_for_pdf,
            "cdc": meta.get("cdc") or "SIN_CDC",
            "dnumdoc": meta.get("dnumdoc") or _ensure_doc_number(con, inv, invoice_id),
            "feemi": meta.get("feemi") or (inv["issued_at"] or inv["created_at"]),
            "total_str": meta.get("total") or str(inv["total"] or 0),
            "iva_total_str": meta.get("tot_iva") or "",
        }
    else:
        # elegir número de documento (persistente)
        dnumdoc = _ensure_doc_number(con, inv, invoice_id)
        issue_dt = _ensure_signed_at(con, inv, invoice_id)

        # generar XML base desde plantilla
        customer_payload = {"name": inv["customer_name"], "ruc": inv["customer_ruc"]}
        lines = con.execute(
            "SELECT * FROM invoice_lines WHERE invoice_id=? ORDER BY id ASC",
            (invoice_id,),
        ).fetchall()
        if not lines:
            abort(400, "La factura no tiene líneas.")

        codseg = _ensure_codseg(con, inv, invoice_id)
        est = (inv["establishment"] or "").strip() if "establishment" in inv.keys() else ""
        pun = (inv["point_exp"] or "").strip() if "point_exp" in inv.keys() else ""
        build = _build_invoice_xml_from_template(
            template_path=template_path,
            invoice_id=invoice_id,
            customer=customer_payload,
            lines=lines,
            doc_number=dnumdoc,
            doc_type=doc_type,
            extra_json=extra_json,
            issue_dt=issue_dt,
            codseg=codseg,
            establishment=est,
            point_exp=pun,
        )

    if not rel_signed:
        repo_root = _repo_root()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = repo_root / "artifacts" / f"webui_emit_{invoice_id}_{ts}"
        base_dir.mkdir(parents=True, exist_ok=True)

        in_path = base_dir / f"rde_input_{build['dnumdoc']}.xml"
        in_path.write_bytes(build["xml_bytes"])

        # firma
        p12_path = os.getenv("SIFEN_SIGN_P12_PATH") or os.getenv("SIFEN_P12_PATH") or os.getenv("SIFEN_CERT_PATH")
        p12_password = os.getenv("SIFEN_SIGN_P12_PASSWORD") or os.getenv("SIFEN_P12_PASSWORD") or os.getenv("SIFEN_CERT_PASSWORD")
        if not p12_path or not p12_password:
            abort(400, "Faltan SIFEN_SIGN_P12_PATH/SIFEN_SIGN_P12_PASSWORD (o equivalentes) para firmar.")

        signed_bytes = sign_de_with_p12(build["xml_bytes"], p12_path, p12_password)
        signed_path = base_dir / f"rde_signed_{build['dnumdoc']}.xml"
        signed_path.write_bytes(signed_bytes)

        # QR
        csc = (os.getenv("SIFEN_CSC") or "").strip()
        csc_id = (os.getenv("SIFEN_CSC_ID") or "0001").strip()
        if not csc:
            abort(400, "Falta SIFEN_CSC para generar QR.")

        signed_qr_text, qr_debug = _update_qr_in_signed_xml(signed_bytes.decode("utf-8"), csc, csc_id)
        signed_qr_path = base_dir / f"rde_signed_qr_{build['dnumdoc']}.xml"
        signed_qr_path.write_text(signed_qr_text, encoding="utf-8")
        (base_dir / f"qr_debug_{build['dnumdoc']}.txt").write_text(
            "\n".join([f"{k}={v}" for k, v in qr_debug.items()]) + "\n",
            encoding="utf-8",
        )

        rel_signed = resolve_existing_xml_path(str(signed_qr_path))
        con.execute(
            "UPDATE invoices SET issued_at=COALESCE(issued_at,?), source_xml_path=? WHERE id=?",
            (issue_dt.isoformat(timespec="seconds"), rel_signed, invoice_id),
        )
        con.commit()

    # enviar a SIFEN
    repo_root_path = _repo_root()
    venv_py = str(repo_root_path / ".venv" / "bin" / "python")
    args = [
        venv_py, "-m", "sifen_minisender", "send",
        "--env", env,
        "--artifacts-root", str(repo_root_path / "artifacts"),
        rel_signed,
    ]

    env_used = os.environ.copy()
    if env == "prod":
        env_used["SIFEN_CONFIRM_PROD"] = "YES"

    code, out, err = run_minisender(args, cwd=str(repo_root_path), env=env_used)
    parsed = parse_minisender_response(out)
    art_dir_raw = detect_artifacts_dir(parsed, out, env_used)
    last_art_dir = normalize_artifacts_dir(art_dir_raw) or ""

    dCodRes = parsed.get("dCodRes")
    dMsgRes = parsed.get("dMsgRes")
    prot = parsed.get("dProtConsLote")

    new_status = inv["status"]
    sent_at = None
    if dCodRes == "0300" and prot:
        new_status = "SENT"
        sent_at = now_iso()

    prot_store = prot or inv["sifen_prot_cons_lote"]
    con.execute(
        "UPDATE invoices SET status=?, sent_at=COALESCE(sent_at,?), sifen_prot_cons_lote=?, last_sifen_code=?, last_sifen_msg=?, last_artifacts_dir=COALESCE(?, last_artifacts_dir), source_xml_path=COALESCE(?, source_xml_path) WHERE id=?",
        (new_status, sent_at, prot_store, dCodRes, dMsgRes, last_art_dir or None, rel_signed or None, invoice_id)
    )
    con.commit()

    if code != 0:
        con.execute(
            "UPDATE invoices SET last_sifen_msg=? WHERE id=?",
            ((dMsgRes or "") + f" | minisender_exit={code} | stderr={err[-500:]}", invoice_id)
        )
        con.commit()
        return redirect(url_for("invoice_detail", invoice_id=invoice_id))

    # consultar estado
    response_xml = None
    source_xml_text = None
    if prot:
        new_status = _consult_lote_and_update(
            invoice_id=invoice_id,
            env=env,
            prot=prot,
            rel_signed=rel_signed,
            prefer_art_dir=last_art_dir,
            attempts=3,
            sleep_between=2,
        )
        if new_status == "CONFIRMING":
            _schedule_lote_poll(invoice_id, env, prot, rel_signed=rel_signed)

        inv_latest = con.execute(
            "SELECT last_artifacts_dir FROM invoices WHERE id=?",
            (invoice_id,),
        ).fetchone()
        art_dir = normalize_artifacts_dir(inv_latest["last_artifacts_dir"] or "") if inv_latest else ""
        if art_dir:
            resp_path = Path(art_dir) / "soap_last_response.xml"
            if resp_path.exists():
                response_xml = resp_path.read_text(encoding="utf-8")

    # enviar email con PDF si aprobado
    if inv["customer_email"] and (new_status == "CONFIRMED_OK"):
        try:
            issuer = _build_issuer_from_xml_text(signed_qr_text) or _build_issuer_from_template(template_path)
            pdf_path = base_dir / f"invoice_{invoice_id}.pdf"
            payload = _build_pdf_payload(
                invoice=inv,
                items_for_pdf=build["items_for_pdf"],
                response_xml=response_xml,
                cdc=build["cdc"],
                dnumdoc=build["dnumdoc"],
                feemi=build["feemi"],
                total_str=build["total_str"],
                iva_total_str=build["iva_total_str"],
                source_xml_text=signed_qr_text,
            )
            render_invoice_pdf(data=payload, issuer=issuer, out_path=pdf_path)
            subject = f"Factura #{invoice_id} ({build['dnumdoc']})"
            body = "Adjuntamos su factura electrónica.\n\nGracias."
            _send_email_with_pdf(inv["customer_email"], subject, body, pdf_path)
            con.execute(
                "UPDATE invoices SET last_sifen_msg=?, pdf_path=?, email_status=? WHERE id=?",
                ((inv["last_sifen_msg"] or "") + " | Email enviado", str(pdf_path), "SENT", invoice_id)
            )
            con.commit()
        except Exception as exc:
            con.execute(
                "UPDATE invoices SET last_sifen_msg=?, email_status=? WHERE id=?",
                ((inv["last_sifen_msg"] or "") + f" | Email error: {exc}", "ERROR", invoice_id)
            )
            con.commit()

    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

def _generate_signed_xml_for_invoice(
    *,
    invoice_id: int,
    inv: sqlite3.Row,
    con: sqlite3.Connection,
    doc_type: str,
    extra_json: dict,
    template_path: str,
) -> tuple[dict, str, str]:
    # elegir número y fecha de emisión persistentes
    dnumdoc = _ensure_doc_number(con, inv, invoice_id)
    issue_dt = _ensure_signed_at(con, inv, invoice_id)

    customer_payload = {"name": inv["customer_name"], "ruc": inv["customer_ruc"]}
    lines = con.execute(
        "SELECT * FROM invoice_lines WHERE invoice_id=? ORDER BY id ASC",
        (invoice_id,),
    ).fetchall()
    if not lines:
        raise RuntimeError("La factura no tiene líneas.")

    codseg = _ensure_codseg(con, inv, invoice_id)
    est = (inv["establishment"] or "").strip() if "establishment" in inv.keys() else ""
    pun = (inv["point_exp"] or "").strip() if "point_exp" in inv.keys() else ""
    build = _build_invoice_xml_from_template(
        template_path=template_path,
        invoice_id=invoice_id,
        customer=customer_payload,
        lines=lines,
        doc_number=dnumdoc,
        doc_type=doc_type,
        extra_json=extra_json,
        issue_dt=issue_dt,
        codseg=codseg,
        establishment=est,
        point_exp=pun,
    )

    p12_path = os.getenv("SIFEN_SIGN_P12_PATH") or os.getenv("SIFEN_P12_PATH") or os.getenv("SIFEN_CERT_PATH")
    p12_password = os.getenv("SIFEN_SIGN_P12_PASSWORD") or os.getenv("SIFEN_P12_PASSWORD") or os.getenv("SIFEN_CERT_PASSWORD")
    if not p12_path or not p12_password:
        raise RuntimeError("Faltan SIFEN_SIGN_P12_PATH/SIFEN_SIGN_P12_PASSWORD (o equivalentes) para firmar.")

    csc = (os.getenv("SIFEN_CSC") or "").strip()
    csc_id = (os.getenv("SIFEN_CSC_ID") or "0001").strip()
    if not csc:
        raise RuntimeError("Falta SIFEN_CSC para generar QR.")

    repo_root = _repo_root()
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = repo_root / "artifacts" / f"webui_sign_{invoice_id}_{ts}"
    base_dir.mkdir(parents=True, exist_ok=True)

    in_path = base_dir / f"rde_input_{dnumdoc}.xml"
    in_path.write_bytes(build["xml_bytes"])

    signed_bytes = sign_de_with_p12(build["xml_bytes"], p12_path, p12_password)
    signed_path = base_dir / f"rde_signed_{dnumdoc}.xml"
    signed_path.write_bytes(signed_bytes)

    signed_qr_text, qr_debug = _update_qr_in_signed_xml(signed_bytes.decode("utf-8"), csc, csc_id)
    signed_qr_path = base_dir / f"rde_signed_qr_{dnumdoc}.xml"
    signed_qr_path.write_text(signed_qr_text, encoding="utf-8")
    (base_dir / f"qr_debug_{dnumdoc}.txt").write_text(
        "\n".join([f"{k}={v}" for k, v in qr_debug.items()]) + "\n",
        encoding="utf-8",
    )

    rel_signed = resolve_existing_xml_path(str(signed_qr_path))
    new_status = inv["status"]
    if new_status == "DRAFT":
        new_status = "READY"
    con.execute(
        "UPDATE invoices SET status=?, issued_at=COALESCE(issued_at,?), source_xml_path=? WHERE id=?",
        (new_status, issue_dt.isoformat(timespec="seconds"), rel_signed, invoice_id),
    )
    con.commit()

    return build, signed_qr_text, rel_signed

@app.route("/invoice/<int:invoice_id>/send_test", methods=["POST"])
def invoice_send_test(invoice_id: int):
    init_db()
    con = get_db()
    inv = con.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    if not inv:
        abort(404)

    repo_root_path = _repo_root()
    xml_path = resolve_existing_xml_path(inv["source_xml_path"] or "")
    if not xml_path:
        last_art_dir = normalize_artifacts_dir(inv["last_artifacts_dir"] or "")
        if last_art_dir:
            xml_path = resolve_source_xml_path(last_art_dir)
            if xml_path:
                con.execute("UPDATE invoices SET source_xml_path=? WHERE id=?", (xml_path, invoice_id))
                con.commit()
    if not xml_path:
        artifacts_root = repo_root_path / "artifacts"
        for cand in list_recent_artifacts_dirs(artifacts_root):
            xml_path = resolve_source_xml_path(str(cand))
            if xml_path:
                con.execute("UPDATE invoices SET source_xml_path=? WHERE id=?", (xml_path, invoice_id))
                con.commit()
                break
    if not xml_path:
        xml_path = resolve_existing_xml_path(get_setting("default_signed_xml_path") or "")
        if xml_path:
            con.execute("UPDATE invoices SET source_xml_path=? WHERE id=?", (xml_path, invoice_id))
            con.commit()
    if not xml_path:
        abort(400, "No pude resolver automáticamente el XML firmado. Abrí /invoice/<id> y seteá source_xml_path, o asegurate de tener artifacts con DE_TAL_CUAL_TRANSMITIDO.xml.")
    # Ejecutar minisender desde repo raíz (un nivel arriba de webui)
    repo_root = str(repo_root_path)
    venv_py = str(repo_root_path / ".venv" / "bin" / "python")
    args = [venv_py, "-m", "sifen_minisender", "send",
        "--env", "test",
        xml_path]

    env_used = os.environ.copy()
    code, out, err = run_minisender(args, cwd=repo_root, env=env_used)
    parsed = parse_minisender_response(out)

    art_dir_raw = detect_artifacts_dir(parsed, out, env_used)
    last_art_dir = normalize_artifacts_dir(art_dir_raw) or ""
    source_xml_match = resolve_source_xml_path(last_art_dir)
    # Guardar resultado
    dCodRes = parsed.get("dCodRes")
    dMsgRes = parsed.get("dMsgRes")
    prot = parsed.get("dProtConsLote")

    new_status = inv["status"]
    sent_at = None
    if dCodRes == "0300" and prot:
        new_status = "SENT"
        sent_at = now_iso()

    prot_store = prot or inv["sifen_prot_cons_lote"]
    con.execute(
        "UPDATE invoices SET status=?, sent_at=COALESCE(sent_at,?), sifen_env=?, sifen_prot_cons_lote=?, last_sifen_code=?, last_sifen_msg=?, last_artifacts_dir=COALESCE(?, last_artifacts_dir), source_xml_path=COALESCE(?, source_xml_path) WHERE id=?",
        (new_status, sent_at, "test", prot_store, dCodRes, dMsgRes, last_art_dir or None, source_xml_match or None, invoice_id)
    )
    con.commit()

    if code != 0:
        # dejamos evidencia en last_sifen_msg
        con.execute(
            "UPDATE invoices SET last_sifen_msg=? WHERE id=?",
            ((dMsgRes or "") + f" | minisender_exit={code} | stderr={err[-500:]}", invoice_id)
        )
        con.commit()

    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

@app.route("/invoice/<int:invoice_id>/consult_test", methods=["POST"])
def invoice_consult_test(invoice_id: int):
    init_db()
    con = get_db()
    inv = con.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    if not inv:
        abort(404)

    con.execute("UPDATE invoices SET sifen_env=? WHERE id=?", ("test", invoice_id))
    con.commit()

    prot = (inv["sifen_prot_cons_lote"] or "").strip()
    if not prot:
        abort(400, "No hay dProtConsLote para consultar.")

    new_status = _consult_lote_and_update(
        invoice_id=invoice_id,
        env="test",
        prot=prot,
        attempts=1,
        sleep_between=0,
    )
    if new_status == "CONFIRMING":
        _schedule_lote_poll(invoice_id, "test", prot)

    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

@app.route("/invoice/<int:invoice_id>/consult_cdc", methods=["POST"])
def invoice_consult_cdc(invoice_id: int):
    init_db()
    con = get_db()
    inv = con.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    if not inv:
        abort(404)

    cdc = _extract_cdc_from_xml_path(inv["source_xml_path"] or "")
    if not cdc:
        abort(400, "No se pudo obtener CDC desde source_xml_path. Guardá el XML firmado primero.")

    env = (request.form.get("env") or get_setting("default_env", "prod") or "prod").strip().lower()
    if env not in ("test", "prod"):
        env = "prod"

    client = None
    try:
        cfg = get_sifen_config(env=env)
        client = SoapClient(cfg)
        result = client.consulta_de_por_cdc_raw(cdc, dump_http=False)
    except Exception as e:
        con.execute(
            "UPDATE invoices SET last_sifen_msg=? WHERE id=?",
            (f"ERROR consulta CDC: {e}", invoice_id),
        )
        con.commit()
        abort(400, str(e))
    finally:
        try:
            if client:
                client.close()
        except Exception:
            pass

    raw_xml = result.get("raw_xml") or ""
    parsed = _parse_consult_de_response(raw_xml)
    dCodRes = parsed.get("dCodRes") or ""
    dMsgRes = (parsed.get("dMsgRes") or "").strip()
    prot_aut = parsed.get("dProtAut") or ""
    http_status = result.get("http_status")
    if http_status:
        dMsgRes = (dMsgRes + f" | http={http_status}").strip()

    est = ""
    if dCodRes == "0422":
        est = "CDC encontrado"

    con.execute(
        "UPDATE invoices SET sifen_env=?, last_sifen_code=?, last_sifen_msg=?, last_sifen_prot_aut=COALESCE(?, last_sifen_prot_aut), last_sifen_est=COALESCE(?, last_sifen_est) WHERE id=?",
        (env, dCodRes or None, dMsgRes or None, prot_aut or None, est or None, invoice_id),
    )
    con.commit()

    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

@app.route("/invoice/<int:invoice_id>/resync", methods=["POST"])
def invoice_resync(invoice_id: int):
    init_db()
    con = get_db()
    inv = con.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    if not inv:
        abort(404)

    env = (request.form.get("env") or inv["sifen_env"] or get_setting("default_env", "prod") or "prod").strip().lower()
    if env not in ("test", "prod"):
        env = "prod"
    con.execute("UPDATE invoices SET sifen_env=? WHERE id=?", (env, invoice_id))
    con.commit()

    prot = (inv["sifen_prot_cons_lote"] or "").strip()
    if prot:
        new_status = _consult_lote_and_update(
            invoice_id=invoice_id,
            env=env,
            prot=prot,
            rel_signed=inv["source_xml_path"] or None,
            prefer_art_dir=inv["last_artifacts_dir"] or None,
            attempts=1,
            sleep_between=0,
        )
        if new_status == "CONFIRMING":
            _schedule_lote_poll(invoice_id, env, prot, rel_signed=inv["source_xml_path"] or None)
        return redirect(url_for("invoice_detail", invoice_id=invoice_id))

    cdc = _extract_cdc_from_xml_path(inv["source_xml_path"] or "")
    if not cdc:
        abort(400, "No hay dProtConsLote ni CDC para sincronizar.")
    _consult_cdc_and_update(invoice_id, env, cdc)
    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

@app.route("/invoice/<int:invoice_id>/refresh_soap", methods=["POST"])
def invoice_refresh_soap(invoice_id: int):
    init_db()
    con = get_db()
    inv = con.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    if not inv:
        abort(404)

    art_dir = normalize_artifacts_dir(inv["last_artifacts_dir"] or "")
    resp_path = None
    if art_dir:
        cand = Path(art_dir) / "soap_last_response.xml"
        if cand.exists():
            resp_path = cand

    if not resp_path:
        artifacts_root = _repo_root() / "artifacts"
        for cand_dir in list_recent_artifacts_dirs(artifacts_root):
            cand = cand_dir / "soap_last_response.xml"
            if cand.exists():
                resp_path = cand
                art_dir = str(cand_dir)
                break

    if not resp_path:
        abort(400, "No se encontró soap_last_response.xml para refrescar.")

    xml_text = resp_path.read_text(encoding="utf-8")
    _refresh_invoice_from_soap(invoice_id, xml_text, art_dir)
    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

@app.route("/invoice/<int:invoice_id>/send_email", methods=["POST"])
def invoice_send_email(invoice_id: int):
    init_db()
    con = get_db()
    inv = con.execute(
        """
        SELECT i.*, c.name AS customer_name, c.ruc AS customer_ruc, c.email AS customer_email
        FROM invoices i JOIN customers c ON c.id=i.customer_id
        WHERE i.id=?
        """,
        (invoice_id,),
    ).fetchone()
    if not inv:
        abort(404)
    if not inv["customer_email"]:
        abort(400, "El cliente no tiene email.")

    template_path = get_setting("template_xml_path", "") or _default_template_path()
    if not template_path or not Path(template_path).exists():
        abort(400, "template_xml_path no configurado o no existe. Configuralo en /settings.")

    pdf_path = (inv["pdf_path"] or "").strip()
    if pdf_path and not Path(pdf_path).exists():
        pdf_path = ""

    response_xml = None
    last_art_dir = normalize_artifacts_dir(inv["last_artifacts_dir"] or "")
    if last_art_dir:
        resp_path = Path(last_art_dir) / "soap_last_response.xml"
        if resp_path.exists():
            response_xml = resp_path.read_text(encoding="utf-8")

    if not pdf_path:
        # Regenerar PDF desde datos de la factura y CDC del XML firmado
        src = resolve_existing_xml_path(inv["source_xml_path"] or "")
        cdc = None
        if src:
            try:
                xml = Path(src).read_text(encoding="utf-8")
                source_xml_text = xml
                m = re.search(r'<DE[^>]+Id="([0-9]{44})"', xml)
                if m:
                    cdc = m.group(1)
            except Exception:
                cdc = None
        if not cdc:
            cdc = "SIN_CDC"

        lines = con.execute(
            "SELECT * FROM invoice_lines WHERE invoice_id=? ORDER BY id ASC",
            (invoice_id,),
        ).fetchall()
        items_for_pdf = []
        for line in lines:
            items_for_pdf.append({
                "descripcion": line["description"],
                "cantidad": line["qty"],
                "precio_unit": line["price_unit"],
                "iva": "10",
                "total": line["line_total"],
            })
        issuer = {}
        src = resolve_existing_xml_path(inv["source_xml_path"] or "")
        if src:
            try:
                issuer = _build_issuer_from_xml_text(Path(src).read_text(encoding="utf-8"))
            except Exception:
                issuer = {}
        if not issuer:
            issuer = _build_issuer_from_template(template_path)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = _repo_root() / "artifacts" / f"webui_email_{invoice_id}_{ts}"
        base_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = str(base_dir / f"invoice_{invoice_id}.pdf")
        payload = _build_pdf_payload(
            invoice=inv,
            items_for_pdf=items_for_pdf,
            response_xml=response_xml,
            cdc=cdc,
            dnumdoc=str(inv["id"]).zfill(7),
            feemi=inv["issued_at"] or inv["created_at"],
            total_str=str(inv["total"] or 0),
            iva_total_str="",
            source_xml_text=source_xml_text,
        )
        render_invoice_pdf(data=payload, issuer=issuer, out_path=Path(pdf_path))
        con.execute(
            "UPDATE invoices SET pdf_path=? WHERE id=?",
            (pdf_path, invoice_id),
        )
        con.commit()

    try:
        subject = f"Factura #{invoice_id}"
        body = "Adjuntamos su factura electrónica.\n\nGracias."
        _send_email_with_pdf(inv["customer_email"], subject, body, Path(pdf_path))
        con.execute(
            "UPDATE invoices SET email_status=? WHERE id=?",
            ("SENT", invoice_id),
        )
        con.commit()
    except Exception as exc:
        con.execute(
            "UPDATE invoices SET email_status=?, last_sifen_msg=? WHERE id=?",
            ("ERROR", (inv["last_sifen_msg"] or "") + f" | Email error: {exc}", invoice_id),
        )
        con.commit()

    return redirect(url_for("invoice_detail", invoice_id=invoice_id))

@app.route("/invoice/<int:invoice_id>/preview_pdf")
def invoice_preview_pdf(invoice_id: int):
    init_db()
    con = get_db()
    inv = con.execute(
        """
        SELECT i.*, c.name AS customer_name, c.ruc AS customer_ruc, c.email AS customer_email
        FROM invoices i JOIN customers c ON c.id=i.customer_id
        WHERE i.id=?
        """,
        (invoice_id,),
    ).fetchone()
    if not inv:
        abort(404)

    template_path = get_setting("template_xml_path", "") or _default_template_path()
    if not template_path or not Path(template_path).exists():
        abort(400, "template_xml_path no configurado o no existe. Configuralo en /settings.")

    response_xml = None
    last_art_dir = normalize_artifacts_dir(inv["last_artifacts_dir"] or "")
    if last_art_dir:
        resp_path = Path(last_art_dir) / "soap_last_response.xml"
        if resp_path.exists():
            response_xml = resp_path.read_text(encoding="utf-8")

    doc_type = normalize_doc_type(inv["doc_type"])
    try:
        extra_json = _parse_extra_json(inv["doc_extra_json"], doc_type)
    except Exception:
        extra_json = {}

    src = resolve_existing_xml_path(inv["source_xml_path"] or "")
    source_xml_text = None
    cdc = None
    dnumdoc = (inv["doc_number"] or "").strip() if "doc_number" in inv.keys() else ""
    feemi = inv["issued_at"] or inv["created_at"]
    if src and Path(src).exists():
        try:
            source_xml_text = Path(src).read_text(encoding="utf-8")
            m = re.search(r'<DE[^>]+Id="([0-9]{44})"', source_xml_text)
            if m:
                cdc = m.group(1)
        except Exception:
            cdc = None
    else:
        try:
            build, signed_qr_text, rel_signed = _generate_signed_xml_for_invoice(
                invoice_id=invoice_id,
                inv=inv,
                con=con,
                doc_type=doc_type,
                extra_json=extra_json,
                template_path=template_path,
            )
            source_xml_text = signed_qr_text
            cdc = build.get("cdc")
            dnumdoc = build.get("dnumdoc") or dnumdoc
            feemi = build.get("feemi") or feemi
        except Exception as e:
            abort(400, str(e))

    if not cdc:
        cdc = "SIN_CDC"

    lines = con.execute(
        "SELECT * FROM invoice_lines WHERE invoice_id=? ORDER BY id ASC",
        (invoice_id,),
    ).fetchall()
    items_for_pdf = []
    for line in lines:
        items_for_pdf.append({
            "descripcion": line["description"],
            "cantidad": line["qty"],
            "precio_unit": line["price_unit"],
            "iva": "10",
            "total": line["line_total"],
        })

    issuer = {}
    if source_xml_text:
        try:
            issuer = _build_issuer_from_xml_text(source_xml_text)
        except Exception:
            issuer = {}
    if not issuer:
        issuer = _build_issuer_from_template(template_path)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = _repo_root() / "artifacts" / f"webui_preview_{invoice_id}_{ts}"
    base_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = base_dir / f"invoice_{invoice_id}.pdf"
    payload = _build_pdf_payload(
        invoice=inv,
        items_for_pdf=items_for_pdf,
        response_xml=response_xml,
        cdc=cdc,
        dnumdoc=dnumdoc or str(inv["id"]).zfill(7),
        feemi=feemi,
        total_str=str(inv["total"] or 0),
        iva_total_str="",
        source_xml_text=source_xml_text,
    )
    render_invoice_pdf(data=payload, issuer=issuer, out_path=pdf_path)
    resp = send_file(pdf_path, mimetype="application/pdf", as_attachment=False, download_name=f"invoice_{invoice_id}.pdf")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.route("/customer/new", methods=["GET", "POST"])
def customer_new():
    init_db()
    con = get_db()

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        ruc = (request.form.get("ruc") or "").strip() or None
        email = (request.form.get("email") or "").strip() or None
        phone = (request.form.get("phone") or "").strip() or None

        if not name:
            abort(400, "Nombre es obligatorio")

        con.execute(
            "INSERT INTO customers (name, ruc, email, phone, created_at) VALUES (?,?,?,?,?)",
            (name, ruc, email, phone, now_iso()),
        )
        con.commit()
        return redirect(url_for("customers"))

    body = render_template_string(
        """
        <div class="card">
          <div class="card-body">
            <h5 class="mb-3">Agregar cliente</h5>
            <form method="post" class="row g-2">
              <div class="col-12">
                <label class="form-label">Nombre / Razón social *</label>
                <input class="form-control" name="name" required autofocus>
              </div>
              <div class="col-md-4">
                <label class="form-label">RUC</label>
                <input class="form-control" name="ruc" placeholder="80012345-6 o 80012345">
              </div>
              <div class="col-md-4">
                <label class="form-label">Email</label>
                <input class="form-control" name="email" type="email" placeholder="cliente@dominio.com">
              </div>
              <div class="col-md-4">
                <label class="form-label">Teléfono</label>
                <input class="form-control" name="phone" placeholder="+595...">
              </div>

              <div class="col-12 d-flex gap-2 mt-2">
                <button class="btn btn-primary" type="submit">Guardar</button>
                <a class="btn btn-outline-secondary" href="{{ url_for('customers') }}">Cancelar</a>
              </div>
            </form>
          </div>
        </div>
        """
    )
    return render_template_string(BASE_HTML, title="Agregar cliente", db_path=DB_PATH, body=body)


@app.route("/customer/quick_add", methods=["POST"])
def customer_quick_add():
    init_db()
    con = get_db()
    payload = request.get_json(silent=True) or request.form or {}

    name = (payload.get("name") or "").strip()
    ruc = (payload.get("ruc") or "").strip() or None
    email = (payload.get("email") or "").strip() or None
    phone = (payload.get("phone") or "").strip() or None

    if not name:
        return jsonify({"error": "Nombre es obligatorio"}), 400

    cur = con.execute(
        "INSERT INTO customers (name, ruc, email, phone, created_at) VALUES (?,?,?,?,?)",
        (name, ruc, email, phone, now_iso()),
    )
    con.commit()

    return jsonify({
        "id": cur.lastrowid,
        "name": name,
        "ruc": ruc,
        "email": email,
        "phone": phone,
    })


@app.route("/customer/<int:customer_id>/edit", methods=["GET", "POST"])
def customer_edit(customer_id: int):
    init_db()
    con = get_db()
    row = con.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
    if not row:
        abort(404)

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        ruc = (request.form.get("ruc") or "").strip() or None
        email = (request.form.get("email") or "").strip() or None
        phone = (request.form.get("phone") or "").strip() or None

        if not name:
            abort(400, "Nombre es obligatorio")

        con.execute(
            "UPDATE customers SET name=?, ruc=?, email=?, phone=? WHERE id=?",
            (name, ruc, email, phone, customer_id),
        )
        con.commit()
        return redirect(url_for("customers"))

    body = render_template_string(
        """
        <div class="card">
          <div class="card-body">
            <h5 class="mb-3">Editar cliente #{{row.id}}</h5>
            <form method="post" class="row g-2">
              <div class="col-12">
                <label class="form-label">Nombre / Razón social *</label>
                <input class="form-control" name="name" value="{{row.name}}" required autofocus>
              </div>
              <div class="col-md-4">
                <label class="form-label">RUC</label>
                <input class="form-control" name="ruc" value="{{row.ruc or ''}}" placeholder="80012345-6 o 80012345">
              </div>
              <div class="col-md-4">
                <label class="form-label">Email</label>
                <input class="form-control" name="email" type="email" value="{{row.email or ''}}" placeholder="cliente@dominio.com">
              </div>
              <div class="col-md-4">
                <label class="form-label">Teléfono</label>
                <input class="form-control" name="phone" value="{{row.phone or ''}}" placeholder="+595...">
              </div>

              <div class="col-12 d-flex gap-2 mt-2">
                <button class="btn btn-primary" type="submit">Guardar</button>
                <a class="btn btn-outline-secondary" href="{{ url_for('customers') }}">Cancelar</a>
              </div>
            </form>
          </div>
        </div>
        """,
        row=row,
    )
    return render_template_string(BASE_HTML, title="Editar cliente", db_path=DB_PATH, body=body)


@app.route("/product/new", methods=["GET", "POST"])
def product_new():
    init_db()
    con = get_db()

    if request.method == "POST":
        sku = (request.form.get("sku") or "").strip() or None
        name = (request.form.get("name") or "").strip()
        unit = (request.form.get("unit") or "").strip() or "UN"
        price_raw = (request.form.get("price_unit") or "").strip()

        if not name:
            abort(400, "Nombre es obligatorio")

        try:
            price_unit = _parse_price_unit(price_raw)
        except RuntimeError as e:
            abort(400, str(e))

        con.execute(
            "INSERT INTO products (sku, name, unit, price_unit, created_at) VALUES (?,?,?,?,?)",
            (sku, name, unit, price_unit, now_iso()),
        )
        con.commit()
        return redirect(url_for("products"))

    body = render_template_string(
        """
        <div class="card">
          <div class="card-body">
            <h5 class="mb-3">Agregar producto/servicio</h5>
            <form method="post" class="row g-2">
              <div class="col-md-3">
                <label class="form-label">SKU</label>
                <input class="form-control" name="sku" placeholder="SKU-001">
              </div>
              <div class="col-md-6">
                <label class="form-label">Nombre *</label>
                <input class="form-control" name="name" required autofocus>
              </div>
              <div class="col-md-3">
                <label class="form-label">Unidad</label>
                <input class="form-control" name="unit" value="UN">
              </div>
              <div class="col-md-4">
                <label class="form-label">Precio Unit. (PYG)</label>
                <input class="form-control mono" name="price_unit" placeholder="1.234.567">
              </div>

              <div class="col-12 d-flex gap-2 mt-2">
                <button class="btn btn-primary" type="submit">Guardar</button>
                <a class="btn btn-outline-secondary" href="{{ url_for('products') }}">Cancelar</a>
              </div>
            </form>
          </div>
        </div>
        """
    )
    return render_template_string(BASE_HTML, title="Agregar producto/servicio", db_path=DB_PATH, body=body)

@app.route("/product/quick_add", methods=["POST"])
def product_quick_add():
    init_db()
    con = get_db()
    payload = request.get_json(silent=True) or request.form or {}

    sku = (payload.get("sku") or "").strip() or None
    name = (payload.get("name") or "").strip()
    unit = (payload.get("unit") or "").strip() or "UN"
    price_raw = (payload.get("price_unit") or "").strip()

    if not name:
        return jsonify({"error": "Nombre es obligatorio"}), 400

    try:
        price_unit = _parse_price_unit(price_raw)
    except RuntimeError as e:
        return jsonify({"error": str(e)}), 400

    cur = con.execute(
        "INSERT INTO products (sku, name, unit, price_unit, created_at) VALUES (?,?,?,?,?)",
        (sku, name, unit, price_unit, now_iso()),
    )
    con.commit()

    return jsonify({
        "id": cur.lastrowid,
        "sku": sku,
        "name": name,
        "unit": unit,
        "price_unit": price_unit,
    })


@app.route("/product/<int:product_id>/edit", methods=["GET", "POST"])
def product_edit(product_id: int):
    init_db()
    con = get_db()
    row = con.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if not row:
        abort(404)

    if request.method == "POST":
        sku = (request.form.get("sku") or "").strip() or None
        name = (request.form.get("name") or "").strip()
        unit = (request.form.get("unit") or "").strip() or "UN"
        price_raw = (request.form.get("price_unit") or "").strip()

        if not name:
            abort(400, "Nombre es obligatorio")

        try:
            price_unit = _parse_price_unit(price_raw)
        except RuntimeError as e:
            abort(400, str(e))

        con.execute(
            "UPDATE products SET sku=?, name=?, unit=?, price_unit=? WHERE id=?",
            (sku, name, unit, price_unit, product_id),
        )
        con.commit()
        return redirect(url_for("products"))

    body = render_template_string(
        """
        <div class="card">
          <div class="card-body">
            <h5 class="mb-3">Editar producto/servicio #{{row.id}}</h5>
            <form method="post" class="row g-2">
              <div class="col-md-3">
                <label class="form-label">SKU</label>
                <input class="form-control" name="sku" value="{{row.sku or ''}}" placeholder="SKU-001">
              </div>
              <div class="col-md-6">
                <label class="form-label">Nombre *</label>
                <input class="form-control" name="name" value="{{row.name}}" required autofocus>
              </div>
              <div class="col-md-3">
                <label class="form-label">Unidad</label>
                <input class="form-control" name="unit" value="{{row.unit or 'UN'}}">
              </div>
              <div class="col-md-4">
                <label class="form-label">Precio Unit. (PYG)</label>
                <input class="form-control mono" name="price_unit" value="{{row.price_unit}}" placeholder="1.234.567">
              </div>

              <div class="col-12 d-flex gap-2 mt-2">
                <button class="btn btn-primary" type="submit">Guardar</button>
                <a class="btn btn-outline-secondary" href="{{ url_for('products') }}">Cancelar</a>
              </div>
            </form>
          </div>
        </div>
        """,
        row=row,
    )
    return render_template_string(BASE_HTML, title="Editar producto/servicio", db_path=DB_PATH, body=body)


@app.route("/customers")
def customers():
    init_db()
    con = get_db()
    rows = con.execute("SELECT * FROM customers ORDER BY id DESC").fetchall()
    body = render_template_string(
        """
        <div class="card">
          <div class="card-body">
            <h5>Clientes</h5>
            <div class=\"d-flex justify-content-between align-items-center mb-2\"><div class=\"text-muted small\">Listado</div><a class=\"btn btn-sm btn-primary\" href=\"{{ url_for('customer_new') }}\">+ Agregar</a></div><div class="table-responsive">
              <table class="table table-sm align-middle">
                <thead><tr><th>ID</th><th>Nombre</th><th>RUC</th><th>Creado</th><th>Acciones</th></tr></thead>
                <tbody>
                  {% for r in rows %}
                    <tr>
                      <td class="mono">{{r.id}}</td>
                      <td>{{r.name}}</td>
                      <td class="mono">{{r.ruc or "—"}}</td>
                      <td class="mono">{{r.created_at}}</td>
                      <td class="nowrap">
                        <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('customer_edit', customer_id=r.id) }}">Editar</a>
                      </td>
                    </tr>
                  {% endfor %}
                  {% if not rows %}
                    <tr><td colspan="5" class="text-muted">Sin clientes.</td></tr>
                  {% endif %}
                </tbody>
              </table>
            </div>
            <a class="btn btn-outline-secondary" href="{{ url_for('invoices') }}">Volver</a>
          </div>
        </div>
        """,
        rows=rows,
    )
    return render_template_string(BASE_HTML, title="Clientes", db_path=DB_PATH, body=body)

@app.route("/products")
def products():
    init_db()
    con = get_db()
    rows = con.execute("SELECT * FROM products ORDER BY id DESC").fetchall()
    body = render_template_string(
        """
        <div class="card">
          <div class="card-body">
            <h5>Productos/Servicios</h5>
            <div class=\"d-flex justify-content-between align-items-center mb-2\"><div class=\"text-muted small\">Listado</div><a class=\"btn btn-sm btn-primary\" href=\"{{ url_for('product_new') }}\">+ Agregar</a></div><div class="text-muted small mb-2">MVP: lista simple (en el siguiente paso agregamos alta/edición y selector en factura).</div>
            <div class="table-responsive">
              <table class="table table-sm align-middle">
                <thead><tr><th>ID</th><th>SKU</th><th>Nombre</th><th>Unidad</th><th>Precio</th><th>Creado</th><th>Acciones</th></tr></thead>
                <tbody>
                  {% for r in rows %}
                    <tr>
                      <td class="mono">{{r.id}}</td>
                      <td class="mono">{{r.sku or "—"}}</td>
                      <td>{{r.name}}</td>
                      <td class="mono">{{r.unit}}</td>
                      <td class="mono">{{ "{:,}".format(r.price_unit).replace(",", ".") }}</td>
                      <td class="mono">{{r.created_at}}</td>
                      <td class="nowrap">
                        <a class="btn btn-sm btn-outline-secondary" href="{{ url_for('product_edit', product_id=r.id) }}">Editar</a>
                      </td>
                    </tr>
                  {% endfor %}
                  {% if not rows %}
                    <tr><td colspan="7" class="text-muted">Sin productos.</td></tr>
                  {% endif %}
                </tbody>
              </table>
            </div>
            <a class="btn btn-outline-secondary" href="{{ url_for('invoices') }}">Volver</a>
          </div>
        </div>
        """,
        rows=rows,
    )
    return render_template_string(BASE_HTML, title="Productos/Servicios", db_path=DB_PATH, body=body)

if __name__ == "__main__":
    # init_db() usa `g`, así que necesita application context
    with app.app_context():
        init_db()
    try:
        app.run(host="127.0.0.1", port=5055, debug=False, use_reloader=False)
    except Exception as exc:
        print(f"APP_RUN_ERROR: {exc!r}", file=sys.stderr)
        raise
