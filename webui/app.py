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
from datetime import datetime, date, timezone
from zoneinfo import ZoneInfo

SIFEN_TZ = ZoneInfo("America/Asuncion")
from xml.sax.saxutils import escape as xml_escape
from flask import Flask, g, request, redirect, url_for, render_template_string, abort, send_file, jsonify, send_from_directory
from pathlib import Path
from typing import Optional
import xml.etree.ElementTree as ET

# requests (HTTP) for eventos
import requests

# Asegurar imports desde repo root (evitar conflicto con webui/app.py)
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) in sys.path:
    sys.path.remove(str(SCRIPT_DIR))
BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app.pdf.invoice_renderer import render_invoice_pdf
from app.sifen_client.xml_generator_v150 import generate_cdc
from app.sifen_client.xmlsec_signer import sign_de_with_p12, sign_event_with_p12
from app.sifen_client.config import get_sifen_config
from app.sifen_client.soap_client import SoapClient
from app.sifen_client.cdc_utils import calc_dv_mod11
from app.sifen_client.xsd_validator import validate_de_xml_against_xsd
from sifen_minisender.core_send import send_lote_from_xml

APP_TITLE = "SIFEN WebUI (SQLite)"
SIFEN_NS = "http://ekuatia.set.gov.py/sifen/xsd"
SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"


def _resolve_db_path() -> str:
    raw = (
        (os.getenv("SIFEN_WEBUI_DB") or "").strip()
        or (os.getenv("SIFEN_WEBUI_DB_PATH") or "").strip()
        or (os.getenv("WEBUI_DB_PATH") or "").strip()
    )
    if raw:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            return str((BASE_DIR / p).resolve())
        return str(p.resolve())
    return str((BASE_DIR / "data" / "webui.db").resolve())


DB_PATH = _resolve_db_path()


def _resolve_uploads_dir() -> Path:
    raw = (os.getenv("WEBUI_UPLOADS_DIR") or "").strip()
    if raw:
        p = Path(raw).expanduser()
        if not p.is_absolute():
            p = (BASE_DIR / p).resolve()
        else:
            p = p.resolve()
        return p
    return (BASE_DIR / "data" / "uploads").resolve()


UPLOADS_DIR = _resolve_uploads_dir()


def _ensure_uploads_dir() -> None:
    base_data = (BASE_DIR / "data").resolve()
    target = UPLOADS_DIR
    try:
        if target == base_data or base_data in target.parents:
            target.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

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

CONSTANCIA_TYPE_MAP = {
    "1": "Constancia de no ser contribuyente",
    "2": "Constancia de microproductores",
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
        global DB_PATH
        resolved = _resolve_db_path()
        if resolved != DB_PATH:
            DB_PATH = resolved
        Path(DB_PATH).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)
        try:
            con = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        except Exception as exc:
            raise RuntimeError(f"Failed to connect SQLite DB at {DB_PATH}") from exc
        con.row_factory = sqlite3.Row
        g.db = con
        con.execute("PRAGMA foreign_keys = ON;")
        con.execute("PRAGMA busy_timeout = 10000;")
        try:
            con.execute("PRAGMA journal_mode = WAL;")
        except Exception:
            # Si está locked durante arranque/concurrencia, no rompas la app
            pass
        con.execute("PRAGMA synchronous = FULL;")
    return g.db

@app.teardown_appcontext
def close_db(_exc):
    con = g.pop("db", None)
    if con is not None:
        con.close()

def init_db():
    _ensure_uploads_dir()
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
            created_at TEXT NOT NULL,
            deleted_at TEXT
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
    def _column_exists(con, table: str, column: str) -> bool:
        rows = con.execute(f"PRAGMA table_info({table})").fetchall()
        return any(r[1] == column for r in rows)  # r[1] es name

    if not _column_exists(con, "invoices", "source_xml_path"):
        con.execute("ALTER TABLE invoices ADD COLUMN source_xml_path TEXT")
    if not _column_exists(con, "invoices", "last_artifacts_dir"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_artifacts_dir TEXT")
    if not _column_exists(con, "invoices", "pdf_path"):
        con.execute("ALTER TABLE invoices ADD COLUMN pdf_path TEXT")
    if not _column_exists(con, "invoices", "email_status"):
        con.execute("ALTER TABLE invoices ADD COLUMN email_status TEXT")
    if not _column_exists(con, "invoices", "last_sifen_est"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_sifen_est TEXT")
    if not _column_exists(con, "invoices", "last_sifen_prot_aut"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_sifen_prot_aut TEXT")
    if not _column_exists(con, "invoices", "last_lote_code"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_lote_code TEXT")
    if not _column_exists(con, "invoices", "last_lote_msg"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_lote_msg TEXT")
    if not _column_exists(con, "invoices", "sifen_env"):
        con.execute("ALTER TABLE invoices ADD COLUMN sifen_env TEXT")
    if not _column_exists(con, "invoices", "doc_number"):
        con.execute("ALTER TABLE invoices ADD COLUMN doc_number TEXT")
    if not _column_exists(con, "invoices", "signed_at"):
        con.execute("ALTER TABLE invoices ADD COLUMN signed_at TEXT")
    if not _column_exists(con, "invoices", "codseg"):
        con.execute("ALTER TABLE invoices ADD COLUMN codseg TEXT")
    if not _column_exists(con, "invoices", "establishment"):
        con.execute("ALTER TABLE invoices ADD COLUMN establishment TEXT")
    if not _column_exists(con, "invoices", "point_exp"):
        con.execute("ALTER TABLE invoices ADD COLUMN point_exp TEXT")
    if not _column_exists(con, "invoices", "doc_type"):
        con.execute("ALTER TABLE invoices ADD COLUMN doc_type TEXT DEFAULT '1'")
    if not _column_exists(con, "invoices", "doc_extra_json"):
        con.execute("ALTER TABLE invoices ADD COLUMN doc_extra_json TEXT")
    if not _column_exists(con, "invoices", "last_event_type"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_type TEXT")
    if not _column_exists(con, "invoices", "last_event_id"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_id TEXT")
    if not _column_exists(con, "invoices", "last_event_est"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_est TEXT")
    if not _column_exists(con, "invoices", "last_event_code"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_code TEXT")
    if not _column_exists(con, "invoices", "last_event_msg"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_msg TEXT")
    if not _column_exists(con, "invoices", "last_event_prot_aut"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_prot_aut TEXT")
    if not _column_exists(con, "invoices", "last_event_at"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_at TEXT")
    if not _column_exists(con, "invoices", "last_event_artifacts_dir"):
        con.execute("ALTER TABLE invoices ADD COLUMN last_event_artifacts_dir TEXT")
    if not _column_exists(con, "customers", "deleted_at"):
        con.execute("ALTER TABLE customers ADD COLUMN deleted_at TEXT")
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
        data.setdefault("autofactura", {})
        if "iNatVen" not in data["autofactura"]:
            data["autofactura"]["iNatVen"] = "1"
        if "iTipIDVen" not in data["autofactura"]:
            data["autofactura"]["iTipIDVen"] = str(
                data["autofactura"].get("tipoDocumento") or "1"
            )
        tip_cons = _resolve_afe_constancia_type(data)
        if tip_cons:
            data["documentoAsociado"]["tipoConstancia"] = tip_cons
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

def _afe_vendor_from_extra(extra_json: dict) -> dict:
    extra_json = extra_json or {}
    vendor = {}
    afe_root = extra_json.get("afe")
    if isinstance(afe_root, dict):
        vend = afe_root.get("vendedor")
        if isinstance(vend, dict):
            vendor.update(vend)
    afe = extra_json.get("autofactura")
    if isinstance(afe, dict):
        vendor.update(afe)
    return vendor

def _afe_pick(afe: dict, *keys: str) -> str:
    for key in keys:
        val = afe.get(key)
        if val is None:
            continue
        raw = str(val).strip()
        if raw != "":
            return raw
    return ""

def _afe_vendor_form_values(afe_vendor: dict) -> dict:
    return {
        "tipo_vendedor": _afe_pick(afe_vendor, "iNatVen", "naturaleza", "tipo_vendedor"),
        "tipo_doc": _afe_pick(afe_vendor, "iTipIDVen", "tipoDocumento", "tipo_doc"),
        "nro_doc": _afe_pick(afe_vendor, "dNumIDVen", "documento", "nro_doc", "nro_doc_identidad"),
        "nombre": _afe_pick(afe_vendor, "dNomVen", "nombre", "nombre_apellido_o_razon"),
        "direccion": _afe_pick(afe_vendor, "dDirVen", "direccion", "direccionVendedor"),
        "num_casa": _afe_pick(afe_vendor, "dNumCasVen", "numCasa"),
        "departamento": _afe_pick(afe_vendor, "cDepVen", "departamentoVendedor", "departamento"),
        "distrito": _afe_pick(afe_vendor, "cDisVen", "distritoVendedor", "distrito"),
        "ciudad": _afe_pick(afe_vendor, "cCiuVen", "ciudadVendedor", "ciudad"),
    }

def _resolve_afe_constancia_type(extra_json: dict, assoc: Optional[dict] = None) -> str:
    extra_json = extra_json or {}
    assoc = assoc or (extra_json.get("documentoAsociado") or {})
    tip = str(
        assoc.get("tipoConstancia")
        or assoc.get("tipoConst")
        or assoc.get("iTipCons")
        or assoc.get("iTiConst")
        or ""
    ).strip()
    if tip in CONSTANCIA_TYPE_MAP:
        return tip
    afe_vendor = _afe_vendor_from_extra(extra_json)
    if _afe_pick(afe_vendor, "iNatVen", "naturaleza", "tipo_vendedor") == "1":
        return "1"
    return ""

def _set_afe_vendor_extra(extra_json: dict, vendor: dict) -> dict:
    extra_json = extra_json or {}
    extra_json.setdefault("autofactura", {}).update(vendor)
    extra_json.setdefault("afe", {}).setdefault("vendedor", {}).update(vendor)
    return extra_json

def _sync_afe_receiver_with_emitter(root: ET.Element, ns: dict, ns_uri: str) -> None:
    g_emis = root.find(".//s:gEmis", ns)
    g_rec = root.find(".//s:gDatRec", ns)
    if g_emis is None or g_rec is None:
        return

    def _copy(tag_em: str, tag_rec: str) -> None:
        src = g_emis.find(f"{{{ns_uri}}}{tag_em}")
        if src is None or not (src.text or "").strip():
            return
        _ensure_child_ns(g_rec, tag_rec, ns_uri).text = (src.text or "").strip()

    _copy("dRucEm", "dRucRec")
    _copy("dDVEmi", "dDVRec")
    _copy("dNomEmi", "dNomRec")
    _copy("dDirEmi", "dDirRec")
    _copy("dNumCas", "dNumCasRec")
    _copy("cDepEmi", "cDepRec")
    _copy("dDesDepEmi", "dDesDepRec")
    _copy("cDisEmi", "cDisRec")
    _copy("dDesDisEmi", "dDesDisRec")
    _copy("cCiuEmi", "cCiuRec")
    _copy("dDesCiuEmi", "dDesCiuRec")
    _copy("dTelEmi", "dTelRec")
    _copy("dEmailE", "dEmailRec")
    _copy("iTipCont", "iTiContRec")

    # MT v150 D201a/D202a: en AFE el receptor es contribuyente y la operación debe ser B2C.
    _ensure_child_ns(g_rec, "iNatRec", ns_uri).text = "1"
    _ensure_child_ns(g_rec, "iTiOpe", ns_uri).text = "2"

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

_GEO_TREE_CACHE = None

def _load_georef_tree() -> dict:
    global _GEO_TREE_CACHE
    if _GEO_TREE_CACHE is not None:
        return _GEO_TREE_CACHE
    candidates = [
        Path("/data/georef_tree.json"),
        Path("/data/georef_tree_2025.json"),
        _repo_root() / "data" / "georef_tree.json",
        _repo_root() / "data" / "georef_tree_2025.json",
    ]
    for path in candidates:
        if path.exists():
            try:
                _GEO_TREE_CACHE = json.loads(path.read_text(encoding="utf-8"))
                return _GEO_TREE_CACHE
            except Exception:
                pass
    _GEO_TREE_CACHE = {
        "dep": {},
        "dist_by_dep": {},
        "city_by_dist": {},
        "city_to_dist": {},
        "dist_to_dep": {},
    }
    return _GEO_TREE_CACHE

def _find_default_afe_geo(tree: dict) -> tuple[str, str, str]:
    city_by_dist = tree.get("city_by_dist") or {}
    dist_to_dep = tree.get("dist_to_dep") or {}
    fallback: tuple[str, str, str] = ("", "", "")
    for dist_code, cities in city_by_dist.items():
        if not isinstance(cities, dict):
            continue
        for city_code, name in cities.items():
            label = str(name or "").strip()
            if not label:
                continue
            norm = label.casefold()
            dep_code = dist_to_dep.get(str(dist_code), "")
            if norm == "asuncion (distrito)":
                return (
                    _geo_display_code(dep_code),
                    _geo_display_code(dist_code),
                    _geo_display_code(city_code),
                )
            if norm == "asuncion":
                return (
                    _geo_display_code(dep_code),
                    _geo_display_code(dist_code),
                    _geo_display_code(city_code),
                )
            if "asuncion" in norm and not any(fallback):
                fallback = (
                    _geo_display_code(dep_code),
                    _geo_display_code(dist_code),
                    _geo_display_code(city_code),
                )
    return fallback

_GEO_REF_CACHE = None

def _geo_name(kind: str, code: str) -> str:
    """
    Devuelve descripción textual para códigos geo (dep/dist/city) según catálogo oficial (XLSX -> JSON).
    kind: "dep" | "dist" | "city"
    """
    global _GEO_REF_CACHE
    if code is None:
        return ""
    code = str(code).strip()
    if not code:
        return ""

    # normalizar largos
    if kind == "dep":
        code = code.zfill(2)
    elif kind == "dist":
        code = code.zfill(4)
    elif kind == "city":
        code = code.zfill(5)

    # cargar JSON una sola vez (cache en memoria)
    if _GEO_REF_CACHE is None:
        try:
            import json
            from pathlib import Path as _P
            _GEO_REF_CACHE = json.loads(_P("/data/catalogos/geo_ref_2025.json").read_text(encoding="utf-8"))
        except Exception:
            _GEO_REF_CACHE = {"dep": {}, "dist": {}, "city": {}}

    try:
        return str(_GEO_REF_CACHE.get(kind, {}).get(code, "") or "")
    except Exception:
        return ""

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
        afe = _afe_vendor_from_extra(extra_json)
        i_nat = _afe_pick(afe, "iNatVen", "naturaleza", "tipo_vendedor")
        if i_nat not in AFE_NAT_MAP:
            errors.append("Autofactura: falta tipo_vendedor (iNatVen 1/2).")
        i_tip = _afe_pick(afe, "iTipIDVen", "tipoDocumento", "tipo_doc")
        if i_tip not in AFE_ID_MAP:
            errors.append("Autofactura: falta tipo_doc_identidad (iTipIDVen).")
        if not _afe_pick(afe, "dNumIDVen", "documento", "nro_doc", "nro_doc_identidad"):
            errors.append("Autofactura: falta nro_doc_identidad (dNumIDVen).")
        if not _afe_pick(afe, "dNomVen", "nombre", "nombre_apellido_o_razon"):
            errors.append("Autofactura: falta nombre del vendedor (dNomVen).")

        # Dirección mínima requerida por XSD en gCamAE
        if not _afe_pick(afe, "dDirVen", "direccion", "direccionVendedor"):
            errors.append("Autofactura: falta dirección del vendedor (dDirVen).")
        num_casa = _afe_pick(afe, "dNumCasVen", "numCasa")
        if not num_casa:
            errors.append("Autofactura: falta número de casa (dNumCasVen).")
        elif not num_casa.isdigit():
            errors.append("Autofactura: número de casa inválido (solo dígitos).")

        dep = _afe_pick(afe, "cDepVen", "departamentoVendedor", "departamento")
        if not dep:
            errors.append("Autofactura: falta departamento del vendedor (cDepVen).")
        elif not dep.isdigit():
            errors.append("Autofactura: departamento inválido (solo dígitos).")

        dis = _afe_pick(afe, "cDisVen", "distritoVendedor", "distrito")
        if not dis:
            errors.append("Autofactura: falta distrito del vendedor (cDisVen).")
        elif not dis.isdigit():
            errors.append("Autofactura: distrito inválido (solo dígitos).")

        ciu = _afe_pick(afe, "cCiuVen", "ciudadVendedor", "ciudad")
        if not ciu:
            errors.append("Autofactura: falta ciudad del vendedor (cCiuVen).")
        elif not ciu.isdigit():
            errors.append("Autofactura: ciudad inválida (solo dígitos).")

        geo_tree = _load_georef_tree()
        if geo_tree:
            dep_norm = _zfill_digits(dep, 2)
            dis_norm = _zfill_digits(dis, 4)
            ciu_norm = _zfill_digits(ciu, 5)
            dep_map = geo_tree.get("dep") or {}
            dist_to_dep = geo_tree.get("dist_to_dep") or {}
            city_to_dist = geo_tree.get("city_to_dist") or {}

            if dep_norm and dep_norm not in dep_map:
                errors.append("Autofactura: departamento inválido (no existe en catálogo).")
            if dis_norm and dis_norm not in dist_to_dep:
                errors.append("Autofactura: distrito inválido (no existe en catálogo).")
            if ciu_norm and ciu_norm not in city_to_dist:
                errors.append("Autofactura: ciudad inválida (no existe en catálogo).")

            expected_dist = city_to_dist.get(ciu_norm)
            if expected_dist:
                if not dis_norm:
                    errors.append("Autofactura: falta distrito del vendedor (cDisVen) para la ciudad indicada.")
                elif expected_dist != dis_norm:
                    errors.append("Autofactura: ciudad no pertenece al distrito indicado.")

            expected_dep = dist_to_dep.get(dis_norm)
            if expected_dep and dep_norm and expected_dep != dep_norm:
                errors.append("Autofactura: distrito no pertenece al departamento indicado.")
        # En AFE el documento asociado debe ser Constancia Electrónica (H002=3)
        assoc = extra_json.get("documentoAsociado") or {}
        tip = str(assoc.get("tipoDocumentoAsoc") or assoc.get("iTipDocAso") or "").strip()
        if tip and tip != "3":
            errors.append("Autofactura: documentoAsociado.tipoDocumentoAsoc debe ser 3 (Constancia electrónica).")
        elif tip == "3":
            tip_cons = _resolve_afe_constancia_type(extra_json, assoc)
            if not tip_cons:
                errors.append("Autofactura: falta tipo de constancia (iTipCons 1/2) para documentoAsociado.tipoDocumentoAsoc=3.")
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

            geo_tree = _load_georef_tree()
            if geo_tree:
                dep_map = geo_tree.get("dep") or {}
                dist_to_dep = geo_tree.get("dist_to_dep") or {}
                city_to_dist = geo_tree.get("city_to_dist") or {}
                for label, loc in [("salida", salida), ("entrega", entrega)]:
                    dep_raw = str(loc.get("departamento") or "").strip()
                    dist_raw = str(loc.get("distrito") or "").strip()
                    city_raw = str(loc.get("ciudad") or "").strip()
                    dep_norm = _zfill_digits(dep_raw, 2)
                    dist_norm = _zfill_digits(dist_raw, 4)
                    city_norm = _zfill_digits(city_raw, 5)

                    if dep_norm and dep_norm not in dep_map:
                        errors.append(f"Transporte {label}: departamento inválido (no existe en catálogo).")
                    if dist_norm and dist_norm not in dist_to_dep:
                        errors.append(f"Transporte {label}: distrito inválido (no existe en catálogo).")
                    if city_norm and city_norm not in city_to_dist:
                        errors.append(f"Transporte {label}: ciudad inválida (no existe en catálogo).")

                    expected_dist = city_to_dist.get(city_norm)
                    if expected_dist:
                        if not dist_norm:
                            errors.append(f"Transporte {label}: falta distrito para la ciudad indicada.")
                        elif expected_dist != dist_norm:
                            errors.append(f"Transporte {label}: ciudad no pertenece al distrito indicado.")

                    expected_dep = dist_to_dep.get(dist_norm)
                    if expected_dep and dep_norm and expected_dep != dep_norm:
                        errors.append(f"Transporte {label}: distrito no pertenece al departamento indicado.")
                    if expected_dist and dep_norm:
                        dep_from_city = dist_to_dep.get(expected_dist)
                        if dep_from_city and dep_from_city != dep_norm:
                            errors.append(f"Transporte {label}: ciudad no pertenece al departamento indicado.")

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

def _asuncion_timestamp() -> str:
    # ARAVO FIX: hora PY (America/Asuncion) SIN offset
    from datetime import datetime, timezone
    return datetime.now(tz=SIFEN_TZ).strftime("%Y-%m-%dT%H:%M:%S")

def _make_did_15() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

def _make_event_id_from_did(did: str) -> str:
    eve_id = (did or "")[-10:]
    eve_id = eve_id.lstrip("0") or "1"
    return eve_id

def _make_event_ids() -> tuple[str, str]:
    did = _make_did_15()
    return did, _make_event_id_from_did(did)

def _zfill_digits(value: Optional[str], width: int) -> str:
    raw = "" if value is None else str(value)
    digits = re.sub(r"\D", "", raw.strip())
    if not digits:
        return ""
    return digits.zfill(width)

def _geo_display_code(value: Optional[str]) -> str:
    if value is None:
        return ""
    digits = re.sub(r"\D", "", str(value).strip())
    if not digits:
        return ""
    trimmed = digits.lstrip("0")
    return trimmed or "0"

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
    if len(cdc) != 44:
        raise RuntimeError(f"CDC debe tener 44 caracteres. Tiene: {len(cdc)}")
    if not event_id or not event_id.isdigit():
        raise RuntimeError("rEve@Id debe ser numérico.")

    ts = _asuncion_timestamp()
    motivo_xml = xml_escape(motivo or "")
    cdc_xml = xml_escape(cdc)

    xml_text = f"""<gGroupGesEve xmlns="{SIFEN_NS}"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="{SIFEN_NS} siRecepEvento_v150.xsd">
  <rGesEve>
    <rEve Id="{event_id}">
      <dFecFirma>{ts}</dFecFirma>
      <dVerFor>150</dVerFor>
      <gGroupTiEvt>
        <rGeVeCan>
          <Id>{cdc_xml}</Id>
          <mOtEve>{motivo_xml}</mOtEve>
        </rGeVeCan>
      </gGroupTiEvt>
    </rEve>
  </rGesEve>
</gGroupGesEve>
"""
    return xml_text.encode("utf-8")

def _strip_xml_decl(xml_text: str) -> str:
    # Quitar BOM + XML declaration real (si viene embebido)
    xml_text = (xml_text or "").lstrip("\ufeff")
    xml_text = re.sub(r"^\s*<\?xml[^>]*\?>\s*", "", xml_text)
    return xml_text.lstrip()

def _build_event_soap(did: str, signed_event_xml: str) -> bytes:
    payload = _strip_xml_decl(signed_event_xml).strip()
    soap_text = f"""<soap:Envelope xmlns:soap="{SOAP_NS}" xmlns:xsd="{SIFEN_NS}">
  <soap:Body>
    <xsd:rEnviEventoDe>
      <xsd:dId>{did}</xsd:dId>
      <xsd:dEvReg>
{payload}
      </xsd:dEvReg>
    </xsd:rEnviEventoDe>
  </soap:Body>
</soap:Envelope>
"""
    return soap_text.encode("utf-8")

def _local_name(tag: str) -> str:
    return tag.split("}", 1)[-1] if "}" in tag else tag

def _guardrail_signed_event_xml(signed_event_xml: str, event_id: str) -> None:
    try:
        root = ET.fromstring(signed_event_xml)
    except Exception as exc:
        raise RuntimeError(f"XML firmado inválido: {exc}") from exc

    if _local_name(root.tag) != "gGroupGesEve":
        raise RuntimeError("XML firmado debe tener raíz gGroupGesEve.")

    rGesEve = None
    for child in root.iter():
        if _local_name(child.tag) == "rGesEve":
            rGesEve = child
            break
    if rGesEve is None:
        raise RuntimeError("XML firmado sin rGesEve.")

    rEve = None
    sig = None
    for child in list(rGesEve):
        if _local_name(child.tag) == "rEve":
            rEve = child
        elif _local_name(child.tag) == "Signature":
            sig = child
    if rEve is None:
        raise RuntimeError("XML firmado sin rEve.")
    if sig is None:
        raise RuntimeError("XML firmado sin Signature como hermana de rEve.")
    if list(rGesEve).index(sig) <= list(rGesEve).index(rEve):
        raise RuntimeError("Signature debe estar después de rEve dentro de rGesEve.")

    eve_id = rEve.get("Id") or rEve.get("id") or ""
    if eve_id != event_id:
        raise RuntimeError("rEve@Id no coincide con event_id esperado.")

    ref = None
    for node in sig.iter():
        if _local_name(node.tag) == "Reference":
            ref = node
            break
    if ref is None:
        raise RuntimeError("Signature sin Reference.")
    uri = ref.get("URI") or ""
    if uri != f"#{event_id}":
        raise RuntimeError("Reference URI no coincide con rEve@Id.")

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
    ns_uri = SIFEN_NS
    ET.register_namespace("", ns_uri)
    root = ET.Element(f"{{{ns_uri}}}gGroupGesEve")
    rGesEve = ET.SubElement(root, f"{{{ns_uri}}}rGesEve")
    rEve = ET.SubElement(rGesEve, f"{{{ns_uri}}}rEve")
    rEve.set("Id", event_id)
    dFecFirma = ET.SubElement(rEve, f"{{{ns_uri}}}dFecFirma")
    dFecFirma.text = _asuncion_timestamp()
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
    did: str,
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
    _guardrail_signed_event_xml(signed_event, event_id)

    # construir SOAP (xsd: wrapper, sin xml declaration dentro del Body)
    soap_bytes = _build_event_soap(did, signed_event)

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
    did: str,
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
    _guardrail_signed_event_xml(signed_event, event_id)

    soap_bytes = _build_event_soap(did, signed_event)

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

def _build_gtransp_from_extra(gdtip: ET.Element, ns_uri: str, transporte_dict: dict) -> None:
    if not isinstance(transporte_dict, dict):
        raise RuntimeError("doc_extra_json.transporte inválido para Remisión (iTiDE=7).")

    def _s(value) -> str:
        return str(value).strip() if value is not None else ""

    def _date_only(value) -> str:
        raw = _s(value)
        return raw.split(" ")[0] if raw else ""

    def _set_opt(parent: ET.Element, tag: str, value: str) -> None:
        if value:
            _ensure_child_ns(parent, tag, ns_uri).text = value

    gtransp = _ensure_child_ns(gdtip, "gTransp", ns_uri)
    for child in list(gtransp):
        gtransp.remove(child)

    i_tip_trans = _s(transporte_dict.get("iTipTrans") or transporte_dict.get("tipoTransporte"))
    if i_tip_trans:
        _ensure_child_ns(gtransp, "iTipTrans", ns_uri).text = i_tip_trans
        _ensure_child_ns(gtransp, "dDesTipTrans", ns_uri).text = TRANS_TIPO_MAP.get(i_tip_trans, "Tercero")

    i_mod = _s(transporte_dict.get("iModTrans") or transporte_dict.get("modalidad"))
    if i_mod not in TRANS_MOD_MAP:
        raise RuntimeError("Transporte: falta modalidad (iModTrans 1-4).")
    _ensure_child_ns(gtransp, "iModTrans", ns_uri).text = i_mod
    _ensure_child_ns(gtransp, "dDesModTrans", ns_uri).text = TRANS_MOD_MAP.get(i_mod, "Terrestre")

    i_resp_flete = _s(transporte_dict.get("iRespFlete") or transporte_dict.get("tipoResponsable"))
    if i_resp_flete not in RESP_FLETE_MAP:
        raise RuntimeError("Transporte: falta tipoResponsable (iRespFlete 1-5).")
    _ensure_child_ns(gtransp, "iRespFlete", ns_uri).text = i_resp_flete

    _set_opt(gtransp, "cCondNeg", _s(transporte_dict.get("condNeg")))
    _set_opt(gtransp, "dNuManif", _s(transporte_dict.get("numManif")))
    _set_opt(gtransp, "dNuDespImp", _s(transporte_dict.get("despachoImp")))
    _set_opt(gtransp, "dIniTras", _date_only(transporte_dict.get("iniFechaEstimadaTrans")))
    _set_opt(gtransp, "dFinTras", _date_only(transporte_dict.get("finFechaEstimadaTrans")))
    pais_dest = _s(transporte_dict.get("paisDest"))
    if pais_dest:
        _ensure_child_ns(gtransp, "cPaisDest", ns_uri).text = pais_dest
        _set_opt(gtransp, "dDesPaisDest", _s(transporte_dict.get("paisDestDesc")))

    def _build_loc(parent: ET.Element, tag: str, loc_data: dict, suffix: str, label: str) -> None:
        if not isinstance(loc_data, dict):
            raise RuntimeError(f"Transporte {label}: bloque inválido.")
        d_dir = _s(loc_data.get("direccion"))
        d_num = _s(loc_data.get("numCasa"))
        c_dep = _zfill_digits(loc_data.get("departamento"), 2)
        c_dis = _zfill_digits(loc_data.get("distrito"), 4)
        c_ciu = _zfill_digits(loc_data.get("ciudad"), 5)
        if not d_dir:
            raise RuntimeError(f"Transporte {label}: falta direccion.")
        if not d_num:
            raise RuntimeError(f"Transporte {label}: falta numCasa.")
        if not c_dep:
            raise RuntimeError(f"Transporte {label}: falta departamento.")
        if not c_ciu:
            raise RuntimeError(f"Transporte {label}: falta ciudad.")

        loc = _ensure_child_ns(parent, tag, ns_uri)
        _ensure_child_ns(loc, f"dDirLoc{suffix}", ns_uri).text = d_dir
        _ensure_child_ns(loc, f"dNumCas{suffix}", ns_uri).text = d_num
        _set_opt(loc, f"dComp1{suffix}", _s(loc_data.get("comp1")))
        _set_opt(loc, f"dComp2{suffix}", _s(loc_data.get("comp2")))
        _ensure_child_ns(loc, f"cDep{suffix}", ns_uri).text = c_dep
        _ensure_child_ns(loc, f"dDesDep{suffix}", ns_uri).text = _geo_name("dep", c_dep) or "CAPITAL"
        if c_dis:
            _ensure_child_ns(loc, f"cDis{suffix}", ns_uri).text = c_dis
            _ensure_child_ns(loc, f"dDesDis{suffix}", ns_uri).text = _geo_name("dist", c_dis) or "ASUNCION"
        _ensure_child_ns(loc, f"cCiu{suffix}", ns_uri).text = c_ciu
        _ensure_child_ns(loc, f"dDesCiu{suffix}", ns_uri).text = _geo_name("city", c_ciu) or "ASUNCION (DISTRITO)"
        _set_opt(loc, f"dTel{suffix}", _s(loc_data.get("telefono")))

    _build_loc(gtransp, "gCamSal", transporte_dict.get("salida") or {}, "Sal", "salida")
    _build_loc(gtransp, "gCamEnt", transporte_dict.get("entrega") or {}, "Ent", "entrega")

    veh = transporte_dict.get("vehiculo") or {}
    if not isinstance(veh, dict):
        veh = {}
    veh_tipo = _s(veh.get("tipo"))
    veh_marca = _s(veh.get("marca"))
    veh_doc_tipo = _s(veh.get("documentoTipo"))
    veh_num = _s(veh.get("numeroIden") or veh.get("numeroMat"))
    if not veh_tipo:
        raise RuntimeError("Vehículo: falta tipo.")
    if not veh_marca:
        raise RuntimeError("Vehículo: falta marca.")
    if veh_doc_tipo not in ("1", "2"):
        raise RuntimeError("Vehículo: falta documentoTipo (dTipIdenVeh=1|2).")
    if not veh_num:
        raise RuntimeError("Vehículo: falta numeroIden / numeroMat.")

    gveh = _ensure_child_ns(gtransp, "gVehTras", ns_uri)
    _ensure_child_ns(gveh, "dTiVehTras", ns_uri).text = VEH_TIPO_MAP.get(veh_tipo, veh_tipo)
    _ensure_child_ns(gveh, "dMarVeh", ns_uri).text = veh_marca
    _ensure_child_ns(gveh, "dTipIdenVeh", ns_uri).text = veh_doc_tipo
    if veh_doc_tipo == "1":
        _ensure_child_ns(gveh, "dNroMatVeh", ns_uri).text = veh_num
    else:
        _ensure_child_ns(gveh, "dNroIDVeh", ns_uri).text = veh_num
    _set_opt(gveh, "dAdicVeh", _s(veh.get("adic")))
    _set_opt(gveh, "dNroVuelo", _s(veh.get("numeroVuelo")))

    trans = transporte_dict.get("transportista") or {}
    if not isinstance(trans, dict):
        trans = {}
    # Matriz Fase 1: gCamTrans opcional solo cuando iModTrans=1 y dTipIdenVeh=1.
    camtrans_required = not (i_mod == "1" and veh_doc_tipo == "1")
    if camtrans_required and not trans:
        raise RuntimeError("Transportista: bloque requerido para esta modalidad de transporte.")
    if trans:
        gcamtrans = _ensure_child_ns(gtransp, "gCamTrans", ns_uri)
        nat = _s(trans.get("iNatTrans") or trans.get("tipo")) or "1"
        nom = _s(trans.get("dNomTrans") or trans.get("nombreTr"))
        num_tr = _s(trans.get("numeroTr") or trans.get("dNumIDTrans"))
        tip_id_trans = _s(trans.get("iTipIDTrans") or trans.get("tipoDocumentoTr"))
        num_ch = _s(trans.get("dNumIDChof") or trans.get("numeroCh"))
        nom_ch = _s(trans.get("dNomChof") or trans.get("nombreCh"))
        dom_fisc = _s(trans.get("dDomFisc") or trans.get("direccionTr"))
        dir_ch = _s(trans.get("dDirChof") or trans.get("direccionCh"))
        if not nom:
            raise RuntimeError("Transportista: falta nombreTr.")
        if not num_ch:
            raise RuntimeError("Transportista: falta numeroCh.")
        if not nom_ch:
            raise RuntimeError("Transportista: falta nombreCh.")
        if not dom_fisc:
            raise RuntimeError("Transportista: falta direccionTr.")
        if not dir_ch:
            raise RuntimeError("Transportista: falta direccionCh.")

        _ensure_child_ns(gcamtrans, "iNatTrans", ns_uri).text = nat
        _ensure_child_ns(gcamtrans, "dNomTrans", ns_uri).text = nom

        ruc_trans, dv_trans = _split_ruc_dv(num_tr)
        if ruc_trans:
            _ensure_child_ns(gcamtrans, "dRucTrans", ns_uri).text = ruc_trans
            if dv_trans:
                _ensure_child_ns(gcamtrans, "dDVTrans", ns_uri).text = dv_trans
        else:
            if tip_id_trans:
                _ensure_child_ns(gcamtrans, "iTipIDTrans", ns_uri).text = tip_id_trans
                _ensure_child_ns(gcamtrans, "dDTipIDTrans", ns_uri).text = AFE_ID_MAP.get(tip_id_trans, "Cédula paraguaya")
            if num_tr:
                _ensure_child_ns(gcamtrans, "dNumIDTrans", ns_uri).text = num_tr

        c_nac = _s(trans.get("cNacTrans") or trans.get("nacionalidad"))
        if c_nac:
            _ensure_child_ns(gcamtrans, "cNacTrans", ns_uri).text = c_nac
            _set_opt(gcamtrans, "dDesNacTrans", _s(trans.get("dDesNacTrans")))

        _ensure_child_ns(gcamtrans, "dNumIDChof", ns_uri).text = num_ch
        _ensure_child_ns(gcamtrans, "dNomChof", ns_uri).text = nom_ch
        _ensure_child_ns(gcamtrans, "dDomFisc", ns_uri).text = dom_fisc
        _ensure_child_ns(gcamtrans, "dDirChof", ns_uri).text = dir_ch

def _validate_remision_transport_before_sign(xml_bytes: bytes) -> None:
    ns_uri = "http://ekuatia.set.gov.py/sifen/xsd"
    ns = {"s": ns_uri}
    root = ET.fromstring(xml_bytes)
    gtransp = root.find(".//s:gDtipDE/s:gTransp", ns)
    if gtransp is None:
        raise RuntimeError("Remisión inválida antes de firmar: falta gTransp.")
    if len(list(gtransp)) == 0:
        raise RuntimeError("Remisión inválida antes de firmar: gTransp no puede estar vacío.")

    def _has_text(path: str) -> bool:
        el = gtransp.find(path, ns)
        return el is not None and bool((el.text or "").strip())

    missing = []
    if not _has_text("s:iModTrans"):
        missing.append("iModTrans")
    if not _has_text("s:iRespFlete"):
        missing.append("iRespFlete")
    if gtransp.find("s:gCamSal", ns) is None:
        missing.append("gCamSal")
    if gtransp.find("s:gCamEnt", ns) is None:
        missing.append("gCamEnt")
    gveh = gtransp.find("s:gVehTras", ns)
    if gveh is None:
        missing.append("gVehTras")
    i_mod = (gtransp.findtext("s:iModTrans", default="", namespaces=ns) or "").strip()
    veh_tip = (gtransp.findtext("s:gVehTras/s:dTipIdenVeh", default="", namespaces=ns) or "").strip()
    needs_camtrans = not (i_mod == "1" and veh_tip == "1")
    if needs_camtrans and gtransp.find("s:gCamTrans", ns) is None:
        missing.append("gCamTrans")

    if missing:
        raise RuntimeError("Remisión inválida antes de firmar: faltan " + ", ".join(missing) + " en gTransp.")

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

    # ARAVO FIX: SIFEN espera hora PY (America/Asuncion) sin offset
    from datetime import datetime, timezone
    now_py_dt = datetime.now(tz=SIFEN_TZ)

    # Si el caller pasa issue_dt (tests/override), usarlo como fecha de emisión.
    if issue_dt is not None:
        dt = issue_dt
        if dt.tzinfo is None:
            # issue_dt naive suele venir en UTC (DB/now_iso). Convertir a PY.
            dt = dt.replace(tzinfo=timezone.utc).astimezone(SIFEN_TZ)
        else:
            dt = dt.astimezone(SIFEN_TZ)
    else:
        dt = now_py_dt

    now = dt
    iso = dt.strftime("%Y-%m-%dT%H:%M:%S")
    _update_text(root, ".//s:gDatGralOpe/s:dFeEmiDE", iso, ns)
    _update_text(root, ".//s:dFecFirma", iso, ns)
    # ARAVO GUARDRAIL: si por algún bug quedara adelantado, abortar antes de enviar
    iso_dt = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=SIFEN_TZ)
    delta = (iso_dt - now_py_dt).total_seconds()
    if delta > 60:
        raise RuntimeError("ARAVO: timestamp adelantado iso={} now_py={} +{:.0f}s (bloqueado)".format(iso, now_py_dt.strftime("%Y-%m-%dT%H:%M:%S"), delta))

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

            # comparar contra la fecha real de emisión del DE (no contra "now")
            fe_emi = _text(".//s:gDatGralOpe/s:dFeEmiDE") or iso
            fe_emi_date = datetime.fromisoformat(fe_emi[:19]).date()
            if fe_emi_date < fe_ini_date:
                raise RuntimeError(
                    f"Fecha de emisión {fe_emi_date.isoformat()} anterior al inicio de timbrado {fe_ini_date.isoformat()}."
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

    if doc_type == "4":
        _sync_afe_receiver_with_emitter(root, ns, ns_uri)

    extra_json = extra_json or {}

    # Ajustes por tipo de documento
    gdtip = root.find(".//s:gDtipDE", ns)
    if gdtip is None:
        raise RuntimeError("No se encontró <gDtipDE> en el XML base.")
    if doc_type != "1":
        _remove_child_ns(gdtip, "gCamFE", ns_uri)
    if doc_type not in ("1", "4", "7"):
        _remove_child_ns(gdtip, "gCamCond", ns_uri)
    if doc_type in ("5", "6"):
        gopecom = root.find(".//s:gDatGralOpe/s:gOpeCom", ns)
        if gopecom is not None:
            _remove_child_ns(gopecom, "iTipTra", ns_uri)
            _remove_child_ns(gopecom, "dDesTipTra", ns_uri)

    # dInfoFisc obligatorio para Remisión
    if doc_type == "7":
        info_fisc = extra_json.get("dInfoFisc") or extra_json.get("infoFisc") or "Traslado de mercaderías"
        gopede = root.find(".//s:gOpeDE", ns)
        if gopede is not None:
            _ensure_child_ns(gopede, "dInfoFisc", ns_uri).text = str(info_fisc)

    afe_payload = None
    # gCamAE (Autofactura)
    if doc_type == "4":
        afe = _afe_vendor_from_extra(extra_json)
        _remove_child_ns(gdtip, "gCamAE", ns_uri)
        i_nat = _afe_pick(afe, "iNatVen", "naturaleza", "tipo_vendedor")
        if i_nat not in AFE_NAT_MAP:
            raise RuntimeError("Autofactura: falta tipo_vendedor (iNatVen 1/2).")

        i_tip_id = _afe_pick(afe, "iTipIDVen", "tipoDocumento", "tipo_doc")
        if i_tip_id not in AFE_ID_MAP:
            raise RuntimeError("Autofactura: falta tipo_doc_identidad (iTipIDVen).")

        num_id = _afe_pick(afe, "dNumIDVen", "documento", "nro_doc", "nro_doc_identidad")
        if not num_id:
            raise RuntimeError("Autofactura: falta nro_doc_identidad (dNumIDVen).")

        nombre = _afe_pick(afe, "dNomVen", "nombre", "nombre_apellido_o_razon")
        if not nombre:
            raise RuntimeError("Autofactura: falta nombre del vendedor (dNomVen).")

        def _emval(path: str) -> str:
            el = root.find(path, ns)
            return (el.text or "").strip() if el is not None and el.text else ""

        dir_ven = _afe_pick(afe, "dDirVen", "direccion", "direccionVendedor")
        if not dir_ven:
            raise RuntimeError("Autofactura: falta dirección del vendedor (dDirVen).")
        num_cas_ven = _afe_pick(afe, "dNumCasVen", "numCasa")
        if not num_cas_ven:
            raise RuntimeError("Autofactura: falta número de casa (dNumCasVen).")

        dep_ven = _afe_pick(afe, "cDepVen", "departamentoVendedor", "departamento")
        if not dep_ven:
            raise RuntimeError("Autofactura: falta departamento del vendedor (cDepVen).")
        des_dep_ven = _afe_pick(afe, "dDesDepVen") or _geo_name("dep", dep_ven) or _emval(".//s:gEmis/s:dDesDepEmi")

        dis_ven = _afe_pick(afe, "cDisVen", "distritoVendedor", "distrito")
        des_dis = _afe_pick(afe, "dDesDisVen") or (_geo_name("dist", dis_ven) if dis_ven else None)

        ciu_ven = _afe_pick(afe, "cCiuVen", "ciudadVendedor", "ciudad")
        if not ciu_ven:
            raise RuntimeError("Autofactura: falta ciudad del vendedor (cCiuVen).")
        des_ciu_ven = _afe_pick(afe, "dDesCiuVen") or _geo_name("city", ciu_ven) or _emval(".//s:gEmis/s:dDesCiuEmi")

        dir_prov = _afe_pick(afe, "dDirProv", "direccionProv") or dir_ven
        dep_prov = _afe_pick(afe, "cDepProv", "departamentoProv") or dep_ven
        des_dep_prov = _afe_pick(afe, "dDesDepProv") or _geo_name("dep", dep_prov) or des_dep_ven
        ciu_prov = _afe_pick(afe, "cCiuProv", "ciudadProv") or ciu_ven
        des_ciu_prov = _afe_pick(afe, "dDesCiuProv") or _geo_name("city", ciu_prov) or des_ciu_ven

        dis_prov = _afe_pick(afe, "cDisProv", "distritoProv")
        des_dis_p = _afe_pick(afe, "dDesDisProv") or (_geo_name("dist", dis_prov) if dis_prov else None)

        afe_payload = {
            "iNatVen": i_nat,
            "dDesNatVen": AFE_NAT_MAP.get(i_nat, "No contribuyente"),
            "iTipIDVen": i_tip_id,
            "dDTipIDVen": AFE_ID_MAP.get(i_tip_id, "Cédula paraguaya"),
            "dNumIDVen": num_id,
            "dNomVen": nombre,
            "dDirVen": dir_ven,
            "dNumCasVen": num_cas_ven,
            "cDepVen": dep_ven,
            "dDesDepVen": des_dep_ven,
            "cDisVen": dis_ven,
            "dDesDisVen": des_dis,
            "cCiuVen": ciu_ven,
            "dDesCiuVen": des_ciu_ven,
            "dDirProv": dir_prov,
            "cDepProv": dep_prov,
            "dDesDepProv": des_dep_prov,
            "cDisProv": dis_prov,
            "dDesDisProv": des_dis_p,
            "cCiuProv": ciu_prov,
            "dDesCiuProv": des_ciu_prov,
        }

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


    # gCamCond (Condición de la operación) - requerido por orden XSD antes de gTransp en Remisión.
    # Normalizamos estructura mínima incluso si la plantilla ya trae gCamCond.
    if doc_type == "7":
        gcamcond = _ensure_child_ns(gdtip, "gCamCond", ns_uri)
        icond = _ensure_child_ns(gcamcond, "iCondOpe", ns_uri)
        if not (icond.text or "").strip():
            icond.text = "1"
        dcond = _ensure_child_ns(gcamcond, "dDCondOpe", ns_uri)
        if not (dcond.text or "").strip():
            dcond.text = "Contado"
        gpa = _ensure_child_ns(gcamcond, "gPaConEIni", ns_uri)
        itipago = _ensure_child_ns(gpa, "iTiPago", ns_uri)
        if not (itipago.text or "").strip():
            itipago.text = "1"
        dtipago = _ensure_child_ns(gpa, "dDesTiPag", ns_uri)
        if not (dtipago.text or "").strip():
            dtipago.text = "Efectivo"
        # Nota: montos se recalculan en otros pasos; dejamos placeholder mínimo válido.
        dmonto = _ensure_child_ns(gpa, "dMonTiPag", ns_uri)
        if not (dmonto.text or "").strip():
            dmonto.text = "0"
        cmon = _ensure_child_ns(gpa, "cMoneTiPag", ns_uri)
        if not (cmon.text or "").strip():
            cmon.text = "PYG"
        dmon = _ensure_child_ns(gpa, "dDMoneTiPag", ns_uri)
        if not (dmon.text or "").strip():
            dmon.text = "Guarani"

    # Ítems y totales base (necesarios para CDC, PDF y gTotSub)
    if not lines:
        raise RuntimeError("La factura no tiene líneas.")

    qty_places = _infer_places_from_xpath(root, ".//s:gDtipDE/s:gCamItem/s:dCantProSer", ns, 2)
    money_places_default = _infer_places_from_xpath(root, ".//s:gDtipDE/s:gCamItem/s:gValorItem/s:dPUniProSer", ns, 0)
    base_places = _infer_places_from_xpath(root, ".//s:gDtipDE/s:gCamItem/s:gCamIVA/s:dBasGravIVA", ns, 4)
    iva_places = _infer_places_from_xpath(root, ".//s:gDtipDE/s:gCamItem/s:gCamIVA/s:dLiqIVAItem", ns, 4)

    sub_exe = Decimal("0")
    sub_exo = Decimal("0")
    sub5 = Decimal("0")
    sub10 = Decimal("0")
    base5 = Decimal("0")
    base10 = Decimal("0")
    iva5 = Decimal("0")
    iva10 = Decimal("0")
    total = Decimal("0")
    items_for_pdf = []

    existing_items = gdtip.findall("s:gCamItem", ns)
    if not existing_items:
        raise RuntimeError("La plantilla no contiene gCamItem.")
    item_template = copy.deepcopy(existing_items[0])
    for it in existing_items:
        gdtip.remove(it)

    for idx, line in enumerate(lines, start=1):
        desc = str(_line_get(line, "description", "") or f"Item {idx}")
        qty = _to_decimal(_line_get(line, "qty"), Decimal("0")) or Decimal("0")
        price_unit = _to_decimal(_line_get(line, "price_unit"), Decimal("0")) or Decimal("0")
        line_total = _to_decimal(_line_get(line, "line_total"), None)
        if line_total is None:
            line_total = qty * price_unit

        try:
            iva_rate = int(str(_line_get(line, "iva_rate", 10) or "10"))
        except Exception:
            iva_rate = 10
        if iva_rate not in (0, 5, 10):
            iva_rate = 10

        item = copy.deepcopy(item_template)
        _update_text(item, "s:dCodInt", str(idx).zfill(3), ns)
        _update_text(item, "s:dDesProSer", desc, ns)
        _update_text(item, "s:dCantProSer", _fmt_decimal_places(qty, qty_places), ns)

        gvalor = item.find("s:gValorItem", ns)
        giva = item.find("s:gCamIVA", ns)

        if doc_type == "7":
            if gvalor is not None:
                item.remove(gvalor)
            if giva is not None:
                item.remove(giva)
        else:
            _update_text(item, "s:gValorItem/s:dPUniProSer", _fmt_decimal_places(price_unit, money_places_default), ns)
            _update_text(item, "s:gValorItem/s:dTotBruOpeItem", _fmt_decimal_places(line_total, money_places_default), ns)
            _update_text(item, "s:gValorItem/s:gValorRestaItem/s:dTotOpeItem", _fmt_decimal_places(line_total, money_places_default), ns)

            if doc_type == "4":
                if giva is not None:
                    item.remove(giva)
            elif giva is not None:
                if iva_rate in (5, 10):
                    divisor = Decimal("1.05") if iva_rate == 5 else Decimal("1.10")
                    base_line = (line_total / divisor).quantize(Decimal("1.0000"), rounding=ROUND_HALF_UP)
                    iva_line = (line_total - base_line).quantize(Decimal("1.0000"), rounding=ROUND_HALF_UP)
                else:
                    base_line = Decimal("0")
                    iva_line = Decimal("0")
                _update_text(item, "s:gCamIVA/s:dTasaIVA", str(iva_rate), ns)
                _update_text(item, "s:gCamIVA/s:dBasGravIVA", _fmt_decimal_places(base_line, base_places), ns)
                _update_text(item, "s:gCamIVA/s:dLiqIVAItem", _fmt_decimal_places(iva_line, iva_places), ns)
                _update_text(item, "s:gCamIVA/s:dBasExe", "0", ns)

        gdtip.append(item)

        total += line_total
        if doc_type != "7":
            if iva_rate == 5:
                sub5 += line_total
                base_line = (line_total / Decimal("1.05")).quantize(Decimal("1.0000"), rounding=ROUND_HALF_UP)
                base5 += base_line
                iva5 += (line_total - base_line).quantize(Decimal("1.0000"), rounding=ROUND_HALF_UP)
            elif iva_rate == 10:
                sub10 += line_total
                base_line = (line_total / Decimal("1.10")).quantize(Decimal("1.0000"), rounding=ROUND_HALF_UP)
                base10 += base_line
                iva10 += (line_total - base_line).quantize(Decimal("1.0000"), rounding=ROUND_HALF_UP)
            else:
                sub_exe += line_total

        items_for_pdf.append(
            {
                "descripcion": desc,
                "cantidad": float(qty),
                "precio_unit": float(price_unit),
                "iva": str(iva_rate),
                "total": float(line_total),
            }
        )

    if doc_type == "4" and afe_payload:
        gcam = _ensure_child_ns(gdtip, "gCamAE", ns_uri)
        for tag in (
            "iNatVen",
            "dDesNatVen",
            "iTipIDVen",
            "dDTipIDVen",
            "dNumIDVen",
            "dNomVen",
            "dDirVen",
            "dNumCasVen",
            "cDepVen",
            "dDesDepVen",
            "cDisVen",
            "dDesDisVen",
            "cCiuVen",
            "dDesCiuVen",
            "dDirProv",
            "cDepProv",
            "dDesDepProv",
            "cDisProv",
            "dDesDisProv",
            "cCiuProv",
            "dDesCiuProv",
        ):
            val = afe_payload.get(tag, "")
            if val:
                _ensure_child_ns(gcam, tag, ns_uri).text = val

        try:
            # AFE XSD: gCamAE debe ir antes de gCamNCDE/gCamNRE/gCamCond/gCamItem/gCamEsp/gTransp.
            def _loc(t):
                return t.split("}", 1)[1] if "}" in t else t

            later_names = {"gCamNCDE", "gCamNRE", "gCamCond", "gCamItem", "gCamEsp", "gTransp"}
            later_nodes = [x for x in list(gdtip) if x is not gcam and _loc(getattr(x, "tag", "")) in later_names]
            if later_nodes:
                first_later = later_nodes[0]
                cur = list(gdtip)
                if gcam in cur and cur.index(gcam) > cur.index(first_later):
                    gdtip.remove(gcam)
                    cur2 = list(gdtip)
                    gdtip.insert(cur2.index(first_later), gcam)
        except Exception:
            pass

    iva_total = (iva5 + iva10).quantize(Decimal("1.0000"), rounding=ROUND_HALF_UP)
    base_total = (base5 + base10).quantize(Decimal("1.0000"), rounding=ROUND_HALF_UP)
    total_str = _fmt_decimal_places(total, money_places_default)
    base_total_str = _fmt_decimal_places(base_total, base_places)
    iva_total_str = _fmt_decimal_places(iva_total, iva_places)
    cdc_total_str = _fmt_decimal_places(total, 0)

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
        transporte = _get_transport_from_extra(extra_json)
        if doc_type == "7" and not transporte:
            raise RuntimeError("doc_extra_json.transporte requerido para Remisión (iTiDE=7).")
        if transporte:
            _build_gtransp_from_extra(gdtip, ns_uri, transporte)

            # Asegurar orden XSD en gDtipDE: gCamNRE, gCamCond, gCamItem, gTransp
            try:
                kids = list(gdtip)

                def _loc(t): return t.split("}", 1)[1] if "}" in t else t

                def _find_one(name):
                    return next((x for x in list(gdtip) if _loc(getattr(x, "tag", "")) == name), None)

                def _find_all(name):
                    return [x for x in list(gdtip) if _loc(getattr(x, "tag", "")) == name]

                def _move_before(node, ref):
                    if node is None or ref is None:
                        return
                    cur = list(gdtip)
                    if node not in cur or ref not in cur:
                        return
                    if cur.index(node) < cur.index(ref):
                        return
                    gdtip.remove(node)
                    cur2 = list(gdtip)
                    gdtip.insert(cur2.index(ref), node)

                def _move_after(node, ref):
                    if node is None or ref is None:
                        return
                    cur = list(gdtip)
                    if node not in cur or ref not in cur:
                        return
                    if cur.index(node) > cur.index(ref):
                        return
                    gdtip.remove(node)
                    cur2 = list(gdtip)
                    gdtip.insert(cur2.index(ref) + 1, node)

                nre   = _find_one("gCamNRE")
                cond  = _find_one("gCamCond")
                tr    = _find_one("gTransp")
                items = _find_all("gCamItem")

                # 1) gCamNRE debe ir antes que gCamCond (si existen ambos)
                _move_before(nre, cond)

                # 2) gCamItem debe ir después de gCamCond (si existe), sino después de gCamNRE
                anchor = cond or nre
                if anchor is not None and items:
                    # remover y reinsertar items manteniendo orden original
                    for it in items:
                        if it in list(gdtip):
                            gdtip.remove(it)
                    cur = list(gdtip)
                    pos = cur.index(anchor) + 1
                    for it in items:
                        gdtip.insert(pos, it)
                        pos += 1

                # 3) gTransp debe ir después del último gCamItem (si hay items)
                if tr is not None:
                    cur = list(gdtip)
                    items_now = [x for x in cur if _loc(getattr(x, "tag", "")) == "gCamItem"]
                    if items_now:
                        last_item = items_now[-1]
                        if cur.index(tr) < cur.index(last_item):
                            gdtip.remove(tr)
                            cur2 = list(gdtip)
                            gdtip.insert(cur2.index(last_item) + 1, tr)
                    else:
                        # sin items, al menos después de gCamCond/gCamNRE si existen
                        _move_after(tr, cond or nre)
            except Exception:
                pass
        elif doc_type == "1":
            _remove_child_ns(gdtip, "gTransp", ns_uri)
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

            # Asegurar orden XSD en gTotSub (DE_v150.xsd tgTotSub)
            # Nota: _ensure_child_ns() agrega al final si falta el tag, y el template puede traer dTBasGraIVA,
            # por eso debemos reordenar para evitar que dBaseGrav* quede después de dTBasGraIVA.
            try:
                def _loc(t):
                    return t.split("}", 1)[1] if "}" in t else t

                xsd_order = [
                    "dSubExe","dSubExo","dSub5","dSub10",
                    "dTotOpe","dTotDesc","dTotDescGlotem","dTotAntItem","dTotAnt",
                    "dPorcDescTotal","dDescTotal","dAnticipo","dRedon","dComi",
                    "dTotGralOpe","dIVA5","dIVA10","dLiqTotIVA5","dLiqTotIVA10","dIVAComi","dTotIVA",
                    "dBaseGrav5","dBaseGrav10","dTBasGraIVA","dTotalGs",
                ]

                kids = list(gtot)
                by_name = {}
                rest = []
                for k in kids:
                    name = _loc(getattr(k, "tag", ""))
                    if name in xsd_order and name not in by_name:
                        by_name[name] = k
                    else:
                        rest.append(k)

                # Limpiar y reinsertar en orden
                for k in kids:
                    try:
                        gtot.remove(k)
                    except Exception:
                        pass

                for name in xsd_order:
                    k = by_name.get(name)
                    if k is not None:
                        gtot.append(k)
                for k in rest:
                    gtot.append(k)
            except Exception:
                pass

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
        elif tip_doc_aso == "3":
            tip_cons = _resolve_afe_constancia_type(extra_json, assoc)
            if not tip_cons:
                raise RuntimeError("documentoAsociado.tipoConstancia/iTipCons requerido para iTipDocAso=3 en Autofactura")
            _ensure_child_ns(gcam, "iTipCons", ns_uri).text = tip_cons
            _ensure_child_ns(gcam, "dDesTipCons", ns_uri).text = CONSTANCIA_TYPE_MAP[tip_cons]

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
            base_url = "https://ekuatia.set.gov.py/consultas/qr"
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

    def _join_code_desc(code: str, desc: str) -> str:
        code = (code or "").strip()
        desc = (desc or "").strip()
        if code and desc:
            return f"{code} - {desc}"
        return code or desc

    def _code_desc_from(tag_code: str, tag_desc: str, mapping: Optional[dict] = None) -> str:
        code = find_tag(tag_code)
        desc = find_tag(tag_desc)
        if not desc and code and mapping:
            desc = mapping.get(code, "")
        return _join_code_desc(code, desc)

    def _append_num_casa(address: str, num_casa: str) -> str:
        address = (address or "").strip()
        num_casa = (num_casa or "").strip()
        if not address:
            return address
        if not num_casa:
            return address
        addr_lower = address.lower()
        if all(token not in addr_lower for token in ("nr", "nro", "n°", "nº")):
            return f"{address} Nr. {num_casa}"
        return address

    def _section(title: str, items: list[tuple[str, str]], *, fill_missing: bool = False) -> Optional[dict]:
        cleaned: list[tuple[str, str]] = []
        has_value = False
        for label, value in items:
            val = (value or "").strip()
            if val:
                has_value = True
                cleaned.append((label, val))
            elif fill_missing:
                cleaned.append((label, "—"))
        if not cleaned or not has_value:
            return None
        return {"title": title, "items": cleaned}

    doc_type = normalize_doc_type(
        find_tag("iTiDE") or (invoice["doc_type"] if "doc_type" in invoice.keys() else "")
    )
    pdf_header_title = {
        "1": "Factura electrónica",
        "4": "Autofactura electrónica",
        "5": "Nota de crédito electrónica",
        "6": "Nota de débito electrónica",
        "7": "Nota de remisión electrónica",
    }.get(doc_type, "Factura electrónica")

    extra_sections: list[dict] = []

    if doc_type == "4":
        dir_ven = _append_num_casa(find_tag("dDirVen"), find_tag("dNumCasVen"))
        dep_ven = _join_code_desc(find_tag("cDepVen"), find_tag("dDesDepVen"))
        ciu_ven = _join_code_desc(find_tag("cCiuVen"), find_tag("dDesCiuVen"))
        section = _section(
            "Datos del vendedor (AFE)",
            [
                ("Naturaleza", _code_desc_from("iNatVen", "dDesNatVen", AFE_NAT_MAP)),
                ("Tipo doc.", _code_desc_from("iTipIDVen", "dDTipIDVen", AFE_ID_MAP)),
                ("Nro doc.", find_tag("dNumIDVen")),
                ("Nombre", find_tag("dNomVen")),
                ("Dirección", dir_ven),
                ("Departamento", dep_ven),
                ("Ciudad", ciu_ven),
            ],
            fill_missing=True,
        )
        if section:
            extra_sections.append(section)

    if doc_type in ("5", "6"):
        section = _section(
            "Documento asociado",
            [
                ("Tipo doc. asociado", _code_desc_from("iTipDocAso", "dDesTipDocAso", DOC_ASOC_TYPE_MAP)),
                ("CDC asociado", find_tag("dCdCDERef")),
            ],
            fill_missing=True,
        )
        if section:
            extra_sections.append(section)

        section = _section(
            "Motivo",
            [
                ("Motivo emisión", _code_desc_from("iMotEmi", "dDesMotEmi", NC_MOTIVO_MAP)),
            ],
            fill_missing=True,
        )
        if section:
            extra_sections.append(section)

    if doc_type == "7":
        resp_flete_code = find_tag("iRespFlete")
        resp_flete = _join_code_desc(resp_flete_code, RESP_FLETE_MAP.get(resp_flete_code, ""))
        section = _section(
            "Remisión / Transporte",
            [
                ("Motivo remisión", _code_desc_from("iMotEmiNR", "dDesMotEmiNR", REM_MOTIVO_MAP)),
                ("Responsable emisión", _code_desc_from("iRespEmiNR", "dDesRespEmiNR", REM_RESP_MAP)),
                ("Km recorridos", find_tag("dKmR")),
                ("Fecha emisión", find_tag("dFecEm")),
                ("Tipo transporte", _code_desc_from("iTipTrans", "dDesTipTrans", TRANS_TIPO_MAP)),
                ("Modalidad transporte", _code_desc_from("iModTrans", "dDesModTrans", TRANS_MOD_MAP)),
                ("Responsable flete", resp_flete),
            ],
            fill_missing=True,
        )
        if section:
            extra_sections.append(section)

        def _loc_section(title: str, suffix: str) -> Optional[dict]:
            dir_loc = _append_num_casa(find_tag(f"dDirLoc{suffix}"), find_tag(f"dNumCas{suffix}"))
            dep_loc = _join_code_desc(find_tag(f"cDep{suffix}"), find_tag(f"dDesDep{suffix}"))
            ciu_loc = _join_code_desc(find_tag(f"cCiu{suffix}"), find_tag(f"dDesCiu{suffix}"))
            tel_loc = find_tag(f"dTel{suffix}")
            return _section(
                title,
                [
                    ("Dirección", dir_loc),
                    ("Departamento", dep_loc),
                    ("Ciudad", ciu_loc),
                    ("Teléfono", tel_loc),
                ],
                fill_missing=True,
            )

        sal_section = _loc_section("Salida", "Sal")
        if sal_section:
            extra_sections.append(sal_section)
        ent_section = _loc_section("Entrega", "Ent")
        if ent_section:
            extra_sections.append(ent_section)

        veh_id = _join_code_desc(find_tag("dTipIdenVeh"), find_tag("dNroMatVeh") or find_tag("dNroIDVeh"))
        section = _section(
            "Vehículo",
            [
                ("Tipo", find_tag("dTiVehTras")),
                ("Marca", find_tag("dMarVeh")),
                ("Identificación / Número", veh_id),
            ],
            fill_missing=True,
        )
        if section:
            extra_sections.append(section)

        trans_doc = ""
        ruc_trans = find_tag("dRucTrans")
        dv_trans = find_tag("dDVTrans")
        if ruc_trans:
            trans_doc = ruc_trans + (f"-{dv_trans}" if dv_trans else "")
        else:
            trans_doc = _join_code_desc(find_tag("iTipIDTrans"), find_tag("dNumIDTrans"))

        section = _section(
            "Transportista / Chofer",
            [
                ("Transportista", find_tag("dNomTrans")),
                ("Documento", trans_doc),
                ("Domicilio", find_tag("dDomFisc")),
                ("Chofer", find_tag("dNomChof")),
                ("Doc. chofer", find_tag("dNumIDChof")),
                ("Dir. chofer", find_tag("dDirChof")),
            ],
            fill_missing=True,
        )
        if section:
            extra_sections.append(section)

    rec_name = find_tag("dNomRec") or ((invoice["customer_name"] if "customer_name" in invoice.keys() else "") or "")
    rec_ruc_raw = find_tag("dRucRec") or cust_ruc
    rec_dv_raw = find_tag("dDVRec")
    ruc_main, ruc_dv = _split_ruc_dv(rec_ruc_raw)
    if rec_dv_raw:
        ruc_dv = rec_dv_raw
    rec_email = find_tag("dEmailRec") or ((invoice["customer_email"] if "customer_email" in invoice.keys() else "") or "")

    dir_rec = _append_num_casa(find_tag("dDirRec"), find_tag("dNumCasRec"))
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
        "dNomRec": rec_name,
        "dRucRec": ruc_main,
        "dDVRec": ruc_dv,
        "dEmailRec": rec_email,
        "dDirRec": dir_rec,
        "dTelRec": tel_rec,
        "dDCondOpe": cond_venta,
        "dNumRem": remision,
    }
    default_logo_path = ""
    try:
        cand = _repo_root() / "assets" / "industria-feris-isotipo.jpg"
        if cand.exists():
            default_logo_path = str(cand)
    except Exception:
        default_logo_path = ""

    return {
        "CDC": cdc,
        "parsed_fields": parsed_fields,
        "items": items_for_pdf,
        "response_xml": response_xml or "",
        "qr_url": qr_url,
        "doc_type": doc_type,
        "pdf_header_title": pdf_header_title,
        "extra_sections": extra_sections,
        "default_logo_path": default_logo_path,
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
    # Prefer explicit env path if it exists; otherwise fallback to our built-in/logo candidates.
    if logo_path and Path(logo_path).exists():
        issuer["logo_path"] = logo_path
    else:
        p, _mt = _find_issuer_logo()
        if p:
            issuer["logo_path"] = str(p)
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
    venv_py = "python3"
    env_used = os.environ.copy()
    last_art_dir = normalize_artifacts_dir(prefer_art_dir or "") or ""
    artifacts_root = _artifacts_root()
    final_status = "CONFIRMING"

    for idx in range(max(1, attempts)):
        args = [
            venv_py, "-m", "sifen_minisender", "consult",
            "--env", env,
            "--prot", prot,
            "--artifacts-dir", str(artifacts_root),
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
        result = client.consulta_de_por_cdc_raw(cdc, dump_http=True)

        # --- persistir artifacts de consulta CDC ---
        try:
            artifacts_root = _artifacts_root()
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            run_dir = Path(artifacts_root) / f"run_{ts}_consulta_de_{env}_invoice_{invoice_id}_cdc_{cdc}"
            run_dir.mkdir(parents=True, exist_ok=True)
            req_xml = (result.get("sent_xml") or "")
            resp_xml = (result.get("raw_xml") or result.get("response_xml") or "")
            (run_dir / "req.xml").write_text(req_xml, encoding="utf-8")
            (run_dir / "resp.xml").write_text(resp_xml, encoding="utf-8")
            meta = {
                "env": env,
                "invoice_id": invoice_id,
                "cdc": cdc,
                "http_status": result.get("http_status"),
            }
            (run_dir / "meta.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
            con.execute("UPDATE invoices SET last_artifacts_dir=COALESCE(?, last_artifacts_dir) WHERE id=?", (str(run_dir), invoice_id))
            con.commit()
        except Exception:
            pass
        # --- end artifacts ---
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
    elif dCodRes in ("0420", "0421", "0423"):
        est = "CDC no encontrado / rechazado"
        if new_status not in ("CONFIRMED_OK", "CONFIRMED_REJECTED"):
            new_status = "CONFIRMED_REJECTED"
    elif dCodRes in ("0420", "0421", "0423"):
        est = "CDC no encontrado / rechazado"
        if new_status not in ("CONFIRMED_OK", "CONFIRMED_REJECTED"):
            new_status = "CONFIRMED_REJECTED"
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
    return BASE_DIR

def _artifacts_root() -> Path:
    raw = (
        (os.getenv("SIFEN_ARTIFACTS_DIR") or "").strip()
        or (os.getenv("ARTIFACTS_DIR") or "").strip()
    )
    if raw:
        root = Path(raw).expanduser()
        if not root.is_absolute():
            root = (_repo_root() / root).resolve()
        else:
            root = root.resolve()
        try:
            root.mkdir(parents=True, exist_ok=True)
            return root
        except Exception:
            pass

    root = (_repo_root() / "data" / "artifacts").resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root

def _safe_resolve_under(base_dir: Path, rel_path: str) -> Optional[Path]:
    try:
        candidate = (base_dir / rel_path).resolve()
        if candidate == base_dir or base_dir in candidate.parents:
            return candidate
    except Exception:
        return None
    return None

def _artifact_relpath(path_value: Optional[str]) -> Optional[str]:
    if not path_value:
        return None
    try:
        p = Path(path_value).expanduser()
        if not p.is_absolute():
            p = (_repo_root() / p).resolve()
        else:
            p = p.resolve()
        root = _artifacts_root()
        if p == root or root in p.parents:
            return p.relative_to(root).as_posix()
    except Exception:
        return None
    return None

def _artifact_url(path_value: Optional[str]) -> Optional[str]:
    rel = _artifact_relpath(path_value)
    if not rel:
        return None
    return url_for("artifact_file", artifact_relpath=rel)


def _parse_bool(value, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    txt = str(value).strip().lower()
    if txt in ("1", "true", "yes", "on", "si", "sí"):
        return True
    if txt in ("0", "false", "no", "off"):
        return False
    return default


def _artifact_links_for_dir(run_dir: Optional[str]) -> dict:
    links = {
        "run_dir": run_dir or None,
        "last_lote_xml": None,
        "last_xde_zip": None,
        "soap_last_request_xml": None,
        "soap_last_response_xml": None,
        "response_json": None,
    }
    art_dir = normalize_artifacts_dir(run_dir or "")
    if not art_dir:
        return links

    p = Path(art_dir)
    if not p.exists() or not p.is_dir():
        return links

    links["last_lote_xml"] = _artifact_url(str(p / "last_lote.xml"))
    links["last_xde_zip"] = _artifact_url(str(p / "last_xde.zip"))
    links["soap_last_request_xml"] = _artifact_url(str(p / "soap_last_request.xml"))
    links["soap_last_response_xml"] = _artifact_url(str(p / "soap_last_response.xml"))

    response_json = None
    for pattern in ("response_recepcion_*.json", "sifen_response.json"):
        cands = sorted(
            p.glob(pattern),
            key=lambda x: x.stat().st_mtime,
            reverse=True,
        )
        if cands:
            response_json = cands[0]
            break
    if response_json is not None:
        links["response_json"] = _artifact_url(str(response_json))
    return links


def _row_get(row: Optional[sqlite3.Row], key: str, default=None):
    if row is None:
        return default
    try:
        if isinstance(row, sqlite3.Row):
            return row[key] if key in row.keys() else default
        if isinstance(row, dict):
            return row.get(key, default)
    except Exception:
        return default
    return default


def _table_columns(con: sqlite3.Connection, table: str) -> set:
    try:
        if table not in {"invoices", "customers"}:
            return set()
        safe_table = table.replace("'", "''")
        rows = con.execute(f"PRAGMA table_info('{safe_table}')").fetchall()
    except Exception:
        return set()
    return {r[1] for r in rows}


def _invoice_api_dict(row: sqlite3.Row) -> dict:
    last_sifen_code = _row_get(row, "last_sifen_code")
    last_lote_code = _row_get(row, "last_lote_code")
    last_event_code = _row_get(row, "last_event_code")
    last_sifen_msg = _row_get(row, "last_sifen_msg")
    last_lote_msg = _row_get(row, "last_lote_msg")
    last_event_msg = _row_get(row, "last_event_msg")
    last_code = last_sifen_code or last_lote_code or last_event_code
    last_message = last_sifen_msg or last_lote_msg or last_event_msg
    sifen_status = _row_get(row, "last_sifen_est") or _row_get(row, "last_event_est")
    return {
        "id": _row_get(row, "id"),
        "customer_id": _row_get(row, "customer_id"),
        "customer_name": _row_get(row, "customer_name"),
        "customer_ruc": _row_get(row, "customer_ruc"),
        "customer_dv": _row_get(row, "customer_dv"),
        "customer_doc_id": _row_get(row, "customer_doc_id"),
        "customer_email": _row_get(row, "customer_email"),
        "customer_phone": _row_get(row, "customer_phone"),
        "status": _row_get(row, "status"),
        "created_at": _row_get(row, "created_at"),
        "issued_at": _row_get(row, "issued_at"),
        "emitted_at": _row_get(row, "issued_at") or _row_get(row, "emitted_at"),
        "queued_at": _row_get(row, "queued_at"),
        "sent_at": _row_get(row, "sent_at"),
        "confirmed_at": _row_get(row, "confirmed_at"),
        "sifen_env": _row_get(row, "sifen_env"),
        "sifen_prot_cons_lote": _row_get(row, "sifen_prot_cons_lote"),
        "last_lote_code": last_lote_code,
        "last_lote_msg": last_lote_msg,
        "last_sifen_code": last_sifen_code,
        "last_sifen_msg": last_sifen_msg,
        "last_sifen_est": _row_get(row, "last_sifen_est"),
        "last_sifen_prot_aut": _row_get(row, "last_sifen_prot_aut"),
        "last_event_code": last_event_code,
        "last_event_msg": last_event_msg,
        "last_event_est": _row_get(row, "last_event_est"),
        "last_code": last_code,
        "last_message": last_message,
        "sifen_status": sifen_status,
        "source_xml_path": _row_get(row, "source_xml_path"),
        "last_artifacts_dir": _row_get(row, "last_artifacts_dir"),
    }

def _latest_send_lote_run() -> Optional[dict]:
    root = _artifacts_root()
    for cand in list_recent_artifacts_dirs(root):
        run_dir = cand
        last_lote = cand / "last_lote.xml"
        if not last_lote.exists():
            nested = sorted(
                cand.glob("*/last_lote.xml"),
                key=lambda x: x.stat().st_mtime,
                reverse=True,
            )
            if not nested:
                continue
            last_lote = nested[0]
            run_dir = last_lote.parent
        response_json = None
        for pattern in ("response_recepcion_*.json", "sifen_response.json"):
            response_cands = sorted(
                run_dir.glob(pattern),
                key=lambda x: x.stat().st_mtime,
                reverse=True,
            )
            if response_cands:
                response_json = response_cands[0]
                break
        return {
            "run_dir": str(run_dir),
            "artifacts": {
                "last_lote_xml": str(last_lote),
                "last_xde_zip": str(run_dir / "last_xde.zip") if (run_dir / "last_xde.zip").exists() else None,
                "soap_request": str(run_dir / "soap_last_request.xml") if (run_dir / "soap_last_request.xml").exists() else None,
                "response_json": str(response_json) if response_json else None,
            },
        }
    return None

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
STATUS_LABELS = {
    "DRAFT": "Borrador",
    "READY": "Listo",
    "PENDING": "Pendiente",
    "QUEUED": "En cola",
    "SENDING": "Enviando",
    "SENT": "Enviado",
    "CONFIRMING": "Confirmando",
    "CONFIRMED": "Confirmado",
    "CONFIRMED_OK": "Confirmado",
    "APPROVED": "Aprobado",
    "REJECTED": "Rechazado",
    "CONFIRMED_REJECTED": "Rechazado",
    "CANCELLED": "Anulado",
    "CANCELLED_OK": "Anulado",
    "CANCELLED_REJECTED": "Anulación rechazada",
    "FAILED": "Error",
    "ERROR": "Error",
    "RETRYING": "Reintentando",
    "EXPIRED": "Vencido",
    "UNKNOWN": "Desconocido",
    "INUTIL_OK": "Inutilizado",
    "INUTIL_REJECTED": "Inutilización rechazada",
    "ACTIVE": "Activo",
    "INACTIVE": "Inactivo",
    "BLOCKED": "Bloqueado",
    "DELETED": "Eliminado",
}

def status_label(status: Optional[str]) -> str:
    if status is None:
        return STATUS_LABELS.get("UNKNOWN", "Desconocido")
    raw = str(status).strip()
    if not raw:
        return STATUS_LABELS.get("UNKNOWN", "Desconocido")
    if raw in STATUS_LABELS:
        return STATUS_LABELS[raw]
    upper = raw.upper()
    return STATUS_LABELS.get(upper, raw)

def badge(status: str) -> str:
    m = {
        "DRAFT": "secondary",
        "READY": "info",
        "PENDING": "warning",
        "QUEUED": "warning",
        "SENDING": "warning",
        "SENT": "primary",
        "CONFIRMING": "warning",
        "CONFIRMED_OK": "success",
        "CONFIRMED_REJECTED": "danger",
        "CANCELLED_OK": "success",
        "CANCELLED_REJECTED": "danger",
        "INUTIL_OK": "success",
        "INUTIL_REJECTED": "danger",
        "FAILED": "danger",
        "ERROR": "danger",
        "RETRYING": "warning",
        "EXPIRED": "secondary",
    }
    key = (status or "").strip().upper()
    cls = m.get(key, "dark")
    label = status_label(status)
    return f'<span class="badge bg-{cls}">{label}</span>'

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
      bottom: 84px;
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
    .status-toast {
      position: fixed;
      right: 20px;
      bottom: 20px;
      background: #6c757d;
      color: #fff;
      padding: 8px 12px;
      border-radius: 8px;
      box-shadow: 0 6px 16px rgba(0,0,0,0.2);
      z-index: 10000;
      max-width: 260px;
      font-size: 13px;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }
    .status-toast.ok { background: #198754; }
    .status-toast.down { background: #dc3545; }
    .status-toast .status-label { font-weight: 600; letter-spacing: 0.2px; }
    .status-toast .status-icon { font-size: 14px; line-height: 1; }
    .status-toast .status-text { font-size: 12px; opacity: 0.9; }
    .status-toast .status-spinner {
      width: 12px;
      height: 12px;
      border: 2px solid rgba(255,255,255,0.5);
      border-top-color: #fff;
      border-radius: 50%;
      display: none;
      animation: sifen-spin 0.8s linear infinite;
    }
    .status-toast.pending .status-spinner { display: inline-block; }
    .status-toast.pending .status-icon { display: none; }
    .status-toast.ok .status-text { display: none; }
    .status-toast.down .status-text { display: inline; }
    @keyframes sifen-spin {
      from { transform: rotate(0deg); }
      to { transform: rotate(360deg); }
    }
  </style>
</head>
<body>
  <div class="container">
    <nav class="navbar navbar-expand-md mb-3">
      <div class="container-fluid px-0">
        <a class="navbar-brand d-flex align-items-center gap-3 mb-0" href="{{ url_for('invoices') }}">
          <img src="{{ url_for('issuer_logo') }}" alt="Industria Feris" class="brand-logo" onerror="this.style.display='none'">
          <span class="h3 mb-0">Industria Feris - Facturación</span>
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#mainNavbar" aria-controls="mainNavbar" aria-expanded="false" aria-label="Alternar navegación">
          <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="mainNavbar">
          <div class="d-flex flex-column flex-md-row ms-auto gap-2 pt-3 pt-md-0 align-items-stretch align-items-md-center">
            <a class="btn btn-outline-secondary" href="{{ url_for('invoices') }}" title="Inicio" aria-label="Inicio">
              <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" fill="currentColor" viewBox="0 0 16 16" aria-hidden="true">
                <path d="M8.354 1.146a.5.5 0 0 0-.708 0l-6 6A.5.5 0 0 0 2 7.5V14a1 1 0 0 0 1 1h4a.5.5 0 0 0 .5-.5V10h1v4.5a.5.5 0 0 0 .5.5h4a1 1 0 0 0 1-1V7.5a.5.5 0 0 0 .146-.354.5.5 0 0 0-.146-.353l-6-6z"/>
              </svg>
            </a>
            <a class="btn btn-outline-secondary" href="{{ url_for('customers') }}">Clientes</a>
            <a class="btn btn-outline-secondary" href="{{ url_for('products') }}">Productos</a>
            <button class="btn btn-primary" type="button" data-bs-toggle="modal" data-bs-target="#newDocModal">Nuevo documento</button>
          </div>
        </div>
      </div>
    </nav>

    {{ body|safe }}

  </div>
  <div class="modal fade" id="newDocModal" tabindex="-1" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title">Nuevo documento</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <div class="d-grid gap-2">
            <a class="btn btn-outline-primary" href="{{ url_for('invoice_new', doc_type=1) }}">Factura electrónica (1)</a>
            <a class="btn btn-outline-primary" href="{{ url_for('invoice_new', doc_type=4) }}">Autofactura electrónica (4)</a>
            <a class="btn btn-outline-primary" href="{{ url_for('invoice_new', doc_type=5) }}">Nota de crédito electrónica (5)</a>
            <a class="btn btn-outline-primary" href="{{ url_for('invoice_new', doc_type=6) }}">Nota de débito electrónica (6)</a>
            <a class="btn btn-outline-primary" href="{{ url_for('invoice_new', doc_type=7) }}">Nota de remisión electrónica (7)</a>
          </div>
        </div>
      </div>
    </div>
  </div>
  <div id="sifen-status-toast" class="status-toast pending" title="SIFEN: verificando..." role="status" aria-live="polite">
    <span class="status-label">SIFEN</span>
    <span class="status-icon" aria-hidden="true"></span>
    <span class="status-text"></span>
    <span class="status-spinner" aria-hidden="true"></span>
  </div>
  <div id="backup-toast" class="backup-toast"></div>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    (function () {
      const toast = document.getElementById("sifen-status-toast");
      if (!toast) return;
      const iconEl = toast.querySelector(".status-icon");
      const textEl = toast.querySelector(".status-text");

      function setStatus(state) {
        const ok = state && Object.prototype.hasOwnProperty.call(state, "ok") ? state.ok : null;
        const checking = Boolean(state && state.checking);
        toast.classList.remove("ok", "down", "pending");
        if (checking || ok === null) {
          toast.classList.add("pending");
          iconEl.textContent = "";
          textEl.textContent = "";
          toast.title = "SIFEN: verificando";
          return;
        }
        if (ok === true) {
          toast.classList.add("ok");
          iconEl.textContent = "✅";
          textEl.textContent = "";
          toast.title = "SIFEN disponible";
        } else {
          toast.classList.add("down");
          iconEl.textContent = "❌";
          textEl.textContent = "No disponible";
          toast.title = "SIFEN no disponible";
        }
      }

      let inFlight = false;
      async function check() {
        if (inFlight) return;
        inFlight = true;
        setStatus({ ok: null, checking: true });
        try {
          const res = await fetch("/api/sifen/status", { cache: "no-store" });
          if (!res.ok) return;
          const data = await res.json();
          setStatus({ ok: data.ok, checking: Boolean(data.checking) });
        } catch (e) {
        } finally {
          inFlight = false;
        }
      }

      setStatus({ ok: null, checking: true });
      check();
      setInterval(check, 30000);
    })();

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
  <style>
  /* Botón fijo abajo-izquierda */
  .logout-fab{
    position:fixed;
    bottom:20px;
    left:20px;
    background:#fff;
    border:1px solid #ddd;
    padding:10px 14px;
    box-shadow:0 4px 12px rgba(0,0,0,0.2);
    font-family:sans-serif;
    border-radius:999px;
    cursor:pointer;
    z-index:9999;
  }

  /* Warning box abajo-derecha */
  #session-warning{
    position:fixed;
    bottom:140px;
    right:20px;
    background:#fff;
    border:1px solid #ddd;
    padding:16px;
    box-shadow:0 4px 12px rgba(0,0,0,0.2);
    font-family:sans-serif;
    width:280px;
    display:none;
    z-index:9999;
  }
  #session-warning button{
    margin-top:10px;
    margin-right:10px;
  }
  </style>

  <button class="logout-fab" type="button" onclick="logout()">Cerrar sesión</button>

  <div id="session-warning">
    <strong>Tu sesión está por expirar</strong><br><br>
    Se cerrará en <span id="countdown">120</span> segundos.
    <br><br>
    <button type="button" onclick="stayLoggedIn()">Seguir conectado</button>
    <button type="button" onclick="logout()">Cerrar sesión</button>
  </div>

  <script>
  (function(){
    const SESSION_LIMIT = 30 * 60 * 1000; // 30 min
    const WARNING_TIME  = 2 * 60 * 1000;  // aviso 2 min antes

    let inactivityTimer;
    let warningTimer;
    let countdownInterval;
    let remaining = 120;

    function _getWarningEl(){
      return document.getElementById("session-warning");
    }
    function _getCountdownEl(){
      return document.getElementById("countdown");
    }

    function resetTimers(){
      clearTimeout(inactivityTimer);
      clearTimeout(warningTimer);
      clearInterval(countdownInterval);

      const box = _getWarningEl();
      if (box) box.style.display = "none";

      warningTimer = setTimeout(showWarning, SESSION_LIMIT - WARNING_TIME);
      inactivityTimer = setTimeout(logout, SESSION_LIMIT);
    }

    function showWarning(){
      const box = _getWarningEl();
      const countdown = _getCountdownEl();
      if (!box || !countdown) return;

      remaining = 120;
      countdown.textContent = remaining;

      box.style.display = "block";

      countdownInterval = setInterval(() => {
        remaining--;
        countdown.textContent = remaining;

        if (remaining <= 0){
          logout();
        }
      }, 1000);
    }

    function refreshSession(){
      const url = "https://auth.fe.if.com.py/oauth2/authorize"+
        "?client_id=6729u9gs4ua36ul6n5m1hl5lbl"+
        "&response_type=code"+
        "&scope=email+openid+phone"+
        "&redirect_uri="+encodeURIComponent(window.location.href)+
        "&prompt=none";

      const iframe = document.createElement("iframe");
      iframe.style.display = "none";
      iframe.src = url;
      document.body.appendChild(iframe);

      setTimeout(() => iframe.remove(), 5000);
    }

    window.stayLoggedIn = function stayLoggedIn(){
      refreshSession();
      resetTimers();
    };

    window.logout = function logout(){
      window.location.href =
        "https://auth.fe.if.com.py/logout"+
        "?client_id=6729u9gs4ua36ul6n5m1hl5lbl"+
        "&logout_uri=https://fe.if.com.py";
    };

    function bindActivityListeners(){
      ["mousemove","keydown","click","scroll"].forEach(event => {
        document.addEventListener(event, () => resetTimers(), { passive: true });
      });
    }

    document.addEventListener("DOMContentLoaded", () => {
      bindActivityListeners();
      resetTimers();
    });
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
    root = _artifacts_root() / "diagnostics"
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


def _issuer_logo_candidates() -> list[tuple[Path, str]]:
    _ensure_uploads_dir()
    uploads = UPLOADS_DIR
    return [
        (uploads / "issuer-logo.jpg", "image/jpeg"),
        (uploads / "issuer-logo.png", "image/png"),
        (_repo_root() / "assets" / "industria-feris-isotipo.jpg", "image/jpeg"),
    ]


def _find_issuer_logo() -> tuple[Optional[Path], Optional[str]]:
    for path, mimetype in _issuer_logo_candidates():
        try:
            if path.exists():
                return path, mimetype
        except Exception:
            continue
    return None, None

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
                extra["autofactura"].setdefault("iNatVen", "1")
                extra["autofactura"].setdefault("iTipIDVen", "1")
                extra["autofactura"].setdefault("documento", "123456")
                extra["autofactura"].setdefault("nombre", "Vendedor")
                extra["autofactura"].setdefault("direccion", "Direccion")
                extra["autofactura"].setdefault("numCasa", "0")
                tip_cons = _resolve_afe_constancia_type(extra)
                if tip_cons:
                    extra["documentoAsociado"]["tipoConstancia"] = tip_cons
                geo_tree = _load_georef_tree()
                dep_code, dist_code, city_code = _find_default_afe_geo(geo_tree)
                if dep_code:
                    extra["autofactura"]["departamentoVendedor"] = dep_code
                if dist_code:
                    extra["autofactura"]["distritoVendedor"] = dist_code
                if city_code:
                    extra["autofactura"]["ciudadVendedor"] = city_code
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
    venv_py = "python3"
    args = [
        venv_py, "-m", "sifen_minisender", "consult",
        "--env", env,
        "--prot", prot,
        "--artifacts-dir", str(_artifacts_root()),
    ]
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

_SIFEN_STATUS_LOCK = threading.Lock()
_SIFEN_STATUS_STATE = {
    "last_checked_at": 0.0,
    "last_ok": None,
    "last_text": "",
    "last_detail": "",
    "next_allowed_at": 0.0,
    "backoff_step": -1,
    "inflight": False,
}
_SIFEN_STATUS_BACKOFF = (60, 120, 300, 600, 900)


def _reset_sifen_status_cache() -> None:
    with _SIFEN_STATUS_LOCK:
        _SIFEN_STATUS_STATE.update(
            {
                "last_checked_at": 0.0,
                "last_ok": None,
                "last_text": "",
                "last_detail": "",
                "next_allowed_at": 0.0,
                "backoff_step": -1,
                "inflight": False,
            }
        )


def _sifen_status_is_dev() -> bool:
    env = (os.getenv("SIFEN_ENV") or "").strip().lower()
    if env and env != "prod":
        return True
    flask_env = (os.getenv("FLASK_ENV") or "").strip().lower()
    if flask_env and flask_env != "production":
        return True
    debug_flag = (os.getenv("FLASK_DEBUG") or "").strip().lower()
    return debug_flag in ("1", "true", "yes")


def _sifen_status_ttl_sec() -> int:
    raw = (os.getenv("SIFEN_STATUS_TTL_SEC") or "").strip()
    try:
        ttl = int(raw) if raw else 300
    except ValueError:
        ttl = 300
    if ttl <= 0:
        ttl = 300
    if _sifen_status_is_dev():
        return min(ttl, 60)
    return ttl


def _sifen_status_payload(*, checking: bool, cached: bool) -> dict:
    debug_flag = (os.getenv("SIFEN_STATUS_DEBUG") or "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    return {
        "ok": _SIFEN_STATUS_STATE["last_ok"],
        "text": _SIFEN_STATUS_STATE["last_text"],
        "detail": _SIFEN_STATUS_STATE["last_detail"] if debug_flag else "",
        "checked_at": _SIFEN_STATUS_STATE["last_checked_at"],
        "cached": cached,
        "checking": checking,
    }

def _sifen_preflight_ok() -> tuple[bool, str]:
    script_path = (BASE_DIR / "tools" / "sifen_preflight.sh").resolve()
    if not script_path.exists():
        return False, f"SIFEN_PREFLIGHT_MISSING: missing {script_path}"
    try:
        result = subprocess.run(
            ["/bin/bash", str(script_path)],
            capture_output=True,
            text=True,
            timeout=10,
            cwd=str(BASE_DIR),
        )
        stdout = (result.stdout or "").strip()
        return result.returncode == 0, stdout[:300]
    except subprocess.TimeoutExpired as exc:
        stdout = (getattr(exc, "stdout", None) or getattr(exc, "output", None) or "").strip()
        detail = stdout[:300] if stdout else "timeout after 10s"
        return False, f"SIFEN_TIMEOUT: {detail}"
    except Exception as exc:
        return False, f"SIFEN_ERROR: {str(exc)[:300]}"

def _run_sifen_preflight() -> dict:
    # CERT/KEY from /secrets when running inside Docker
    import os
    if os.path.exists("/secrets/cert.pem") and os.path.exists("/secrets/key.pem"):
        os.environ["CERT"] = "/secrets/cert.pem"
        os.environ["KEY"] = "/secrets/key.pem"
    ok, detail = _sifen_preflight_ok()
    text = "SIFEN_OK" if ok else "SIFEN_DOWN"
    if detail:
        if detail.startswith("SIFEN_PREFLIGHT_MISSING:"):
            text = "SIFEN_PREFLIGHT_MISSING"
            detail = detail.split(":", 1)[1].strip()
        elif detail.startswith("SIFEN_TIMEOUT:"):
            text = "SIFEN_TIMEOUT"
            detail = detail.split(":", 1)[1].strip()
        elif detail.startswith("SIFEN_ERROR:"):
            text = "SIFEN_ERROR"
            detail = detail.split(":", 1)[1].strip()
        else:
            text = detail.splitlines()[0].strip()[:120]
    return {
        "ok": ok,
        "text": text,
        "detail": (detail or "")[:300],
    }


def _get_sifen_status_cached() -> dict:
    now = time.time()
    ttl = _sifen_status_ttl_sec()
    with _SIFEN_STATUS_LOCK:
        if _SIFEN_STATUS_STATE["inflight"]:
            return _sifen_status_payload(checking=True, cached=True)
        last_checked = _SIFEN_STATUS_STATE["last_checked_at"]
        if last_checked and (now - last_checked) < ttl:
            return _sifen_status_payload(checking=False, cached=True)
        next_allowed = _SIFEN_STATUS_STATE["next_allowed_at"]
        if next_allowed and now < next_allowed:
            return _sifen_status_payload(checking=False, cached=True)
        _SIFEN_STATUS_STATE["inflight"] = True

    try:
        result = _run_sifen_preflight()
    except Exception as exc:
        result = {
            "ok": False,
            "text": "SIFEN_ERROR",
            "detail": f"{exc}"[:300],
        }

    checked_at = time.time()
    ok = bool(result.get("ok"))
    with _SIFEN_STATUS_LOCK:
        _SIFEN_STATUS_STATE["inflight"] = False
        _SIFEN_STATUS_STATE["last_checked_at"] = checked_at
        _SIFEN_STATUS_STATE["last_ok"] = result.get("ok")
        _SIFEN_STATUS_STATE["last_text"] = (result.get("text") or "")
        _SIFEN_STATUS_STATE["last_detail"] = (result.get("detail") or "")
        if ok:
            _SIFEN_STATUS_STATE["backoff_step"] = -1
            _SIFEN_STATUS_STATE["next_allowed_at"] = 0.0
        else:
            step = min(
                _SIFEN_STATUS_STATE["backoff_step"] + 1,
                len(_SIFEN_STATUS_BACKOFF) - 1,
            )
            _SIFEN_STATUS_STATE["backoff_step"] = step
            _SIFEN_STATUS_STATE["next_allowed_at"] = checked_at + _SIFEN_STATUS_BACKOFF[step]

    return _sifen_status_payload(checking=False, cached=False)

@app.get("/api/sifen/status")
def sifen_status():
    return jsonify(_get_sifen_status_cached())

@app.route("/backup/status")
def backup_status():
    return {
        "last_backup_at": get_setting("last_backup_at", ""),
        "last_backup_file": get_setting("last_backup_file", ""),
    }


@app.get("/health")
@app.get("/healthz")
def health_check():
    return jsonify({"ok": True}), 200


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
    path, mimetype = _find_issuer_logo()
    if not path or not mimetype:
        abort(
            404,
            description=(
                "Issuer logo not found. Expected data/uploads/issuer-logo.jpg "
                "or assets/industria-feris-isotipo.jpg."
            ),
        )
    resp = send_file(path, mimetype=mimetype, as_attachment=False)
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

    customers = con.execute("SELECT id, name FROM customers WHERE deleted_at IS NULL ORDER BY name ASC").fetchall()

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
                      <td>{% if r.doc_type == "4" %}Autofactura (Emisor){% else %}{{r.customer_name}}{% endif %}</td>
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

@app.route("/artifacts/<path:artifact_relpath>")
def artifact_file(artifact_relpath: str):
    root = _artifacts_root()
    safe_path = _safe_resolve_under(root, artifact_relpath)
    if safe_path is None:
        abort(403, "Ruta inválida.")
    if not safe_path.exists() or not safe_path.is_file():
        abort(404)
    return send_file(safe_path, as_attachment=False)

@app.route("/data/georef_tree.json")
def georef_tree():
    candidates = [
        Path("/data/georef_tree.json"),
        Path("/data/georef_tree_2025.json"),
        (_repo_root() / "data" / "georef_tree.json").resolve(),
        (_repo_root() / "data" / "georef_tree_2025.json").resolve(),
    ]
    for path in candidates:
        if path.exists() and path.is_file():
            return send_file(path, mimetype="application/json", as_attachment=False)
    abort(404)


@app.route("/data/georef_tree_2025.json")
def georef_tree_2025():
    return georef_tree()


@app.route("/api/artifacts/<path:artifact_relpath>")
def api_artifact_file(artifact_relpath: str):
    return artifact_file(artifact_relpath)


@app.route("/api/runs", methods=["GET"])
def api_runs():
    init_db()
    con = get_db()
    try:
        limit = int((request.args.get("limit") or "20").strip())
    except Exception:
        limit = 20
    limit = max(1, min(limit, 200))
    rows = con.execute(
        """
        SELECT id, created_at, issued_at, queued_at, sent_at, confirmed_at, status,
               sifen_env, sifen_prot_cons_lote, last_lote_code, last_lote_msg,
               last_sifen_code, last_sifen_msg, last_sifen_est, last_sifen_prot_aut,
               source_xml_path, last_artifacts_dir
        FROM invoices
        ORDER BY COALESCE(sent_at, queued_at, created_at) DESC, id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    items = []
    for row in rows:
        item = _invoice_api_dict(row)
        item["detail_url"] = url_for("invoice_detail", invoice_id=row["id"])
        item["artifact_links"] = _artifact_links_for_dir(row["last_artifacts_dir"])
        items.append(item)
    return jsonify({"items": items, "count": len(items), "limit": limit})


@app.route("/api/invoices", methods=["GET"])
def api_invoices():
    init_db()
    con = get_db()
    try:
        try:
            limit = int((request.args.get("limit") or "200").strip())
        except Exception:
            limit = 200
        limit = max(1, min(limit, 1000))

        try:
            offset = int((request.args.get("offset") or "0").strip())
        except Exception:
            offset = 0
        offset = max(0, offset)

        invoice_cols = _table_columns(con, "invoices")
        customer_cols = _table_columns(con, "customers")

        select_parts = ["i.*"]
        customer_selects = []
        if "name" in customer_cols:
            customer_selects.append("c.name AS customer_name")
        if "ruc" in customer_cols:
            customer_selects.append("c.ruc AS customer_ruc")
        if "dv" in customer_cols:
            customer_selects.append("c.dv AS customer_dv")
        if "doc_id" in customer_cols:
            customer_selects.append("c.doc_id AS customer_doc_id")
        if "email" in customer_cols:
            customer_selects.append("c.email AS customer_email")
        if "phone" in customer_cols:
            customer_selects.append("c.phone AS customer_phone")

        join_clause = ""
        if customer_selects:
            select_parts.extend(customer_selects)
            join_clause = "LEFT JOIN customers c ON c.id=i.customer_id"

        if "created_at" in invoice_cols:
            order_clause = "ORDER BY i.created_at DESC, i.id DESC"
        else:
            order_clause = "ORDER BY i.id DESC"

        rows = con.execute(
            f"""
            SELECT {", ".join(select_parts)}
            FROM invoices i
            {join_clause}
            {order_clause}
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

        items = [_invoice_api_dict(row) for row in rows]
        resp = jsonify(items)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Total-Count"] = str(len(items))
        return resp
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/customers", methods=["GET"])
def api_customers():
    init_db()
    con = get_db()
    try:
        try:
            limit = int((request.args.get("limit") or "500").strip())
        except Exception:
            limit = 500
        limit = max(1, min(limit, 2000))

        try:
            offset = int((request.args.get("offset") or "0").strip())
        except Exception:
            offset = 0
        offset = max(0, offset)

        customer_cols = _table_columns(con, "customers")
        base_cols = ["id", "name", "ruc", "dv", "doc_id", "email", "phone", "created_at"]
        select_cols = [f"c.{col}" for col in base_cols if col in customer_cols]
        if not select_cols:
            select_cols = ["c.*"]

        rows = con.execute(
            f"""
            SELECT {", ".join(select_cols)}
            FROM customers c
            WHERE c.deleted_at IS NULL
            ORDER BY c.id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

        items = []
        for row in rows:
            ruc = _row_get(row, "ruc")
            dv = _row_get(row, "dv")
            if dv is None and ruc:
                parts = str(ruc).split("-")
                if len(parts) >= 2 and parts[-1]:
                    dv = parts[-1]
            item = {
                "id": _row_get(row, "id"),
                "name": _row_get(row, "name"),
                "ruc": ruc,
                "dv": dv,
                "doc_id": _row_get(row, "doc_id"),
            }
            for key in ("email", "phone", "created_at"):
                val = _row_get(row, key)
                if val is not None:
                    item[key] = val
            items.append(item)

        resp = jsonify(items)
        resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Total-Count"] = str(len(items))
        return resp
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/runs/latest-lote", methods=["GET"])
def api_runs_latest_lote():
    latest_run = _latest_send_lote_run()
    if not latest_run:
        return jsonify({"run": None})
    artifacts = latest_run.get("artifacts") or {}
    return jsonify(
        {
            "run": {
                "run_dir": latest_run.get("run_dir"),
                "artifacts": artifacts,
                "artifact_links": {
                    key: _artifact_url(path_value)
                    for key, path_value in artifacts.items()
                },
            }
        }
    )


@app.route("/api/invoices/<int:invoice_id>/artifacts", methods=["GET"])
def api_invoice_artifacts(invoice_id: int):
    init_db()
    con = get_db()
    inv = con.execute(
        "SELECT id, last_artifacts_dir, last_event_artifacts_dir, source_xml_path FROM invoices WHERE id=?",
        (invoice_id,),
    ).fetchone()
    if not inv:
        return jsonify({"error": "invoice not found"}), 404

    return jsonify(
        {
            "invoice_id": invoice_id,
            "source_xml_path": inv["source_xml_path"],
            "last_artifacts": _artifact_links_for_dir(inv["last_artifacts_dir"]),
            "last_event_artifacts": _artifact_links_for_dir(inv["last_event_artifacts_dir"]),
        }
    )


@app.route("/api/invoices/<int:invoice_id>/event/cancel", methods=["POST"])
def api_invoice_cancel_event(invoice_id: int):
    init_db()
    con = get_db()
    payload = request.get_json(silent=True) or request.form or {}

    env = (payload.get("env") or get_setting("default_env", "prod") or "prod").strip().lower()
    if env not in ("test", "prod"):
        return jsonify({"error": "env inválido (usar test|prod)"}), 400

    confirm = (payload.get("confirm_emit") or "").strip().upper()
    if env == "prod" and confirm != "YES":
        return jsonify({"error": "confirmación requerida para PROD"}), 400

    motivo = (payload.get("motivo") or "").strip()
    motivo_preset = (payload.get("motivo_preset") or "").strip()
    if not motivo and motivo_preset:
        motivo = motivo_preset
    if len(motivo) < 5 or len(motivo) > 500:
        return jsonify({"error": "motivo inválido (5-500 caracteres)"}), 400

    inv = con.execute(
        """
        SELECT i.*, c.name AS customer_name, c.ruc AS customer_ruc, c.email AS customer_email
        FROM invoices i JOIN customers c ON c.id=i.customer_id
        WHERE i.id=?
        """,
        (invoice_id,),
    ).fetchone()
    if not inv:
        return jsonify({"error": "invoice not found"}), 404

    doc_type = normalize_doc_type(inv["doc_type"])
    if doc_type != "1":
        return (
            jsonify(
                {
                    "error": "cancel_event_not_allowed",
                    "detail": f"Cancelación solo habilitada para iTiDE=1. Documento iTiDE={doc_type}.",
                }
            ),
            400,
        )

    cdc = _extract_cdc_from_xml_path(inv["source_xml_path"] or "")
    if not cdc or len(cdc) != 44:
        return (
            jsonify(
                {
                    "error": "cdc_not_found",
                    "detail": "CDC no encontrado (44). Primero emití y aprobá/firmá el documento.",
                }
            ),
            400,
        )

    did, event_id = _make_event_ids()
    try:
        parsed = _send_cancel_event(
            env=env,
            cdc=cdc,
            motivo=motivo,
            event_id=event_id,
            did=did,
            artifacts_root=_artifacts_root(),
        )
    except Exception as e:
        con.execute(
            "UPDATE invoices SET last_event_type=?, last_event_msg=?, last_event_at=? WHERE id=?",
            ("cancel", f"ERROR: {e}", now_iso(), invoice_id),
        )
        con.commit()
        return jsonify({"ok": False, "error": str(e)}), 400

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

    ok = (code == "0600") or est.lower().startswith("aprob")
    return jsonify(
        {
            "ok": ok,
            "dEstRes": est,
            "dCodRes": code,
            "dMsgRes": msg,
            "dProtAut": prot_aut,
            "event_id": event_id,
        }
    )


@app.route("/api/smoke", methods=["POST"])
def api_smoke():
    init_db()
    payload = request.get_json(silent=True) or request.form or {}
    env_choice = (payload.get("env") or "prod").strip().lower()
    if env_choice == "both":
        envs = ["test", "prod"]
    elif env_choice in ("test", "prod"):
        envs = [env_choice]
    else:
        return jsonify({"error": "env debe ser test, prod o both"}), 400

    ruc = re.sub(r"\D", "", (payload.get("ruc") or ""))
    cdc = re.sub(r"\D", "", (payload.get("cdc") or ""))
    prot = re.sub(r"\D", "", (payload.get("prot") or ""))

    result = {
        "started_at": now_iso(),
        "envs": envs,
        "inputs": {"ruc": ruc, "cdc": cdc, "prot": prot},
        "dry_run": None,
        "consult_ruc": {},
        "consult_cdc": {},
        "consult_lote": {},
    }

    do_dry_run = _parse_bool(payload.get("do_dry_run"), default=True)
    do_consult_ruc = _parse_bool(payload.get("do_consult_ruc"), default=True)
    do_consult_cdc = _parse_bool(payload.get("do_consult_cdc"), default=True)
    do_consult_lote = _parse_bool(payload.get("do_consult_lote"), default=True)

    if do_dry_run:
        result["dry_run"] = _diagnostics_dry_run()

    for env in envs:
        if do_consult_ruc and ruc:
            try:
                result["consult_ruc"][env] = _diagnostics_consult_ruc(env, ruc)
            except Exception as exc:
                result["consult_ruc"][env] = {"error": str(exc)}
        if do_consult_cdc and cdc and len(cdc) == 44:
            try:
                result["consult_cdc"][env] = _diagnostics_consult_cdc(env, cdc)
            except Exception as exc:
                result["consult_cdc"][env] = {"error": str(exc)}
        if do_consult_lote and prot:
            try:
                result["consult_lote"][env] = _diagnostics_consult_lote(env, prot)
            except Exception as exc:
                result["consult_lote"][env] = {"error": str(exc)}

    persist = _parse_bool(payload.get("persist"), default=True)
    if persist:
        out_dir = _diagnostics_artifacts_dir()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"diagnostics_{ts}.json"
        out_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        set_setting("diagnostics_last_path", str(out_path))
        result["saved_to"] = str(out_path)

    return jsonify(result)


@app.route("/api/invoices/<int:invoice_id>/consult-lote", methods=["POST"])
def api_invoice_consult_lote(invoice_id: int):
    init_db()
    con = get_db()
    inv = con.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    if not inv:
        return jsonify({"error": "invoice not found"}), 404

    payload = request.get_json(silent=True) or request.form or {}
    env = (
        (payload.get("env") or inv["sifen_env"] or get_setting("default_env", "prod") or "prod")
        .strip()
        .lower()
    )
    if env not in ("test", "prod"):
        return jsonify({"error": "env debe ser test o prod"}), 400

    prot = re.sub(r"\D", "", (payload.get("prot") or inv["sifen_prot_cons_lote"] or ""))
    if not prot:
        return jsonify({"error": "No hay dProtConsLote para consultar."}), 400

    try:
        attempts = int(payload.get("attempts") or "1")
    except Exception:
        attempts = 1
    attempts = max(1, min(attempts, 5))

    con.execute("UPDATE invoices SET sifen_env=? WHERE id=?", (env, invoice_id))
    con.commit()

    new_status = _consult_lote_and_update(
        invoice_id=invoice_id,
        env=env,
        prot=prot,
        rel_signed=inv["source_xml_path"] or None,
        prefer_art_dir=inv["last_artifacts_dir"] or None,
        attempts=attempts,
        sleep_between=0,
    )
    if new_status == "CONFIRMING":
        _schedule_lote_poll(invoice_id, env, prot, rel_signed=inv["source_xml_path"] or None)

    updated = con.execute(
        """
        SELECT id, created_at, issued_at, queued_at, sent_at, confirmed_at, status,
               sifen_env, sifen_prot_cons_lote, last_lote_code, last_lote_msg,
               last_sifen_code, last_sifen_msg, last_sifen_est, last_sifen_prot_aut,
               source_xml_path, last_artifacts_dir
        FROM invoices
        WHERE id=?
        """,
        (invoice_id,),
    ).fetchone()
    item = _invoice_api_dict(updated)
    item["detail_url"] = url_for("invoice_detail", invoice_id=invoice_id)
    item["artifact_links"] = _artifact_links_for_dir(updated["last_artifacts_dir"])
    return jsonify({"invoice": item})


@app.route("/send-lote", methods=["GET", "POST"])
def send_lote_page():
    init_db()

    default_env = (get_setting("default_env", "test") or "test").strip().lower()
    if default_env not in ("test", "prod"):
        default_env = "test"

    selected_env = default_env
    xml_path_value = (get_setting("default_signed_xml_path", "") or "").strip()
    dump_http_checked = False
    result = None
    error = None

    if request.method == "POST":
        selected_env = (request.form.get("env") or default_env).strip().lower()
        if selected_env not in ("test", "prod"):
            selected_env = default_env

        xml_path_value = (request.form.get("xml_path") or "").strip()
        dump_http_checked = bool(request.form.get("dump_http"))
        uploaded = request.files.get("xml_upload")

        xml_candidate: Optional[Path] = None
        if uploaded and uploaded.filename:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            upload_dir = _artifacts_root() / f"webui_send_lote_upload_{ts}"
            upload_dir.mkdir(parents=True, exist_ok=True)
            upload_name = Path(uploaded.filename).name or "uploaded.xml"
            xml_candidate = upload_dir / upload_name
            uploaded.save(str(xml_candidate))
            xml_path_value = str(xml_candidate)
        elif xml_path_value:
            p = Path(xml_path_value).expanduser()
            if not p.is_absolute():
                p = (_repo_root() / p).resolve()
            xml_candidate = p

        if xml_candidate is None:
            error = "Debés indicar un XML por path o subir un archivo."
        else:
            try:
                result = send_lote_from_xml(
                    env=selected_env,
                    xml_path=xml_candidate,
                    dump_http=dump_http_checked,
                    artifacts_dir=None,
                )
                artifacts = result.get("artifacts") or {}
                result["artifact_links"] = {
                    key: _artifact_url(path_value)
                    for key, path_value in artifacts.items()
                }
            except Exception as exc:
                error = str(exc)

    latest_run = _latest_send_lote_run()
    if latest_run:
        latest_artifacts = latest_run.get("artifacts") or {}
        latest_run["artifact_links"] = {
            key: _artifact_url(path_value)
            for key, path_value in latest_artifacts.items()
        }

    body = render_template_string(
        """
        <div class="card">
          <div class="card-body">
            <h5 class="mb-3">Enviar lote desde XML firmado</h5>
            <form method="post" enctype="multipart/form-data" class="row g-3">
              <div class="col-md-3">
                <label class="form-label">Ambiente</label>
                <select class="form-select" name="env">
                  <option value="test" {% if selected_env == "test" %}selected{% endif %}>TEST</option>
                  <option value="prod" {% if selected_env == "prod" %}selected{% endif %}>PROD</option>
                </select>
              </div>
              <div class="col-md-9">
                <label class="form-label">XML path</label>
                <input class="form-control mono" name="xml_path" value="{{ xml_path_value }}" placeholder="/Users/.../signed_rde.xml">
              </div>
              <div class="col-md-9">
                <label class="form-label">O subir XML</label>
                <input class="form-control" type="file" name="xml_upload" accept=".xml,text/xml,application/xml">
              </div>
              <div class="col-md-3 d-flex align-items-end">
                <div class="form-check mb-2">
                  <input class="form-check-input" type="checkbox" id="dump_http" name="dump_http" {% if dump_http_checked %}checked{% endif %}>
                  <label class="form-check-label" for="dump_http">dump_http</label>
                </div>
              </div>
              <div class="col-12">
                <button class="btn btn-primary" type="submit">Enviar</button>
              </div>
            </form>
          </div>
        </div>

        {% if error %}
          <div class="alert alert-danger mt-3">{{ error }}</div>
        {% endif %}

        {% if result %}
          <div class="card mt-3">
            <div class="card-body">
              <h6 class="mb-2">Resultado</h6>
              <div>success: <span class="mono">{{ result.success }}</span></div>
              <div>dCodRes: <span class="mono">{{ result.dCodRes or "—" }}</span></div>
              <div>dMsgRes: {{ result.dMsgRes or "—" }}</div>
              <div>dProtConsLote: <span class="mono">{{ result.dProtConsLote or "—" }}</span></div>
              <div class="mt-2">run_dir: <span class="mono">{{ result.run_dir }}</span></div>
              <div class="mt-2">Artifacts:</div>
              <ul class="mb-0">
                <li>last_lote.xml:
                  {% if result.artifact_links.last_lote_xml %}
                    <a class="mono" href="{{ result.artifact_links.last_lote_xml }}" target="_blank">abrir</a>
                  {% else %}<span class="text-muted">—</span>{% endif %}
                </li>
                <li>soap_last_request.xml:
                  {% if result.artifact_links.soap_request %}
                    <a class="mono" href="{{ result.artifact_links.soap_request }}" target="_blank">abrir</a>
                  {% else %}<span class="text-muted">—</span>{% endif %}
                </li>
                <li>last_xde.zip:
                  {% if result.artifact_links.last_xde_zip %}
                    <a class="mono" href="{{ result.artifact_links.last_xde_zip }}" target="_blank">descargar</a>
                  {% else %}<span class="text-muted">—</span>{% endif %}
                </li>
                <li>response_recepcion_*.json:
                  {% if result.artifact_links.response_json %}
                    <a class="mono" href="{{ result.artifact_links.response_json }}" target="_blank">abrir</a>
                  {% else %}<span class="text-muted">—</span>{% endif %}
                </li>
              </ul>
              {% if result.logs %}
                <details class="mt-3">
                  <summary>Logs</summary>
                  <pre class="mono small mt-2 mb-0">{{ result.logs }}</pre>
                </details>
              {% endif %}
            </div>
          </div>
        {% endif %}

        {% if latest_run %}
          <div class="card mt-3">
            <div class="card-body">
              <h6 class="mb-2">Último run</h6>
              <div class="mono">{{ latest_run.run_dir }}</div>
              <ul class="mb-0 mt-2">
                <li>last_lote.xml:
                  {% if latest_run.artifact_links.last_lote_xml %}
                    <a class="mono" href="{{ latest_run.artifact_links.last_lote_xml }}" target="_blank">abrir</a>
                  {% else %}<span class="text-muted">—</span>{% endif %}
                </li>
                <li>soap_last_request.xml:
                  {% if latest_run.artifact_links.soap_request %}
                    <a class="mono" href="{{ latest_run.artifact_links.soap_request }}" target="_blank">abrir</a>
                  {% else %}<span class="text-muted">—</span>{% endif %}
                </li>
                <li>last_xde.zip:
                  {% if latest_run.artifact_links.last_xde_zip %}
                    <a class="mono" href="{{ latest_run.artifact_links.last_xde_zip }}" target="_blank">descargar</a>
                  {% else %}<span class="text-muted">—</span>{% endif %}
                </li>
                <li>response_recepcion_*.json:
                  {% if latest_run.artifact_links.response_json %}
                    <a class="mono" href="{{ latest_run.artifact_links.response_json }}" target="_blank">abrir</a>
                  {% else %}<span class="text-muted">—</span>{% endif %}
                </li>
              </ul>
            </div>
          </div>
        {% endif %}
        """,
        selected_env=selected_env,
        xml_path_value=xml_path_value,
        dump_http_checked=dump_http_checked,
        result=result,
        latest_run=latest_run,
        error=error,
    )
    return render_template_string(BASE_HTML, title="Enviar lote XML", db_path=DB_PATH, body=body)

@app.route("/invoice/new", methods=["GET", "POST"])
def invoice_new():
    init_db()
    con = get_db()

    # Seed mínimo si DB está vacía (para que puedas ver algo ya)
    if con.execute("SELECT COUNT(*) n FROM customers WHERE deleted_at IS NULL").fetchone()["n"] == 0:
        con.execute("INSERT INTO customers (name, ruc, created_at) VALUES (?,?,?)", ("Cliente Demo S.A.", "80012345-6", now_iso()))
        con.commit()

    customers = con.execute("SELECT id, name, ruc FROM customers WHERE deleted_at IS NULL ORDER BY name ASC").fetchall()
    products = con.execute("SELECT id, sku, name, unit, price_unit FROM products ORDER BY name ASC").fetchall()
    default_est = get_setting("default_establishment", "001")
    default_pun = get_setting("default_point_exp", "001")
    available_pun = [p.strip() for p in (get_setting("available_point_exp", "001,002,003") or "").split(",") if p.strip()]
    if not available_pun:
        available_pun = [default_pun or "001"]

    def _clean_digits(value: Optional[str]) -> str:
        return re.sub(r"\D", "", (value or "").strip())

    def _clean_text(value: Optional[str]) -> str:
        return re.sub(r"\s+", " ", (value or "").strip())

    selected_doc_type = normalize_doc_type(
        request.form.get("doc_type") if request.method == "POST" else request.args.get("doc_type")
    )

    geo_tree = _load_georef_tree()
    dep_map = geo_tree.get("dep") or {}
    afe_departamentos: list[tuple[str, str]] = []
    for code, name in dep_map.items():
        code = str(code or "").strip()
        label = str(name or "").strip()
        if not code or not label:
            continue
        afe_departamentos.append((_geo_display_code(code), label))
    afe_departamentos.sort(key=lambda item: item[1].casefold())
    geo_departamentos = afe_departamentos

    default_afe_dep = ""
    default_afe_dist = ""
    default_afe_city = ""
    if request.method == "GET" and selected_doc_type == "4":
        default_afe_dep, default_afe_dist, default_afe_city = _find_default_afe_geo(geo_tree)
    default_nre_dep = ""
    default_nre_dist = ""
    default_nre_city = ""
    if request.method == "GET" and selected_doc_type == "7":
        default_nre_dep, default_nre_dist, default_nre_city = _find_default_afe_geo(geo_tree)

    def _form_value(name: str, default: str = "") -> str:
        if request.method == "POST":
            return (request.form.get(name) or "").strip()
        return default

    form_values = {
        "doc_type": selected_doc_type,
        "customer_id": _form_value("customer_id", ""),
        "establishment": _form_value("establishment", default_est),
        "point_exp": _form_value("point_exp", default_pun),
        # AFE
        "afe_tipo_vendedor": _form_value("afe_tipo_vendedor", ""),
        "afe_tipo_doc": _form_value("afe_tipo_doc", ""),
        "afe_nro_doc": _form_value("afe_nro_doc", ""),
        "afe_nombre": _form_value("afe_nombre", ""),
        "afe_direccion": _form_value("afe_direccion", ""),
        "afe_num_casa": _form_value("afe_num_casa", "0"),
        "afe_departamento": _form_value("afe_departamento", default_afe_dep),
        "afe_distrito": _form_value("afe_distrito", default_afe_dist),
        "afe_ciudad": _form_value("afe_ciudad", default_afe_city),
        # NC/ND
        "nc_doc_asoc_tipo": _form_value("nc_doc_asoc_tipo", "1"),
        "nc_cdc_asoc": _form_value("nc_cdc_asoc", ""),
        "nc_timbrado_asoc": _form_value("nc_timbrado_asoc", ""),
        "nc_est_asoc": _form_value("nc_est_asoc", ""),
        "nc_pun_asoc": _form_value("nc_pun_asoc", ""),
        "nc_num_asoc": _form_value("nc_num_asoc", ""),
        "nc_tipo_doc_imp": _form_value("nc_tipo_doc_imp", ""),
        "nc_fecha_doc_imp": _form_value("nc_fecha_doc_imp", ""),
        "nc_motivo": _form_value("nc_motivo", "1"),
        # NRE
        "nre_motivo": _form_value("nre_motivo", "1"),
        "nre_responsable": _form_value("nre_responsable", "1"),
        "nre_km": _form_value("nre_km", ""),
        "nre_fecha_factura": _form_value("nre_fecha_factura", ""),
        "nre_trans_tipo": _form_value("nre_trans_tipo", ""),
        "nre_trans_modalidad": _form_value("nre_trans_modalidad", "1"),
        "nre_trans_resp_flete": _form_value("nre_trans_resp_flete", "1"),
        "nre_sal_direccion": _form_value("nre_sal_direccion", ""),
        "nre_sal_num_casa": _form_value("nre_sal_num_casa", ""),
        "nre_sal_departamento": _form_value("nre_sal_departamento", default_nre_dep),
        "nre_sal_distrito": _form_value("nre_sal_distrito", default_nre_dist),
        "nre_sal_ciudad": _form_value("nre_sal_ciudad", default_nre_city),
        "nre_sal_telefono": _form_value("nre_sal_telefono", ""),
        "nre_ent_direccion": _form_value("nre_ent_direccion", ""),
        "nre_ent_num_casa": _form_value("nre_ent_num_casa", ""),
        "nre_ent_departamento": _form_value("nre_ent_departamento", default_nre_dep),
        "nre_ent_distrito": _form_value("nre_ent_distrito", default_nre_dist),
        "nre_ent_ciudad": _form_value("nre_ent_ciudad", default_nre_city),
        "nre_ent_telefono": _form_value("nre_ent_telefono", ""),
        "nre_veh_tipo": _form_value("nre_veh_tipo", "1"),
        "nre_veh_marca": _form_value("nre_veh_marca", ""),
        "nre_veh_doc_tipo": _form_value("nre_veh_doc_tipo", "1"),
        "nre_veh_numero": _form_value("nre_veh_numero", ""),
        "nre_transp_tipo": _form_value("nre_transp_tipo", "1"),
        "nre_transp_nombre": _form_value("nre_transp_nombre", ""),
        "nre_transp_numero": _form_value("nre_transp_numero", ""),
        "nre_transp_tipo_doc": _form_value("nre_transp_tipo_doc", ""),
        "nre_transp_dir": _form_value("nre_transp_dir", ""),
        "nre_transp_nacionalidad": _form_value("nre_transp_nacionalidad", ""),
        "nre_chof_nombre": _form_value("nre_chof_nombre", ""),
        "nre_chof_numero": _form_value("nre_chof_numero", ""),
        "nre_chof_dir": _form_value("nre_chof_dir", ""),
    }

    def _geo_entries(raw_map: dict) -> list[tuple[str, str]]:
        entries: list[tuple[str, str]] = []
        for code, name in (raw_map or {}).items():
            code_disp = _geo_display_code(code)
            label = str(name or "").strip()
            if not code_disp or not label:
                continue
            entries.append((code_disp, label))
        entries.sort(key=lambda item: item[1].casefold())
        return entries

    afe_distritos: list[tuple[str, str]] = []
    afe_ciudades: list[tuple[str, str]] = []
    dep_sel = _zfill_digits(form_values.get("afe_departamento"), 2)
    dist_sel = _zfill_digits(form_values.get("afe_distrito"), 4)
    if dep_sel:
        afe_distritos = _geo_entries((geo_tree.get("dist_by_dep") or {}).get(dep_sel, {}))
    if dist_sel:
        afe_ciudades = _geo_entries((geo_tree.get("city_by_dist") or {}).get(dist_sel, {}))
    nre_sal_distritos: list[tuple[str, str]] = []
    nre_sal_ciudades: list[tuple[str, str]] = []
    nre_ent_distritos: list[tuple[str, str]] = []
    nre_ent_ciudades: list[tuple[str, str]] = []
    nre_sal_dep_sel = _zfill_digits(form_values.get("nre_sal_departamento"), 2)
    nre_sal_dist_sel = _zfill_digits(form_values.get("nre_sal_distrito"), 4)
    nre_ent_dep_sel = _zfill_digits(form_values.get("nre_ent_departamento"), 2)
    nre_ent_dist_sel = _zfill_digits(form_values.get("nre_ent_distrito"), 4)
    if nre_sal_dep_sel:
        nre_sal_distritos = _geo_entries((geo_tree.get("dist_by_dep") or {}).get(nre_sal_dep_sel, {}))
    if nre_sal_dist_sel:
        nre_sal_ciudades = _geo_entries((geo_tree.get("city_by_dist") or {}).get(nre_sal_dist_sel, {}))
    if nre_ent_dep_sel:
        nre_ent_distritos = _geo_entries((geo_tree.get("dist_by_dep") or {}).get(nre_ent_dep_sel, {}))
    if nre_ent_dist_sel:
        nre_ent_ciudades = _geo_entries((geo_tree.get("city_by_dist") or {}).get(nre_ent_dist_sel, {}))

    def _build_items_form() -> list[dict]:
        if request.method == "POST":
            descs = request.form.getlist("description")
            qtys = request.form.getlist("qty")
            prices = request.form.getlist("price_unit")
            product_ids = request.form.getlist("product_id")
            max_len = max(len(descs), len(qtys), len(prices), len(product_ids), 1)
            items = []
            for idx in range(max_len):
                items.append(
                    {
                        "description": (descs[idx] if idx < len(descs) else "").strip(),
                        "qty": (qtys[idx] if idx < len(qtys) else "1").strip() or "1",
                        "price_unit": (prices[idx] if idx < len(prices) else "0").strip() or "0",
                        "product_id": (product_ids[idx] if idx < len(product_ids) else "").strip(),
                    }
                )
            return items
        return [{"description": "", "qty": "1", "price_unit": "0", "product_id": ""}]

    items_form = _build_items_form()

    def _render_form(error: Optional[str] = None, status: int = 200):
        body = render_template_string(
            """
        <div class="card">
          <div class="card-body">
            <h5>Nuevo documento</h5>
            {% if error %}
              <div class="alert alert-danger mt-3" style="white-space: pre-line;">{{ error }}</div>
            {% endif %}
            <form method="post" class="row g-3 mt-1">
              <div class="col-md-6" id="customer-block">
                <label class="form-label">Cliente</label>
                <select class="form-select" name="customer_id" id="customer-select" required>
                  {% for c in customers %}
                    <option value="{{c.id}}" {% if form.get("customer_id") == (c.id|string) %}selected{% endif %}>{{c.name}} ({{c.ruc or "sin RUC"}})</option>
                  {% endfor %}
                </select>
                <button class="btn btn-sm btn-outline-primary mt-2" type="button" data-bs-toggle="modal" data-bs-target="#customerModal">+ Agregar cliente nuevo</button>
              </div>
              <div class="col-md-6 d-none" id="afe-receptor-block">
                <label class="form-label">Receptor</label>
                <div class="form-control-plaintext">Emisor (Autofactura)</div>
                <div class="small text-muted">En AFE el receptor debe ser el mismo emisor.</div>
              </div>
              <div class="col-md-6">
                <label class="form-label">Tipo de documento</label>
                <select class="form-select" name="doc_type" id="doc-type-select" required>
                  <option value="1" {% if form.get("doc_type") == "1" %}selected{% endif %}>Factura electrónica</option>
                  <option value="4" {% if form.get("doc_type") == "4" %}selected{% endif %}>Autofactura electrónica</option>
                  <option value="5" {% if form.get("doc_type") == "5" %}selected{% endif %}>Nota de crédito electrónica</option>
                  <option value="6" {% if form.get("doc_type") == "6" %}selected{% endif %}>Nota de débito electrónica</option>
                  <option value="7" {% if form.get("doc_type") == "7" %}selected{% endif %}>Nota de remisión electrónica</option>
                </select>
              </div>
              <div class="col-12"></div>
              <div class="col-md-3">
                <label class="form-label">Establecimiento</label>
                <input class="form-control mono" name="establishment" value="{{ form.get('establishment') or default_est }}" required>
              </div>
              <div class="col-md-3">
                <label class="form-label">Punto de expedición</label>
                <select class="form-select mono" name="point_exp" required>
                  {% for p in available_pun %}
                    <option value="{{p}}" {% if (form.get('point_exp') or default_pun) == p %}selected{% endif %}>{{p}}</option>
                  {% endfor %}
                </select>
              </div>

              <div class="col-12 d-none" id="afe-vendor-block">
                <div class="card border-0 bg-light">
                  <div class="card-body py-3">
                    <h6 class="mb-3">Datos del vendedor (AFE)</h6>
                    <div class="row g-3">
                      <div class="col-md-4">
                        <label class="form-label">Tipo vendedor</label>
                        <select class="form-select" name="afe_tipo_vendedor" data-afe-required="1">
                          {% for code, label in afe_nat.items() %}
                            <option value="{{code}}" {% if form.get("afe_tipo_vendedor") == code %}selected{% endif %}>{{label}}</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">Tipo doc. identidad</label>
                        <select class="form-select" name="afe_tipo_doc" data-afe-required="1">
                          {% for code, label in afe_id.items() %}
                            <option value="{{code}}" {% if form.get("afe_tipo_doc") == code %}selected{% endif %}>{{label}}</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">Nro doc. identidad</label>
                        <input class="form-control" name="afe_nro_doc" data-afe-required="1" placeholder="Documento" value="{{ form.get('afe_nro_doc') }}">
                      </div>
                      <div class="col-md-6">
                        <label class="form-label">Nombre / Razón social</label>
                        <input class="form-control" name="afe_nombre" data-afe-required="1" placeholder="Nombre del vendedor" value="{{ form.get('afe_nombre') }}">
                      </div>
                      <div class="col-md-6">
                        <label class="form-label">Dirección</label>
                        <input class="form-control" name="afe_direccion" data-afe-required="1" placeholder="Dirección" value="{{ form.get('afe_direccion') }}">
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">N° casa</label>
                        <input class="form-control mono" name="afe_num_casa" data-afe-required="1" value="{{ form.get('afe_num_casa') or '0' }}">
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Departamento</label>
                        <select class="form-select" name="afe_departamento" id="afe-dep-select" data-afe-required="1"
                                data-georef-url="{{ georef_url }}" data-initial="{{ form.get('afe_departamento') }}">
                          <option value="" {% if not form.get('afe_departamento') %}selected{% endif %}>Elegí un departamento</option>
                          {% for code, name in afe_departamentos %}
                            <option value="{{code}}" {% if form.get("afe_departamento") == code %}selected{% endif %}>{{name}} ({{code}})</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Distrito</label>
                        <select class="form-select" name="afe_distrito" id="afe-dist-select" data-afe-required="1"
                                data-initial="{{ form.get('afe_distrito') }}" disabled>
                          <option value="" {% if not form.get('afe_distrito') %}selected{% endif %}>Elegí un distrito</option>
                          {% for code, name in afe_distritos %}
                            <option value="{{code}}" {% if form.get("afe_distrito") == code %}selected{% endif %}>{{name}} ({{code}})</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Ciudad</label>
                        <select class="form-select" name="afe_ciudad" id="afe-city-select" data-afe-required="1"
                                data-initial="{{ form.get('afe_ciudad') }}" disabled>
                          <option value="" {% if not form.get('afe_ciudad') %}selected{% endif %}>Elegí una ciudad</option>
                          {% for code, name in afe_ciudades %}
                            <option value="{{code}}" {% if form.get("afe_ciudad") == code %}selected{% endif %}>{{name}} ({{code}})</option>
                          {% endfor %}
                        </select>
                      </div>
                    </div>
                    <div class="small text-muted mt-2">
                      Campos mínimos para gCamAE (E300). Departamento/Ciudad deben ser códigos válidos.
                    </div>
                  </div>
                </div>
              </div>

              <div class="col-12 d-none" id="ncnd-block">
                <div class="card border-0 bg-light">
                  <div class="card-body py-3">
                    <h6 class="mb-3">Nota de crédito / débito</h6>
                    <div class="row g-3">
                      <div class="col-md-4">
                        <label class="form-label">Motivo</label>
                        <select class="form-select" name="nc_motivo" id="nc-motivo" data-nc-required="1">
                          {% for code, label in nc_motivos.items() %}
                            <option value="{{code}}" {% if form.get("nc_motivo") == code %}selected{% endif %}>{{label}}</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">Documento asociado</label>
                        <select class="form-select" name="nc_doc_asoc_tipo" id="nc-doc-asoc-type" data-nc-required="1">
                          <option value="1" {% if form.get("nc_doc_asoc_tipo") == "1" %}selected{% endif %}>Electrónico (CDC)</option>
                          <option value="2" {% if form.get("nc_doc_asoc_tipo") == "2" %}selected{% endif %}>Impreso</option>
                        </select>
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">CDC asociado</label>
                        <input class="form-control mono" name="nc_cdc_asoc" id="nc-doc-asoc-cdc" data-nc-type1-required="1" placeholder="44 dígitos" value="{{ form.get('nc_cdc_asoc') }}">
                      </div>
                    </div>

                    <div class="row g-3 mt-1 d-none" id="nc-doc-asoc-impreso">
                      <div class="col-md-3">
                        <label class="form-label">Timbrado</label>
                        <input class="form-control mono" name="nc_timbrado_asoc" data-nc-type2-required="1" placeholder="8 dígitos" value="{{ form.get('nc_timbrado_asoc') }}">
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Establecimiento</label>
                        <input class="form-control mono" name="nc_est_asoc" data-nc-type2-required="1" placeholder="001" value="{{ form.get('nc_est_asoc') }}">
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Punto exp.</label>
                        <input class="form-control mono" name="nc_pun_asoc" data-nc-type2-required="1" placeholder="001" value="{{ form.get('nc_pun_asoc') }}">
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Número</label>
                        <input class="form-control mono" name="nc_num_asoc" data-nc-type2-required="1" placeholder="0000001" value="{{ form.get('nc_num_asoc') }}">
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">Tipo doc. impreso</label>
                        <select class="form-select" name="nc_tipo_doc_imp">
                          <option value="">(opcional)</option>
                          {% for code, label in doc_impreso_types.items() %}
                            <option value="{{code}}" {% if form.get("nc_tipo_doc_imp") == code %}selected{% endif %}>{{label}}</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">Fecha doc. impreso</label>
                        <input class="form-control" type="date" name="nc_fecha_doc_imp" value="{{ form.get('nc_fecha_doc_imp') }}">
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div class="col-12 d-none" id="nre-block">
                <div class="card border-0 bg-light">
                  <div class="card-body py-3">
                    <h6 class="mb-3">Nota de remisión</h6>
                    <div class="row g-3">
                      <div class="col-md-4">
                        <label class="form-label">Motivo</label>
                        <select class="form-select" name="nre_motivo" data-nre-required="1">
                          {% for code, label in rem_motivos.items() %}
                            <option value="{{code}}" {% if form.get("nre_motivo") == code %}selected{% endif %}>{{label}}</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">Responsable emisión</label>
                        <select class="form-select" name="nre_responsable" data-nre-required="1">
                          {% for code, label in rem_resp.items() %}
                            <option value="{{code}}" {% if form.get("nre_responsable") == code %}selected{% endif %}>{{label}}</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-2">
                        <label class="form-label">KM estimado</label>
                        <input class="form-control mono" name="nre_km" placeholder="0" value="{{ form.get('nre_km') }}">
                      </div>
                      <div class="col-md-2">
                        <label class="form-label">Fecha factura</label>
                        <input class="form-control" type="date" name="nre_fecha_factura" value="{{ form.get('nre_fecha_factura') }}">
                      </div>
                    </div>

                    <hr class="my-3">
                    <div class="row g-3">
                      <div class="col-md-4">
                        <label class="form-label">Modalidad transporte</label>
                        <select class="form-select" name="nre_trans_modalidad" data-nre-required="1">
                          {% for code, label in trans_mod.items() %}
                            <option value="{{code}}" {% if form.get("nre_trans_modalidad") == code %}selected{% endif %}>{{label}}</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">Responsable flete</label>
                        <select class="form-select" name="nre_trans_resp_flete" data-nre-required="1">
                          {% for code, label in resp_flete.items() %}
                            <option value="{{code}}" {% if form.get("nre_trans_resp_flete") == code %}selected{% endif %}>{{label}}</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">Tipo transporte</label>
                        <select class="form-select" name="nre_trans_tipo">
                          <option value="">(opcional)</option>
                          {% for code, label in trans_tipo.items() %}
                            <option value="{{code}}" {% if form.get("nre_trans_tipo") == code %}selected{% endif %}>{{label}}</option>
                          {% endfor %}
                        </select>
                      </div>
                    </div>

                    <div class="row g-3 mt-1">
                      <div class="col-12"><strong>Salida</strong></div>
                      <div class="col-md-6">
                        <label class="form-label">Dirección</label>
                        <input class="form-control" name="nre_sal_direccion" data-nre-required="1" value="{{ form.get('nre_sal_direccion') }}">
                      </div>
                      <div class="col-md-2">
                        <label class="form-label">N° casa</label>
                        <input class="form-control mono" name="nre_sal_num_casa" data-nre-required="1" value="{{ form.get('nre_sal_num_casa') }}">
                      </div>
                      <div class="col-md-2">
                        <label class="form-label">Departamento</label>
                        <select class="form-select" name="nre_sal_departamento" id="nre-sal-dep-select" data-nre-required="1"
                                data-georef-url="{{ georef_url }}" data-initial="{{ form.get('nre_sal_departamento') }}">
                          <option value="" {% if not form.get('nre_sal_departamento') %}selected{% endif %}>Seleccioná departamento…</option>
                          {% for code, name in geo_departamentos %}
                            <option value="{{code}}" {% if form.get("nre_sal_departamento") == code %}selected{% endif %}>{{name}} ({{code}})</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-2">
                        <label class="form-label">Distrito</label>
                        <select class="form-select" name="nre_sal_distrito" id="nre-sal-dist-select" data-nre-required="1"
                                data-initial="{{ form.get('nre_sal_distrito') }}" disabled>
                          <option value="" {% if not form.get('nre_sal_distrito') %}selected{% endif %}>Seleccioná distrito…</option>
                          {% for code, name in nre_sal_distritos %}
                            <option value="{{code}}" {% if form.get("nre_sal_distrito") == code %}selected{% endif %}>{{name}} ({{code}})</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-2">
                        <label class="form-label">Ciudad</label>
                        <select class="form-select" name="nre_sal_ciudad" id="nre-sal-city-select" data-nre-required="1"
                                data-initial="{{ form.get('nre_sal_ciudad') }}" disabled>
                          <option value="" {% if not form.get('nre_sal_ciudad') %}selected{% endif %}>Seleccioná ciudad…</option>
                          {% for code, name in nre_sal_ciudades %}
                            <option value="{{code}}" {% if form.get("nre_sal_ciudad") == code %}selected{% endif %}>{{name}} ({{code}})</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">Teléfono</label>
                        <input class="form-control" name="nre_sal_telefono" value="{{ form.get('nre_sal_telefono') }}">
                      </div>
                    </div>

                    <div class="row g-3 mt-2">
                      <div class="col-12"><strong>Entrega</strong></div>
                      <div class="col-md-6">
                        <label class="form-label">Dirección</label>
                        <input class="form-control" name="nre_ent_direccion" data-nre-required="1" value="{{ form.get('nre_ent_direccion') }}">
                      </div>
                      <div class="col-md-2">
                        <label class="form-label">N° casa</label>
                        <input class="form-control mono" name="nre_ent_num_casa" data-nre-required="1" value="{{ form.get('nre_ent_num_casa') }}">
                      </div>
                      <div class="col-md-2">
                        <label class="form-label">Departamento</label>
                        <select class="form-select" name="nre_ent_departamento" id="nre-ent-dep-select" data-nre-required="1"
                                data-georef-url="{{ georef_url }}" data-initial="{{ form.get('nre_ent_departamento') }}">
                          <option value="" {% if not form.get('nre_ent_departamento') %}selected{% endif %}>Seleccioná departamento…</option>
                          {% for code, name in geo_departamentos %}
                            <option value="{{code}}" {% if form.get("nre_ent_departamento") == code %}selected{% endif %}>{{name}} ({{code}})</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-2">
                        <label class="form-label">Distrito</label>
                        <select class="form-select" name="nre_ent_distrito" id="nre-ent-dist-select" data-nre-required="1"
                                data-initial="{{ form.get('nre_ent_distrito') }}" disabled>
                          <option value="" {% if not form.get('nre_ent_distrito') %}selected{% endif %}>Seleccioná distrito…</option>
                          {% for code, name in nre_ent_distritos %}
                            <option value="{{code}}" {% if form.get("nre_ent_distrito") == code %}selected{% endif %}>{{name}} ({{code}})</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-2">
                        <label class="form-label">Ciudad</label>
                        <select class="form-select" name="nre_ent_ciudad" id="nre-ent-city-select" data-nre-required="1"
                                data-initial="{{ form.get('nre_ent_ciudad') }}" disabled>
                          <option value="" {% if not form.get('nre_ent_ciudad') %}selected{% endif %}>Seleccioná ciudad…</option>
                          {% for code, name in nre_ent_ciudades %}
                            <option value="{{code}}" {% if form.get("nre_ent_ciudad") == code %}selected{% endif %}>{{name}} ({{code}})</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-4">
                        <label class="form-label">Teléfono</label>
                        <input class="form-control" name="nre_ent_telefono" value="{{ form.get('nre_ent_telefono') }}">
                      </div>
                    </div>

                    <div class="row g-3 mt-2">
                      <div class="col-12"><strong>Vehículo</strong></div>
                      <div class="col-md-3">
                        <label class="form-label">Tipo</label>
                        <select class="form-select" name="nre_veh_tipo" data-nre-required="1">
                          {% for code, label in veh_tipos.items() %}
                            <option value="{{code}}" {% if form.get("nre_veh_tipo") == code %}selected{% endif %}>{{label}}</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Marca</label>
                        <input class="form-control" name="nre_veh_marca" data-nre-required="1" value="{{ form.get('nre_veh_marca') }}">
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Tipo documento</label>
                        <select class="form-select" name="nre_veh_doc_tipo" data-nre-required="1">
                          <option value="1" {% if form.get("nre_veh_doc_tipo") == "1" %}selected{% endif %}>Matrícula</option>
                          <option value="2" {% if form.get("nre_veh_doc_tipo") == "2" %}selected{% endif %}>Otro ID</option>
                        </select>
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Número ID</label>
                        <input class="form-control" name="nre_veh_numero" data-nre-required="1" value="{{ form.get('nre_veh_numero') }}">
                      </div>
                    </div>

                    <div class="row g-3 mt-2">
                      <div class="col-12"><strong>Transportista</strong></div>
                      <div class="col-md-3">
                        <label class="form-label">Tipo</label>
                        <select class="form-select" name="nre_transp_tipo" data-nre-required="1">
                          <option value="1" {% if form.get("nre_transp_tipo") == "1" %}selected{% endif %}>Persona física</option>
                          <option value="2" {% if form.get("nre_transp_tipo") == "2" %}selected{% endif %}>Persona jurídica</option>
                        </select>
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Nombre</label>
                        <input class="form-control" name="nre_transp_nombre" data-nre-required="1" value="{{ form.get('nre_transp_nombre') }}">
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Número doc.</label>
                        <input class="form-control" name="nre_transp_numero" data-nre-required="1" value="{{ form.get('nre_transp_numero') }}">
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Tipo doc.</label>
                        <select class="form-select" name="nre_transp_tipo_doc">
                          <option value="">(opcional)</option>
                          {% for code, label in afe_id.items() %}
                            <option value="{{code}}" {% if form.get("nre_transp_tipo_doc") == code %}selected{% endif %}>{{label}}</option>
                          {% endfor %}
                        </select>
                      </div>
                      <div class="col-md-6">
                        <label class="form-label">Dirección transportista</label>
                        <input class="form-control" name="nre_transp_dir" data-nre-required="1" value="{{ form.get('nre_transp_dir') }}">
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Nacionalidad (código)</label>
                        <input class="form-control mono" name="nre_transp_nacionalidad" placeholder="PRY" value="{{ form.get('nre_transp_nacionalidad') }}">
                      </div>
                      <div class="col-md-3"></div>
                      <div class="col-md-3">
                        <label class="form-label">Nombre chofer</label>
                        <input class="form-control" name="nre_chof_nombre" data-nre-required="1" value="{{ form.get('nre_chof_nombre') }}">
                      </div>
                      <div class="col-md-3">
                        <label class="form-label">Número doc. chofer</label>
                        <input class="form-control" name="nre_chof_numero" data-nre-required="1" value="{{ form.get('nre_chof_numero') }}">
                      </div>
                      <div class="col-md-6">
                        <label class="form-label">Dirección chofer</label>
                        <input class="form-control" name="nre_chof_dir" data-nre-required="1" value="{{ form.get('nre_chof_dir') }}">
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div class="col-12"><hr></div>

              <div id="items-container">
                {% for item in items %}
                <div class="row g-3 item-row align-items-end">
                  <div class="col-md-5">
                    <label class="form-label">Descripción</label>
                    {% if products %}
                      <select class="form-select product-select" name="description" required>
                        <option value="" {% if not item.description %}selected{% endif %}>Seleccionar producto/servicio...</option>
                        {% for p in products %}
                          <option value="{{p.name}}" data-id="{{p.id}}" data-price="{{p.price_unit}}" {% if item.description == p.name %}selected{% endif %}>{{p.name}}{% if p.sku %} ({{p.sku}}){% endif %}</option>
                        {% endfor %}
                      </select>
                    {% else %}
                      <input class="form-control" name="description" value="{{ item.description or 'Servicio' }}" required>
                    {% endif %}
                    <input type="hidden" name="product_id" value="{{ item.product_id }}">
                  </div>
                  <div class="col-md-2">
                    <label class="form-label">Cantidad</label>
                    <input class="form-control" name="qty" type="number" value="{{ item.qty or '1' }}" required>
                  </div>
                  <div class="col-md-3">
                    <label class="form-label">Precio unitario (PYG)</label>
                    <input class="form-control" name="price_unit" type="number" value="{{ item.price_unit or '0' }}" required>
                  </div>
                  <div class="col-md-2">
                    <label class="form-label d-block">&nbsp;</label>
                    <button class="btn btn-outline-danger w-100 remove-item" type="button" aria-label="Eliminar ítem" title="Eliminar ítem">
                      <span aria-hidden="true">🗑️</span>
                    </button>
                  </div>
                </div>
                {% endfor %}
              </div>
              <div class="col-12">
                <button class="btn btn-sm btn-outline-secondary" type="button" id="add-item">+ Agregar ítem</button>
                <button class="btn btn-sm btn-outline-primary ms-2" type="button" data-bs-toggle="modal" data-bs-target="#productModal">+ Agregar producto nuevo</button>
              </div>

              <div class="col-12 d-flex flex-wrap align-items-center gap-3">
                <div class="form-check">
                  <input class="form-check-input" type="checkbox" name="confirm_emit" value="YES" id="confirm-emit-new" required>
                  <label class="form-check-label" for="confirm-emit-new">Confirmo emisión</label>
                </div>
                <button class="btn btn-primary" type="submit">Emitir ahora</button>
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
                const docTypeSelect = document.getElementById("doc-type-select");
                const customerBlock = document.getElementById("customer-block");
                const customerSelect = document.getElementById("customer-select");
                const afeReceptorBlock = document.getElementById("afe-receptor-block");
                const afeVendorBlock = document.getElementById("afe-vendor-block");
                const ncndBlock = document.getElementById("ncnd-block");
                const ncDocAsocType = document.getElementById("nc-doc-asoc-type");
                const ncDocAsocImpreso = document.getElementById("nc-doc-asoc-impreso");
                const ncDocAsocCdc = document.getElementById("nc-doc-asoc-cdc");
                const nreBlock = document.getElementById("nre-block");

                function toggleSection(section, enabled) {
                  if (!section) return;
                  section.classList.toggle("d-none", !enabled);
                  section.querySelectorAll("input, select, textarea").forEach((el) => {
                    el.disabled = !enabled;
                  });
                }

                function toggleDocSections() {
                  const val = docTypeSelect ? docTypeSelect.value : "1";
                  const isAfe = val === "4";
                  const isNcNd = val === "5" || val === "6";
                  const isNre = val === "7";

                  if (customerBlock) customerBlock.classList.toggle("d-none", isAfe);
                  if (customerSelect) {
                    customerSelect.disabled = !!isAfe;
                    customerSelect.required = !isAfe;
                  }
                  if (afeReceptorBlock) afeReceptorBlock.classList.toggle("d-none", !isAfe);
                  if (afeVendorBlock) {
                    afeVendorBlock.classList.toggle("d-none", !isAfe);
                    afeVendorBlock.querySelectorAll("input, select, textarea").forEach((el) => {
                      el.disabled = !isAfe;
                    });
                    afeVendorBlock.querySelectorAll("[data-afe-required]").forEach((el) => {
                      el.required = !!isAfe;
                    });
                  }

                  if (isAfe) {
                    syncGeoDisabled();
                  }

                  toggleSection(ncndBlock, isNcNd);
                  if (ncndBlock) {
                    ncndBlock.querySelectorAll("[data-nc-required]").forEach((el) => {
                      el.required = isNcNd;
                    });
                    const asocType = ncDocAsocType ? ncDocAsocType.value : "1";
                    const isType1 = isNcNd && asocType === "1";
                    const isType2 = isNcNd && asocType === "2";
                    if (ncDocAsocCdc) {
                      const cdcWrap = ncDocAsocCdc.closest(".col-md-4");
                      if (cdcWrap) cdcWrap.classList.toggle("d-none", !isType1);
                    }
                    toggleSection(ncDocAsocImpreso, isType2);
                    if (ncDocAsocCdc) {
                      ncDocAsocCdc.disabled = !isType1;
                      ncDocAsocCdc.required = isType1;
                    }
                    if (ncDocAsocImpreso) {
                      ncDocAsocImpreso.querySelectorAll("[data-nc-type2-required]").forEach((el) => {
                        el.required = isType2;
                      });
                    }
                  }

                  toggleSection(nreBlock, isNre);
                  if (nreBlock) {
                    nreBlock.querySelectorAll("[data-nre-required]").forEach((el) => {
                      el.required = isNre;
                    });
                  }
                }

                if (docTypeSelect) {
                  docTypeSelect.addEventListener("change", toggleDocSections);
                }
                if (ncDocAsocType) {
                  ncDocAsocType.addEventListener("change", toggleDocSections);
                }
                document.addEventListener("DOMContentLoaded", function () {
                  toggleDocSections();
                  initGeoCascades();
                });

                function normalizeGeo(value, width) {
                  if (!value) return "";
                  const digits = String(value).replace(/\\D/g, "");
                  if (!digits) return "";
                  return digits.padStart(width, "0");
                }

                function displayGeo(value) {
                  if (!value) return "";
                  const digits = String(value).replace(/\\D/g, "");
                  if (!digits) return "";
                  const trimmed = digits.replace(/^0+/, "");
                  return trimmed || "0";
                }

                function sortEntries(mapObj) {
                  return Object.entries(mapObj || {}).sort((a, b) => {
                    const an = String(a[1] || "").toLowerCase();
                    const bn = String(b[1] || "").toLowerCase();
                    if (an === bn) return String(a[0]).localeCompare(String(b[0]));
                    return an.localeCompare(bn);
                  });
                }

                function setSelectOptions(selectEl, entries, placeholder, selectedValue) {
                  if (!selectEl) return;
                  selectEl.innerHTML = "";
                  const opt = document.createElement("option");
                  opt.value = "";
                  opt.textContent = placeholder;
                  selectEl.appendChild(opt);
                  entries.forEach(([code, name]) => {
                    const option = document.createElement("option");
                    const display = displayGeo(code);
                    option.value = display;
                    option.textContent = `${name} (${display})`;
                    selectEl.appendChild(option);
                  });
                  if (selectedValue) {
                    selectEl.value = selectedValue;
                  }
                }

                function syncGeoDisabled() {
                  const afeDepSelect = document.getElementById("afe-dep-select");
                  const afeDistSelect = document.getElementById("afe-dist-select");
                  const afeCitySelect = document.getElementById("afe-city-select");
                  if (!afeDepSelect || !afeDistSelect || !afeCitySelect) return;
                  const depVal = (afeDepSelect.value || "").trim();
                  const distVal = (afeDistSelect.value || "").trim();
                  afeDistSelect.disabled = !depVal;
                  afeCitySelect.disabled = !distVal;
                }

                const geoCache = { promise: null, data: null };

                function loadGeoTree(georefUrl) {
                  if (!georefUrl) {
                    return Promise.reject(new Error("missing georef url"));
                  }
                  if (geoCache.data) {
                    return Promise.resolve(geoCache.data);
                  }
                  if (!geoCache.promise) {
                    geoCache.promise = fetch(georefUrl).then((resp) => {
                      if (!resp.ok) throw new Error("HTTP " + resp.status);
                      return resp.json();
                    }).then((data) => {
                      geoCache.data = data;
                      return data;
                    });
                  }
                  return geoCache.promise;
                }

                function bindGeoCascade(depSelect, distSelect, citySelect, placeholders) {
                  if (!depSelect || !distSelect || !citySelect) return;
                  const georefUrl = depSelect.getAttribute("data-georef-url");
                  if (!georefUrl) return;

                  const distPlaceholder = (placeholders && placeholders.dist) || "Seleccioná distrito…";
                  const cityPlaceholder = (placeholders && placeholders.city) || "Seleccioná ciudad…";

                  loadGeoTree(georefUrl).then((geo) => {
                    const distByDep = geo.dist_by_dep || {};
                    const cityByDist = geo.city_by_dist || {};
                    const cityToDist = geo.city_to_dist || {};
                    const distToDep = geo.dist_to_dep || {};

                    let depVal = normalizeGeo(depSelect.getAttribute("data-initial"), 2);
                    let distVal = normalizeGeo(distSelect.getAttribute("data-initial"), 4);
                    let cityVal = normalizeGeo(citySelect.getAttribute("data-initial"), 5);

                    if (!distVal && cityVal) {
                      distVal = normalizeGeo(cityToDist[cityVal], 4);
                    }
                    if (!depVal && distVal) {
                      depVal = normalizeGeo(distToDep[distVal], 2);
                    }

                    const depDisplay = displayGeo(depVal);
                    const distDisplay = displayGeo(distVal);
                    const cityDisplay = displayGeo(cityVal);

                    if (depDisplay) {
                      depSelect.value = depDisplay;
                    }

                    function updateCities(selectedCity) {
                      const distCode = normalizeGeo(distSelect.value, 4);
                      const cityEntries = sortEntries(cityByDist[distCode] || {});
                      setSelectOptions(citySelect, cityEntries, cityPlaceholder, selectedCity);
                      citySelect.disabled = !distCode;
                    }

                    function updateDistricts(selectedDist, selectedCity) {
                      const depCode = normalizeGeo(depSelect.value, 2);
                      const distEntries = sortEntries(distByDep[depCode] || {});
                      setSelectOptions(distSelect, distEntries, distPlaceholder, selectedDist);
                      distSelect.disabled = !depCode;
                      if (selectedDist) {
                        distSelect.value = selectedDist;
                      }
                      updateCities(selectedCity);
                      if (selectedCity) {
                        citySelect.value = selectedCity;
                      }
                    }

                    updateDistricts(distDisplay, cityDisplay);

                    depSelect.addEventListener("change", function () {
                      updateDistricts(\"\", \"\");
                    });
                    distSelect.addEventListener("change", function () {
                      updateCities(\"\");
                    });
                  }).catch((err) => {
                    console.warn("No se pudo cargar georef_tree.json", err);
                  });
                }

                function initGeoCascades() {
                  const afeDepSelect = document.getElementById("afe-dep-select");
                  const afeDistSelect = document.getElementById("afe-dist-select");
                  const afeCitySelect = document.getElementById("afe-city-select");
                  bindGeoCascade(afeDepSelect, afeDistSelect, afeCitySelect, {
                    dist: "Elegí un distrito",
                    city: "Elegí una ciudad",
                  });

                  const nreSalDepSelect = document.getElementById("nre-sal-dep-select");
                  const nreSalDistSelect = document.getElementById("nre-sal-dist-select");
                  const nreSalCitySelect = document.getElementById("nre-sal-city-select");
                  bindGeoCascade(nreSalDepSelect, nreSalDistSelect, nreSalCitySelect, {
                    dist: "Seleccioná distrito…",
                    city: "Seleccioná ciudad…",
                  });

                  const nreEntDepSelect = document.getElementById("nre-ent-dep-select");
                  const nreEntDistSelect = document.getElementById("nre-ent-dist-select");
                  const nreEntCitySelect = document.getElementById("nre-ent-city-select");
                  bindGeoCascade(nreEntDepSelect, nreEntDistSelect, nreEntCitySelect, {
                    dist: "Seleccioná distrito…",
                    city: "Seleccioná ciudad…",
                  });

                  syncGeoDisabled();
                }

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

                function syncProductMeta(sel) {
                  if (!sel) return;
                  const row = sel.closest(".item-row");
                  if (!row) return;
                  const opt = sel.selectedOptions[0];
                  if (!opt) return;
                  const price = opt.getAttribute("data-price") || "";
                  const pid = opt.getAttribute("data-id") || "";
                  const priceInput = row.querySelector('input[name="price_unit"]');
                  const pidInput = row.querySelector('input[name="product_id"]');
                  if (priceInput && price && !priceInput.value) priceInput.value = price;
                  if (pidInput && pid && !pidInput.value) pidInput.value = pid;
                }

                container.addEventListener("change", function (ev) {
                  const sel = ev.target.closest(".product-select");
                  if (!sel) return;
                  syncProductMeta(sel);
                });
                container.querySelectorAll(".product-select").forEach((sel) => syncProductMeta(sel));

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
                const customerSelectEl = customerSelect;
                if (quickCustomerForm && customerSelectEl) {
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
                      customerSelectEl.appendChild(opt);
                      customerSelectEl.value = String(out.id);
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
            afe_nat=AFE_NAT_MAP,
            afe_id=AFE_ID_MAP,
            nc_motivos=NC_MOTIVO_MAP,
            rem_motivos=REM_MOTIVO_MAP,
            rem_resp=REM_RESP_MAP,
            trans_tipo=TRANS_TIPO_MAP,
            trans_mod=TRANS_MOD_MAP,
            resp_flete=RESP_FLETE_MAP,
            veh_tipos=VEH_TIPO_MAP,
            doc_impreso_types=DOC_IMPRESO_TYPE_MAP,
            form=form_values,
            afe_departamentos=afe_departamentos,
            afe_distritos=afe_distritos,
            afe_ciudades=afe_ciudades,
            geo_departamentos=geo_departamentos,
            nre_sal_distritos=nre_sal_distritos,
            nre_sal_ciudades=nre_sal_ciudades,
            nre_ent_distritos=nre_ent_distritos,
            nre_ent_ciudades=nre_ent_ciudades,
            georef_url=url_for("georef_tree"),
            items=items_form,
            error=error,
        )
        return render_template_string(BASE_HTML, title="Nuevo documento", db_path=DB_PATH, body=body), status

    if request.method == "POST":
        doc_type = normalize_doc_type(request.form.get("doc_type"))
        doc_extra_json = None
        customer_id = int(request.form.get("customer_id") or "0")
        if doc_type != "4":
            if not customer_id:
                return _render_form("Customer_id requerido.", 400)
            exists = con.execute(
                "SELECT 1 FROM customers WHERE id=? AND deleted_at IS NULL",
                (customer_id,),
            ).fetchone()
            if not exists:
                return _render_form("Cliente inválido o eliminado.", 400)
        if doc_type == "4":
            # customer_id se usa solo por restricción del modelo actual;
            # en AFE el receptor real se fuerza a emisor en XML.
            row = con.execute(
                "SELECT id FROM customers WHERE deleted_at IS NULL ORDER BY id ASC LIMIT 1"
            ).fetchone()
            if row:
                customer_id = int(row["id"])
            else:
                con.execute(
                    "INSERT INTO customers (name, ruc, created_at) VALUES (?,?,?)",
                    ("Cliente Demo S.A.", "80012345-6", now_iso()),
                )
                customer_id = int(con.execute("SELECT last_insert_rowid()").fetchone()[0])

            vendor = {
                "iNatVen": (request.form.get("afe_tipo_vendedor") or "").strip(),
                "iTipIDVen": (request.form.get("afe_tipo_doc") or "").strip(),
                "documento": _clean_text(request.form.get("afe_nro_doc")),
                "nombre": _clean_text(request.form.get("afe_nombre")),
                "direccion": _clean_text(request.form.get("afe_direccion")),
                "numCasa": _clean_digits(request.form.get("afe_num_casa")),
                "departamentoVendedor": _clean_digits(request.form.get("afe_departamento")),
                "distritoVendedor": _clean_digits(request.form.get("afe_distrito")),
                "ciudadVendedor": _clean_digits(request.form.get("afe_ciudad")),
            }
            extra_json = {"documentoAsociado": {"tipoDocumentoAsoc": "3"}}
            _set_afe_vendor_extra(extra_json, vendor)
            tip_cons = _resolve_afe_constancia_type(extra_json)
            if tip_cons:
                extra_json["documentoAsociado"]["tipoConstancia"] = tip_cons
            errors = _validate_doc_extra(doc_type, extra_json)
            if errors:
                return _render_form("En Autofactura debes completar los datos del vendedor.\n- " + "\n- ".join(errors), 400)
            doc_extra_json = json.dumps(extra_json, ensure_ascii=False)
        elif doc_type in ("5", "6"):
            assoc_type = (request.form.get("nc_doc_asoc_tipo") or "1").strip()
            assoc = {"tipoDocumentoAsoc": assoc_type}
            if assoc_type == "1":
                assoc["cdcAsociado"] = _clean_digits(request.form.get("nc_cdc_asoc"))
            elif assoc_type == "2":
                assoc["timbradoAsoc"] = _clean_digits(request.form.get("nc_timbrado_asoc"))
                assoc["establecimientoAsoc"] = _clean_digits(request.form.get("nc_est_asoc"))
                assoc["puntoAsoc"] = _clean_digits(request.form.get("nc_pun_asoc"))
                assoc["numeroAsoc"] = _clean_digits(request.form.get("nc_num_asoc"))
                tipo_imp = (request.form.get("nc_tipo_doc_imp") or "").strip()
                if tipo_imp:
                    assoc["tipoDocumentoIm"] = tipo_imp
                fecha_imp = (request.form.get("nc_fecha_doc_imp") or "").strip()
                if fecha_imp:
                    assoc["fechaDocIm"] = fecha_imp
            extra_json = {
                "documentoAsociado": assoc,
                "iMotEmi": (request.form.get("nc_motivo") or "").strip(),
            }
            errors = _validate_doc_extra(doc_type, extra_json)
            if errors:
                return _render_form("Completa los datos de Nota de crédito/débito.\n- " + "\n- ".join(errors), 400)
            doc_extra_json = json.dumps(extra_json, ensure_ascii=False)
        elif doc_type == "7":
            remision = {
                "motivo": (request.form.get("nre_motivo") or "").strip(),
                "responsableEmi": (request.form.get("nre_responsable") or "").strip(),
            }
            km = (request.form.get("nre_km") or "").strip()
            if km:
                remision["kmEstimado"] = km
            fec = (request.form.get("nre_fecha_factura") or "").strip()
            if fec:
                remision["fechaFactura"] = fec

            transporte = {
                "modalidad": (request.form.get("nre_trans_modalidad") or "").strip(),
                "tipoResponsable": (request.form.get("nre_trans_resp_flete") or "").strip(),
                "salida": {
                    "direccion": _clean_text(request.form.get("nre_sal_direccion")),
                    "numCasa": _clean_digits(request.form.get("nre_sal_num_casa")),
                    "departamento": _clean_digits(request.form.get("nre_sal_departamento")),
                    "distrito": _clean_digits(request.form.get("nre_sal_distrito")),
                    "ciudad": _clean_digits(request.form.get("nre_sal_ciudad")),
                    "telefono": _clean_text(request.form.get("nre_sal_telefono")),
                },
                "entrega": {
                    "direccion": _clean_text(request.form.get("nre_ent_direccion")),
                    "numCasa": _clean_digits(request.form.get("nre_ent_num_casa")),
                    "departamento": _clean_digits(request.form.get("nre_ent_departamento")),
                    "distrito": _clean_digits(request.form.get("nre_ent_distrito")),
                    "ciudad": _clean_digits(request.form.get("nre_ent_ciudad")),
                    "telefono": _clean_text(request.form.get("nre_ent_telefono")),
                },
                "vehiculo": {
                    "tipo": (request.form.get("nre_veh_tipo") or "").strip(),
                    "marca": _clean_text(request.form.get("nre_veh_marca")),
                    "documentoTipo": (request.form.get("nre_veh_doc_tipo") or "").strip(),
                    "numeroIden": _clean_text(request.form.get("nre_veh_numero")),
                },
                "transportista": {
                    "tipo": (request.form.get("nre_transp_tipo") or "").strip(),
                    "nombreTr": _clean_text(request.form.get("nre_transp_nombre")),
                    "numeroTr": _clean_text(request.form.get("nre_transp_numero")),
                    "tipoDocumentoTr": (request.form.get("nre_transp_tipo_doc") or "").strip(),
                    "direccionTr": _clean_text(request.form.get("nre_transp_dir")),
                    "nacionalidad": (request.form.get("nre_transp_nacionalidad") or "").strip(),
                    "nombreCh": _clean_text(request.form.get("nre_chof_nombre")),
                    "numeroCh": _clean_text(request.form.get("nre_chof_numero")),
                    "direccionCh": _clean_text(request.form.get("nre_chof_dir")),
                },
            }
            tipo_trans = (request.form.get("nre_trans_tipo") or "").strip()
            if tipo_trans:
                transporte["tipoTransporte"] = tipo_trans

            extra_json = {"remision": remision, "transporte": transporte}
            errors = _validate_doc_extra(doc_type, extra_json)
            if errors:
                return _render_form("Completa los datos de Remisión y Transporte.\n- " + "\n- ".join(errors), 400)
            doc_extra_json = json.dumps(extra_json, ensure_ascii=False)
        else:
            pass

        issued_at = now_iso()
        est = _zfill_digits(request.form.get("establishment") or default_est, 3)
        pun = _zfill_digits(request.form.get("point_exp") or default_pun, 3)
        cur = con.execute(
            "INSERT INTO invoices (created_at, issued_at, customer_id, status, doc_type, establishment, point_exp, doc_extra_json) VALUES (?,?,?,?,?,?,?,?)",
            (now_iso(), issued_at, customer_id, "DRAFT", doc_type, est, pun, doc_extra_json),
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

        confirm_emit = (request.form.get("confirm_emit") or "").strip().upper()
        if confirm_emit == "YES":
            env = (request.form.get("env") or get_setting("default_env", "prod") or "prod").strip().lower()
            if env not in ("test", "prod"):
                abort(400, "env inválido (usar test|prod)")
            return _emit_invoice_existing_flow(invoice_id, env)

        return redirect(url_for("invoice_detail", invoice_id=invoice_id))
    return _render_form()

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
    afe_vendor = _afe_vendor_from_extra(extra_parsed) if doc_type == "4" else {}
    afe_form = _afe_vendor_form_values(afe_vendor) if doc_type == "4" else {}
    ui_debug = (os.getenv("SIFEN_UI_DEBUG") or "").strip() == "1"

    body = render_template_string(
        """
        <div class="d-flex justify-content-between align-items-center mb-3">
          <div>
            <h4 class="mb-0">Documento #{{inv.id}}</h4>
            <div class="text-muted">
              {% if doc_type == "4" %}Autofactura (Emisor){% else %}{{inv.customer_name}}{% endif %} — <span class="mono">{{inv.customer_ruc or "—"}}</span><br>
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

                {% if doc_type == "1" %}
                <form method="post" action="{{ url_for('invoice_cancel', invoice_id=inv.id) }}" class="d-flex gap-2 flex-wrap align-items-center js-cancel-event" data-invoice-id="{{ inv.id }}">
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
                <div class="small mt-1 text-muted" id="cancel-result-{{inv.id}}"></div>
                {% else %}
                <div class="d-flex gap-2 flex-wrap align-items-center">
                  <button class="btn btn-sm btn-danger" type="button" disabled title="Cancelación disponible solo para iTiDE=1 (por ahora)">
                    Cancelar
                  </button>
                  <span class="small text-muted">Cancelación disponible solo para iTiDE=1 (por ahora).</span>
                </div>
                {% endif %}

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

                <script>
                  (function () {
                    document.querySelectorAll(".js-cancel-event").forEach((form) => {
                      form.addEventListener("submit", async function (ev) {
                        ev.preventDefault();
                        const invoiceId = form.getAttribute("data-invoice-id");
                        const resultEl = document.getElementById(`cancel-result-${invoiceId}`);
                        if (resultEl) {
                          resultEl.textContent = "Enviando cancelación...";
                          resultEl.classList.remove("text-danger");
                        }

                        const data = new FormData(form);
                        const payload = {
                          env: data.get("env"),
                          confirm_emit: data.get("confirm_emit") || "",
                          motivo: data.get("motivo") || "",
                          motivo_preset: data.get("motivo_preset") || "",
                        };

                        try {
                          const res = await fetch(`/api/invoices/${invoiceId}/event/cancel`, {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify(payload),
                          });
                          const out = await res.json();
                          if (!res.ok) {
                            throw new Error(out.detail || out.error || "Error al cancelar");
                          }
                          const msg = [
                            out.dEstRes ? `Estado=${out.dEstRes}` : null,
                            out.dCodRes ? `Código=${out.dCodRes}` : null,
                            out.dMsgRes ? `Mensaje=${out.dMsgRes}` : null,
                            out.dProtAut ? `Prot=${out.dProtAut}` : null,
                            out.event_id ? `EventID=${out.event_id}` : null,
                          ].filter(Boolean).join(" | ");
                          if (resultEl) {
                            resultEl.textContent = msg || "Cancelación enviada.";
                            resultEl.classList.remove("text-danger");
                          }
                        } catch (err) {
                          if (resultEl) {
                            resultEl.textContent = err.message || "Error al cancelar";
                            resultEl.classList.add("text-danger");
                          }
                        }
                      });
                    });
                  })();
                </script>

                {% if ui_debug %}
                <hr>
                <div class="accordion" id="invoice-advanced-{{ inv.id }}">
                  <div class="accordion-item">
                    <h2 class="accordion-header" id="invoice-advanced-heading-{{ inv.id }}">
                      <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#invoice-advanced-body-{{ inv.id }}" aria-expanded="false" aria-controls="invoice-advanced-body-{{ inv.id }}">
                        Avanzado
                      </button>
                    </h2>
                    <div id="invoice-advanced-body-{{ inv.id }}" class="accordion-collapse collapse" aria-labelledby="invoice-advanced-heading-{{ inv.id }}">
                      <div class="accordion-body">
                        <h6>Acciones SIFEN</h6>
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

                        <hr class="my-3">
                        <h6>Emisión integrada</h6>
                        <div class="small text-muted mb-2">
                          Email cliente: <span class="mono">{% if doc_type == "4" %}—{% else %}{{ inv.customer_email or "—" }}{% endif %}</span>
                        </div>
                        <div class="small text-muted mb-2">
                          Tipo: <b>{{ doc_type_label(inv.doc_type) }}</b> — si no es Factura, configurá la plantilla específica en /settings.
                        </div>
                        <form method="post" action="{{ url_for('invoice_set_extra', invoice_id=inv.id) }}" class="mb-2">
                          <label class="form-label small text-muted">doc_extra_json (pegar JSON de ejemplo si aplica)</label>
                          <textarea class="form-control form-control-sm mono" name="doc_extra_json" rows="8" placeholder="{}">{{ extra_prefill or "" }}</textarea>
                          <button class="btn btn-sm btn-outline-secondary mt-2" type="submit">Guardar JSON extra</button>
                        </form>
                        {% if doc_type == "4" %}
                        <div class="card mt-3">
                          <div class="card-body">
                            <h6>Datos del vendedor (AFE)</h6>
                            <form method="post" action="{{ url_for('invoice_set_afe_vendedor', invoice_id=inv.id) }}">
                              <div class="row g-2">
                                <div class="col-md-4">
                                  <label class="form-label small">Tipo vendedor</label>
                                  <select class="form-select form-select-sm" name="afe_tipo_vendedor" required>
                                    {% for code, label in afe_nat.items() %}
                                      <option value="{{code}}" {% if afe_form.tipo_vendedor==code %}selected{% endif %}>{{label}}</option>
                                    {% endfor %}
                                  </select>
                                </div>
                                <div class="col-md-4">
                                  <label class="form-label small">Tipo doc. identidad</label>
                                  <select class="form-select form-select-sm" name="afe_tipo_doc" required>
                                    {% for code, label in afe_id.items() %}
                                      <option value="{{code}}" {% if afe_form.tipo_doc==code %}selected{% endif %}>{{label}}</option>
                                    {% endfor %}
                                  </select>
                                </div>
                                <div class="col-md-4">
                                  <label class="form-label small">Nro doc. identidad</label>
                                  <input class="form-control form-control-sm" name="afe_nro_doc" value="{{ afe_form.nro_doc }}" required>
                                </div>
                                <div class="col-md-6">
                                  <label class="form-label small">Nombre / Razón social</label>
                                  <input class="form-control form-control-sm" name="afe_nombre" value="{{ afe_form.nombre }}" required>
                                </div>
                                <div class="col-md-6">
                                  <label class="form-label small">Dirección</label>
                                  <input class="form-control form-control-sm" name="afe_direccion" value="{{ afe_form.direccion }}" required>
                                </div>
                                <div class="col-md-3">
                                  <label class="form-label small">N° casa</label>
                                  <input class="form-control form-control-sm mono" name="afe_num_casa" value="{{ afe_form.num_casa or '0' }}" required>
                                </div>
                                <div class="col-md-3">
                                  <label class="form-label small">Departamento (código)</label>
                                  <input class="form-control form-control-sm mono" name="afe_departamento" value="{{ afe_form.departamento }}" required>
                                </div>
                                <div class="col-md-3">
                                  <label class="form-label small">Distrito (código)</label>
                                  <input class="form-control form-control-sm mono" name="afe_distrito" value="{{ afe_form.distrito }}">
                                </div>
                                <div class="col-md-3">
                                  <label class="form-label small">Ciudad (código)</label>
                                  <input class="form-control form-control-sm mono" name="afe_ciudad" value="{{ afe_form.ciudad }}" required>
                                </div>
                              </div>
                              <button class="btn btn-sm btn-outline-primary mt-2" type="submit">Guardar vendedor AFE</button>
                            </form>
                          </div>
                        </div>
                        {% endif %}
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

                        <hr class="my-3">
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
                </div>
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
        doc_type=doc_type,
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
        afe_nat=AFE_NAT_MAP,
        afe_id=AFE_ID_MAP,
        afe_form=afe_form,
        ui_debug=ui_debug,
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

@app.route("/invoice/<int:invoice_id>/set_afe_vendedor", methods=["POST"])
def invoice_set_afe_vendedor(invoice_id: int):
    init_db()
    con = get_db()
    inv = con.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,)).fetchone()
    if not inv:
        abort(404)
    doc_type = normalize_doc_type(inv["doc_type"])
    if doc_type != "4":
        abort(400, "Solo disponible para Autofactura (iTiDE=4).")
    try:
        extra = _parse_extra_json(inv["doc_extra_json"], doc_type)
    except Exception:
        extra = _default_extra_json_for(doc_type) or {}

    def _clean_digits(value: Optional[str]) -> str:
        return re.sub(r"\D", "", (value or "").strip())

    def _clean_text(value: Optional[str]) -> str:
        return re.sub(r"\s+", " ", (value or "").strip())

    vendor = {
        "iNatVen": (request.form.get("afe_tipo_vendedor") or "").strip(),
        "iTipIDVen": (request.form.get("afe_tipo_doc") or "").strip(),
        "documento": _clean_text(request.form.get("afe_nro_doc")),
        "nombre": _clean_text(request.form.get("afe_nombre")),
        "direccion": _clean_text(request.form.get("afe_direccion")),
        "numCasa": _clean_digits(request.form.get("afe_num_casa")),
        "departamentoVendedor": _clean_digits(request.form.get("afe_departamento")),
        "distritoVendedor": _clean_digits(request.form.get("afe_distrito")),
        "ciudadVendedor": _clean_digits(request.form.get("afe_ciudad")),
    }
    extra = extra or {}
    extra["documentoAsociado"] = {"tipoDocumentoAsoc": "3"}
    _set_afe_vendor_extra(extra, vendor)
    tip_cons = _resolve_afe_constancia_type(extra)
    if tip_cons:
        extra["documentoAsociado"]["tipoConstancia"] = tip_cons

    errors = _validate_doc_extra(doc_type, extra)
    if errors:
        abort(400, "En Autofactura debes completar los datos del vendedor.\n- " + "\n- ".join(errors))

    con.execute(
        "UPDATE invoices SET doc_extra_json=? WHERE id=?",
        (json.dumps(extra, ensure_ascii=False), invoice_id),
    )
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
    return _emit_invoice_existing_flow(invoice_id, env)


def _emit_invoice_existing_flow(invoice_id: int, env: str):
    if env == "prod":
        ok, _detail = _sifen_preflight_ok()
        if not ok:
            init_db()
            con = get_db()
            con.execute(
                """
                UPDATE invoices
                SET status=?,
                    queued_at=?,
                    sifen_env=?,
                    last_sifen_msg=COALESCE(last_sifen_msg,'') || ' | SIFEN DOWN: encolado automático'
                WHERE id=?
                """,
                ("QUEUED", now_iso(), env, invoice_id),
            )
            con.commit()
            _enqueue_invoice(invoice_id, env)
            return redirect(url_for("invoice_detail", invoice_id=invoice_id))

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

@app.route("/api/invoices/<int:invoice_id>/dry-run", methods=["POST"])
def api_invoice_dry_run(invoice_id: int):
    init_db()
    con = get_db()
    payload = request.get_json(silent=True) or request.form or {}
    persist_source_xml = _parse_bool(payload.get("persist_source_xml"), default=False)

    inv = con.execute(
        """
        SELECT i.*, c.name AS customer_name, c.ruc AS customer_ruc, c.email AS customer_email
        FROM invoices i JOIN customers c ON c.id=i.customer_id
        WHERE i.id=?
        """,
        (invoice_id,),
    ).fetchone()
    if not inv:
        return jsonify({"ok": False, "error": "invoice not found"}), 404

    doc_type = normalize_doc_type(inv["doc_type"])
    try:
        extra_json = _parse_extra_json(inv["doc_extra_json"], doc_type)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    errors = _validate_doc_extra(doc_type, extra_json)
    if errors:
        return jsonify({"ok": False, "error": "Errores de validación", "details": errors}), 400

    template_path = _template_for_doc_type(doc_type)
    if not template_path or not Path(template_path).exists():
        return jsonify({"ok": False, "error": f"Plantilla no configurada para {doc_type_label(doc_type)}"}), 400

    lines = con.execute(
        "SELECT * FROM invoice_lines WHERE invoice_id=? ORDER BY id ASC",
        (invoice_id,),
    ).fetchall()
    if not lines:
        return jsonify({"ok": False, "error": "La factura no tiene líneas."}), 400

    dnumdoc = _ensure_doc_number(con, inv, invoice_id)
    issue_dt = _ensure_signed_at(con, inv, invoice_id)
    codseg = _ensure_codseg(con, inv, invoice_id)
    est = (inv["establishment"] or "").strip() if "establishment" in inv.keys() else ""
    pun = (inv["point_exp"] or "").strip() if "point_exp" in inv.keys() else ""

    try:
        build = _build_invoice_xml_from_template(
            template_path=template_path,
            invoice_id=invoice_id,
            customer={"name": inv["customer_name"], "ruc": inv["customer_ruc"]},
            lines=lines,
            doc_number=dnumdoc,
            doc_type=doc_type,
            extra_json=extra_json,
            issue_dt=issue_dt,
            codseg=codseg,
            establishment=est,
            point_exp=pun,
        )
        base_dir, _, rel_signed = _create_signed_qr_artifacts(
            invoice_id=invoice_id,
            build=build,
            doc_type=doc_type,
            run_prefix="webui_dryrun",
        )
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400

    schemas_dir = _repo_root() / "schemas_sifen"
    signed_qr_path = Path(rel_signed)
    if not signed_qr_path.is_absolute():
        signed_qr_path = (_repo_root() / signed_qr_path).resolve()
    try:
        signed_qr_text = signed_qr_path.read_text(encoding="utf-8")
    except Exception as exc:
        return jsonify({"ok": False, "error": f"No se pudo leer XML firmado con QR: {exc}"}), 400

    xsd_ok, xsd_errors = validate_de_xml_against_xsd(signed_qr_text, schemas_dir=schemas_dir)
    if not xsd_ok:
        xsd_error_lines = [str(x).strip() for x in (xsd_errors or []) if str(x).strip()]
        if not xsd_error_lines:
            xsd_error_lines = ["Validación XSD falló sin detalle."]
        (base_dir / "xsd_errors.txt").write_text("\n".join(xsd_error_lines) + "\n", encoding="utf-8")
        return jsonify(
            {
                "ok": False,
                "error": "XSD validation failed",
                "details": xsd_error_lines,
                "artifacts_dir": str(base_dir),
                "invoice_id": invoice_id,
                "doc_type": doc_type,
                "dnumdoc": build.get("dnumdoc"),
                "cdc": build.get("cdc"),
            }
        ), 400

    if persist_source_xml:
        con.execute(
            "UPDATE invoices SET issued_at=COALESCE(issued_at,?), source_xml_path=? WHERE id=?",
            (issue_dt.isoformat(timespec="seconds"), rel_signed, invoice_id),
        )
        con.commit()

    return jsonify(
        {
            "ok": True,
            "invoice_id": invoice_id,
            "doc_type": doc_type,
            "doc_type_label": doc_type_label(doc_type),
            "dry_run": True,
            "sent": False,
            "persist_source_xml": persist_source_xml,
            "source_xml_path": rel_signed if persist_source_xml else None,
            "artifacts_dir": str(base_dir),
            "artifact_links": _artifact_links_for_dir(str(base_dir)),
            "cdc": build.get("cdc"),
            "dnumdoc": build.get("dnumdoc"),
            "xsd_ok": True,
        }
    )

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

    doc_type = normalize_doc_type(inv["doc_type"])
    if doc_type != "1":
        abort(400, f"Cancelación solo habilitada para iTiDE=1. Documento iTiDE={doc_type}.")

    cdc = _extract_cdc_from_xml_path(inv["source_xml_path"] or "")
    if not cdc or len(cdc) != 44:
        abort(400, "No se pudo obtener CDC válido (44) desde source_xml_path. Primero emití y aprobá/firmá el documento.")

    did, event_id = _make_event_ids()
    try:
        parsed = _send_cancel_event(
            env=env,
            cdc=cdc,
            motivo=motivo,
            event_id=event_id,
            did=did,
            artifacts_root=_artifacts_root(),
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

    did, event_id = _make_event_ids()
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
            did=did,
            artifacts_root=_artifacts_root(),
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

def _create_signed_qr_artifacts(
    *,
    invoice_id: int,
    build: dict,
    doc_type: str,
    run_prefix: str,
) -> tuple[Path, str, str]:
    if doc_type == "7":
        _validate_remision_transport_before_sign(build["xml_bytes"])

    base_dir = _artifacts_root() / f"{run_prefix}_{invoice_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    base_dir.mkdir(parents=True, exist_ok=True)

    in_path = base_dir / f"rde_input_{build['dnumdoc']}.xml"
    in_path.write_bytes(build["xml_bytes"])

    p12_path = os.getenv("SIFEN_SIGN_P12_PATH") or os.getenv("SIFEN_P12_PATH") or os.getenv("SIFEN_CERT_PATH")
    p12_password = os.getenv("SIFEN_SIGN_P12_PASSWORD") or os.getenv("SIFEN_P12_PASSWORD") or os.getenv("SIFEN_CERT_PASSWORD")
    if not p12_path or not p12_password:
        raise RuntimeError("Faltan SIFEN_SIGN_P12_PATH/SIFEN_SIGN_P12_PASSWORD (o equivalentes) para firmar.")

    signed_bytes = sign_de_with_p12(build["xml_bytes"], p12_path, p12_password)
    signed_path = base_dir / f"rde_signed_{build['dnumdoc']}.xml"
    signed_path.write_bytes(signed_bytes)

    csc = (os.getenv("SIFEN_CSC") or "").strip()
    csc_id = (os.getenv("SIFEN_CSC_ID") or "0001").strip()
    if not csc:
        raise RuntimeError("Falta SIFEN_CSC para generar QR.")

    signed_qr_text, qr_debug = _update_qr_in_signed_xml(signed_bytes.decode("utf-8"), csc, csc_id)
    signed_qr_path = base_dir / f"rde_signed_qr_{build['dnumdoc']}.xml"
    signed_qr_path.write_text(signed_qr_text, encoding="utf-8")
    (base_dir / f"qr_debug_{build['dnumdoc']}.txt").write_text(
        "\n".join([f"{k}={v}" for k, v in qr_debug.items()]) + "\n",
        encoding="utf-8",
    )

    rel_signed = resolve_existing_xml_path(str(signed_qr_path))
    return base_dir, signed_qr_text, rel_signed

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

    base_dir = None
    if not rel_signed:
        try:
            base_dir, signed_qr_text, rel_signed = _create_signed_qr_artifacts(
                invoice_id=invoice_id,
                build=build,
                doc_type=doc_type,
                run_prefix="webui_emit",
            )
        except RuntimeError as exc:
            abort(400, str(exc))

        con.execute(
            "UPDATE invoices SET issued_at=COALESCE(issued_at,?), source_xml_path=? WHERE id=?",
            (issue_dt.isoformat(timespec="seconds"), rel_signed, invoice_id),
        )
        con.commit()

    # enviar a SIFEN
    repo_root_path = _repo_root()
    venv_py = "python3"
    artifacts_root = _artifacts_root()
    args = [
        venv_py, "-m", "sifen_minisender", "send",
        "--env", env,
        "--artifacts-root", str(artifacts_root),
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
    if doc_type != "4" and inv["customer_email"] and (new_status == "CONFIRMED_OK"):
        try:
            issuer = _build_issuer_from_xml_text(signed_qr_text) or _build_issuer_from_template(template_path)
            pdf_base_dir = base_dir or (_artifacts_root() / f"webui_emit_{invoice_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}")
            pdf_base_dir.mkdir(parents=True, exist_ok=True)
            pdf_path = pdf_base_dir / f"invoice_{invoice_id}.pdf"
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

    _, signed_qr_text, rel_signed = _create_signed_qr_artifacts(
        invoice_id=invoice_id,
        build=build,
        doc_type=doc_type,
        run_prefix="webui_sign",
    )
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
        artifacts_root = _artifacts_root()
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
    venv_py = "python3"
    args = [
        venv_py, "-m", "sifen_minisender", "send",
        "--env", "test",
        "--artifacts-root", str(_artifacts_root()),
        xml_path,
    ]

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
        artifacts_root = _artifacts_root()
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
        base_dir = _artifacts_root() / f"webui_email_{invoice_id}_{ts}"
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
    base_dir = _artifacts_root() / f"webui_preview_{invoice_id}_{ts}"
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
    row = con.execute("SELECT * FROM customers WHERE id=? AND deleted_at IS NULL", (customer_id,)).fetchone()
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
                <button class="btn btn-outline-danger ms-auto" type="button" data-bs-toggle="modal" data-bs-target="#deleteCustomerModal">Eliminar cliente</button>
              </div>
            </form>
            <div class="modal fade" id="deleteCustomerModal" tabindex="-1" aria-hidden="true">
              <div class="modal-dialog modal-dialog-centered">
                <div class="modal-content">
                  <div class="modal-header">
                    <h5 class="modal-title">Eliminar cliente</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Cerrar"></button>
                  </div>
                  <div class="modal-body">
                    ¿Seguro que deseas eliminar este cliente? Esta acción no se puede deshacer.
                  </div>
                  <div class="modal-footer">
                    <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancelar</button>
                    <form method="post" action="{{ url_for('customer_delete', customer_id=row.id) }}">
                      <input type="hidden" name="confirm_delete" value="YES">
                      <button class="btn btn-danger" type="submit">Sí, eliminar</button>
                    </form>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
        """,
        row=row,
    )
    return render_template_string(BASE_HTML, title="Editar cliente", db_path=DB_PATH, body=body)


@app.route("/customer/<int:customer_id>/delete", methods=["POST"])
def customer_delete(customer_id: int):
    init_db()
    con = get_db()
    confirm = (request.form.get("confirm_delete") or "").strip().upper()
    if confirm != "YES":
        abort(400, "Confirmación requerida")

    row = con.execute("SELECT id, deleted_at FROM customers WHERE id=?", (customer_id,)).fetchone()
    if not row:
        abort(404)
    if row["deleted_at"]:
        return redirect(url_for("customers", msg="deleted"))

    inv_count = con.execute(
        "SELECT COUNT(*) n FROM invoices WHERE customer_id=?",
        (customer_id,),
    ).fetchone()["n"]
    if inv_count:
        return redirect(url_for("customers", err="has_invoices"))

    try:
        con.execute("UPDATE customers SET deleted_at=? WHERE id=?", (now_iso(), customer_id))
        con.commit()
    except Exception:
        return redirect(url_for("customers", err="delete_failed"))

    return redirect(url_for("customers", msg="deleted"))


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
    rows = con.execute("SELECT * FROM customers WHERE deleted_at IS NULL ORDER BY id DESC").fetchall()
    msg = (request.args.get("msg") or "").strip()
    err = (request.args.get("err") or "").strip()
    alert = None
    alert_cls = "success"
    if msg == "deleted":
        alert = "Cliente eliminado correctamente."
    elif err == "delete_failed":
        alert = "No se pudo eliminar el cliente. Intenta de nuevo."
        alert_cls = "danger"
    elif err == "has_invoices":
        alert = "No se puede eliminar: el cliente tiene facturas asociadas."
        alert_cls = "warning"
    body = render_template_string(
        """
        <div class="card">
          <div class="card-body">
            <h5>Clientes</h5>
            {% if alert %}
              <div class="alert alert-{{alert_cls}} py-2">{{ alert }}</div>
            {% endif %}
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
        alert=alert,
        alert_cls=alert_cls,
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
        host = os.getenv("WEBUI_HOST", "0.0.0.0")
        port = int(os.getenv("WEBUI_PORT", "8000"))
        app.run(host=host, port=port, debug=False, use_reloader=False)
    except Exception as exc:
        print(f"APP_RUN_ERROR: {exc!r}", file=sys.stderr)
        raise

# ---- PUBLIC FILES (PDFs) ----
import os
WEBUI_PUBLIC_DIR = os.environ.get("WEBUI_PUBLIC_DIR", "/data/public")

@app.route("/public/<path:filename>")
def public_file(filename):
    return send_from_directory(WEBUI_PUBLIC_DIR, filename)
