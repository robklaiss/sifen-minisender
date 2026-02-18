#!/usr/bin/env python3
from __future__ import annotations

import argparse
import logging
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict

from reportlab import rl_config

# Permite ejecutar como `python -m tools.test_smtp_pdf_flow`
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.post_consulta_lote import handle_post_consulta_lote

logger = logging.getLogger(__name__)


def _load_dotenv(dotenv_path: Path) -> Dict[str, str]:
    if not dotenv_path.exists():
        raise RuntimeError(f"No se encontró archivo .env en: {dotenv_path}")

    loaded: Dict[str, str] = {}
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]

        loaded[key] = value
        os.environ[key] = value

    return loaded


def _need_env(name: str) -> str:
    value = (os.getenv(name) or "").strip()
    if not value:
        raise RuntimeError(f"Falta configuración requerida en .env: {name}")
    return value


def _safe_for_path(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", (value or "").strip()) or "de"


def _build_test_payload(cdc: str, today_iso: str) -> dict:
    return {
        "CDC": cdc,
        "serie": "TST",
        "numero": today_iso.replace("-", ""),
        "fecha": today_iso,
        "parsed_fields": {
            "dCodRes": "0260",
            "dMsgRes": "FACTURA APROBADA TEST SMTP",
            "dNomRec": "FACTURA APROBADA TEST SMTP",
        },
        "items": [
            {
                "cantidad": "1",
                "descripcion": "FACTURA APROBADA TEST SMTP",
                "precio_unit": "0",
                "total": "0",
                "iva": "0",
            },
            {
                "cantidad": "1",
                "descripcion": f"CDC: {cdc}",
                "precio_unit": "0",
                "total": "0",
                "iva": "0",
            },
            {
                "cantidad": "1",
                "descripcion": f"FECHA: {today_iso}",
                "precio_unit": "0",
                "total": "0",
                "iva": "0",
            },
        ],
    }


def _expected_pdf_path(artifacts_root: Path, cdc: str) -> Path:
    cdc_safe = _safe_for_path(cdc)
    return artifacts_root / "post_consulta_lote" / cdc_safe / f"invoice_{cdc_safe}.pdf"


def _validate_pdf(pdf_path: Path, *, cdc: str, today_iso: str) -> None:
    if not pdf_path.exists():
        raise RuntimeError(f"PDF no encontrado: {pdf_path}")

    pdf_bytes = pdf_path.read_bytes()
    if not pdf_bytes.startswith(b"%PDF"):
        raise RuntimeError(f"PDF inválido (no empieza con %PDF): {pdf_path}")

    expected_texts = (
        "FACTURA APROBADA TEST SMTP",
        f"CDC: {cdc}",
        today_iso,
    )
    missing = [text for text in expected_texts if text.encode("utf-8") not in pdf_bytes]
    if missing:
        raise RuntimeError(f"PDF generado pero faltan textos esperados: {missing}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Verifica flujo PDF + SMTP post-consulta lote (dCodRes=0260).")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true", help="Genera PDF pero no envía email.")
    mode.add_argument("--real", action="store_true", help="Genera PDF y envía email real por SMTP.")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    email_sent = False
    success = False

    dot_env_path = Path(".env")
    try:
        _load_dotenv(dot_env_path)

        smtp_host = _need_env("SMTP_HOST")
        smtp_port = (os.getenv("SMTP_PORT") or "587").strip()
        smtp_user = (os.getenv("SMTP_USER") or "").strip()
        smtp_pass = os.getenv("SMTP_PASS") or ""
        mail_from = _need_env("MAIL_FROM")
        email_to = (os.getenv("SIFEN_EMAIL_TO") or "").strip() or "robin@vinculo.com.py"
        if args.real:
            os.environ["SMTP_DEBUG"] = "1"

        now = datetime.now()
        today_iso = now.date().isoformat()
        cdc = f"TESTSMTP{now.strftime('%Y%m%d%H%M%S')}"
        artifacts_root = Path("artifacts") / "test_smtp"
        expected_pdf = _expected_pdf_path(artifacts_root, cdc)
        subject = f"FACTURA APROBADA TEST SMTP {today_iso}"

        # Facilita validación textual del PDF en bytes (sin compresión de streams).
        rl_config.pageCompression = 0

        print(f"SMTP_HOST: {smtp_host}")
        print(f"SMTP_PORT: {smtp_port}")
        print(f"SMTP_USER: {smtp_user or '<vacío>'}")
        print(f"SMTP_PASS: {'<set>' if smtp_pass else '<vacío>'}")
        print(f"MAIL_FROM: {mail_from}")
        print(f"EMAIL_TO: {email_to}")
        print(f"SUBJECT: {subject}")
        print(f"PDF_PATH (esperado): {expected_pdf}")
        if args.real:
            print("SMTP_DEBUG: 1")

        try:
            result = handle_post_consulta_lote(
                dCodRes="0260",
                de_id=cdc,
                otros_campos={
                    "artifacts_root": artifacts_root,
                    "email_to": "" if args.dry_run else email_to,
                    "pdf_data": _build_test_payload(cdc=cdc, today_iso=today_iso),
                    "email_subject": subject,
                    "email_body": f"Prueba SMTP/PDF OK. CDC: {cdc}. Fecha: {today_iso}",
                },
            )
            pdf_path = Path(result.get("pdf_path") or expected_pdf)
            email_sent = bool(result.get("email_sent"))
        except Exception as exc:
            pdf_path = expected_pdf
            email_sent = False
            logger.exception("Error durante handle_post_consulta_lote")
            print(f"EMAIL ERROR: {exc}")

        if args.dry_run:
            print("EMAIL SKIPPED (dry-run)")
        elif email_sent:
            print("EMAIL SENT OK")

        print(f"PDF_PATH (generado): {pdf_path}")
        if pdf_path.exists():
            print(f"PDF_SIZE_BYTES: {pdf_path.stat().st_size}")

        try:
            _validate_pdf(pdf_path, cdc=cdc, today_iso=today_iso)
            pdf_ok = True
        except Exception as exc:
            pdf_ok = False
            logger.exception("Validación PDF falló")
            print(f"PDF VALIDATION ERROR: {exc}")

        success = pdf_ok and (args.dry_run or email_sent)
    except Exception as exc:
        logger.exception("Error fatal en script de verificación")
        print(f"FATAL: {exc}")
        success = False
        email_sent = False
        pdf_path = Path("artifacts") / "test_smtp" / "post_consulta_lote" / "unknown" / "invoice_unknown.pdf"

    print("=== RESULT ===")
    print(f"PDF: {pdf_path}")
    print(f"EMAIL_SENT: {email_sent}")
    print(f"SUCCESS: {success}")
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
