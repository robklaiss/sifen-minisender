#!/usr/bin/env python3
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any, Dict

from app.pdf.invoice_renderer import render_invoice_pdf
from tools.render_invoice_pdf import build_issuer
from tools.send_invoice_email import send_email

logger = logging.getLogger(__name__)


def _safe_for_path(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", (value or "").strip()) or "de"


def _build_pdf_data(dcodres: str, de_id: str, otros_campos: Dict[str, Any]) -> Dict[str, Any]:
    data = dict(otros_campos.get("pdf_data") or {})
    parsed_fields = dict(data.get("parsed_fields") or {})
    parsed_fields.setdefault("dCodRes", dcodres)
    parsed_fields.setdefault("dMsgRes", otros_campos.get("dMsgRes") or "Aprobado")
    data["parsed_fields"] = parsed_fields
    data.setdefault("CDC", de_id)
    data.setdefault("numero", otros_campos.get("numero") or de_id[-8:] if de_id else "")
    data.setdefault("serie", otros_campos.get("serie") or "001")
    return data


def handle_post_consulta_lote(
    dCodRes: str,
    de_id: str,
    otros_campos: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    otros_campos = dict(otros_campos or {})
    dCodRes = (dCodRes or "").strip()
    de_id = (de_id or "").strip()

    if not de_id:
        raise ValueError("de_id es requerido")

    if dCodRes == "0260":
        artifacts_root = Path(otros_campos.get("artifacts_root") or "artifacts").expanduser()
        cdc_safe = _safe_for_path(de_id)
        pdf_dir = artifacts_root / "post_consulta_lote" / cdc_safe
        pdf_path = Path(otros_campos.get("pdf_path") or (pdf_dir / f"invoice_{cdc_safe}.pdf"))
        pdf_path.parent.mkdir(parents=True, exist_ok=True)

        issuer = dict(otros_campos.get("issuer") or build_issuer(otros_campos.get("env")))
        pdf_data = _build_pdf_data(dCodRes, de_id, otros_campos)
        pdf_renderer = otros_campos.get("pdf_renderer") or render_invoice_pdf
        pdf_renderer(data=pdf_data, issuer=issuer, out_path=pdf_path)
        logger.info("PDF generado para CDC=%s en %s", de_id, pdf_path)

        email_to = str(otros_campos.get("email_to") or "").strip()
        if not email_to:
            logger.warning("dCodRes=0260 pero email_to vacío para CDC=%s; se omite envío de email.", de_id)
            return {
                "processed": True,
                "email_sent": False,
                "pdf_generated": True,
                "pdf_path": str(pdf_path),
                "dCodRes": dCodRes,
                "de_id": de_id,
            }

        smtp_host = str(otros_campos.get("smtp_host") or os.getenv("SMTP_HOST") or "").strip()
        smtp_port = int(otros_campos.get("smtp_port") or os.getenv("SMTP_PORT") or "587")
        smtp_user = otros_campos.get("smtp_user") if "smtp_user" in otros_campos else os.getenv("SMTP_USER")
        smtp_pass = otros_campos.get("smtp_pass") if "smtp_pass" in otros_campos else os.getenv("SMTP_PASS")
        mail_from = str(otros_campos.get("mail_from") or os.getenv("MAIL_FROM") or "").strip()
        if not smtp_host or not mail_from:
            raise RuntimeError("SMTP_HOST y MAIL_FROM son requeridos para enviar email")

        email_subject = str(otros_campos.get("email_subject") or f"Factura aprobada - CDC {de_id}")
        email_body = str(
            otros_campos.get("email_body")
            or f"El DE con CDC {de_id} fue aprobado por SIFEN (dCodRes=0260). Se adjunta PDF."
        )
        email_sender = otros_campos.get("email_sender") or send_email
        email_sender(
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_user=smtp_user,
            smtp_pass=smtp_pass,
            mail_from=mail_from,
            mail_to=email_to,
            subject=email_subject,
            body_text=email_body,
            pdf_path=pdf_path,
        )
        logger.info("Email enviado a %s para CDC=%s", email_to, de_id)

        return {
            "processed": True,
            "email_sent": True,
            "pdf_generated": True,
            "pdf_path": str(pdf_path),
            "dCodRes": dCodRes,
            "de_id": de_id,
        }

    logger.info("dCodRes=%s para CDC=%s, no se genera PDF ni se envía email.", dCodRes or "<vacío>", de_id)
    return {
        "processed": False,
        "email_sent": False,
        "pdf_generated": False,
        "pdf_path": None,
        "dCodRes": dCodRes,
        "de_id": de_id,
    }
