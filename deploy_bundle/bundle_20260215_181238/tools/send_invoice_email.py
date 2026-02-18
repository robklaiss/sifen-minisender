#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path


def _need(env: str) -> str:
    v = os.getenv(env)
    if not v:
        raise SystemExit(f"Falta env var requerida: {env}")
    return v


def send_email(
    *,
    smtp_host: str,
    smtp_port: int,
    smtp_user: str | None,
    smtp_pass: str | None,
    mail_from: str,
    mail_to: str,
    subject: str,
    body_text: str,
    pdf_path: Path,
) -> None:
    pdf_path = Path(pdf_path)
    if not pdf_path.exists():
        raise SystemExit(f"PDF no encontrado para adjuntar: {pdf_path}")
    if not pdf_path.is_file():
        raise SystemExit(f"Ruta PDF inválida (no es archivo): {pdf_path}")

    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = mail_to
    msg["Subject"] = subject
    msg.set_content(body_text)

    pdf_bytes = pdf_path.read_bytes()
    msg.add_attachment(
        pdf_bytes,
        maintype="application",
        subtype="pdf",
        filename=pdf_path.name,
    )

    context = ssl.create_default_context()
    smtp_debug = os.getenv("SMTP_DEBUG") == "1"

    # 587 = STARTTLS (recomendado). 465 = SSL directo.
    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=30) as s:
            if smtp_debug:
                s.set_debuglevel(1)
            if smtp_user:
                s.login(smtp_user, smtp_pass or "")
            s.send_message(msg)
    else:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as s:
            if smtp_debug:
                s.set_debuglevel(1)
            s.ehlo()
            s.starttls(context=context)
            s.ehlo()
            if smtp_user:
                s.login(smtp_user, smtp_pass or "")
            s.send_message(msg)


def main() -> int:
    ap = argparse.ArgumentParser(description="Envía una factura PDF por email (SMTP).")
    ap.add_argument("--to", required=True, help="Email destinatario")
    ap.add_argument("--pdf", required=True, help="Ruta al PDF a adjuntar")
    ap.add_argument("--subject", default=None, help="Asunto (opcional)")
    ap.add_argument("--body", default=None, help="Cuerpo texto (opcional)")
    args = ap.parse_args()

    smtp_host = _need("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")  # puede ser None
    smtp_pass = os.getenv("SMTP_PASS")  # puede ser None
    mail_from = _need("MAIL_FROM")

    subject = args.subject or f"Factura - {Path(args.pdf).name}"
    body = args.body or "Adjunto encontrarás tu factura en PDF.\n\nSaludos."

    send_email(
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        smtp_user=smtp_user,
        smtp_pass=smtp_pass,
        mail_from=mail_from,
        mail_to=args.to,
        subject=subject,
        body_text=body,
        pdf_path=Path(args.pdf),
    )

    print("✅ Email enviado OK (SMTP).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
