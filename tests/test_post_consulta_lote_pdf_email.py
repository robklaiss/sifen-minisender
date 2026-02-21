from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import Mock
import sys

from reportlab import rl_config

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.post_consulta_lote import handle_post_consulta_lote


def _base_issuer() -> dict:
    return {
        "razon_social": "Empresa Demo S.A.",
        "ruc": "80012345",
        "dv": "6",
        "direccion": "Av. Principal 123",
        "telefono": "0991 000000",
        "email": "facturacion@empresa.demo",
        "timbrado": "12345678",
        "vigencia": "2026-12-31",
    }


def test_handle_post_consulta_lote_0260_genera_pdf_y_envia_email(tmp_path, monkeypatch, caplog):
    email_mock = Mock()
    monkeypatch.setattr("tools.post_consulta_lote.send_email", email_mock)
    caplog.set_level(logging.INFO)

    cdc = "01800600505001001000000012026021219999999999"
    result = handle_post_consulta_lote(
        dCodRes="0260",
        de_id=cdc,
        otros_campos={
            "artifacts_root": tmp_path / "artifacts",
            "issuer": _base_issuer(),
            "email_to": "cliente@example.com",
            "smtp_host": "smtp.example.test",
            "smtp_port": 587,
            "mail_from": "no-reply@example.test",
            "pdf_data": {"numero": "1001", "serie": "001"},
        },
    )

    assert result["processed"] is True
    assert result["pdf_generated"] is True
    assert result["email_sent"] is True

    pdf_path = Path(result["pdf_path"])
    assert pdf_path.exists()
    assert "artifacts/post_consulta_lote" in str(pdf_path)

    email_mock.assert_called_once()
    call_kwargs = email_mock.call_args.kwargs
    assert call_kwargs["mail_to"] == "cliente@example.com"
    assert Path(call_kwargs["pdf_path"]).exists()

    assert f"PDF generado para CDC={cdc}" in caplog.text
    assert "Email enviado a cliente@example.com" in caplog.text


def test_handle_post_consulta_lote_distinto_de_0260_no_genera_pdf_ni_email(tmp_path):
    email_mock = Mock()
    pdf_renderer_mock = Mock()
    cdc = "01800600505001001000000013026021218888888888"

    result = handle_post_consulta_lote(
        dCodRes="0300",
        de_id=cdc,
        otros_campos={
            "artifacts_root": tmp_path / "artifacts",
            "issuer": _base_issuer(),
            "email_to": "cliente@example.com",
            "smtp_host": "smtp.example.test",
            "mail_from": "no-reply@example.test",
            "email_sender": email_mock,
            "pdf_renderer": pdf_renderer_mock,
        },
    )

    assert result["processed"] is False
    assert result["pdf_generated"] is False
    assert result["email_sent"] is False
    assert result["pdf_path"] is None

    pdf_renderer_mock.assert_not_called()
    email_mock.assert_not_called()
    assert not (tmp_path / "artifacts" / "post_consulta_lote").exists()


def test_pdf_generado_en_artifacts_tiene_contenido_minimo(tmp_path, monkeypatch):
    # El PDF esperado se busca en: artifacts/post_consulta_lote/<CDC>/invoice_<CDC>.pdf
    monkeypatch.setattr(rl_config, "pageCompression", 0, raising=False)

    cdc = "01800600505001001000000012026021217777777777"
    result = handle_post_consulta_lote(
        dCodRes="0260",
        de_id=cdc,
        otros_campos={
            "artifacts_root": tmp_path / "artifacts",
            "issuer": _base_issuer(),
            "email_to": "",
            "pdf_data": {"numero": "7777", "serie": "002"},
        },
    )

    pdf_path = Path(result["pdf_path"])
    assert pdf_path.exists()
    pdf_bytes = pdf_path.read_bytes()
    assert pdf_bytes.startswith(b"%PDF")
    assert b"FACTURA" in pdf_bytes
    assert b"7777" in pdf_bytes
