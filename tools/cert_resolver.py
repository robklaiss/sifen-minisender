# tools/cert_resolver.py
# Utilidades livianas para validar cert mTLS y guardar artefactos de diagnóstico.

from __future__ import annotations

from pathlib import Path
from typing import Optional, Tuple

def _read_pem_cert(cert_path: str) -> bytes:
    p = Path(cert_path).expanduser()
    return p.read_bytes()

def validate_no_self_signed(cert_path: str, label=None) -> Tuple[bool, str]:
    """
    Valida (best-effort) que el certificado no sea autofirmado.
    Retorna (ok, mensaje).
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        pem = _read_pem_cert(cert_path)
        cert = x509.load_pem_x509_certificate(pem, default_backend())
        subj = cert.subject.rfc4514_string()
        iss = cert.issuer.rfc4514_string()

        # Heurística: self-signed si issuer == subject
        if subj == iss:
            return (False, "Certificado parece autofirmado (issuer == subject)")
        return (True, "Certificado OK (no parece autofirmado)")
    except Exception as e:
        # No bloqueamos si falla la inspección; reportamos.
        return (True, f"WARNING: no pude inspeccionar certificado ({type(e).__name__}: {e})")

def save_resolved_certs_artifact(
    *,
    artifacts_dir: str,
    cert_path: Optional[str] = None,
    key_path: Optional[str] = None,
    note: str = "",
) -> None:
    """
    Guarda un artifact de texto con los paths efectivos usados para mTLS.
    """
    out_dir = Path(artifacts_dir).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "resolved_certs.txt"
    lines = []
    if note:
        lines.append(f"note={note}")
    if cert_path:
        lines.append(f"cert_path={cert_path}")
    if key_path:
        lines.append(f"key_path={key_path}")
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
