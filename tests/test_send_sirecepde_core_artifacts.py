from pathlib import Path
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.send_sirecepde import ensure_core_artifacts


def test_ensure_core_artifacts_creates_required_files(tmp_path: Path):
    run_dir = tmp_path / "run_20260217_000000"
    run_dir.mkdir(parents=True, exist_ok=True)

    (run_dir / "soap_last_request_SENT.xml").write_text(
        "<soap:Envelope xmlns:soap='http://www.w3.org/2003/05/soap-envelope'/>",
        encoding="utf-8",
    )
    (run_dir / "last_lote.xml").write_text(
        "<rLoteDE xmlns='http://ekuatia.set.gov.py/sifen/xsd'>"
        "<rDE><DE Id='01234567890123456789012345678901234567890123'/>"
        "<Signature xmlns='http://www.w3.org/2000/09/xmldsig#'/>"
        "<gCamFuFD><dCarQR>x</dCarQR></gCamFuFD>"
        "</rDE></rLoteDE>",
        encoding="utf-8",
    )

    ensure_core_artifacts(
        artifacts_dir=run_dir,
        result={
            "success": False,
            "error": "network error",
            "error_type": "SifenClientError",
        },
    )

    assert (run_dir / "de.xml").exists()
    assert (run_dir / "soap_last_request.xml").exists()
    assert (run_dir / "soap_last_response.xml").exists()
    assert (run_dir / "sifen_response.json").exists()

    payload = json.loads((run_dir / "sifen_response.json").read_text(encoding="utf-8"))
    assert payload["success"] is False
    assert payload["error_type"] == "SifenClientError"


def test_ensure_core_artifacts_writes_fallbacks_on_early_failure(tmp_path: Path):
    run_dir = tmp_path / "run_20260217_000001"
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "factura_input.xml").write_text(
        "<rDE xmlns='http://ekuatia.set.gov.py/sifen/xsd'/>",
        encoding="utf-8",
    )

    ensure_core_artifacts(
        artifacts_dir=run_dir,
        result={
            "success": False,
            "error": "Certificado P12 no encontrado",
            "error_type": "XMLSecError",
        },
    )

    assert (run_dir / "de.xml").exists()
    assert (run_dir / "soap_last_request.xml").exists()
    assert (run_dir / "soap_last_response.xml").exists()
    assert (run_dir / "sifen_response.json").exists()

    request_text = (run_dir / "soap_last_request.xml").read_text(encoding="utf-8")
    assert "NO_REQUEST_CAPTURED" in request_text
    de_text = (run_dir / "de.xml").read_text(encoding="utf-8")
    assert "<rDE" in de_text
