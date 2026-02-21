from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.consulta_lote_poll import generate_did, parse_consulta_lote_response


def test_generate_did_is_digits_only():
    did = generate_did()
    assert did.isdigit()
    assert len(did) == 14
    assert "_" not in did


def test_parser_extracts_gresproclote_from_fixture():
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "consulta_lote_poll_response.xml"
    parsed = parse_consulta_lote_response(fixture_path.read_bytes(), http_status=200)

    assert parsed["http_status"] == 200
    assert parsed["root_tag"] == "rResEnviConsLoteDe"
    assert parsed["dCodResLot"] == "0365"
    assert parsed["dMsgResLot"] == "Procesado con observaciones"
    assert parsed["gResProcLote"] == [
        {
            "id": "01800600505001001000000012026021219999999999",
            "dEstRes": "1",
            "dCodRes": "0000",
            "dMsgRes": "Aprobado",
        },
        {
            "id": "01800600505001001000000013026021218888888888",
            "dEstRes": "2",
            "dCodRes": "0200",
            "dMsgRes": "Error de validacion",
        },
    ]
