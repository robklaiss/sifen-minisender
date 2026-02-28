from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.sifen_client.utils import sifen_timestamp  # noqa: E402


def test_sifen_timestamp_includes_offset():
    ts = sifen_timestamp()
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$", ts)


def test_sifen_timestamp_normalizes_string_without_offset():
    ts = sifen_timestamp("2026-02-27T19:55:00")
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2}$", ts)
