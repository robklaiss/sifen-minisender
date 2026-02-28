from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def test_cancel_guardrail_expired_window():
    tz = ZoneInfo("America/Asuncion")
    issued_at = datetime(2024, 1, 1, 10, 0, 0, tzinfo=tz)
    now = issued_at + timedelta(hours=24, minutes=1)
    with pytest.raises(RuntimeError) as exc:
        webapp._validate_cancel_allowed(
            "CONFIRMED_OK",
            issued_at.isoformat(timespec="seconds"),
            now=now,
        )
    assert "Cancelación fuera de plazo" in str(exc.value)


def test_cancel_guardrail_status_not_confirmed():
    tz = ZoneInfo("America/Asuncion")
    issued_at = datetime(2024, 1, 1, 10, 0, 0, tzinfo=tz)
    now = issued_at + timedelta(hours=1)
    with pytest.raises(RuntimeError) as exc:
        webapp._validate_cancel_allowed(
            "DRAFT",
            issued_at.isoformat(timespec="seconds"),
            now=now,
        )
    assert "CONFIRMED_OK" in str(exc.value)


def test_cancel_guardrail_ok_within_window():
    tz = ZoneInfo("America/Asuncion")
    issued_at = datetime(2024, 1, 1, 10, 0, 0, tzinfo=tz)
    now = issued_at + timedelta(hours=23)
    deadline_iso, remaining = webapp._validate_cancel_allowed(
        "CONFIRMED_OK",
        issued_at.isoformat(timespec="seconds"),
        now=now,
    )
    assert deadline_iso is not None
    assert remaining == 3600
