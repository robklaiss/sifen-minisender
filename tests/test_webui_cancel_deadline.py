from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import webui.app as webapp


def test_cancel_remaining_seconds_two_hours():
    tz = ZoneInfo("America/Asuncion")
    issued_at = datetime(2024, 1, 1, 10, 0, 0, tzinfo=tz)
    now = issued_at + timedelta(hours=22)
    deadline_iso, remaining = webapp._compute_cancel_deadline_and_remaining(
        issued_at.isoformat(timespec="seconds"),
        now=now,
    )
    assert deadline_iso is not None
    assert remaining == 2 * 3600


def test_cancel_remaining_seconds_thirty_minutes():
    tz = ZoneInfo("America/Asuncion")
    issued_at = datetime(2024, 1, 1, 10, 0, 0, tzinfo=tz)
    now = issued_at + timedelta(hours=23, minutes=30)
    deadline_iso, remaining = webapp._compute_cancel_deadline_and_remaining(
        issued_at.isoformat(timespec="seconds"),
        now=now,
    )
    assert deadline_iso is not None
    assert remaining == 30 * 60


def test_cancel_remaining_seconds_expired():
    tz = ZoneInfo("America/Asuncion")
    issued_at = datetime(2024, 1, 1, 10, 0, 0, tzinfo=tz)
    now = issued_at + timedelta(hours=24, minutes=5)
    deadline_iso, remaining = webapp._compute_cancel_deadline_and_remaining(
        issued_at.isoformat(timespec="seconds"),
        now=now,
    )
    assert deadline_iso is not None
    assert remaining == -5 * 60
