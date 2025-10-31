import threading
from unittest.mock import MagicMock, patch

import pytest

from dnsrobocert.core import background


@patch("dnsrobocert.core.background.schedule")
@patch("dnsrobocert.core.background._launch_background_jobs")
def test_worker_starts_and_cleans_up(
    mock_launch: MagicMock, mock_schedule: MagicMock
) -> None:
    thread = MagicMock()
    thread.is_alive.return_value = True
    mock_launch.return_value = thread

    chained_schedule = MagicMock()
    mock_schedule.every.return_value = chained_schedule
    chained_schedule.day.return_value = chained_schedule
    chained_schedule.at.return_value = chained_schedule
    chained_schedule.tag.return_value = chained_schedule

    with background.worker("config", "directory", threading.Lock()):
        pass

    mock_schedule.clear.assert_any_call(background._RENEW_JOB_TAG)
    mock_launch.assert_called_once()
    thread.join.assert_called_once_with(timeout=5.0)


def test_launch_background_jobs_honors_stop_event(monkeypatch: pytest.MonkeyPatch) -> None:
    stop_event = threading.Event()
    run_triggered = threading.Event()

    monkeypatch.setattr(background.schedule, "idle_seconds", lambda: 0.05)

    def fake_run_pending() -> None:
        run_triggered.set()
        stop_event.set()

    monkeypatch.setattr(background.schedule, "run_pending", fake_run_pending)

    thread = background._launch_background_jobs(stop_event, interval=0.1)

    assert run_triggered.wait(timeout=1.0)
    thread.join(timeout=1.0)

    assert not thread.is_alive()

