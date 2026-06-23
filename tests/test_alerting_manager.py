"""Tests for the alert manager: severity floor, dedup, throttle, routing, firewall."""

from __future__ import annotations

import pytest
from structlog.testing import capture_logs

from sentinel.alerting.manager import AlertManager
from sentinel.alerting.model import Alert
from sentinel.alerting.sinks.base import AlertSink
from tests.conftest import make_detection


def _clock() -> float:
    return 1000.0  # constant → every event lands inside any window


class _Clock:
    """An advanceable monotonic-style clock for window-expiry tests."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _Recorder(AlertSink):
    name = "recorder"

    def __init__(self, *, name: str = "recorder", min_severity: int = 0) -> None:
        super().__init__(name=name, min_severity=min_severity)
        self.received: list[Alert] = []

    async def emit(self, alert: Alert) -> None:
        self.received.append(alert)


class _Boom(AlertSink):
    name = "boom"

    def __init__(self, *, message: str = "explode") -> None:
        super().__init__()
        self._message = message

    async def emit(self, alert: Alert) -> None:
        raise RuntimeError(self._message)


class TestGates:
    @pytest.mark.asyncio
    async def test_emits_to_sink(self) -> None:
        sink = _Recorder()
        manager = AlertManager([sink])

        alert = await manager.process(make_detection())

        assert alert is not None
        assert len(sink.received) == 1
        assert manager.stats["emitted"] == 1

    @pytest.mark.asyncio
    async def test_severity_floor_suppresses(self) -> None:
        sink = _Recorder()
        manager = AlertManager([sink], min_severity=6)

        result = await manager.process(make_detection(severity=3))

        assert result is None
        assert sink.received == []
        assert manager.stats["suppressed_severity"] == 1

    @pytest.mark.asyncio
    async def test_dedup_collapses_identical_detections(self) -> None:
        sink = _Recorder()
        manager = AlertManager([sink], time_source=_clock)
        detection = make_detection(event_id="a" * 64)

        for _ in range(3):
            await manager.process(detection)

        assert len(sink.received) == 1
        assert manager.stats["deduped"] == 2

    @pytest.mark.asyncio
    async def test_throttle_caps_per_rule(self) -> None:
        sink = _Recorder()
        manager = AlertManager([sink], throttle_max=2, time_source=_clock)

        # Same rule, distinct events (so dedup lets them through) — only the
        # first two within the window should reach the sink.
        for i in range(5):
            await manager.process(make_detection(event_id=f"{i:064d}"))

        assert len(sink.received) == 2
        assert manager.stats["throttled"] == 3

    @pytest.mark.asyncio
    async def test_throttle_window_evicts_old_entries(self) -> None:
        sink = _Recorder()
        clock = _Clock()
        manager = AlertManager(
            [sink], throttle_max=2, throttle_window_seconds=60, time_source=clock
        )

        for i in range(3):  # two pass, the third is throttled
            await manager.process(make_detection(event_id=f"{i:064d}"))
        assert len(sink.received) == 2

        clock.advance(61)  # slide past the throttle window — old hits expire
        await manager.process(make_detection(event_id="f" * 64))
        assert len(sink.received) == 3

    def test_sinks_property_exposes_configured_sinks(self) -> None:
        sink = _Recorder()
        manager = AlertManager([sink])
        assert list(manager.sinks) == [sink]


class TestRoutingAndFirewall:
    @pytest.mark.asyncio
    async def test_routes_by_sink_severity(self) -> None:
        low = _Recorder(name="low", min_severity=0)
        high = _Recorder(name="high", min_severity=6)
        manager = AlertManager([low, high])

        await manager.process(make_detection(severity=4))

        assert len(low.received) == 1
        assert high.received == []  # below the email-grade sink's floor

    @pytest.mark.asyncio
    async def test_one_failing_sink_does_not_stop_others(self) -> None:
        good = _Recorder()
        manager = AlertManager([_Boom(), good])

        alert = await manager.process(make_detection())

        assert alert is not None  # delivery was attempted and counted
        assert len(good.received) == 1
        assert manager.stats["sink_errors"] == 1

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_sink_error_log_does_not_leak_payload_or_secret(self) -> None:
        secret = "TOP-SECRET-VALUE"  # pragma: allowlist secret
        manager = AlertManager([_Boom(message=f"smtp auth failed for {secret}")])

        with capture_logs() as logs:
            await manager.process(make_detection())

        blob = repr(logs)
        assert secret not in blob  # the exception message must not be logged
        assert any(entry.get("error") == "RuntimeError" for entry in logs)
