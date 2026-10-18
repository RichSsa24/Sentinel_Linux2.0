"""Tests for the alert manager: severity floor, dedup, throttle, routing, firewall."""

from __future__ import annotations

import asyncio

import pytest
from structlog.testing import capture_logs

from sentinel.alerting.manager import AlertManager
from sentinel.alerting.model import Alert
from sentinel.alerting.sinks.base import AlertSink
from sentinel.detection.schema import Throttle
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
        await manager.drain()

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
        await manager.drain()

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
        await manager.drain()

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
        await manager.drain()
        assert len(sink.received) == 2

        clock.advance(61)  # slide past the throttle window — old hits expire
        await manager.process(make_detection(event_id="f" * 64))
        await manager.drain()
        assert len(sink.received) == 3

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_throttled_alerts_are_kept_for_storage_and_announced(self) -> None:
        # Regression: decoys that exhaust a rule's budget made the real attack's
        # alert vanish: neither notified nor stored, with no trace but a counter.
        sink = _Recorder()
        clock = _Clock()
        manager = AlertManager(
            [sink], throttle_max=1, throttle_window_seconds=60, time_source=clock
        )
        await manager.process(make_detection(event_id="1" * 64))  # the decoy
        with capture_logs() as logs:
            withheld = [await manager.process(make_detection(event_id=f"{i:064d}")) for i in (2, 3)]
        assert [alert.notified for alert in withheld if alert] == [False, False]
        assert [e["event"] for e in logs] == ["alert.throttled"]  # once per window

        clock.advance(61)
        delivered = await manager.process(make_detection(event_id="4" * 64))
        await manager.drain()
        assert delivered is not None
        assert delivered.notified
        assert "+2 more alert(s) from this rule withheld" in sink.received[-1].summary

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
        await manager.drain()

        assert len(low.received) == 1
        assert high.received == []  # below the email-grade sink's floor

    @pytest.mark.asyncio
    async def test_one_failing_sink_does_not_stop_others(self) -> None:
        good = _Recorder()
        manager = AlertManager([_Boom(), good])

        alert = await manager.process(make_detection())
        await manager.drain()

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
            await manager.drain()

        blob = repr(logs)
        assert secret not in blob  # the exception message must not be logged
        assert any(entry.get("error") == "RuntimeError" for entry in logs)


class _CloseBoom(_Recorder):
    async def aclose(self) -> None:
        raise OSError("socket already closed")


class TestDeliveryAccounting:
    @pytest.mark.asyncio
    async def test_counts_successful_deliveries_per_sink(self) -> None:
        good, bad = _Recorder(name="good"), _Boom()
        manager = AlertManager([good, bad])
        await manager.process(make_detection(event_id="1" * 64))
        await manager.process(make_detection(event_id="2" * 64))
        await manager.drain()
        assert manager.delivered_by_sink == {"good": 2, "boom": 0}

    @pytest.mark.asyncio
    async def test_rule_throttle_override(self) -> None:
        sink = _Recorder()
        manager = AlertManager(
            [sink],
            throttle_max=100,
            rule_throttles={"noisy": Throttle(window_seconds=60, max_alerts=1)},
            time_source=_clock,
        )
        for i in range(3):
            await manager.process(make_detection(rule_id="noisy", event_id=f"{i:064d}"))
        await manager.process(make_detection(rule_id="quiet", event_id="9" * 64))
        await manager.drain()
        assert [a.rule_id for a in sink.received] == ["noisy", "quiet"]


class TestClose:
    @pytest.mark.asyncio
    async def test_aclose_closes_every_sink_despite_failures(self) -> None:
        first, second = _CloseBoom(name="first"), _Recorder(name="second")
        manager = AlertManager([first, second])
        with capture_logs() as logs:
            await manager.aclose()  # must not raise
        assert any(entry["event"] == "alert.sink.close_error" for entry in logs)


class _Hung(AlertSink):
    """A channel that never answers (an unresponsive webhook, broken DNS)."""

    name = "hung"

    def __init__(self) -> None:
        super().__init__()
        self.attempts = 0

    async def emit(self, alert: Alert) -> None:
        self.attempts += 1
        await asyncio.Event().wait()


@pytest.mark.security
class TestBulkheads:
    """Regression: one slow channel held the single consumer for ~16.5 s per alert."""

    @pytest.mark.asyncio
    async def test_a_hung_sink_delays_neither_detection_nor_other_sinks(self) -> None:
        hung, good = _Hung(), _Recorder()
        manager = AlertManager([hung, good], delivery_timeout_seconds=0.05)
        loop = asyncio.get_running_loop()

        started = loop.time()
        for i in range(3):
            await manager.process(make_detection(event_id=f"{i:064d}"))
        assert loop.time() - started < 0.05  # the consumer never waits on a sink

        await manager.drain(max_wait=2)
        assert len(good.received) == 3
        assert manager.stats["sink_errors"] == 3  # each delivery hit its deadline
        assert manager.delivered_by_sink == {"hung": 0, "recorder": 3}

    @pytest.mark.asyncio
    async def test_a_full_sink_queue_drops_and_counts(self) -> None:
        manager = AlertManager([_Hung()], sink_queue_size=1, delivery_timeout_seconds=60)
        with capture_logs() as logs:
            await manager.process(make_detection(event_id="0" * 64))
            await asyncio.sleep(0)  # the worker takes the first alert
            for i in range(1, 4):
                await manager.process(make_detection(event_id=f"{i:064d}"))
        # One in flight, one queued, two dropped.
        assert manager.dropped_by_sink == {"hung": 2}
        assert sum(entry["event"] == "alert.sink.queue_full" for entry in logs) == 2
        await manager.aclose(drain_timeout=0)

    @pytest.mark.asyncio
    async def test_shutdown_counts_what_it_could_not_deliver(self) -> None:
        manager = AlertManager([_Hung()], delivery_timeout_seconds=60)
        for i in range(3):
            await manager.process(make_detection(event_id=f"{i:064d}"))
        with capture_logs() as logs:
            await manager.aclose(drain_timeout=0.05)
        assert manager.dropped_by_sink == {"hung": 2}  # the third was in flight
        assert any(entry["event"] == "alert.sink.undelivered_at_shutdown" for entry in logs)

    @pytest.mark.asyncio
    async def test_latency_is_observed_on_delivery(self) -> None:
        latencies: list[float] = []
        manager = AlertManager([_Recorder()], on_delivered=latencies.append)
        await manager.process(make_detection())
        await manager.drain()
        assert len(latencies) == 1
        assert latencies[0] >= 0
