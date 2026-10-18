"""Tests for the composition root (`sentinel.runtime`) and the app lifespan.

These cover the wiring that previously had no tests at all: which collectors and
sinks a given `Settings` produces, that every configured alert gate (including a
rule's own throttle) is honoured, and — end to end — that a brute-force burst
written to an auth log becomes a persisted alert, with the pipeline's health
visible through `/readyz` and its counters through `/metrics`.
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import structlog
from prometheus_client.parser import text_string_to_metric_families
from pydantic import SecretStr
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError

from sentinel.alerting import Alert, AlertSink, ConsoleSink, EmailSink, WebhookSink
from sentinel.api import app as app_module, create_app
from sentinel.api.app import get_app
from sentinel.collectors.authlog import AuthLogCollector
from sentinel.collectors.base import AbstractCollector
from sentinel.collectors.integrity import FileIntegrityCollector
from sentinel.collectors.network import NetworkCollector
from sentinel.collectors.process import ProcessCollector
from sentinel.detection.schema import Rule
from sentinel.events import Event
from sentinel.logging import redact_sensitive_processor
from sentinel.metrics import Metrics
from sentinel.pipeline import runner
from sentinel.pipeline.queue import BoundedEventQueue
from sentinel.pipeline.runner import Pipeline
from sentinel.runtime import (
    ConfigurationError,
    Runtime,
    build_alert_manager,
    build_collectors,
    build_sinks,
    resolve_host_name,
)
from sentinel.storage import Database, Repository
from tests.conftest import auth_header, make_api_settings, make_detection, make_event

_FAILED = (
    "Jun 16 12:00:{sec:02d} web01 sshd[{pid}]: "
    "Failed password for root from 203.0.113.7 port {port} ssh2"
)


def _brute_force_lines(count: int) -> str:
    return "".join(_FAILED.format(sec=i, pid=1000 + i, port=40000 + i) + "\n" for i in range(count))


async def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:  # noqa: ASYNC109 — poll loop, not an `asyncio.timeout()` block
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


class _Recorder(AlertSink):
    name = "recorder"

    def __init__(self) -> None:
        super().__init__()
        self.received: list[Alert] = []
        self.closed = False

    async def emit(self, alert: Alert) -> None:
        self.received.append(alert)

    async def aclose(self) -> None:
        self.closed = True


class _Replay(AbstractCollector):
    """Emits a fixed list of events once, then idles until stopped."""

    name = "replay"

    def __init__(self, events: list[Event]) -> None:
        super().__init__()
        self._events = events

    async def run(self, queue: BoundedEventQueue) -> None:
        for event in self._events:
            await queue.put(event)
        await self.wait_stop()


class _PgError(Exception):
    """A driver error carrying a SQLSTATE, as asyncpg's adapted errors do."""

    def __init__(self, message: str, sqlstate: str) -> None:
        super().__init__(message)
        self.sqlstate = sqlstate


def _events(count: int) -> list[Event]:
    return [make_event(event_id=f"{i:064d}", message=f"e{i}") for i in range(count)]


async def _count_events(database: Database) -> int:
    async with database.session() as session:
        return await Repository(session).count_events()


class _Crashing(AbstractCollector):
    name = "crashing"

    async def run(self, queue: BoundedEventQueue) -> None:
        raise RuntimeError("collector bug")


class _CrashingOnce(AbstractCollector):
    """Raises on its first run; once restarted, emits its events and idles."""

    name = "crashing-once"

    def __init__(self, events: list[Event]) -> None:
        super().__init__()
        self._events = events
        self.runs = 0

    async def run(self, queue: BoundedEventQueue) -> None:
        self.runs += 1
        if self.runs == 1:
            raise RuntimeError("collector bug")
        for event in self._events:
            await queue.put(event)
        await self.wait_stop()


class TestBuildCollectors:
    def test_defaults_enable_all_four_on_bare_metal(self) -> None:
        collectors = build_collectors(make_api_settings())
        assert [c.name for c in collectors] == ["auth-log", "file-integrity", "process", "network"]

    def test_subset_is_honoured(self) -> None:
        collectors = build_collectors(make_api_settings(collectors="auth-log, network"))
        assert [c.name for c in collectors] == ["auth-log", "network"]

    def test_host_root_relocates_every_source(self) -> None:
        settings = make_api_settings(host_root="/host", auth_log_path="/var/log/secure")
        by_name = {c.name: c for c in build_collectors(settings)}
        auth = by_name["auth-log"]
        assert isinstance(auth, AuthLogCollector)
        assert auth._path == Path("/host/var/log/secure")
        process = by_name["process"]
        assert isinstance(process, ProcessCollector)
        assert process._proc_root == Path("/host/proc")
        # Behind a host mount, /proc/net is *our* netns; PID 1's is the host's.
        network = by_name["network"]
        assert isinstance(network, NetworkCollector)
        assert network._net_dir == Path("/host/proc/1/net")
        fim = by_name["file-integrity"]
        assert isinstance(fim, FileIntegrityCollector)
        assert fim._host_root == Path("/host")

    def test_bare_metal_network_reads_own_namespace(self) -> None:
        by_name = {c.name: c for c in build_collectors(make_api_settings())}
        network = by_name["network"]
        assert isinstance(network, NetworkCollector)
        assert network._net_dir == Path("/proc/net")


class TestResolveHostName:
    def test_explicit_setting_wins(self, tmp_path: Path) -> None:
        (tmp_path / "etc").mkdir()
        (tmp_path / "etc" / "hostname").write_text("from-file\n", encoding="utf-8")
        settings = make_api_settings(host_root=str(tmp_path), host_name="explicit")
        assert resolve_host_name(settings) == "explicit"

    def test_container_reports_the_monitored_host(self, tmp_path: Path) -> None:
        (tmp_path / "etc").mkdir()
        (tmp_path / "etc" / "hostname").write_text("\n  web01  \n", encoding="utf-8")
        assert resolve_host_name(make_api_settings(host_root=str(tmp_path))) == "web01"

    def test_falls_back_to_local_hostname(self, tmp_path: Path) -> None:
        # Bare metal, or a host root without a readable /etc/hostname.
        expected = socket.gethostname() or "localhost"
        assert resolve_host_name(make_api_settings()) == expected
        assert resolve_host_name(make_api_settings(host_root=str(tmp_path))) == expected

    def test_collectors_carry_the_resolved_name(self, tmp_path: Path) -> None:
        settings = make_api_settings(host_name="web01", collectors="process,network")
        assert {c._host for c in build_collectors(settings)} == {"web01"}  # type: ignore[attr-defined]


class TestBuildSinks:
    def test_console_only_by_default(self) -> None:
        assert [type(s) for s in build_sinks(make_api_settings())] == [ConsoleSink]

    @pytest.mark.security
    def test_webhook_without_hmac_secret_fails_closed(self) -> None:
        settings = make_api_settings(webhook_url="https://hooks.example.com/x")
        with pytest.raises(ConfigurationError, match="HMAC"):
            build_sinks(settings)

    async def test_webhook_with_secret_is_enabled(self) -> None:
        settings = make_api_settings(
            webhook_url="https://hooks.example.com/x",
            webhook_hmac_secret=SecretStr("s3cret"),  # pragma: allowlist secret
        )
        sinks = build_sinks(settings)
        assert [type(s) for s in sinks] == [ConsoleSink, WebhookSink]
        await sinks[1].aclose()

    def test_smtp_without_recipients_fails_closed(self) -> None:
        settings = make_api_settings(smtp_host="smtp.example.com", email_from="s@example.com")
        with pytest.raises(ConfigurationError, match="RECIPIENTS"):
            build_sinks(settings)

    def test_fully_configured_email_is_enabled(self) -> None:
        settings = make_api_settings(
            smtp_host="smtp.example.com",
            email_from="sentinel@example.com",
            email_recipients="soc@example.com, oncall@example.com",
        )
        assert [type(s) for s in build_sinks(settings)] == [ConsoleSink, EmailSink]


class TestBuildAlertManager:
    async def test_rule_throttle_overrides_the_global_budget(self, rules: tuple[Rule, ...]) -> None:
        # ssh-brute-force.yml declares `throttle: {window_seconds: 300, max_alerts: 1}`
        # while the global default allows 10 per minute.
        sink = _Recorder()
        manager = build_alert_manager(make_api_settings(), rules, [sink])
        for i in range(3):
            await manager.process(make_detection(rule_id="ssh-brute-force", event_id=f"{i:064d}"))
        assert len(sink.received) == 1
        assert manager.stats["throttled"] == 2

    async def test_rules_without_throttle_use_the_global_budget(
        self, rules: tuple[Rule, ...]
    ) -> None:
        sink = _Recorder()
        manager = build_alert_manager(make_api_settings(alert_throttle_max=2), rules, [sink])
        for i in range(3):
            await manager.process(make_detection(event_id=f"{i:064d}"))
        assert len(sink.received) == 2

    async def test_min_severity_setting_is_applied(self, rules: tuple[Rule, ...]) -> None:
        sink = _Recorder()
        manager = build_alert_manager(make_api_settings(alert_min_severity=6), rules, [sink])
        assert await manager.process(make_detection(severity=5)) is None
        assert sink.received == []


@pytest.mark.integration
class TestRuntimeEndToEnd:
    async def test_brute_force_burst_becomes_a_persisted_alert(
        self, tmp_path: Path, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        log = tmp_path / "auth.log"
        log.write_text("", encoding="utf-8")
        sink = _Recorder()
        metrics = Metrics()
        runtime = Runtime(
            make_api_settings(),
            database=database,
            metrics=metrics,
            rules=rules,
            collectors=[AuthLogCollector(log, poll_interval=0.01, year=2026)],
            sinks=[sink],
        )
        runtime.start()
        try:
            assert await _wait_for(lambda: runtime.running)
            with log.open("a", encoding="utf-8") as handle:
                handle.write(_brute_force_lines(6))
            assert await _wait_for(lambda: len(sink.received) == 1)
            assert await _wait_for(lambda: metrics.events_ingested._value.get() == 6)
        finally:
            await runtime.stop()

        assert not runtime.running
        assert sink.closed
        assert sink.received[0].rule_id == "ssh-brute-force"
        async with database.session() as session:
            repo = Repository(session)
            assert await repo.count_events() == 6
            alerts = await repo.list_alerts(limit=10)
        assert [a.rule_id for a in alerts] == ["ssh-brute-force"]

        families = {f.name: f for f in text_string_to_metric_families(metrics.render().decode())}
        delivered = {s.labels["sink"]: s.value for s in families["sentinel_alerts_emitted"].samples}
        assert delivered == {"recorder": 1.0}
        assert "sentinel_queue_depth" in families
        dropped = {
            s.labels["reason"]
            for s in families["sentinel_events_dropped"].samples
            if s.name.endswith("_total")
        }
        assert dropped == {
            "queue_full",
            "duplicate",
            "consumer_error",
            "dead_letter",
            "persist_error",
        }

    async def test_a_crashed_collector_is_restarted(
        self, database: Database, rules: tuple[Rule, ...], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Regression: a collector exception ended that collector for good, so
        # one hostile input or parser bug left its source unmonitored while
        # the API looked healthy. It is now supervised and restarted.
        monkeypatch.setattr(runner, "_RESTART_MIN_S", 0.01)
        collector = _CrashingOnce(_events(3))
        metrics = Metrics()
        runtime = Runtime(
            make_api_settings(), database=database, metrics=metrics, rules=rules,
            collectors=[collector], sinks=[],
        )  # fmt: skip
        with structlog.testing.capture_logs() as logs:
            runtime.start()
            assert await _wait_for(lambda: metrics.events_ingested._value.get() == 3)
            assert runtime.running
            await runtime.stop()

        assert collector.runs == 2
        assert runtime.snapshot().collector_restarts == {"crashing-once": 1}
        crash = next(entry for entry in logs if entry["event"] == "pipeline.collector_crashed")
        assert crash["collector"] == "crashing-once"
        assert crash["exc_info"] is True  # the traceback is logged, not just the type
        exposition = metrics.render().decode()
        assert 'sentinel_collector_restarts_total{collector="crashing-once"} 1.0' in exposition

    async def test_stop_interrupts_a_restart_backoff(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        runtime = Runtime(
            make_api_settings(), database=database, metrics=Metrics(), rules=rules,
            collectors=[_Crashing()], sinks=[],
        )  # fmt: skip
        runtime.start()
        assert await _wait_for(lambda: bool(runtime.snapshot().collector_restarts))
        started = asyncio.get_running_loop().time()
        await runtime.stop()
        assert asyncio.get_running_loop().time() - started < 0.5  # not the full backoff

    async def test_a_dead_pipeline_ends_the_process_for_a_restart(
        self, database: Database, rules: tuple[Rule, ...], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Regression: Docker's restart policy ignores health checks, so a dead
        # pipeline left an unhealthy container serving forever.
        async def broken_pipeline(self: Pipeline) -> None:
            raise RuntimeError("framework bug")

        monkeypatch.setattr(Pipeline, "run", broken_pipeline)
        fatal: list[bool] = []
        metrics = Metrics()
        runtime = Runtime(
            make_api_settings(), database=database, metrics=metrics, rules=rules,
            collectors=[_Replay([])], sinks=[], on_fatal=lambda: fatal.append(True),
        )  # fmt: skip
        with structlog.testing.capture_logs() as logs:
            runtime.start()
            assert await _wait_for(lambda: bool(fatal))
        await runtime.stop()  # must not raise the pipeline's exception

        assert fatal == [True]
        assert not runtime.running
        assert "sentinel_pipeline_up 0.0" in metrics.render().decode()
        crashed = next(entry for entry in logs if entry["event"] == "runtime.pipeline_crashed")
        assert crashed["exc_info"] is not None

    async def test_start_twice_is_rejected(
        self, tmp_path: Path, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        runtime = Runtime(
            make_api_settings(),
            database=database,
            metrics=Metrics(),
            rules=rules,
            collectors=[AuthLogCollector(tmp_path / "none.log", poll_interval=0.01)],
            sinks=[],
        )
        runtime.start()
        try:
            with pytest.raises(RuntimeError, match="already started"):
                runtime.start()
        finally:
            await runtime.stop()

    async def test_warns_when_no_rule_is_enabled(self, tmp_path: Path, database: Database) -> None:
        runtime = Runtime(
            make_api_settings(),
            database=database,
            metrics=Metrics(),
            rules=[],
            collectors=[AuthLogCollector(tmp_path / "none.log", poll_interval=0.01)],
            sinks=[],
        )
        with structlog.testing.capture_logs() as logs:
            runtime.start()
        await runtime.stop()
        assert any(entry["event"] == "runtime.no_enabled_rules" for entry in logs)


@pytest.mark.integration
class TestWriteBehind:
    async def test_full_batches_are_written_without_waiting(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        metrics = Metrics()
        runtime = Runtime(
            make_api_settings(persist_batch_size=4, persist_flush_interval_seconds=60),
            database=database,
            metrics=metrics,
            rules=rules,
            collectors=[_Replay(_events(10))],
            sinks=[],
        )
        runtime.start()
        try:
            assert await _wait_for(lambda: metrics.events_ingested._value.get() == 10)
            # A full batch wakes the flusher at once — no waiting for the 60 s
            # timer (how many land per write depends on scheduling).
            written = 0
            for _ in range(100):
                written = await _count_events(database)
                if written >= 4:
                    break
                await asyncio.sleep(0.02)
            assert written >= 4
        finally:
            await runtime.stop()
        assert await _count_events(database) == 10  # shutdown flushes the remainder

    async def test_detection_never_waits_on_a_slow_database(
        self,
        database: Database,
        rules: tuple[Rule, ...],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Regression: a full batch used to be written inline by the consumer, so
        # detection and alerting stalled for the whole commit.
        writing, release = asyncio.Event(), asyncio.Event()
        original = Repository.save_batch

        async def blocked_save(self: Repository, **batch: Any) -> int:
            writing.set()
            await release.wait()
            return await original(self, **batch)

        monkeypatch.setattr(Repository, "save_batch", blocked_save)
        metrics = Metrics()
        runtime = Runtime(
            make_api_settings(persist_batch_size=2, persist_flush_interval_seconds=60),
            database=database,
            metrics=metrics,
            rules=rules,
            collectors=[_Replay(_events(30))],
            sinks=[],
        )
        runtime.start()
        try:
            await asyncio.wait_for(writing.wait(), timeout=2)
            # Every event is analyzed while the first write is still blocked.
            assert await _wait_for(lambda: metrics.events_ingested._value.get() == 30)
        finally:
            release.set()
            await runtime.stop()
        assert await _count_events(database) == 30

    async def test_failed_batches_are_retried_not_dropped(
        self,
        database: Database,
        rules: tuple[Rule, ...],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        failures = {"left": 2}
        original = Repository.save_batch

        async def flaky_save(self: Repository, **batch: Any) -> int:
            if failures["left"]:
                failures["left"] -= 1
                raise OSError("database restarting")
            return await original(self, **batch)

        monkeypatch.setattr(Repository, "save_batch", flaky_save)
        runtime = Runtime(
            make_api_settings(persist_batch_size=1, persist_flush_interval_seconds=0.01),
            database=database,
            metrics=Metrics(),
            rules=rules,
            collectors=[_Replay(_events(5))],
            sinks=[],
        )
        runtime.start()
        try:
            written = 0
            for _ in range(200):
                written = await _count_events(database)
                if written == 5:
                    break
                await asyncio.sleep(0.02)
            assert written == 5
        finally:
            await runtime.stop()
        assert failures["left"] == 0
        assert runtime.snapshot().dropped["persist_error"] == 0

    @pytest.mark.parametrize(
        "rejection",
        [
            IntegrityError("INSERT INTO events", {}, Exception("check failed")),
            # What SQLAlchemy's asyncpg adapter raises for "value too long": a bare
            # DBAPIError whose original exception carries the SQLSTATE.
            DBAPIError("INSERT INTO events", {}, _PgError("value too long", "22001")),
        ],
        ids=["integrity-error", "asyncpg-data-error"],
    )
    async def test_a_rejected_row_does_not_block_the_rest(
        self,
        database: Database,
        rules: tuple[Rule, ...],
        monkeypatch: pytest.MonkeyPatch,
        rejection: DBAPIError,
    ) -> None:
        # Regression: with whole-batch retries, one row the database rejects
        # (an integrity/data error) failed every attempt and stalled persistence
        # until the buffer overflowed and dropped good records with it.
        poison = _events(5)[2].event.id
        original = Repository.save_batch

        async def picky_save(self: Repository, **batch: Any) -> int:
            if any(event.event.id == poison for event in batch.get("events", ())):
                raise rejection
            return await original(self, **batch)

        monkeypatch.setattr(Repository, "save_batch", picky_save)
        runtime = Runtime(
            make_api_settings(persist_batch_size=5, persist_flush_interval_seconds=0.01),
            database=database,
            metrics=Metrics(),
            rules=rules,
            collectors=[_Replay(_events(5))],
            sinks=[],
        )
        with structlog.testing.capture_logs() as logs:
            runtime.start()
            written = 0
            for _ in range(200):
                written = await _count_events(database)
                if written == 4:
                    break
                await asyncio.sleep(0.02)
            await runtime.stop()
        assert written == 4  # everything except the rejected row
        assert runtime.snapshot().dropped["persist_error"] == 1
        assert any(entry["event"] == "runtime.persist_rejected" for entry in logs)

    async def test_an_outage_while_isolating_rows_requeues_instead_of_dropping(
        self,
        database: Database,
        rules: tuple[Rule, ...],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Regression: during the row-by-row retry every failure counted as a
        # rejection, so a database outage starting midway dropped all the rows
        # not yet written. Only the poison row may be lost.
        replay = _events(5)
        poison, interrupted = replay[1].event.id, replay[3].event.id
        original = Repository.save_batch
        outages = [OperationalError("INSERT INTO events", {}, Exception("connection lost"))]

        async def flaky_save(self: Repository, **batch: Any) -> int:
            ids = [event.event.id for event in batch.get("events", ())]
            if poison in ids:
                raise IntegrityError("INSERT INTO events", {}, Exception("check failed"))
            if ids == [interrupted] and outages:
                raise outages.pop()
            return await original(self, **batch)

        monkeypatch.setattr(Repository, "save_batch", flaky_save)
        runtime = Runtime(
            make_api_settings(), database=database, metrics=Metrics(), rules=rules, sinks=[]
        )
        for event in replay:  # one deterministic batch, no flusher task
            await runtime._consume(event)

        assert await runtime.flush() is False  # e0, e2 written; e1 rejected; outage at e3
        assert await _count_events(database) == 2
        assert len(runtime._pending_events) == 2  # e3, e4 kept for the retry
        assert await runtime.flush() is True
        assert await _count_events(database) == 4
        assert runtime.snapshot().dropped["persist_error"] == 1  # only the poison row

    async def test_outage_buffer_is_bounded_and_losses_are_counted(
        self, unreachable_database: Database, rules: tuple[Rule, ...]
    ) -> None:
        broken = unreachable_database
        metrics = Metrics()
        runtime = Runtime(
            make_api_settings(
                persist_batch_size=1,
                persist_flush_interval_seconds=0.01,
                persist_max_buffered=16,  # the buffer holds at most 16 records
            ),
            database=broken,
            metrics=metrics,
            rules=rules,
            collectors=[_Replay(_events(40))],
            sinks=[],
        )
        runtime.start()
        assert await _wait_for(lambda: metrics.events_ingested._value.get() == 40)
        assert len(runtime._pending_events) <= 16
        await runtime.stop()
        snapshot = runtime.snapshot()
        # Everything is accounted for: dropped by the cap, or unwritten at shutdown.
        assert snapshot.dropped["persist_error"] == 40
        alerts = runtime._alerts.stats
        # Throttled alerts are stored too, so they are lost (and counted) as well.
        assert snapshot.alerts_unpersisted == alerts["emitted"] + alerts["throttled"] > 0

    async def test_flush_interval_bounds_staleness(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        runtime = Runtime(
            make_api_settings(persist_batch_size=1000, persist_flush_interval_seconds=0.05),
            database=database,
            metrics=Metrics(),
            rules=rules,
            collectors=[_Replay(_events(3))],
            sinks=[],
        )
        runtime.start()
        try:
            written = 0
            for _ in range(100):
                written = await _count_events(database)
                if written == 3:
                    break
                await asyncio.sleep(0.02)
            assert written == 3
        finally:
            await runtime.stop()

    async def test_database_outage_does_not_stall_detection(
        self, unreachable_database: Database, rules: tuple[Rule, ...]
    ) -> None:
        broken = unreachable_database
        metrics = Metrics()
        runtime = Runtime(
            make_api_settings(persist_batch_size=1),
            database=broken,
            metrics=metrics,
            rules=rules,
            collectors=[_Replay(_events(3))],
            sinks=[],
        )
        with structlog.testing.capture_logs() as logs:
            runtime.start()
            assert await _wait_for(lambda: metrics.events_ingested._value.get() == 3)
            await runtime.stop()
        assert runtime.snapshot().dropped["persist_error"] == 3
        failures = [entry for entry in logs if entry["event"] == "runtime.persist_failed"]
        assert failures
        assert all(entry["error"] == "OperationalError" for entry in failures)

    async def test_stop_never_cancels_a_flush_in_flight(
        self,
        database: Database,
        rules: tuple[Rule, ...],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Regression: stop() used to cancel the periodic flusher. A batch is
        # taken out of the buffer before it is written, so cancelling mid-write
        # silently lost that whole batch.
        writing = asyncio.Event()
        saved: list[int] = []
        original = Repository.save_batch

        async def slow_save(self: Repository, **batch: Any) -> int:
            writing.set()
            await asyncio.sleep(0.2)  # stop() lands while this write is in flight
            written = await original(self, **batch)
            saved.append(written)
            return written

        monkeypatch.setattr(Repository, "save_batch", slow_save)
        metrics = Metrics()
        runtime = Runtime(
            make_api_settings(persist_batch_size=1000, persist_flush_interval_seconds=0.01),
            database=database,
            metrics=metrics,
            rules=rules,
            collectors=[_Replay(_events(5))],
            sinks=[],
        )
        runtime.start()
        assert await _wait_for(lambda: metrics.events_ingested._value.get() == 5)
        await asyncio.wait_for(writing.wait(), timeout=2)
        await runtime.stop()
        assert saved  # the in-flight write completed instead of being cancelled
        assert await _count_events(database) == 5


@pytest.mark.integration
class TestAppLifespan:
    async def test_readyz_tracks_pipeline_health(
        self, database: Database, rules: tuple[Rule, ...], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def broken_pipeline(self: Pipeline) -> None:
            raise RuntimeError("framework bug")

        monkeypatch.setattr(Pipeline, "run", broken_pipeline)
        fatal: list[bool] = []
        app = create_app(
            make_api_settings(),
            database=database,
            metrics=Metrics(),
            rules=rules,
            collectors=[_Replay([])],
            sinks=[],
            on_fatal=lambda: fatal.append(True),
        )
        transport = httpx.ASGITransport(app=app)
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=transport, base_url="http://t") as client,
        ):
            runtime = app.state.runtime
            assert await _wait_for(lambda: not runtime.running)
            resp = await client.get("/readyz")
            assert resp.status_code == 503
            assert resp.json()["error"]["message"] == "detection pipeline is not running"
            assert fatal == [True]

    async def test_metrics_endpoint_exposes_runtime_series(
        self, tmp_path: Path, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        app = create_app(
            make_api_settings(),
            database=database,
            metrics=Metrics(),
            rules=rules,
            collectors=[AuthLogCollector(tmp_path / "auth.log", poll_interval=0.01)],
            sinks=[],
        )
        transport = httpx.ASGITransport(app=app)
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=transport, base_url="http://t") as client,
        ):
            assert (await client.get("/readyz")).status_code == 200
            body = (await client.get("/metrics", headers=auth_header())).text
        assert "sentinel_queue_depth" in body
        assert 'sentinel_alerts_suppressed_total{reason="throttled"}' in body

    async def test_failed_startup_still_releases_the_database(
        self, database: Database, rules: tuple[Rule, ...], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        disposed: list[bool] = []
        original = database.dispose

        async def spy() -> None:
            disposed.append(True)
            await original()

        monkeypatch.setattr(database, "dispose", spy)
        app = create_app(
            make_api_settings(webhook_url="https://hooks.example.com/x"),  # no HMAC secret
            database=database,
            metrics=Metrics(),
            rules=rules,
        )
        with pytest.raises(ConfigurationError):
            async with app.router.lifespan_context(app):
                pass
        assert disposed == [True]

    async def test_readyz_reports_a_missing_schema(
        self, tmp_path: Path, rules: tuple[Rule, ...]
    ) -> None:
        # Regression: a reachable but never-migrated database read as ready while
        # every write failed. (No create_all here: the schema does not exist.)
        bare = Database(f"sqlite+aiosqlite:///{tmp_path / 'unmigrated.db'}")
        app = create_app(make_api_settings(), database=bare, metrics=Metrics(), rules=rules)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            resp = await client.get("/readyz")
        await bare.dispose()
        assert resp.status_code == 503
        assert "schema missing" in resp.json()["error"]["message"]


class TestGetApp:
    def test_configures_logging_and_loads_rules_from_settings(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        rules_dir = Path(__file__).resolve().parent.parent / "rules"
        monkeypatch.setenv("SENTINEL_ENV", "test")
        monkeypatch.setenv("SENTINEL_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path / 'x.db'}")
        monkeypatch.setenv("SENTINEL_RULES_DIR", str(rules_dir))
        monkeypatch.chdir(tmp_path)  # no stray .env file is picked up
        try:
            app = get_app()
            processors = structlog.get_config()["processors"]
            # The security processors are live in the production factory.
            assert redact_sensitive_processor in processors
            assert len(app.state.rules) == len(list(rules_dir.glob("*.yml")))
        finally:
            structlog.reset_defaults()


def test_the_production_app_shuts_down_gracefully_when_the_pipeline_dies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: sent.append((pid, sig)))
    app_module._shut_down_for_restart()
    assert sent == [(os.getpid(), signal.SIGTERM)]  # uvicorn's graceful-shutdown path
