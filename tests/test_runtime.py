"""Tests for the composition root (`sentinel.runtime`) and the app lifespan.

These cover the wiring that previously had no tests at all: which collectors and
sinks a given `Settings` produces, that every configured alert gate (including a
rule's own throttle) is honoured, and — end to end — that a brute-force burst
written to an auth log becomes a persisted alert, with the pipeline's health
visible through `/readyz` and its counters through `/metrics`.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import socket
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import structlog
from prometheus_client.parser import text_string_to_metric_families
from pydantic import SecretStr
from sqlalchemy.exc import DBAPIError, IntegrityError, OperationalError

from sentinel import runtime as runtime_module
from sentinel.alerting import Alert, AlertSink, ConsoleSink, EmailSink, WebhookSink
from sentinel.api import app as app_module, create_app
from sentinel.api.app import get_app
from sentinel.collectors.authlog import AuthLogCollector
from sentinel.collectors.base import AbstractCollector
from sentinel.collectors.integrity import FileIntegrityCollector
from sentinel.collectors.network import NetworkCollector
from sentinel.collectors.process import ProcessCollector
from sentinel.detection.schema import Condition, Rule
from sentinel.events import Event
from sentinel.logging import redact_sensitive_processor
from sentinel.metrics import Metrics
from sentinel.pipeline import runner
from sentinel.pipeline.queue import BoundedEventQueue
from sentinel.pipeline.runner import Pipeline
from sentinel.runtime import (
    ConfigurationError,
    Runtime,
    _file_path_prefixes,
    build_alert_manager,
    build_collectors,
    build_sinks,
    resolve_host_name,
    unwatched_rule_paths,
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


@contextlib.asynccontextmanager
async def _partitioned_session() -> AsyncIterator[Any]:
    """A database session on a partitioned network, as SQLAlchemy's asyncpg adapter has it.

    The query never answers, and when it is cancelled the adapter closes the
    connection inside asyncio.shield — which never answers either, so
    asyncio.timeout around the call cannot end it.
    """
    try:
        await asyncio.Event().wait()
        yield None  # pragma: no cover - never reached
    finally:
        await asyncio.shield(asyncio.Event().wait())


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

    @pytest.mark.parametrize(("backfill", "skips_history"), [(False, True), (True, False)])
    def test_the_service_tails_the_auth_log_from_its_end_unless_backfilling(
        self, backfill: bool, skips_history: bool
    ) -> None:
        settings = make_api_settings(collectors="auth-log", auth_log_backfill=backfill)
        (auth,) = build_collectors(settings)
        assert isinstance(auth, AuthLogCollector)
        assert auth._skip_history is skips_history

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
    @pytest.mark.parametrize(("log_format", "json_lines"), [("json", True), ("console", False)])
    def test_console_alerts_follow_the_log_format(self, log_format: str, json_lines: bool) -> None:
        (console,) = build_sinks(make_api_settings(log_format=log_format))
        assert isinstance(console, ConsoleSink)
        assert console._json is json_lines

    def test_console_only_by_default(self) -> None:
        assert [type(s) for s in build_sinks(make_api_settings())] == [ConsoleSink]

    @pytest.mark.security
    def test_webhook_without_hmac_secret_fails_closed(self) -> None:
        settings = make_api_settings(webhook_url="https://hooks.example.com/x")
        with pytest.raises(ConfigurationError, match="HMAC"):
            build_sinks(settings)

    @pytest.mark.security
    @pytest.mark.parametrize(
        "url",
        ["http://hooks.example.com/x", "https://169.254.169.254/latest/meta-data"],
        ids=["plain-http", "cloud-metadata-literal"],
    )
    def test_an_unsafe_webhook_url_fails_at_startup(self, url: str) -> None:
        # Regression: these were accepted and failed only at the first alert.
        settings = make_api_settings(
            webhook_url=url,
            webhook_hmac_secret=SecretStr("s3cret-" + "x" * 32),  # pragma: allowlist secret
        )
        with pytest.raises(ConfigurationError, match="SENTINEL_WEBHOOK_URL"):
            build_sinks(settings)

    async def test_webhook_with_secret_is_enabled(self) -> None:
        settings = make_api_settings(
            webhook_url="https://hooks.example.com/x",
            webhook_hmac_secret=SecretStr("s3cret-" + "x" * 32),  # pragma: allowlist secret
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
        await manager.drain()
        assert len(sink.received) == 1
        assert manager.stats["throttled"] == 2

    async def test_rules_without_throttle_use_the_global_budget(
        self, rules: tuple[Rule, ...]
    ) -> None:
        sink = _Recorder()
        manager = build_alert_manager(make_api_settings(alert_throttle_max=2), rules, [sink])
        for i in range(3):
            await manager.process(make_detection(event_id=f"{i:064d}"))
        await manager.drain()
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

    async def test_the_outage_buffer_drops_the_oldest_records(
        self, unreachable_database: Database, rules: tuple[Rule, ...]
    ) -> None:
        runtime = Runtime(
            make_api_settings(persist_batch_size=1, persist_max_buffered=2),
            database=unreachable_database,
            metrics=Metrics(),
            rules=rules,
            sinks=[],
        )
        for event in _events(5):
            await runtime._consume(event)
        assert [e.message for e in runtime._pending_events] == ["e3", "e4"]
        assert runtime.snapshot().dropped["persist_error"] == 3

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

    async def test_a_hung_database_bounds_writes_and_shutdown(
        self,
        database: Database,
        rules: tuple[Rule, ...],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Regression: a database that stopped answering (no RST, as in a
        # network partition) held the write forever; stop() then never
        # returned and the supervisor's SIGKILL lost the whole buffer.
        async def hung_save(self: Repository, **batch: Any) -> int:
            await asyncio.Event().wait()
            return 0  # pragma: no cover - never reached

        monkeypatch.setattr(Repository, "save_batch", hung_save)
        metrics = Metrics()
        runtime = Runtime(
            make_api_settings(
                persist_batch_size=1,
                persist_flush_interval_seconds=0.01,
                persist_write_timeout_seconds=0.05,
            ),
            database=database,
            metrics=metrics,
            rules=rules,
            collectors=[_Replay(_events(3))],
            sinks=[],
        )
        with structlog.testing.capture_logs() as logs:
            runtime.start()
            assert await _wait_for(lambda: not runtime.persisting)
            assert await _wait_for(lambda: metrics.events_ingested._value.get() == 3)
            snapshot = runtime.snapshot()
            assert snapshot.persist_failures >= 1
            assert snapshot.persist_buffered["events"] == 3  # kept for the retry
            await asyncio.wait_for(runtime.stop(), timeout=2)
        assert runtime.snapshot().dropped["persist_error"] == 3  # lost, and counted
        failures = [entry for entry in logs if entry["event"] == "runtime.persist_failed"]
        assert {entry["error"] for entry in failures} == {"TimeoutError"}

    async def test_a_partitioned_database_cannot_hold_writes_or_shutdown(
        self, database: Database, rules: tuple[Rule, ...], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Regression: the write deadline only held when cancelling the write was
        # clean. Against a partitioned PostgreSQL the driver's shielded cleanup
        # never ended: a 1 s deadline still hung after 60 s, and stop() with it.
        monkeypatch.setattr(database, "session", _partitioned_session)
        runtime = Runtime(
            make_api_settings(
                persist_batch_size=1,
                persist_flush_interval_seconds=0.01,
                persist_write_timeout_seconds=0.05,
            ),
            database=database,
            metrics=Metrics(),
            rules=rules,
            collectors=[_Replay(_events(2))],
            sinks=[],
        )
        runtime.start()
        assert await _wait_for(lambda: not runtime.persisting)
        assert runtime.snapshot().persist_failures >= 1
        await asyncio.wait_for(runtime.stop(), timeout=2)
        assert runtime.snapshot().dropped["persist_error"] == 2  # lost, and counted

    async def test_persistence_health_recovers_with_the_database(
        self,
        database: Database,
        rules: tuple[Rule, ...],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        full = {"disk": True}
        original = Repository.save_batch

        async def save(self: Repository, **batch: Any) -> int:
            if full["disk"]:
                raise OperationalError("INSERT", {}, Exception("database or disk is full"))
            return await original(self, **batch)

        monkeypatch.setattr(Repository, "save_batch", save)
        runtime = Runtime(
            make_api_settings(), database=database, metrics=Metrics(), rules=rules, sinks=[]
        )
        healthy: list[bool] = [runtime.persisting]
        await runtime._consume(_events(1)[0])
        assert await runtime.flush() is False
        healthy.append(runtime.persisting)
        assert runtime.snapshot().persist_failures == 1
        full["disk"] = False
        assert await runtime.flush() is True
        healthy.append(runtime.persisting)
        assert healthy == [True, False, True]
        assert runtime.snapshot().persist_buffered == {"events": 0, "alerts": 0}

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
        assert 'sentinel_collector_source_up{collector="auth-log"} 0.0' in body  # no file

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

    async def test_readyz_reports_failing_writes(
        self, database: Database, rules: tuple[Rule, ...], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Regression: with a full disk, reads (and so the probe) still worked
        # while every write failed — the service reported ready and lost data.
        full = {"disk": True}
        original = Repository.save_batch

        async def save(self: Repository, **batch: Any) -> int:
            if full["disk"]:
                raise OperationalError("INSERT", {}, Exception("database or disk is full"))
            return await original(self, **batch)

        monkeypatch.setattr(Repository, "save_batch", save)
        app = create_app(
            make_api_settings(persist_batch_size=1, persist_flush_interval_seconds=0.01),
            database=database,
            metrics=Metrics(),
            rules=rules,
            collectors=[_Replay(_events(1))],
            sinks=[],
        )
        transport = httpx.ASGITransport(app=app)
        async with (
            app.router.lifespan_context(app),
            httpx.AsyncClient(transport=transport, base_url="http://t") as client,
        ):
            runtime = app.state.runtime
            assert await _wait_for(lambda: not runtime.persisting)
            resp = await client.get("/readyz")
            assert resp.status_code == 503
            assert resp.json()["error"]["message"] == "database writes failing"
            body = (await client.get("/metrics", headers=auth_header())).text
            assert 'sentinel_persist_buffered{kind="events"} 1.0' in body
            assert "sentinel_persist_failures_total" in body

            full["disk"] = False
            assert await _wait_for(lambda: runtime.persisting)
            assert (await client.get("/readyz")).status_code == 200

    async def test_readyz_answers_while_the_database_hangs(
        self, database: Database, rules: tuple[Rule, ...], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Regression: the probe waited on a hung database for as long as the
        # driver did (asyncpg: 60 s), far past the healthcheck's own timeout.
        monkeypatch.setattr(app_module, "_READY_TIMEOUT_S", 0.05)
        monkeypatch.setattr(database, "session", _partitioned_session)
        app = create_app(make_api_settings(), database=database, metrics=Metrics(), rules=rules)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
            resp = await asyncio.wait_for(client.get("/readyz"), timeout=2)
        assert resp.status_code == 503
        assert resp.json()["error"]["message"] == "database not responding"

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


async def _count_alerts(database: Database) -> int:
    async with database.session() as session:
        return await Repository(session).count_alerts()


async def _store(database: Database, events: int, alerts: int) -> None:
    async with database.session() as session:
        await Repository(session).save_batch(
            events=_events(events),
            alerts=[
                Alert.from_detection(make_detection(event_id=f"{i:064d}")) for i in range(alerts)
            ],
        )


class TestRetention:
    async def test_deletes_only_what_outlived_the_retention_period(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        await _store(database, events=5, alerts=3)
        stored = datetime.now(tz=UTC)
        runtime = Runtime(
            make_api_settings(retention_days=1), database=database, metrics=Metrics(), rules=rules
        )
        assert await runtime.prune(now=stored + timedelta(hours=23)) is True
        assert (await _count_events(database), await _count_alerts(database)) == (5, 3)

        assert await runtime.prune(now=stored + timedelta(days=1, minutes=1)) is True
        assert (await _count_events(database), await _count_alerts(database)) == (0, 0)
        assert runtime.snapshot().retention_deleted == {"events": 5, "alerts": 3}

    @pytest.mark.security
    async def test_a_forged_old_timestamp_does_not_expire_evidence(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        # Retention counts from when Sentinel stored a record. The event's own
        # timestamp comes from the host (a syslog line an attacker can write),
        # so measuring from it would let a forged date delete the evidence.
        forged = make_event(timestamp=datetime(2001, 1, 1, tzinfo=UTC))
        async with database.session() as session:
            await Repository(session).save_batch(events=[forged])
        runtime = Runtime(
            make_api_settings(retention_days=1), database=database, metrics=Metrics(), rules=rules
        )
        assert await runtime.prune() is True
        assert await _count_events(database) == 1

    async def test_large_backlogs_are_deleted_in_bounded_batches(
        self,
        database: Database,
        rules: tuple[Rule, ...],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setattr(runtime_module, "_PRUNE_BATCH", 2)
        batches: list[tuple[int, int]] = []
        original = Repository.delete_stored_before

        async def spy(self: Repository, cutoff: datetime, *, limit: int) -> tuple[int, int]:
            deleted = await original(self, cutoff, limit=limit)
            batches.append(deleted)
            return deleted

        monkeypatch.setattr(Repository, "delete_stored_before", spy)
        await _store(database, events=5, alerts=3)
        runtime = Runtime(
            make_api_settings(retention_days=1), database=database, metrics=Metrics(), rules=rules
        )
        assert await runtime.prune(now=datetime.now(tz=UTC) + timedelta(days=2)) is True
        assert batches == [(2, 2), (2, 1), (1, 0)]  # one short transaction each
        assert await _count_events(database) == 0

    async def test_a_failed_prune_is_reported_and_retried_later(
        self, unreachable_database: Database, rules: tuple[Rule, ...]
    ) -> None:
        runtime = Runtime(
            make_api_settings(retention_days=1),
            database=unreachable_database,
            metrics=Metrics(),
            rules=rules,
        )
        with structlog.testing.capture_logs() as logs:
            assert await runtime.prune() is False
        assert [entry["error"] for entry in logs if entry["event"] == "runtime.prune_failed"] == [
            "OperationalError"
        ]

    async def test_runs_at_start_up_and_never_delays_shutdown(
        self, database: Database, rules: tuple[Rule, ...], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        await _store(database, events=3, alerts=0)
        # Everything stored so far is already past a one-day retention.
        later = datetime.now(tz=UTC) + timedelta(days=2)
        original = Runtime.prune

        async def prune_later(self: Runtime, *, now: datetime | None = None) -> bool:
            return await original(self, now=now or later)

        monkeypatch.setattr(Runtime, "prune", prune_later)
        metrics = Metrics()
        runtime = Runtime(
            make_api_settings(retention_days=1),
            database=database,
            metrics=metrics,
            rules=rules,
            collectors=[_Replay([])],
            sinks=[],
        )
        runtime.start()
        assert await _wait_for(lambda: runtime.snapshot().retention_deleted["events"] == 3)
        await asyncio.wait_for(runtime.stop(), timeout=2)  # not after the hourly sleep
        body = metrics.render().decode()
        assert 'sentinel_retention_deleted_total{kind="events"} 3.0' in body

    async def test_a_partitioned_database_cannot_hold_a_prune(
        self, database: Database, rules: tuple[Rule, ...], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(database, "session", _partitioned_session)
        runtime = Runtime(
            make_api_settings(retention_days=1, persist_write_timeout_seconds=0.05),
            database=database,
            metrics=Metrics(),
            rules=rules,
        )
        assert await asyncio.wait_for(runtime.prune(), timeout=2) is False

    async def test_disabled_by_default(self, database: Database, rules: tuple[Rule, ...]) -> None:
        await _store(database, events=2, alerts=0)
        runtime = Runtime(make_api_settings(), database=database, metrics=Metrics(), rules=rules)
        assert await runtime.prune(now=datetime.now(tz=UTC) + timedelta(days=36_500)) is True
        assert await _count_events(database) == 2


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


class TestRuleCoverage:
    """Regression: with the default paths, log-tampering could never fire, silently."""

    def test_the_library_is_covered_by_the_default_paths_except_log_tampering(
        self, rules: tuple[Rule, ...]
    ) -> None:
        default = make_api_settings().fim_path_list
        assert unwatched_rule_paths(rules, default) == {"log-tampering": ["/var/log/"]}

    def test_watching_var_log_covers_it(self, rules: tuple[Rule, ...]) -> None:
        assert unwatched_rule_paths(rules, ["/etc", "/var/spool/cron", "/var/log"]) == {}

    async def test_startup_warns_about_rules_that_cannot_fire(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        runtime = Runtime(
            make_api_settings(), database=database, metrics=Metrics(), rules=rules,
            collectors=[_Replay([])], sinks=[],
        )  # fmt: skip
        with structlog.testing.capture_logs() as logs:
            runtime.start()
            await runtime.stop()
        warning = next(e for e in logs if e["event"] == "runtime.rule_paths_not_watched")
        assert warning["rules"] == {"log-tampering": ["/var/log/"]}


@pytest.mark.parametrize(
    ("pattern", "prefixes"),
    [
        ("^/etc/g?shadow$", ["/etc/"]),
        (
            "^(?:/etc/cron|/etc/crontab|/var/spool/cron)",
            ["/etc/cron", "/etc/crontab", "/var/spool/cron"],
        ),
        ("^/(?:etc|bin)/", ["/"]),
        ("shadow$", []),  # unanchored: nothing can be said, so nothing is claimed
    ],
)
def test_path_prefixes_of_rule_regexes(pattern: str, prefixes: list[str]) -> None:
    condition = Condition.model_validate({"field": "file.path", "op": "regex", "value": pattern})
    assert _file_path_prefixes(condition) == prefixes
