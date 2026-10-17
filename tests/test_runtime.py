"""Tests for the composition root (`sentinel.runtime`) and the app lifespan.

These cover the wiring that previously had no tests at all: which collectors and
sinks a given `Settings` produces, that every configured alert gate (including a
rule's own throttle) is honoured, and — end to end — that a brute-force burst
written to an auth log becomes a persisted alert, with the pipeline's health
visible through `/readyz` and its counters through `/metrics`.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest
import structlog
from prometheus_client.parser import text_string_to_metric_families
from pydantic import SecretStr

from sentinel.alerting import Alert, AlertSink, ConsoleSink, EmailSink, WebhookSink
from sentinel.api import create_app
from sentinel.api.app import get_app
from sentinel.collectors.authlog import AuthLogCollector
from sentinel.collectors.base import AbstractCollector
from sentinel.collectors.integrity import FileIntegrityCollector
from sentinel.collectors.network import NetworkCollector
from sentinel.collectors.process import ProcessCollector
from sentinel.detection.schema import Rule
from sentinel.logging import redact_sensitive_processor
from sentinel.metrics import Metrics
from sentinel.pipeline.queue import BoundedEventQueue
from sentinel.runtime import (
    ConfigurationError,
    Runtime,
    build_alert_manager,
    build_collectors,
    build_sinks,
)
from sentinel.storage import Database, Repository
from tests.conftest import auth_header, make_api_settings, make_detection

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


class _Crashing(AbstractCollector):
    name = "crashing"

    async def run(self, queue: BoundedEventQueue) -> None:
        raise RuntimeError("collector bug")


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
        assert dropped == {"queue_full", "duplicate", "consumer_error", "dead_letter"}

    async def test_crashed_collector_is_reported_not_running(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        runtime = Runtime(
            make_api_settings(),
            database=database,
            metrics=Metrics(),
            rules=rules,
            collectors=[_Crashing()],
            sinks=[],
        )
        with structlog.testing.capture_logs() as logs:
            runtime.start()
            assert await _wait_for(lambda: not runtime.running)
        assert any(entry["event"] == "runtime.pipeline_crashed" for entry in logs)
        await runtime.stop()  # must not raise the collector's exception

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
class TestAppLifespan:
    async def test_readyz_tracks_pipeline_health(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        app = create_app(
            make_api_settings(),
            database=database,
            metrics=Metrics(),
            rules=rules,
            collectors=[_Crashing()],
            sinks=[],
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
