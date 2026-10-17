"""Composition root — assemble the running detection system from `Settings`.

This is the one place the layers are wired together:

    collectors -> Pipeline (bounded queue + dedup) -> DetectionEngine
               -> AlertManager (gates + sinks)       [immediately]
               -> write-behind buffer -> Repository  [batched]

Everything an operator configures through ``SENTINEL_*`` variables is honoured
here — which collectors run and where they read the host from, which alert
sinks are enabled, the alert gates, and each rule's own throttle — so there is
no second, hard-coded wiring hiding in the web layer. :class:`Runtime` owns the
lifecycle (start, health, graceful drain, resource release) and is exercised
end to end by ``tests/test_runtime.py`` without any HTTP in the way.

Configuration errors fail closed at construction time: a half-configured sink
(a webhook URL without its HMAC secret, SMTP without recipients) raises
:class:`ConfigurationError` instead of silently running without that channel.

**Write-behind persistence.** Detection and alert delivery happen as each event
is consumed; only the database write is deferred. Events and their alerts are
buffered and written in one transaction when ``persist_batch_size`` events have
accumulated or ``persist_flush_interval_seconds`` has elapsed, whichever comes
first, and the buffer is always flushed on shutdown. One commit per event caps
SQLite at a few hundred events per second; batching is what lets persistence
keep up with the pipeline. The cost is bounded staleness in the read API (at
most one flush interval) and, on a hard kill, losing at most one unflushed
batch — events that were only in memory anyway.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import time
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Final

from sentinel.alerting import (
    Alert,
    AlertManager,
    AlertSink,
    ConsoleSink,
    EmailSink,
    WebhookSink,
)
from sentinel.collectors.authlog import AuthLogCollector
from sentinel.collectors.base import AbstractCollector
from sentinel.collectors.integrity import FileIntegrityCollector
from sentinel.collectors.network import NetworkCollector
from sentinel.collectors.process import ProcessCollector
from sentinel.detection import DetectionEngine, Rule
from sentinel.events import Event
from sentinel.logging import get_logger
from sentinel.metrics import Metrics, RuntimeSnapshot
from sentinel.pipeline import Pipeline
from sentinel.settings import Settings
from sentinel.storage import Database, Repository

_HOST_ROOT: Final[Path] = Path("/")
_PROC: Final[Path] = Path("/proc")


class ConfigurationError(ValueError):
    """The settings describe a system that cannot run safely."""


def _under(root: Path, host_path: Path) -> Path:
    """Where a host-native absolute path is visible beneath `root`."""
    return root / host_path.relative_to(host_path.anchor)


def resolve_host_name(settings: Settings) -> str:
    """The monitored host's name — which, in a container, is not our own hostname."""
    if settings.host_name:
        return settings.host_name
    if settings.host_root != _HOST_ROOT:
        try:
            lines = (settings.host_root / "etc" / "hostname").read_text(encoding="utf-8")
        except OSError:
            lines = ""
        name = next((line.strip() for line in lines.splitlines() if line.strip()), "")
        if name and len(name) <= 253:  # noqa: PLR2004 — DNS name length limit
            return name
    return socket.gethostname() or "localhost"


def build_collectors(settings: Settings) -> list[AbstractCollector]:
    """Instantiate the enabled collectors, reading the host via `host_root`.

    The auth-log collector keeps the host name each syslog line carries; the
    others report :func:`resolve_host_name`.
    """
    root = settings.host_root
    host = resolve_host_name(settings)
    enabled = set(settings.enabled_collectors)
    collectors: list[AbstractCollector] = []
    if "auth-log" in enabled:
        collectors.append(AuthLogCollector(_under(root, settings.auth_log_path)))
    if "file-integrity" in enabled:
        collectors.append(
            FileIntegrityCollector(paths=list(settings.fim_path_list), host_root=root, host=host)
        )
    if "process" in enabled:
        collectors.append(ProcessCollector(proc_root=_under(root, _PROC), host=host))
    if "network" in enabled:
        # Behind a host-root mount, /proc/net would resolve to *our* (container)
        # namespace; PID 1's view of the host procfs is the host's.
        netns_pid = None if root == _HOST_ROOT else 1
        collectors.append(
            NetworkCollector(proc_root=_under(root, _PROC), netns_pid=netns_pid, host=host)
        )
    return collectors


def build_sinks(settings: Settings) -> list[AlertSink]:
    """Console always; webhook and email when (fully) configured."""
    sinks: list[AlertSink] = [ConsoleSink()]
    if settings.webhook_url is not None:
        if settings.webhook_hmac_secret is None:
            msg = "SENTINEL_WEBHOOK_URL is set but SENTINEL_WEBHOOK_HMAC_SECRET is not"
            raise ConfigurationError(msg)
        sinks.append(
            WebhookSink(
                settings.webhook_url,
                settings.webhook_hmac_secret.get_secret_value(),
                allow_private=settings.webhook_allow_private,
            )
        )
    if settings.smtp_host is not None:
        recipients = settings.email_recipient_list
        if not settings.email_from or not recipients:
            msg = "SENTINEL_SMTP_HOST requires SENTINEL_EMAIL_FROM and SENTINEL_EMAIL_RECIPIENTS"
            raise ConfigurationError(msg)
        sinks.append(
            EmailSink(
                host=settings.smtp_host,
                port=settings.smtp_port,
                sender=settings.email_from,
                recipients=recipients,
                username=settings.smtp_username,
                password=(
                    settings.smtp_password.get_secret_value() if settings.smtp_password else None
                ),
                use_starttls=settings.smtp_starttls,
            )
        )
    return sinks


def build_alert_manager(
    settings: Settings, rules: Iterable[Rule], sinks: Sequence[AlertSink]
) -> AlertManager:
    """An alert manager with the configured gates and every rule's own throttle."""
    return AlertManager(
        sinks,
        min_severity=settings.alert_min_severity,
        dedup_window_seconds=settings.alert_dedup_window_seconds,
        throttle_max=settings.alert_throttle_max,
        throttle_window_seconds=settings.alert_throttle_window_seconds,
        rule_throttles={rule.id: rule.throttle for rule in rules if rule.throttle is not None},
    )


class Runtime:
    """The running system: owns the pipeline task and every per-event step."""

    def __init__(
        self,
        settings: Settings,
        *,
        database: Database,
        metrics: Metrics,
        rules: Iterable[Rule],
        collectors: Iterable[AbstractCollector] | None = None,
        sinks: Sequence[AlertSink] | None = None,
    ) -> None:
        rule_list = tuple(rules)
        self._database = database
        self._metrics = metrics
        self._log = get_logger("sentinel.runtime")
        self._engine = DetectionEngine(rule_list)
        self._alerts = build_alert_manager(
            settings, rule_list, sinks if sinks is not None else build_sinks(settings)
        )
        self._collectors = tuple(
            collectors if collectors is not None else build_collectors(settings)
        )
        self._pipeline = Pipeline(settings)
        for collector in self._collectors:
            self._pipeline.register(collector)
        self._pipeline.set_consumer(self._consume)
        metrics.observe_runtime(self.snapshot)
        self._task: asyncio.Task[None] | None = None
        # Write-behind buffer (see module docstring). The lock serialises the
        # size-triggered and timer-triggered flushes so commits stay ordered.
        self._batch_size = settings.persist_batch_size
        self._flush_interval = settings.persist_flush_interval_seconds
        self._pending_events: list[Event] = []
        self._pending_alerts: list[Alert] = []
        self._flush_lock = asyncio.Lock()
        self._flusher: asyncio.Task[None] | None = None
        self._stop_flushing = asyncio.Event()
        self._persist_failed = 0

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        """Start collectors and the consumer in a background task."""
        if self._task is not None:
            msg = "runtime already started"
            raise RuntimeError(msg)
        if not self._engine.rules:
            self._log.warning("runtime.no_enabled_rules")
        self._task = asyncio.create_task(self._pipeline.run(), name="sentinel.runtime")
        self._task.add_done_callback(self._on_pipeline_exit)
        self._flusher = asyncio.create_task(self._flush_periodically(), name="sentinel.flusher")
        self._log.info(
            "runtime.started",
            collectors=[collector.name for collector in self._collectors],
            rules=len(self._engine.rules),
            sinks=[sink.name for sink in self._alerts.sinks],
        )

    @property
    def running(self) -> bool:
        """True while the pipeline task is alive (drives the readiness probe)."""
        return self._task is not None and not self._task.done()

    async def stop(self) -> None:
        """Drain the pipeline, then release sink resources. Idempotent.

        Collectors are stopped even if the pipeline task already died (a
        crashed collector does not stop its siblings). ``asyncio.wait`` is used
        rather than awaiting the task so that the pipeline's own cancellation —
        or an exception already reported by :meth:`_on_pipeline_exit` — is not
        re-raised into the caller's shutdown path.
        """
        if self._task is not None:
            await self._pipeline.stop()
            await asyncio.wait({self._task})
        if self._flusher is not None:
            # Ask, never cancel: a batch leaves the buffer before it is written,
            # so cancelling a flush mid-write would silently drop that batch.
            self._stop_flushing.set()
            await self._flusher
        await self.flush()  # everything the drained pipeline consumed lands
        await self._alerts.aclose()

    def _on_pipeline_exit(self, task: asyncio.Task[None]) -> None:
        # A dead pipeline behind a healthy API is the worst failure mode for a
        # detector — make it loud. /readyz reports it via `running`.
        if not task.cancelled() and task.exception() is not None:
            self._log.error("runtime.pipeline_crashed", error=type(task.exception()).__name__)

    # ------------------------------------------------------------------ per event

    async def _consume(self, event: Event) -> None:
        """Detect and alert now; buffer the event and its alerts for persistence."""
        for detection in self._engine.evaluate(event):
            self._metrics.detections_fired.labels(
                rule_id=detection.rule_id, severity=str(detection.severity)
            ).inc()
            started = time.perf_counter()
            alert = await self._alerts.process(detection)
            if alert is not None:
                self._metrics.alert_latency.observe(time.perf_counter() - started)
                self._pending_alerts.append(alert)
        self._pending_events.append(event)
        self._metrics.events_ingested.inc()
        if len(self._pending_events) >= self._batch_size:
            await self.flush()

    async def flush(self) -> None:
        """Write every buffered event and alert in one transaction.

        A failed write is logged (exception type only) and counted as
        ``dropped{reason="persist_error"}``; it never propagates into the
        consumer, so a database outage cannot stall detection and alerting.
        """
        async with self._flush_lock:
            events, self._pending_events = self._pending_events, []
            alerts, self._pending_alerts = self._pending_alerts, []
            if not events and not alerts:
                return
            try:
                async with self._database.session() as session:
                    await Repository(session).save_batch(events=events, alerts=alerts)
            except Exception as exc:
                self._persist_failed += len(events)
                self._log.error(
                    "runtime.persist_failed",
                    events=len(events),
                    alerts=len(alerts),
                    error=type(exc).__name__,
                )

    async def _flush_periodically(self) -> None:
        while not self._stop_flushing.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop_flushing.wait(), timeout=self._flush_interval)
            await self.flush()

    # ------------------------------------------------------------------ observability

    def snapshot(self) -> RuntimeSnapshot:
        """Counters for the Prometheus scrape (see :meth:`Metrics.observe_runtime`)."""
        pipeline = self._pipeline.stats
        alerts = self._alerts.stats
        dead_letters = sum(c.stats.get("dead_lettered", 0) for c in self._collectors)
        return RuntimeSnapshot(
            queue_depth=pipeline["queue_size"],
            dropped={
                "queue_full": pipeline["queue_dropped"],
                "duplicate": pipeline["deduped"],
                "consumer_error": pipeline["consumer_errors"],
                "dead_letter": dead_letters,
                "persist_error": self._persist_failed,
            },
            alerts_delivered=self._alerts.delivered_by_sink,
            alerts_suppressed={
                "severity": alerts["suppressed_severity"],
                "duplicate": alerts["deduped"],
                "throttled": alerts["throttled"],
            },
            sink_errors=alerts["sink_errors"],
        )
