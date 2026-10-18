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
is consumed; the database write never sits on that path. Events and their
alerts are buffered and a dedicated flusher task writes them in one transaction
when ``persist_batch_size`` events have accumulated (the consumer signals it)
or ``persist_flush_interval_seconds`` has elapsed, whichever comes first; the
buffer is always flushed on shutdown. One commit per event caps SQLite at a few
hundred events per second; batching is what lets persistence keep up.

A failed write (a database restart, a lock timeout) is put back at the front of
the buffer and retried with exponential backoff, so a transient outage loses
nothing. A batch the database *rejects* (an integrity or data error) would fail
every retry, so it is instead written row by row and only the offending rows
are dropped. The buffer is capped at ``persist_max_buffered`` records; beyond
that the oldest are dropped and counted, as is anything unwritten at shutdown.

The costs are bounded staleness in the read API (about one flush interval) and,
on a hard kill, losing what was buffered — events that were only in memory
anyway.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import Callable, Iterable, Sequence
from pathlib import Path
from typing import Final

from sqlalchemy.exc import DataError, DBAPIError, IntegrityError

from sentinel.alerting import (
    Alert,
    AlertManager,
    AlertSink,
    ConsoleSink,
    DestinationBlockedError,
    EmailSink,
    WebhookSink,
    validate_destination,
)
from sentinel.collectors.authlog import AuthLogCollector
from sentinel.collectors.base import AbstractCollector, under_host_root
from sentinel.collectors.integrity import FileIntegrityCollector
from sentinel.collectors.network import NetworkCollector
from sentinel.collectors.process import ProcessCollector
from sentinel.detection import DetectionEngine, Rule
from sentinel.detection.schema import Condition, Operator
from sentinel.events import Event
from sentinel.logging import get_logger
from sentinel.metrics import Metrics, RuntimeSnapshot
from sentinel.pipeline import Pipeline
from sentinel.settings import Settings
from sentinel.storage import Database, Repository

_HOST_ROOT: Final[Path] = Path("/")
_PROC: Final[Path] = Path("/proc")
_SMTPS_PORT: Final[int] = 465
# Cap on the retry backoff while the database is failing.
_MAX_RETRY_BACKOFF_S: Final[float] = 30.0
# SQLSTATE classes meaning "the database rejects this data", not "the database
# is unavailable": 22 data exception, 23 integrity constraint violation.
_REJECTED_SQLSTATE_CLASSES: Final[frozenset[str]] = frozenset({"22", "23"})


def _is_rejection(exc: Exception) -> bool:
    """True if the database refused the rows themselves; retrying them cannot help.

    Exception types alone are not enough: SQLAlchemy's asyncpg adapter maps only
    integrity violations to IntegrityError and every other server error (a value
    too long, a NUL byte, a numeric overflow) to a bare DBAPIError. It keeps the
    server's SQLSTATE on the original exception, so the class decides.
    """
    if isinstance(exc, DataError | IntegrityError):
        return True
    if isinstance(exc, DBAPIError):
        sqlstate = getattr(exc.orig, "sqlstate", None)
        return isinstance(sqlstate, str) and sqlstate[:2] in _REJECTED_SQLSTATE_CLASSES
    return False


_REGEX_META: Final[str] = ".^$*+?{}[]()|\\"
_QUANTIFIERS: Final[str] = "?*{"


def _literal_prefix(pattern: str) -> str:
    """The literal text a regex alternative starts with (empty if none)."""
    prefix: list[str] = []
    for index, char in enumerate(pattern):
        if char in _REGEX_META:
            if char in _QUANTIFIERS and prefix:
                prefix.pop()  # `g?` makes the g optional
            break
        prefix.append(char)
        if index + 1 < len(pattern) and pattern[index + 1] in _QUANTIFIERS:
            prefix.pop()
            break
    return "".join(prefix)


def _regex_path_prefixes(pattern: str) -> list[str]:
    """Literal path prefixes of an anchored regex such as ``^(?:/etc/cron|/var/spool)``."""
    if not pattern.startswith("^"):
        return []
    body = pattern[1:]
    if body.startswith("(?:") and ")" in body:
        group, rest = body[3:].split(")", 1)
        return [_literal_prefix(alternative + rest) for alternative in group.split("|")]
    return [_literal_prefix(body)]


def _file_path_prefixes(condition: Condition) -> list[str]:
    """Every literal ``file.path`` prefix a condition tree tests."""
    if condition.threshold is not None:
        return _file_path_prefixes(condition.threshold.match)
    children = condition.all_ or condition.any_ or ([condition.not_] if condition.not_ else [])
    if children:
        return [prefix for child in children for prefix in _file_path_prefixes(child)]
    if condition.field != "file.path" or not isinstance(condition.value, str):
        return []
    if condition.op in (Operator.EQUALS, Operator.STARTSWITH):
        return [condition.value]
    if condition.op is Operator.REGEX:
        return [prefix for prefix in _regex_path_prefixes(condition.value) if prefix]
    return []


def unwatched_rule_paths(rules: Iterable[Rule], watched: Sequence[str]) -> dict[str, list[str]]:
    """Rules whose file paths no watched path covers, with those paths.

    Such a rule can never fire (e.g. log-tampering while /var/log is not
    watched); the runtime warns about them once at startup.
    """

    def covered(prefix: str) -> bool:
        return any(
            prefix.startswith(root.rstrip("/") + "/") or prefix == root or root.startswith(prefix)
            for root in watched
        )

    uncovered: dict[str, list[str]] = {}
    for rule in rules:
        missing = [p for p in _file_path_prefixes(rule.condition) if not covered(p)]
        if missing:
            uncovered[rule.id] = missing
    return uncovered


class ConfigurationError(ValueError):
    """The settings describe a system that cannot run safely."""


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
        collectors.append(AuthLogCollector(under_host_root(root, settings.auth_log_path)))
    if "file-integrity" in enabled:
        collectors.append(
            FileIntegrityCollector(paths=list(settings.fim_path_list), host_root=root, host=host)
        )
    if "process" in enabled:
        collectors.append(ProcessCollector(proc_root=under_host_root(root, _PROC), host=host))
    if "network" in enabled:
        # Behind a host-root mount, /proc/net would resolve to *our* (container)
        # namespace; PID 1's view of the host procfs is the host's.
        netns_pid = None if root == _HOST_ROOT else 1
        collectors.append(
            NetworkCollector(proc_root=under_host_root(root, _PROC), netns_pid=netns_pid, host=host)
        )
    return collectors


def build_sinks(settings: Settings) -> list[AlertSink]:
    """Console always; webhook and email when (fully) configured."""
    sinks: list[AlertSink] = [ConsoleSink()]
    if settings.webhook_url is not None:
        if settings.webhook_hmac_secret is None:
            msg = "SENTINEL_WEBHOOK_URL is set but SENTINEL_WEBHOOK_HMAC_SECRET is not"
            raise ConfigurationError(msg)
        try:  # https, a host, no blocked IP literal; names are checked per send
            validate_destination(
                settings.webhook_url.get_secret_value(),
                allow_private=settings.webhook_allow_private,
            )
        except DestinationBlockedError as exc:
            raise ConfigurationError(f"SENTINEL_WEBHOOK_URL: {exc}") from exc
        sinks.append(
            WebhookSink(
                settings.webhook_url.get_secret_value(),
                settings.webhook_hmac_secret.get_secret_value(),
                allow_private=settings.webhook_allow_private,
            )
        )
    if settings.smtp_host is not None:
        recipients = settings.email_recipient_list
        if not settings.email_from or not recipients:
            msg = "SENTINEL_SMTP_HOST requires SENTINEL_EMAIL_FROM and SENTINEL_EMAIL_RECIPIENTS"
            raise ConfigurationError(msg)
        try:
            email = EmailSink(
                host=settings.smtp_host,
                port=settings.smtp_port,
                sender=settings.email_from,
                recipients=recipients,
                username=settings.smtp_username,
                password=(
                    settings.smtp_password.get_secret_value() if settings.smtp_password else None
                ),
                use_starttls=settings.smtp_starttls,
                # Port 465 is SMTP submission over implicit TLS (RFC 8314).
                implicit_tls=settings.smtp_port == _SMTPS_PORT,
            )
        except ValueError as exc:
            raise ConfigurationError(f"email sink: {exc}") from exc
        sinks.append(email)
    return sinks


def build_alert_manager(
    settings: Settings,
    rules: Iterable[Rule],
    sinks: Sequence[AlertSink],
    on_delivered: Callable[[float], None] | None = None,
) -> AlertManager:
    """An alert manager with the configured gates and every rule's own throttle."""
    return AlertManager(
        sinks,
        min_severity=settings.alert_min_severity,
        dedup_window_seconds=settings.alert_dedup_window_seconds,
        throttle_max=settings.alert_throttle_max,
        throttle_window_seconds=settings.alert_throttle_window_seconds,
        rule_throttles={rule.id: rule.throttle for rule in rules if rule.throttle is not None},
        on_delivered=on_delivered,
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
        on_fatal: Callable[[], None] | None = None,
    ) -> None:
        rule_list = tuple(rules)
        self._on_fatal = on_fatal
        self._fim_paths = settings.fim_path_list
        self._enabled = settings.enabled_collectors
        self._database = database
        self._metrics = metrics
        self._log = get_logger("sentinel.runtime")
        self._engine = DetectionEngine(rule_list)
        self._alerts = build_alert_manager(
            settings,
            rule_list,
            sinks if sinks is not None else build_sinks(settings),
            on_delivered=metrics.alert_latency.observe,
        )
        self._collectors = tuple(
            collectors if collectors is not None else build_collectors(settings)
        )
        self._pipeline = Pipeline(settings)
        for collector in self._collectors:
            self._pipeline.register(collector)
        self._pipeline.set_consumer(self._consume)
        self._task: asyncio.Task[None] | None = None
        # Write-behind buffer (see module docstring). The lock serialises the
        # flusher's writes with the final shutdown flush so commits stay ordered.
        self._batch_size = settings.persist_batch_size
        self._flush_interval = settings.persist_flush_interval_seconds
        self._max_pending = settings.persist_max_buffered
        self._pending_events: list[Event] = []
        self._pending_alerts: list[Alert] = []
        self._flush_lock = asyncio.Lock()
        self._flush_wanted = asyncio.Event()
        self._stop_flushing = asyncio.Event()
        self._flusher: asyncio.Task[None] | None = None
        self._events_unpersisted = 0
        self._alerts_unpersisted = 0
        # Last: a registry may call snapshot() during registration.
        metrics.observe_runtime(self.snapshot)

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        """Start collectors and the consumer in a background task."""
        if self._task is not None:
            msg = "runtime already started"
            raise RuntimeError(msg)
        if not self._engine.rules:
            self._log.warning("runtime.no_enabled_rules")
        watched = self._fim_paths if "file-integrity" in self._enabled else ()
        unwatched = unwatched_rule_paths(self._engine.rules, watched)
        if unwatched:
            self._log.warning(
                "runtime.rule_paths_not_watched",
                rules=unwatched,
                hint="add the paths to SENTINEL_FIM_PATHS or these rules cannot fire",
            )
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
            self._flush_wanted.set()
            await self._flusher
        if not await self.flush():  # one last attempt for what the drain consumed
            self._discard_pending("runtime.unpersisted_at_shutdown")
        await self._alerts.aclose()

    def _on_pipeline_exit(self, task: asyncio.Task[None]) -> None:
        # A dead pipeline behind a healthy API is the worst failure mode for a
        # detector. Collector failures are already contained (restarted), so
        # this is a framework bug: log it with its traceback, report it via
        # `running` (/readyz, sentinel_pipeline_up), and let on_fatal end the
        # process so its supervisor (Docker, systemd) starts a fresh one —
        # neither restarts a process merely for failing a health check.
        if task.cancelled() or task.exception() is None:
            return
        error = task.exception()
        self._log.error("runtime.pipeline_crashed", error=type(error).__name__, exc_info=error)
        if self._on_fatal is not None:
            self._on_fatal()

    # ------------------------------------------------------------------ per event

    async def _consume(self, event: Event) -> None:
        """Detect and alert now; buffer the event and its alerts for persistence."""
        for detection in self._engine.evaluate(event):
            self._metrics.detections_fired.labels(
                rule_id=detection.rule_id, severity=str(detection.severity)
            ).inc()
            # Notifications are queued per sink; latency is observed on delivery.
            alert = await self._alerts.process(detection)
            if alert is not None:  # notified or throttled: stored either way
                self._pending_alerts.append(alert)
        self._pending_events.append(event)
        self._metrics.events_ingested.inc()
        if len(self._pending_events) > self._max_pending:
            self._trim_pending()
        if len(self._pending_events) >= self._batch_size:
            self._flush_wanted.set()  # the flusher writes; detection never waits on it

    async def flush(self) -> bool:
        """Write every buffered event and alert in one transaction.

        Returns False if the write failed. The batch is then put back at the
        front of the buffer (order preserved) for the next attempt, and the
        failure is logged by exception type only — it never propagates, so a
        database outage cannot stall detection and alerting.
        """
        async with self._flush_lock:
            events, self._pending_events = self._pending_events, []
            alerts, self._pending_alerts = self._pending_alerts, []
            if not events and not alerts:
                return True
            failure = await self._save(events=events, alerts=alerts)
            if failure is None:
                return True
            if _is_rejection(failure):
                return await self._write_row_by_row(events, alerts)
            self._requeue(events, alerts, failure)
            return False

    async def _save(
        self, *, events: Sequence[Event] = (), alerts: Sequence[Alert] = ()
    ) -> Exception | None:
        """Write records in one transaction; return the failure instead of raising."""
        try:
            async with self._database.session() as session:
                await Repository(session).save_batch(events=events, alerts=alerts)
        except Exception as exc:
            return exc
        return None

    async def _write_row_by_row(self, events: list[Event], alerts: list[Alert]) -> bool:
        """Isolate rows the database rejects so they cannot block the rest.

        Each record gets its own transaction; one the database rejects is
        dropped, counted and logged (exception type only). If the database
        fails for any other reason midway, the records not yet written are put
        back like a failed batch and False is returned.
        """
        rejected_events = rejected_alerts = 0
        error = ""
        outage: tuple[list[Event], list[Alert], Exception] | None = None
        for i, event in enumerate(events):
            failure = await self._save(events=[event])
            if failure is not None and not _is_rejection(failure):
                outage = (events[i:], alerts, failure)
                break
            if failure is not None:
                rejected_events += 1
                error = type(failure).__name__
        else:
            for j, alert in enumerate(alerts):
                failure = await self._save(alerts=[alert])
                if failure is not None and not _is_rejection(failure):
                    outage = ([], alerts[j:], failure)
                    break
                if failure is not None:
                    rejected_alerts += 1
                    error = type(failure).__name__
        self._events_unpersisted += rejected_events
        self._alerts_unpersisted += rejected_alerts
        if rejected_events or rejected_alerts:
            self._log.error(
                "runtime.persist_rejected",
                events=rejected_events,
                alerts=rejected_alerts,
                error=error,
            )
        if outage is not None:
            self._requeue(*outage)
            return False
        return True

    def _requeue(self, events: list[Event], alerts: list[Alert], failure: Exception) -> None:
        """Put unwritten records back at the front of the buffer (order kept)."""
        self._pending_events[:0] = events
        self._pending_alerts[:0] = alerts
        self._trim_pending()
        self._log.error(
            "runtime.persist_failed",
            events=len(events),
            alerts=len(alerts),
            buffered=len(self._pending_events),
            error=type(failure).__name__,
        )

    async def _flush_periodically(self) -> None:
        """Flush on a full batch or every interval; back off while writes fail."""
        delay = self._flush_interval
        while not self._stop_flushing.is_set():
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._flush_wanted.wait(), timeout=delay)
            self._flush_wanted.clear()
            if await self.flush():
                delay = self._flush_interval
            else:
                # Do not hammer a database that is down: wait out the backoff
                # (unless shutting down) before the next attempt.
                delay = min(delay * 2, _MAX_RETRY_BACKOFF_S)
                with contextlib.suppress(TimeoutError):
                    await asyncio.wait_for(self._stop_flushing.wait(), timeout=delay)

    def _trim_pending(self) -> None:
        """Enforce the buffer cap by dropping (and counting) the oldest records."""
        excess_events = len(self._pending_events) - self._max_pending
        if excess_events > 0:
            del self._pending_events[:excess_events]
            self._events_unpersisted += excess_events
        excess_alerts = len(self._pending_alerts) - self._max_pending
        if excess_alerts > 0:
            del self._pending_alerts[:excess_alerts]
            self._alerts_unpersisted += excess_alerts

    def _discard_pending(self, reason: str) -> None:
        """Count and log whatever is still buffered as lost."""
        events, alerts = len(self._pending_events), len(self._pending_alerts)
        if events or alerts:
            self._events_unpersisted += events
            self._alerts_unpersisted += alerts
            self._pending_events.clear()
            self._pending_alerts.clear()
            self._log.error(reason, events=events, alerts=alerts)

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
                "persist_error": self._events_unpersisted,
            },
            alerts_delivered=self._alerts.delivered_by_sink,
            alerts_suppressed={
                "severity": alerts["suppressed_severity"],
                "duplicate": alerts["deduped"],
                "throttled": alerts["throttled"],
            },
            sink_errors=alerts["sink_errors"],
            alert_deliveries_dropped=self._alerts.dropped_by_sink,
            alerts_unpersisted=self._alerts_unpersisted,
            pipeline_up=self.running,
            collector_restarts=self._pipeline.collector_restarts,
        )
