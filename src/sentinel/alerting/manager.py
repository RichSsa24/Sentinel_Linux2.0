"""Alert manager — turns detections into delivered alerts, without storms.

The manager is the one place a :class:`~sentinel.detection.engine.Detection`
becomes an :class:`~sentinel.alerting.model.Alert` and fans out to sinks. It
applies three gates, in order, so a detection flood cannot become an alert
flood (a notification-channel DoS):

1. **Severity floor** — alerts below ``min_severity`` are dropped.
2. **Dedup** — the exact same rule firing on the exact same event (identical
   ``dedup_key``) within a TTL window collapses to a single alert.
3. **Throttle** — a per-rule sliding-window rate limit caps how many alerts one
   rule can emit per window, regardless of distinct events.

Delivery is firewalled: a sink that raises is counted and logged (by type, never
the payload or any secret) and the other sinks still receive the alert.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from typing import Final

from sentinel.alerting.model import Alert
from sentinel.alerting.sinks.base import AlertSink
from sentinel.detection.engine import Detection
from sentinel.logging import get_logger
from sentinel.pipeline.dedup import DedupWindow

_DEFAULT_DEDUP_WINDOW_S: Final[float] = 300.0
_DEFAULT_DEDUP_MAX_ENTRIES: Final[int] = 100_000
_DEFAULT_THROTTLE_MAX: Final[int] = 10
_DEFAULT_THROTTLE_WINDOW_S: Final[float] = 60.0


class AlertManager:
    """Dedup + throttle + severity-routed fan-out of alerts to sinks."""

    def __init__(
        self,
        sinks: Iterable[AlertSink],
        *,
        min_severity: int = 0,
        dedup_window_seconds: float = _DEFAULT_DEDUP_WINDOW_S,
        dedup_max_entries: int = _DEFAULT_DEDUP_MAX_ENTRIES,
        throttle_max: int = _DEFAULT_THROTTLE_MAX,
        throttle_window_seconds: float = _DEFAULT_THROTTLE_WINDOW_S,
        time_source: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sinks: tuple[AlertSink, ...] = tuple(sinks)
        self._min_severity = min_severity
        self._dedup = DedupWindow(dedup_window_seconds, dedup_max_entries, time_source=time_source)
        self._throttle_max = throttle_max
        self._throttle_window = throttle_window_seconds
        self._now = time_source
        # Keyed on rule id (a finite, trusted set), so this cannot grow unbounded.
        self._rule_hits: dict[str, deque[float]] = {}
        self._log = get_logger("sentinel.alerting.manager")
        self._emitted = 0
        self._suppressed_severity = 0
        self._deduped = 0
        self._throttled = 0
        self._sink_errors = 0

    async def process(self, detection: Detection) -> Alert | None:
        """Run a detection through the gates and deliver it, or return None."""
        alert = Alert.from_detection(detection)
        if alert.severity < self._min_severity:
            self._suppressed_severity += 1
            return None
        if self._dedup.seen(alert.dedup_key):
            self._deduped += 1
            return None
        if self._is_throttled(alert.rule_id):
            self._throttled += 1
            return None
        await self._dispatch(alert)
        self._emitted += 1
        return alert

    def _is_throttled(self, rule_id: str) -> bool:
        now = self._now()
        window = self._rule_hits.setdefault(rule_id, deque())
        cutoff = now - self._throttle_window
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= self._throttle_max:
            return True
        window.append(now)
        return False

    async def _dispatch(self, alert: Alert) -> None:
        for sink in self._sinks:
            if not sink.accepts(alert):
                continue
            try:
                await sink.emit(alert)
            except Exception as exc:
                # Firewall: a failing sink must not stop the others, and must
                # not leak the alert payload or any secret — log the type only.
                self._sink_errors += 1
                self._log.warning(
                    "alert.sink.error",
                    sink=sink.name,
                    rule_id=alert.rule_id,
                    error=type(exc).__name__,
                )

    @property
    def sinks(self) -> Sequence[AlertSink]:
        """The configured sinks."""
        return self._sinks

    @property
    def stats(self) -> dict[str, int]:
        """Snapshot counters for observability and tests."""
        return {
            "emitted": self._emitted,
            "suppressed_severity": self._suppressed_severity,
            "deduped": self._deduped,
            "throttled": self._throttled,
            "sink_errors": self._sink_errors,
        }
