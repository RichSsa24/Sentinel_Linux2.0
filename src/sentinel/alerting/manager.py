"""Alert manager — turns detections into delivered alerts, without storms.

The manager is the one place a :class:`~sentinel.detection.engine.Detection`
becomes an :class:`~sentinel.alerting.model.Alert` and fans out to sinks. It
applies three gates, in order, so a detection flood cannot become an alert
flood (a notification-channel DoS):

1. **Severity floor** — alerts below ``min_severity`` are dropped.
2. **Dedup** — the exact same rule firing on the exact same event (identical
   ``dedup_key``) within a TTL window collapses to a single alert.
3. **Throttle** — a per-rule sliding-window rate limit caps how many
   *notifications* one rule can send per window, regardless of distinct
   events. A rule's own ``throttle:`` block (from its YAML) overrides the global
   default, so a brute-force rule can say "one alert per five minutes" while
   the rest of the library keeps the global budget. A throttled alert is still
   returned (``notified=False``) so it is stored: an attacker who exhausts a
   rule's budget with decoys cannot hide the real attack from the record. The
   first throttled alert of a window is logged, and the rule's next
   notification states how many were withheld.

Delivery is firewalled: a sink that raises is counted and logged (by type, never
the payload or any secret) and the other sinks still receive the alert.
"""

from __future__ import annotations

import time
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Final

from sentinel.alerting.model import Alert
from sentinel.alerting.sinks.base import AlertSink
from sentinel.detection.engine import Detection
from sentinel.detection.schema import Throttle
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
        rule_throttles: Mapping[str, Throttle] | None = None,
        time_source: Callable[[], float] = time.monotonic,
    ) -> None:
        self._sinks: tuple[AlertSink, ...] = tuple(sinks)
        self._min_severity = min_severity
        self._dedup = DedupWindow(dedup_window_seconds, dedup_max_entries, time_source=time_source)
        self._throttle_max = throttle_max
        self._throttle_window = throttle_window_seconds
        self._rule_throttles: dict[str, Throttle] = dict(rule_throttles or {})
        self._now = time_source
        # Keyed on rule id (a finite, trusted set), so this cannot grow unbounded.
        self._rule_hits: dict[str, deque[float]] = {}
        # Alerts withheld per rule since its last notification (same finite key set).
        self._withheld: dict[str, int] = {}
        self._log = get_logger("sentinel.alerting.manager")
        self._emitted = 0
        self._suppressed_severity = 0
        self._deduped = 0
        self._throttled = 0
        self._sink_errors = 0
        self._delivered: dict[str, int] = {sink.name: 0 for sink in self._sinks}

    async def process(self, detection: Detection) -> Alert | None:
        """Run a detection through the gates; return the alert to store, or None.

        None means the alert was discarded (below the severity floor, or a
        duplicate). A throttled alert is returned with ``notified=False``: it
        was not sent, but it is evidence and must be stored.
        """
        alert = Alert.from_detection(detection)
        if alert.severity < self._min_severity:
            self._suppressed_severity += 1
            return None
        if self._dedup.seen(alert.dedup_key):
            self._deduped += 1
            return None
        if self._is_throttled(alert.rule_id):
            self._throttled += 1
            withheld = self._withheld.get(alert.rule_id, 0) + 1
            self._withheld[alert.rule_id] = withheld
            if withheld == 1:
                limit, window = self._throttle_for(alert.rule_id)
                self._log.warning(
                    "alert.throttled", rule_id=alert.rule_id, limit=limit, window_seconds=window
                )
            return alert.model_copy(update={"notified": False})
        withheld = self._withheld.pop(alert.rule_id, 0)
        if withheld:
            note = f" [+{withheld} more alert(s) from this rule withheld by the throttle]"
            alert = alert.model_copy(update={"summary": alert.summary + note})
        await self._dispatch(alert)
        self._emitted += 1
        return alert

    def _is_throttled(self, rule_id: str) -> bool:
        limit, window_seconds = self._throttle_for(rule_id)
        now = self._now()
        window = self._rule_hits.setdefault(rule_id, deque())
        cutoff = now - window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= limit:
            return True
        window.append(now)
        return False

    def _throttle_for(self, rule_id: str) -> tuple[int, float]:
        """The (max alerts, window seconds) budget for a rule."""
        override = self._rule_throttles.get(rule_id)
        if override is not None:
            return override.max_alerts, float(override.window_seconds)
        return self._throttle_max, self._throttle_window

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
            else:
                self._delivered[sink.name] = self._delivered.get(sink.name, 0) + 1

    async def aclose(self) -> None:
        """Release every sink's resources (e.g. pooled HTTP connections)."""
        for sink in self._sinks:
            try:
                await sink.aclose()
            except Exception as exc:
                self._log.warning(
                    "alert.sink.close_error", sink=sink.name, error=type(exc).__name__
                )

    @property
    def sinks(self) -> Sequence[AlertSink]:
        """The configured sinks."""
        return self._sinks

    @property
    def delivered_by_sink(self) -> Mapping[str, int]:
        """Successful deliveries per sink name (a snapshot)."""
        return dict(self._delivered)

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
