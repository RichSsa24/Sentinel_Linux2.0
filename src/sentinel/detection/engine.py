"""Detection engine — runs each normalized event through the rule library.

The engine is the stateful counterpart to the stateless
:class:`~sentinel.detection.evaluator.ConditionEvaluator`. For an ordinary rule
it just asks the evaluator whether the event matches; for a **threshold** rule
(brute force and friends) it keeps a per-``group_by`` sliding window of event
timestamps and fires when ``count`` matches fall inside ``window_seconds``.

Two safety properties matter here:

- **Bounded memory.** Each window holds at most ``count`` timestamps (it is
  cleared when it fires, so there is no per-event alert storm), and the number
  of tracked groups is capped — the oldest group is evicted when the cap is hit,
  so an attacker spraying unique ``group_by`` values cannot grow state without
  bound.
- **Never throws on event data.** All matching goes through the evaluator, which
  degrades to "no match" on malformed input, so a single bad event cannot crash
  the engine.

Windows key off the *event* timestamp, not wall-clock, so detection is
deterministic and replayable in tests.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from sentinel.detection.evaluator import evaluate_condition, resolve_field
from sentinel.detection.schema import Rule, Threshold
from sentinel.events import Event
from sentinel.logging import get_logger

_DEFAULT_MAX_THRESHOLD_GROUPS: Final[int] = 100_000

_WindowKey = tuple[str, str]  # (rule_id, group value)


class Detection(BaseModel):
    """A fired rule — carries the rule's framework mappings and the trigger."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    title: str
    severity: int = Field(ge=0, le=7)
    attack: tuple[str, ...]
    nist_csf: tuple[str, ...]
    d3fend: tuple[str, ...]
    event_id: str
    timestamp: datetime
    message: str


class DetectionEngine:
    """Evaluates events against a fixed rule set, emitting Detections."""

    def __init__(
        self,
        rules: Iterable[Rule],
        *,
        max_threshold_groups: int = _DEFAULT_MAX_THRESHOLD_GROUPS,
    ) -> None:
        self._rules: tuple[Rule, ...] = tuple(rule for rule in rules if rule.enabled)
        self._max_groups = max_threshold_groups
        self._windows: dict[_WindowKey, deque[float]] = {}
        self._log = get_logger("sentinel.detection.engine")
        self._evaluations = 0
        self._fired = 0

    @property
    def rules(self) -> tuple[Rule, ...]:
        """The enabled rules this engine evaluates."""
        return self._rules

    def evaluate(self, event: Event) -> list[Detection]:
        """Return every rule that fires for this event (possibly none)."""
        self._evaluations += 1
        view = event.model_dump(mode="json")
        detections: list[Detection] = []
        for rule in self._rules:
            if self._fires(rule, event, view):
                self._fired += 1
                detections.append(self._build(rule, event))
        return detections

    def _fires(self, rule: Rule, event: Event, view: Mapping[str, object]) -> bool:
        threshold = rule.condition.threshold
        if threshold is not None:
            return self._threshold_fires(rule.id, threshold, event, view)
        return evaluate_condition(rule.condition, view)

    def _threshold_fires(
        self, rule_id: str, threshold: Threshold, event: Event, view: Mapping[str, object]
    ) -> bool:
        if not evaluate_condition(threshold.match, view):
            return False
        group = resolve_field(threshold.group_by, view)
        if group is None:
            return False  # cannot bucket an event missing the group field
        key: _WindowKey = (rule_id, str(group))
        moment = event.timestamp.timestamp()
        window = self._window_for(key)
        window.append(moment)
        cutoff = moment - threshold.window_seconds
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= threshold.count:
            window.clear()  # fire once per accumulation — no per-event storm
            return True
        return False

    def _window_for(self, key: _WindowKey) -> deque[float]:
        existing = self._windows.get(key)
        if existing is not None:
            return existing
        if len(self._windows) >= self._max_groups:
            # Bounded memory: evict the oldest-tracked group (insertion order).
            oldest = next(iter(self._windows))
            del self._windows[oldest]
            self._log.warning("detection.threshold_groups_capped", cap=self._max_groups)
        window: deque[float] = deque()
        self._windows[key] = window
        return window

    def _build(self, rule: Rule, event: Event) -> Detection:
        techniques = ",".join(rule.attack)
        return Detection(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            attack=tuple(rule.attack),
            nist_csf=tuple(rule.nist_csf),
            d3fend=tuple(rule.d3fend),
            event_id=event.event.id,
            timestamp=event.timestamp,
            message=f"{rule.title} [{techniques}] — {event.event.action} on {event.host.name}",
        )

    @property
    def stats(self) -> dict[str, int]:
        """Snapshot counters for observability and tests."""
        return {
            "rules": len(self._rules),
            "evaluations": self._evaluations,
            "fired": self._fired,
            "threshold_groups": len(self._windows),
        }
