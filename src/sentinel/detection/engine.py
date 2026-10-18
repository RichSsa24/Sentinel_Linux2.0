"""Detection engine — runs each normalized event through the rule library.

The engine is the stateful counterpart to the stateless
:class:`~sentinel.detection.evaluator.ConditionEvaluator`. For an ordinary rule
it just asks the evaluator whether the event matches; for a **threshold** rule
(brute force and friends) it keeps a per-``group_by`` sliding window of event
timestamps and fires when ``count`` matches fall inside ``window_seconds``.

Two safety properties matter here:

- **No address rotation.** An IPv6 ``group_by`` value is bucketed by its /64
  (and an IPv4-mapped one by its IPv4 address), so cycling through the
  addresses of one assignment cannot dodge a threshold.
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

**Action index.** Most rules pin ``event.action`` (``process_started``,
``ssh_login_failed`` ...). :func:`required_actions` derives, by static analysis
of a rule's condition tree, the set of actions it could *possibly* match, and
the engine only evaluates the rules whose set contains the event's action (plus
the rules no set could be derived for). The derivation is conservative — it
answers "any action" whenever it cannot prove otherwise — so the index skips
work, never detections; ``tests/test_detection_engine.py`` checks that property
against randomly generated conditions.
"""

from __future__ import annotations

import ipaddress
from collections import deque
from collections.abc import Iterable, Mapping
from datetime import datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from sentinel.detection.evaluator import EvaluationIncomplete, evaluate_condition, resolve_field
from sentinel.detection.schema import Condition, Operator, Rule, Threshold
from sentinel.events import Event
from sentinel.logging import get_logger

_DEFAULT_MAX_THRESHOLD_GROUPS: Final[int] = 100_000
_ACTION_FIELD: Final[str] = "event.action"
# Candidate lists are cached per action; actions come from a small, fixed
# vocabulary, but the cap keeps a misbehaving source from growing it unbounded.
_MAX_CACHED_ACTIONS: Final[int] = 1_024

_WindowKey = tuple[str, str]  # (rule_id, group value)


# The smallest IPv6 block a single subscriber is assigned (RFC 6177): one host
# can rotate through 2**64 addresses, so per-address counting would never fire.
_IPV6_SUBSCRIBER_PREFIX: Final[int] = 64


def _group_key(value: object) -> str:
    """The threshold bucket for a ``group_by`` value: IPv6 addresses by their /64."""
    text = str(value)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return text
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        network = ipaddress.ip_network(f"{address}/{_IPV6_SUBSCRIBER_PREFIX}", strict=False)
        return str(network)
    return text


def required_actions(condition: Condition) -> frozenset[str] | None:
    """The ``event.action`` values `condition` can match, or ``None`` for "any".

    Sound by construction: whenever a subtree cannot *prove* a restriction it
    reports ``None``, so a rule is never excluded for an action it could match.

    - ``event.action equals X`` -> ``{X}``; ``event.action in [...]`` -> that set
    - ``all`` -> intersection of the children that restrict (all must hold)
    - ``any`` -> union, but only if *every* child restricts
    - ``threshold`` -> its per-event ``match`` (non-matching events never count)
    - ``not``, negative operators and any other field -> ``None``
    """
    if condition.field is not None:
        return _field_actions(condition)
    if condition.all_ is not None:
        restricting = [r for r in map(required_actions, condition.all_) if r is not None]
        return frozenset.intersection(*restricting) if restricting else None
    if condition.any_ is not None:
        branches: list[frozenset[str]] = []
        for child in condition.any_:
            actions = required_actions(child)
            if actions is None:
                return None  # one unrestricted branch makes the whole `any` unrestricted
            branches.append(actions)
        return frozenset[str]().union(*branches) if branches else None
    if condition.threshold is not None:
        return required_actions(condition.threshold.match)
    return None  # `not`: the complement of a set is not a finite set


def _field_actions(condition: Condition) -> frozenset[str] | None:
    if condition.field != _ACTION_FIELD:
        return None
    if condition.op is Operator.EQUALS and isinstance(condition.value, str):
        return frozenset({condition.value})
    if condition.op is Operator.IN and isinstance(condition.value, list):
        values = condition.value
        if all(isinstance(value, str) for value in values):
            return frozenset(str(value) for value in values)
    return None


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
    host: str
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
        self._rule_actions = [(rule, required_actions(rule.condition)) for rule in self._rules]
        self._candidates: dict[str, tuple[Rule, ...]] = {}
        self._max_groups = max_threshold_groups
        self._windows: dict[_WindowKey, deque[float]] = {}
        self._log = get_logger("sentinel.detection.engine")
        self._evaluations = 0
        self._fired = 0
        self._incomplete = 0

    @property
    def rules(self) -> tuple[Rule, ...]:
        """The enabled rules this engine evaluates."""
        return self._rules

    def evaluate(self, event: Event) -> list[Detection]:
        """Return every rule that fires for this event (possibly none)."""
        self._evaluations += 1
        candidates = self._candidates_for(event.event.action)
        if not candidates:
            return []  # skip even building the dict view
        view = event.model_dump(mode="json")
        detections: list[Detection] = []
        for rule in candidates:
            try:
                fired, complete = self._fires(rule, event, view), True
            except EvaluationIncomplete:
                # Fail safe: an undecidable match fires (a false positive, never a
                # miss), so padding an input until the regex gives up hides nothing.
                fired, complete = True, False
                self._incomplete += 1
                self._log.warning("detection.evaluation_incomplete", rule_id=rule.id)
            if fired:
                self._fired += 1
                detections.append(self._build(rule, event, complete=complete))
        return detections

    def _candidates_for(self, action: str) -> tuple[Rule, ...]:
        """Rules that could match `action`, in library order (cached per action)."""
        cached = self._candidates.get(action)
        if cached is not None:
            return cached
        candidates = tuple(
            rule for rule, actions in self._rule_actions if actions is None or action in actions
        )
        if len(self._candidates) < _MAX_CACHED_ACTIONS:
            self._candidates[action] = candidates
        return candidates

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
        key: _WindowKey = (rule_id, _group_key(group))
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

    def _build(self, rule: Rule, event: Event, *, complete: bool = True) -> Detection:
        techniques = ",".join(rule.attack)
        note = "" if complete else " (evaluation incomplete: a pattern timed out; review)"
        return Detection(
            rule_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            attack=tuple(rule.attack),
            nist_csf=tuple(rule.nist_csf),
            d3fend=tuple(rule.d3fend),
            event_id=event.event.id,
            host=event.host.name,
            timestamp=event.timestamp,
            message=f"{rule.title} [{techniques}] — {event.event.action} on {event.host.name}"
            + note,
        )

    @property
    def stats(self) -> dict[str, int]:
        """Snapshot counters for observability and tests."""
        return {
            "rules": len(self._rules),
            "evaluations": self._evaluations,
            "fired": self._fired,
            "incomplete": self._incomplete,
            "threshold_groups": len(self._windows),
        }
