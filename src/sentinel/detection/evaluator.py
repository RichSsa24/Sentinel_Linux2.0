"""Safe, allowlisted evaluator for the detection match grammar.

This is the interpreter that makes "rules are data, never code" true: it walks a
:class:`~sentinel.detection.schema.Condition` tree and applies a *fixed* set of
comparison operators to fields of a normalized event. There is no ``eval``, no
``exec``, no attribute access driven by rule content — a field path can only
index into the event's plain-dict form, and an operator can only be one of the
closed :class:`~sentinel.detection.schema.Operator` set, dispatched through a
literal table.

Two hostile inputs are defended against:

- **Malformed events.** Every operator degrades to ``False`` on a missing field
  or a type mismatch; evaluation never raises on event data, so one odd event
  cannot stall the engine.
- **ReDoS, and evasion through it.** A ``regex`` match runs through the
  :mod:`regex` engine with a hard ``timeout`` (which stdlib ``re`` cannot do)
  over a bounded input. Running out of time must not mean "no match": an
  attacker who controls the input (a command line) could otherwise pad it
  until the rule gives up. A timeout raises :class:`EvaluationIncomplete`,
  which the engine treats as a match — a false positive, never a miss.
  Values up to ``_MAX_REGEX_INPUT`` are scanned whole; longer ones by their
  head *and* tail, so padding on one side cannot push a payload out of reach.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from functools import lru_cache
from typing import Final

import regex

from sentinel.detection.schema import Condition, Operator
from sentinel.logging import get_logger

_log = get_logger("sentinel.detection.evaluator")

# ReDoS bounds: a single match may not run longer than this, and a value longer
# than _MAX_REGEX_INPUT is scanned as two windows (head and tail) of half that.
# Collectors clip command lines to 10,000 characters, so they are scanned whole.
_REGEX_TIMEOUT_S: Final[float] = 0.1
_MAX_REGEX_INPUT: Final[int] = 16_384


class EvaluationIncomplete(Exception):  # noqa: N818 — a state, not an error to fix
    """A condition could not be decided in time; the caller must not read it as False."""


@lru_cache(maxsize=1024)
def _compiled(pattern: str) -> regex.Pattern:
    """Compile (and cache) a rule regex, case-insensitive."""
    return regex.compile(pattern, flags=regex.IGNORECASE)


@lru_cache(maxsize=1024)
def _field_path(field: str) -> tuple[str, ...]:
    """Split (and cache) a dotted field path — rules reuse a handful of paths."""
    return tuple(field.split("."))


def resolve_field(field: str, event: Mapping[str, object]) -> object:
    """Walk a dotted field path into the event dict; missing -> ``None``.

    Shared with the engine, which uses it to resolve a threshold's ``group_by``.
    """
    current: object = event
    for part in _field_path(field):
        # `dict` is listed first on purpose: the event view is built from plain
        # dicts, and an exact-type hit short-circuits before the ABC check that
        # `Mapping` needs (~30 ns vs ~100 ns per call on CPython 3.13, timeit);
        # any other Mapping is still admitted.
        if not isinstance(current, (dict, Mapping)):
            return None
        current = current.get(part)
        if current is None:
            return None
    return current


def _contains(actual: object, expected: object) -> bool:
    if isinstance(actual, str) and isinstance(expected, str):
        return expected in actual
    if isinstance(actual, list):
        return expected in actual
    return False


def _numeric_compare(actual: object, expected: object, op: Callable[[float, float], bool]) -> bool:
    # bool is an int subclass; never treat True/False as 1/0 in comparisons.
    if isinstance(actual, bool) or isinstance(expected, bool):
        return False
    if isinstance(actual, int | float) and isinstance(expected, int | float):
        return op(actual, expected)
    return False


def _scan_windows(value: str) -> tuple[str, ...]:
    """The parts of ``value`` a regex scans: all of it, or its head and its tail."""
    if len(value) <= _MAX_REGEX_INPUT:
        return (value,)
    half = _MAX_REGEX_INPUT // 2
    return (value[:half], value[-half:])


def _regex_search(actual: object, expected: object) -> bool:
    if not isinstance(actual, str) or not isinstance(expected, str):
        return False
    try:
        pattern = _compiled(expected)
        return any(
            pattern.search(window, timeout=_REGEX_TIMEOUT_S) is not None
            for window in _scan_windows(actual)
        )
    except TimeoutError as exc:
        _log.warning("detection.regex_timeout", value_len=len(actual))
        raise EvaluationIncomplete from exc
    except regex.error:
        # Patterns are compiled and validated at load; this is belt-and-braces.
        return False


# The closed operator table — the whole vocabulary a rule can express. Each
# handler takes (actual_event_value, rule_value) and returns a bool, degrading
# to False on any type mismatch rather than raising.
_OPERATORS: Final[dict[Operator, Callable[[object, object], bool]]] = {
    Operator.EQUALS: lambda a, e: bool(a == e),
    Operator.NOT_EQUALS: lambda a, e: bool(a != e),
    Operator.CONTAINS: _contains,
    Operator.NOT_CONTAINS: lambda a, e: not _contains(a, e),
    Operator.STARTSWITH: lambda a, e: isinstance(a, str) and isinstance(e, str) and a.startswith(e),
    Operator.ENDSWITH: lambda a, e: isinstance(a, str) and isinstance(e, str) and a.endswith(e),
    Operator.REGEX: _regex_search,
    Operator.GT: lambda a, e: _numeric_compare(a, e, lambda x, y: x > y),
    Operator.GTE: lambda a, e: _numeric_compare(a, e, lambda x, y: x >= y),
    Operator.LT: lambda a, e: _numeric_compare(a, e, lambda x, y: x < y),
    Operator.LTE: lambda a, e: _numeric_compare(a, e, lambda x, y: x <= y),
    Operator.IN: lambda a, e: isinstance(e, list) and a in e,
    Operator.NOT_IN: lambda a, e: not (isinstance(e, list) and a in e),
}


def evaluate_condition(condition: Condition, event: Mapping[str, object]) -> bool:
    """True if the event satisfies the condition.

    Never raises on event data, except :class:`EvaluationIncomplete` when a
    regex ran out of time — that answer is unknown, not False.

    A ``threshold`` node contributes only its per-event ``match`` here; the
    stateful sliding window lives in :class:`~sentinel.detection.engine.DetectionEngine`.
    """
    if condition.all_ is not None:
        return all(evaluate_condition(child, event) for child in condition.all_)
    if condition.any_ is not None:
        return any(evaluate_condition(child, event) for child in condition.any_)
    if condition.not_ is not None:
        return not evaluate_condition(condition.not_, event)
    if condition.threshold is not None:
        return evaluate_condition(condition.threshold.match, event)
    if condition.field is None or condition.op is None:  # pragma: no cover - schema-guaranteed
        return False
    actual = resolve_field(condition.field, event)
    return _OPERATORS[condition.op](actual, condition.value)
