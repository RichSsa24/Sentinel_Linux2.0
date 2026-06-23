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
- **ReDoS from hostile rule regexes.** Rule files are untrusted config, so a
  ``regex`` match runs through the :mod:`regex` engine with a hard ``timeout``
  (which stdlib ``re`` cannot do) and a bounded input length; a catastrophic
  pattern is abandoned and logged, never allowed to hang the process.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from functools import lru_cache
from typing import Final

import regex

from sentinel.detection.schema import Condition, Operator
from sentinel.logging import get_logger

_log = get_logger("sentinel.detection.evaluator")

# ReDoS bounds: a single match may not run longer than this, and only the first
# N characters of a value are ever scanned (catastrophic backtracking grows with
# input length, so the cap is defence in depth atop the timeout).
_REGEX_TIMEOUT_S: Final[float] = 0.1
_MAX_REGEX_INPUT: Final[int] = 8_192


@lru_cache(maxsize=1024)
def _compiled(pattern: str) -> regex.Pattern:
    """Compile (and cache) a rule regex, case-insensitive."""
    return regex.compile(pattern, flags=regex.IGNORECASE)


def resolve_field(field: str, event: Mapping[str, object]) -> object:
    """Walk a dotted field path into the event dict; missing -> ``None``.

    Shared with the engine, which uses it to resolve a threshold's ``group_by``.
    """
    current: object = event
    for part in field.split("."):
        if not isinstance(current, Mapping):
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


def _regex_search(actual: object, expected: object) -> bool:
    if not isinstance(actual, str) or not isinstance(expected, str):
        return False
    value = actual[:_MAX_REGEX_INPUT]
    try:
        return _compiled(expected).search(value, timeout=_REGEX_TIMEOUT_S) is not None
    except TimeoutError:
        _log.warning("detection.regex_timeout", value_len=len(actual))
        return False
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
    """True if the event satisfies the condition. Never raises on event data.

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
