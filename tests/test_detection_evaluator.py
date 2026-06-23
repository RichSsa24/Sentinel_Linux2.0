"""Tests for the allowlisted condition evaluator.

Covers every operator (including None/type-mismatch degradation), boolean
composition, dotted field resolution, and — crucially — that a hostile rule
regex cannot hang the process (ReDoS is bounded by a hard timeout).
"""

from __future__ import annotations

import time

import pytest

from sentinel.detection.evaluator import evaluate_condition, resolve_field
from sentinel.detection.schema import Condition


def _match(field: str, op: str, value: object, event: dict[str, object]) -> bool:
    condition = Condition.model_validate({"field": field, "op": op, "value": value})
    return evaluate_condition(condition, event)


class TestResolveField:
    def test_nested_path(self) -> None:
        assert resolve_field("a.b.c", {"a": {"b": {"c": 7}}}) == 7

    def test_missing_leaf_is_none(self) -> None:
        assert resolve_field("a.b.z", {"a": {"b": {"c": 7}}}) is None

    def test_non_mapping_midway_is_none(self) -> None:
        assert resolve_field("a.b.c", {"a": {"b": 5}}) is None

    def test_top_level(self) -> None:
        assert resolve_field("a", {"a": "x"}) == "x"


class TestOperators:
    @pytest.mark.parametrize(
        ("field", "op", "value", "event", "expected"),
        [
            ("a", "equals", "x", {"a": "x"}, True),
            ("a", "equals", "x", {"a": "y"}, False),
            ("a", "equals", "x", {}, False),
            ("a", "equals", 4444, {"a": 4444}, True),
            ("a", "not_equals", "x", {"a": "y"}, True),
            ("a", "not_equals", "x", {}, True),  # missing field is "not equal"
            ("a", "contains", "ell", {"a": "hello"}, True),
            ("a", "contains", "z", {"a": "hello"}, False),
            ("a", "contains", 2, {"a": [1, 2, 3]}, True),
            ("a", "contains", "x", {"a": 99}, False),  # non-str/list
            ("a", "not_contains", "z", {"a": "hello"}, True),
            ("a", "startswith", "he", {"a": "hello"}, True),
            ("a", "startswith", "he", {"a": 42}, False),
            ("a", "endswith", "lo", {"a": "hello"}, True),
            ("a", "endswith", "x", {"a": "hello"}, False),
            ("a", "regex", "^h.llo$", {"a": "hello"}, True),
            ("a", "regex", "^x", {"a": "hello"}, False),
            ("a", "regex", "x", {"a": 123}, False),  # non-str actual
            ("a", "gt", 5, {"a": 10}, True),
            ("a", "gt", 5, {"a": 3}, False),
            ("a", "gt", 5, {"a": "10"}, False),  # string is not numeric
            ("a", "gte", 5, {"a": 5}, True),
            ("a", "lt", 5, {"a": 3}, True),
            ("a", "lte", 5, {"a": 5}, True),
            ("a", "gt", 0, {"a": True}, False),  # bool is not a number here
            ("a", "in", [1, 2, 3], {"a": 2}, True),
            ("a", "in", [1, 2, 3], {"a": 9}, False),
            ("a", "in", [1, 2, 3], {}, False),
            ("a", "not_in", [1, 2, 3], {"a": 9}, True),
            ("a", "not_in", [1, 2, 3], {"a": 2}, False),
        ],
    )
    def test_operator(
        self, field: str, op: str, value: object, event: dict[str, object], expected: bool
    ) -> None:
        assert _match(field, op, value, event) is expected


class TestBoolean:
    def test_all_requires_every_child(self) -> None:
        condition = Condition.model_validate(
            {
                "all": [
                    {"field": "a", "op": "equals", "value": 1},
                    {"field": "b", "op": "equals", "value": 2},
                ]
            }
        )
        assert evaluate_condition(condition, {"a": 1, "b": 2}) is True
        assert evaluate_condition(condition, {"a": 1, "b": 9}) is False

    def test_any_requires_one_child(self) -> None:
        condition = Condition.model_validate(
            {
                "any": [
                    {"field": "a", "op": "equals", "value": 1},
                    {"field": "b", "op": "equals", "value": 2},
                ]
            }
        )
        assert evaluate_condition(condition, {"a": 0, "b": 2}) is True
        assert evaluate_condition(condition, {"a": 0, "b": 0}) is False

    def test_not_inverts(self) -> None:
        condition = Condition.model_validate({"not": {"field": "a", "op": "equals", "value": 1}})
        assert evaluate_condition(condition, {"a": 2}) is True
        assert evaluate_condition(condition, {"a": 1}) is False

    def test_threshold_node_uses_its_match(self) -> None:
        # Evaluated outside the engine, a threshold contributes only its match.
        condition = Condition.model_validate(
            {
                "threshold": {
                    "match": {"field": "a", "op": "equals", "value": 1},
                    "window_seconds": 60,
                    "count": 3,
                    "group_by": "a",
                }
            }
        )
        assert evaluate_condition(condition, {"a": 1}) is True
        assert evaluate_condition(condition, {"a": 2}) is False


class TestReDoSResistance:
    @pytest.mark.security
    def test_catastrophic_regex_is_bounded_not_hanging(self) -> None:
        # A classic exponential-backtracking pattern + adversarial input. The
        # engine-level timeout must abandon it quickly and report no match.
        condition = Condition.model_validate({"field": "m", "op": "regex", "value": "(a|a|a)*$"})
        evil = {"m": "a" * 80 + "!"}

        start = time.perf_counter()
        result = evaluate_condition(condition, evil)
        elapsed = time.perf_counter() - start

        assert result is False
        assert elapsed < 1.0, f"regex took {elapsed:.2f}s — timeout did not fire"

    def test_invalid_pattern_degrades_to_false(self) -> None:
        # A pattern that fails to compile (loader guards against this, but the
        # evaluator must not raise) yields no match rather than an error.
        condition = Condition.model_validate({"field": "m", "op": "regex", "value": "("})
        assert evaluate_condition(condition, {"m": "anything"}) is False
