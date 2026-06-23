"""Tests for the detection-rule schema and the "rules are data" guarantee."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinel.detection.evaluator import evaluate_condition
from sentinel.detection.schema import Condition, Rule

_VALID_RULE = {
    "id": "example-rule",
    "title": "Example",
    "description": "d",
    "severity": 5,
    "attack": ["T1059.004"],
    "nist_csf": ["DE.CM"],
    "condition": {"field": "event.action", "op": "equals", "value": "process_started"},
}


class TestConditionForms:
    def test_field_form_is_valid(self) -> None:
        Condition.model_validate({"field": "a", "op": "equals", "value": 1})

    def test_empty_condition_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="exactly one"):
            Condition.model_validate({})

    def test_two_forms_are_rejected(self) -> None:
        with pytest.raises(ValidationError, match="exactly one"):
            Condition.model_validate({"field": "a", "op": "equals", "value": 1, "all": []})

    def test_field_without_op_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="requires an 'op'"):
            Condition.model_validate({"field": "a", "value": 1})

    def test_field_without_value_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="requires a 'value'"):
            Condition.model_validate({"field": "a", "op": "equals"})

    def test_bare_op_value_without_a_form_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="exactly one"):
            Condition.model_validate({"op": "equals", "value": 1})

    def test_op_value_on_a_boolean_form_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="only valid together with 'field'"):
            Condition.model_validate(
                {"not": {"field": "a", "op": "equals", "value": 1}, "op": "equals"}
            )

    def test_in_requires_a_list_value(self) -> None:
        with pytest.raises(ValidationError, match="requires a list"):
            Condition.model_validate({"field": "a", "op": "in", "value": "scalar"})

    def test_equals_rejects_a_list_value(self) -> None:
        with pytest.raises(ValidationError, match="requires a scalar"):
            Condition.model_validate({"field": "a", "op": "equals", "value": [1, 2]})

    def test_unknown_key_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Condition.model_validate({"field": "a", "op": "equals", "value": 1, "bogus": 1})


class TestRuleValidation:
    def test_valid_rule(self) -> None:
        rule = Rule.model_validate(_VALID_RULE)
        assert rule.id == "example-rule"
        assert rule.enabled is True

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("id", "Has Spaces"),
            ("id", "UPPERCASE"),
            ("attack", ["T999"]),  # too few digits
            ("attack", ["1059"]),  # missing T
            ("nist_csf", ["DECM"]),  # missing dot
            ("d3fend", ["NOT-D3"]),
            ("severity", 9),  # out of 0-7
        ],
    )
    def test_malformed_field_is_rejected(self, key: str, value: object) -> None:
        with pytest.raises(ValidationError):
            Rule.model_validate({**_VALID_RULE, key: value})

    def test_unknown_top_level_key_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Rule.model_validate({**_VALID_RULE, "exec": "rm -rf /"})

    def test_nested_boolean_condition(self) -> None:
        rule = Rule.model_validate(
            {
                **_VALID_RULE,
                "condition": {
                    "all": [
                        {"any": [{"field": "a", "op": "equals", "value": 1}]},
                        {"not": {"field": "b", "op": "equals", "value": 2}},
                    ]
                },
            }
        )
        assert rule.condition.all_ is not None


class TestRulesAreData:
    @pytest.mark.security
    def test_code_like_value_is_compared_as_a_string(self) -> None:
        # A value that looks like Python is inert data: the evaluator only ever
        # compares it, it is never evaluated or executed.
        payload = "__import__('os').system('touch /tmp/pwned')"
        condition = Condition.model_validate(
            {"field": "process.command_line", "op": "equals", "value": payload}
        )
        assert evaluate_condition(condition, {"process": {"command_line": payload}}) is True
        assert evaluate_condition(condition, {"process": {"command_line": "ls"}}) is False
