"""The engine's action index must skip work, never detections.

`required_actions` statically derives which `event.action` values a condition
can match. Two independent checks keep it honest:

1. **Property test (Hypothesis).** For randomly generated condition trees —
   nested all/any/not over positive and negative operators — whenever the
   evaluator says a view matches, the derived set must contain that view's
   action (or be ``None``, meaning "any").
2. **Differential test.** Over the real rule library and a mixed event stream,
   the indexed engine fires exactly the same rules, in the same order, as an
   engine with the index disabled.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st

import sentinel.detection.engine as engine_module
from sentinel.detection import DetectionEngine, Rule, load_rules
from sentinel.detection.engine import required_actions
from sentinel.detection.evaluator import evaluate_condition
from sentinel.detection.schema import Condition
from sentinel.events import Event
from tests.test_detection_rules import CASES

_ROOT = Path(__file__).resolve().parent.parent
_LIBRARY: dict[str, Rule] = {rule.id: rule for rule in load_rules(_ROOT / "rules")}
_ACTIONS = ["alpha", "beta", "gamma", "delta"]

_actions = st.sampled_from(_ACTIONS)
_action_lists = st.lists(_actions, min_size=1, max_size=3)
_leaf: st.SearchStrategy[dict[str, Any]] = st.one_of(
    st.builds(lambda v: {"field": "event.action", "op": "equals", "value": v}, _actions),
    st.builds(lambda v: {"field": "event.action", "op": "in", "value": v}, _action_lists),
    st.builds(lambda v: {"field": "event.action", "op": "not_equals", "value": v}, _actions),
    st.builds(lambda v: {"field": "event.action", "op": "not_in", "value": v}, _action_lists),
    st.builds(lambda v: {"field": "event.action", "op": "startswith", "value": v}, _actions),
    st.builds(lambda v: {"field": "source.port", "op": "gte", "value": v}, st.integers(0, 9)),
)
_conditions = st.recursive(
    _leaf,
    lambda children: st.one_of(
        st.lists(children, min_size=1, max_size=3).map(lambda xs: {"all": xs}),
        st.lists(children, min_size=1, max_size=3).map(lambda xs: {"any": xs}),
        children.map(lambda child: {"not": child}),
    ),
    max_leaves=10,
)


@settings(max_examples=500, deadline=None)
@given(
    tree=_conditions,
    action=st.sampled_from([*_ACTIONS, "unlisted"]),
    port=st.integers(0, 9),
)
def test_index_never_excludes_an_action_that_matches(
    tree: dict[str, Any], action: str, port: int
) -> None:
    condition = Condition.model_validate(tree)
    view = {"event": {"action": action}, "source": {"port": port}}
    allowed = required_actions(condition)
    if evaluate_condition(condition, view):
        assert allowed is None or action in allowed


class TestDerivation:
    @pytest.mark.parametrize(
        ("rule_id", "expected"),
        [
            ("ssh-brute-force", {"ssh_login_failed"}),  # through a threshold
            ("reverse-shell-process", {"process_started"}),  # through `all`
            ("new-suid-binary", {"file_created", "file_attributes_modified"}),  # `any` union
            ("cron-persistence", None),  # no action constraint at all
            ("world-writable-sensitive", None),  # only a negative constraint
        ],
    )
    def test_library_rules(self, rule_id: str, expected: set[str] | None) -> None:
        derived = required_actions(_LIBRARY[rule_id].condition)
        assert derived == (frozenset(expected) if expected is not None else None)

    def test_any_with_an_unrestricted_branch_is_unrestricted(self) -> None:
        condition = Condition.model_validate(
            {
                "any": [
                    {"field": "event.action", "op": "equals", "value": "alpha"},
                    {"field": "source.port", "op": "gt", "value": 1},
                ]
            }
        )
        assert required_actions(condition) is None

    def test_in_with_non_string_values_is_unrestricted(self) -> None:
        condition = Condition.model_validate({"field": "event.action", "op": "in", "value": [1]})
        assert required_actions(condition) is None


def test_indexed_engine_matches_unindexed_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    rules = load_rules(_ROOT / "rules")
    stream: list[Event] = [
        event
        for case in CASES.values()
        for event in [*case.positive, case.negative, *case.positive]
    ]
    indexed = DetectionEngine(rules)
    monkeypatch.setattr(engine_module, "required_actions", lambda _condition: None)
    brute_force = DetectionEngine(rules)

    for event in stream:
        assert [d.rule_id for d in indexed.evaluate(event)] == [
            d.rule_id for d in brute_force.evaluate(event)
        ]
    assert indexed.stats["fired"] == brute_force.stats["fired"] > 0
