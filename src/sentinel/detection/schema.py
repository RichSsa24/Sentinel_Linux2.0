"""Declarative detection-rule schema — rules are *data*, never code.

A rule is a strict, frozen Pydantic model loaded from YAML. Its ``condition`` is
a small recursive match grammar (field operators plus ``all``/``any``/``not``
and a windowed ``threshold`` for rate rules like brute force). The grammar is
deliberately tiny and closed: there is **no** field that can carry Python, a
shell command, or anything executable, so a hostile rule file can only ever
describe a comparison — never run code. The engine that evaluates these
conditions (:mod:`sentinel.detection.evaluator`) is an allowlisted interpreter
of this schema, not an ``eval``.

Every rule must declare its MITRE ATT&CK technique(s) and NIST CSF 2.0
category(ies); those identifiers are format-validated at load so a typo'd or
garbage mapping fails closed instead of shipping a mislabelled detection.
"""

from __future__ import annotations

import re
import types
from enum import StrEnum
from functools import cache
from typing import Final, Union, get_args, get_origin

from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinel.events import Event

# Frozen + extra-forbid: a rule is immutable once loaded, and an unknown key
# (a typo, an injected field) is rejected rather than silently ignored (§3.3).
_RULE_MODEL: Final[ConfigDict] = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

# Identifier formats. ATT&CK techniques are ``T####`` with an optional
# ``.###`` sub-technique; NIST CSF 2.0 categories are ``FN.CC`` with an optional
# ``-##`` subcategory; D3FEND ids are ``D3-XXX``. Format validation is what the
# directive means by "flag unknown ids" without vendoring the full catalogs.
_ATTACK_RE: Final[re.Pattern[str]] = re.compile(r"^T\d{4}(\.\d{3})?$")
_NIST_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Z]{2}\.[A-Z]{2}(-\d{2})?$")
_D3FEND_RE: Final[re.Pattern[str]] = re.compile(r"^D3-[A-Za-z]+$")
_RULE_ID_RE: Final[re.Pattern[str]] = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")

_MAX_SEVERITY: Final[int] = 7
_MAX_WINDOW_SECONDS: Final[int] = 86_400
_MAX_THRESHOLD_COUNT: Final[int] = 100_000

# A rule-supplied comparison value: a scalar, or a list for `in`/`not_in`.
RuleValue = str | int | float | bool | list[str | int | float]


class Operator(StrEnum):
    """The closed set of field operators a condition may use."""

    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    REGEX = "regex"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    NOT_IN = "not_in"


_NUMERIC_OPS: Final[frozenset[Operator]] = frozenset(
    {Operator.GT, Operator.GTE, Operator.LT, Operator.LTE}
)
_TEXT_OPS: Final[frozenset[Operator]] = frozenset(
    {
        Operator.CONTAINS, Operator.NOT_CONTAINS, Operator.STARTSWITH, Operator.ENDSWITH,
        Operator.REGEX,
    }
)  # fmt: skip

_SCALAR_OPS: Final[frozenset[Operator]] = frozenset(
    {
        Operator.EQUALS, Operator.NOT_EQUALS, Operator.CONTAINS, Operator.NOT_CONTAINS,
        Operator.STARTSWITH, Operator.ENDSWITH, Operator.REGEX,
        Operator.GT, Operator.GTE, Operator.LT, Operator.LTE,
    }
)  # fmt: skip
_LIST_OPS: Final[frozenset[Operator]] = frozenset({Operator.IN, Operator.NOT_IN})


class Threshold(BaseModel):
    """A windowed counter: fire when ``match`` recurs ``count`` times per group."""

    model_config = _RULE_MODEL

    match: Condition = Field(description="Per-event condition that is counted.")
    window_seconds: int = Field(ge=1, le=_MAX_WINDOW_SECONDS)
    count: int = Field(ge=2, le=_MAX_THRESHOLD_COUNT, description="Fire at this many matches.")
    group_by: str = Field(
        min_length=1,
        max_length=100,
        description="Dotted event field to bucket on (e.g. source.ip).",
    )


class Throttle(BaseModel):
    """Optional alert-rate limit for a rule (consumed by the Phase 5 alerter)."""

    model_config = _RULE_MODEL

    window_seconds: int = Field(ge=1, le=_MAX_WINDOW_SECONDS)
    max_alerts: int = Field(default=1, ge=1, le=10_000)


class Condition(BaseModel):
    """One node of the match grammar — exactly one form per node.

    Forms: a **field match** (``field`` + ``op`` + ``value``), a boolean
    ``all`` / ``any`` / ``not``, or a windowed ``threshold``. The
    ``model_validator`` enforces that precisely one form is present, so a node
    can never be ambiguous.
    """

    model_config = _RULE_MODEL

    field: str | None = Field(default=None, max_length=200)
    op: Operator | None = None
    value: RuleValue | None = None
    all_: list[Condition] | None = Field(default=None, alias="all", max_length=64)
    any_: list[Condition] | None = Field(default=None, alias="any", max_length=64)
    not_: Condition | None = Field(default=None, alias="not")
    threshold: Threshold | None = None

    @model_validator(mode="after")
    def _exactly_one_form(self) -> Condition:
        forms = (
            self.field is not None,
            self.all_ is not None,
            self.any_ is not None,
            self.not_ is not None,
            self.threshold is not None,
        )
        if sum(forms) != 1:
            msg = "a condition must be exactly one of: field, all, any, not, threshold"
            raise ValueError(msg)
        if self.field is not None:
            self._validate_field_form()
        elif self.op is not None or self.value is not None:
            msg = "'op'/'value' are only valid together with 'field'"
            raise ValueError(msg)
        return self

    def _validate_field_form(self) -> None:
        if self.op is None:
            msg = "a field condition requires an 'op'"
            raise ValueError(msg)
        if self.value is None:
            msg = "a field condition requires a 'value'"
            raise ValueError(msg)
        is_list = isinstance(self.value, list)
        if self.op in _LIST_OPS and not is_list:
            msg = f"operator '{self.op}' requires a list value"
            raise ValueError(msg)
        if self.op in _SCALAR_OPS and is_list:
            msg = f"operator '{self.op}' requires a scalar value"
            raise ValueError(msg)


def _leaf_kinds(annotation: object) -> set[str]:
    """JSON kinds ('str', 'int', 'float', 'bool') a field annotation can hold."""
    if get_origin(annotation) in (Union, types.UnionType):
        return set().union(*(_leaf_kinds(arg) for arg in get_args(annotation)))
    if annotation is type(None):
        return set()
    if annotation is bool:
        return {"bool"}
    if annotation is int:
        return {"int"}
    if annotation is float:
        return {"float"}
    return {"str"}  # str, StrEnum, datetime: all strings in the evaluated view


def _model_fields(model: type[BaseModel], prefix: str = "") -> dict[str, frozenset[str]]:
    fields: dict[str, frozenset[str]] = {}
    for name, info in model.model_fields.items():
        nested = [
            arg
            for arg in (get_args(info.annotation) or (info.annotation,))
            if isinstance(arg, type) and issubclass(arg, BaseModel)
        ]
        if nested:
            for sub in nested:
                fields.update(_model_fields(sub, f"{prefix}{name}."))
        else:
            fields[f"{prefix}{name}"] = frozenset(_leaf_kinds(info.annotation))
    return fields


@cache
def event_fields() -> dict[str, frozenset[str]]:
    """Every dotted field path a rule can reference, with the kinds it can hold."""
    return _model_fields(Event)


def _kind_of(value: object) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    return "float" if isinstance(value, float) else "str"


def _check_field(condition: Condition) -> None:
    """A field condition must name a real field and compare it with a value it can hold."""
    path, op, value = condition.field, condition.op, condition.value
    kinds = event_fields().get(path or "")
    if kinds is None:
        msg = f"unknown field {path!r}; a rule can only match fields of the event model"
        raise ValueError(msg)
    numeric = kinds & {"int", "float"}
    if op in _NUMERIC_OPS and not numeric:
        msg = f"operator '{op}' needs a numeric field; {path!r} is not one"
        raise ValueError(msg)
    if op in _TEXT_OPS and "str" not in kinds:
        msg = f"operator '{op}' needs a text field; {path!r} is not one"
        raise ValueError(msg)
    values = value if isinstance(value, list) else [value]
    for item in values:
        kind = _kind_of(item)
        compatible = kind in kinds or (kind in {"int", "float"} and bool(numeric))
        if not compatible:
            msg = f"{path!r} never holds a {kind} value like {item!r}; the rule could not fire"
            raise ValueError(msg)


def _check_condition(condition: Condition, *, root: bool) -> None:
    """Walk a condition tree: real fields, compatible values, thresholds only at the root."""
    if condition.threshold is not None:
        if not root:
            msg = "'threshold' is only valid as a rule's top-level condition"
            raise ValueError(msg)
        if condition.threshold.group_by not in event_fields():
            msg = f"unknown group_by field {condition.threshold.group_by!r}"
            raise ValueError(msg)
        _check_condition(condition.threshold.match, root=False)
    elif condition.all_ is not None or condition.any_ is not None:
        for child in condition.all_ or condition.any_ or []:
            _check_condition(child, root=False)
    elif condition.not_ is not None:
        _check_condition(condition.not_, root=False)
    else:
        _check_field(condition)


class Rule(BaseModel):
    """A single detection rule, mapped to ATT&CK and NIST CSF."""

    model_config = _RULE_MODEL

    id: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=2_000)
    severity: int = Field(ge=0, le=_MAX_SEVERITY)
    attack: list[str] = Field(
        min_length=1, max_length=16, description="MITRE ATT&CK technique ids."
    )
    nist_csf: list[str] = Field(min_length=1, max_length=16, description="NIST CSF 2.0 categories.")
    d3fend: list[str] = Field(default_factory=list, max_length=16)
    references: list[str] = Field(default_factory=list, max_length=16)
    condition: Condition
    throttle: Throttle | None = None
    enabled: bool = True

    @model_validator(mode="after")
    def _validate_ids(self) -> Rule:
        if not _RULE_ID_RE.match(self.id):
            msg = f"rule id {self.id!r} must be lowercase kebab-case"
            raise ValueError(msg)
        _check_all(self.attack, _ATTACK_RE, "ATT&CK technique")
        _check_all(self.nist_csf, _NIST_RE, "NIST CSF category")
        _check_all(self.d3fend, _D3FEND_RE, "D3FEND id")
        return self

    @model_validator(mode="after")
    def _validate_condition(self) -> Rule:
        # A rule that can never fire is a silent gap in coverage, not a valid rule.
        _check_condition(self.condition, root=True)
        return self


def _check_all(values: list[str], pattern: re.Pattern[str], label: str) -> None:
    """Fail closed if any identifier does not match its expected format."""
    for value in values:
        if not pattern.match(value):
            msg = f"malformed {label} id: {value!r}"
            raise ValueError(msg)


# Resolve the mutual Condition <-> Threshold forward references.
Threshold.model_rebuild()
Condition.model_rebuild()
