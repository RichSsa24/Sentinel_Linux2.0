"""Load and validate the YAML rule library — fail closed on anything wrong.

Rule files are **untrusted configuration**, so loading is defensive end to end:

- Parsing is ``yaml.safe_load`` only — never ``yaml.load`` — so a rule file can
  never construct arbitrary Python objects.
- Each document must be a mapping and must validate against the strict
  :class:`~sentinel.detection.schema.Rule` model (unknown keys rejected).
- Every ``regex`` pattern is compiled at load time, so a malformed pattern is
  caught here, not at runtime against a live event.
- Duplicate rule ids are rejected.

Any failure raises :class:`RuleLoadError`; a caller that loads rules at startup
should let it propagate and refuse to run, rather than silently dropping a
detection.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import regex
import yaml
from pydantic import ValidationError

from sentinel.detection.schema import Condition, Operator, Rule
from sentinel.logging import get_logger

_log = get_logger("sentinel.detection.loader")


class RuleLoadError(Exception):
    """A rule file could not be read, parsed, or validated."""


def load_rules(rules_dir: Path) -> list[Rule]:
    """Load every ``*.yml`` / ``*.yaml`` rule under ``rules_dir``, validated.

    Raises :class:`RuleLoadError` on the first unreadable, malformed, or
    duplicate rule — the library loads in full or not at all (fail closed).
    """
    paths = sorted({*rules_dir.glob("*.yml"), *rules_dir.glob("*.yaml")})
    rules: list[Rule] = []
    seen: dict[str, Path] = {}
    for path in paths:
        rule = _load_one(path)
        if rule.id in seen:
            msg = f"duplicate rule id {rule.id!r} in {path} (already defined in {seen[rule.id]})"
            raise RuleLoadError(msg)
        seen[rule.id] = path
        rules.append(rule)
    _log.info("detection.rules_loaded", count=len(rules), source=str(rules_dir))
    return rules


def _load_one(path: Path) -> Rule:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        msg = f"cannot read rule file {path}: {exc}"
        raise RuleLoadError(msg) from exc
    if not isinstance(raw, dict):
        msg = f"rule file {path} must contain a YAML mapping, got {type(raw).__name__}"
        raise RuleLoadError(msg)
    try:
        rule = Rule.model_validate(raw)
    except ValidationError as exc:
        msg = f"invalid rule in {path}: {exc}"
        raise RuleLoadError(msg) from exc
    _validate_regexes(rule, path)
    return rule


def _iter_conditions(condition: Condition) -> Iterator[Condition]:
    """Yield every condition node in the tree (depth-first)."""
    yield condition
    for child in condition.all_ or []:
        yield from _iter_conditions(child)
    for child in condition.any_ or []:
        yield from _iter_conditions(child)
    if condition.not_ is not None:
        yield from _iter_conditions(condition.not_)
    if condition.threshold is not None:
        yield from _iter_conditions(condition.threshold.match)


def _validate_regexes(rule: Rule, path: Path) -> None:
    """Compile every regex pattern in the rule so a bad one fails at load."""
    for node in _iter_conditions(rule.condition):
        if node.op is Operator.REGEX and isinstance(node.value, str):
            try:
                regex.compile(node.value)
            except regex.error as exc:
                msg = f"rule {rule.id!r} in {path} has an invalid regex {node.value!r}: {exc}"
                raise RuleLoadError(msg) from exc
