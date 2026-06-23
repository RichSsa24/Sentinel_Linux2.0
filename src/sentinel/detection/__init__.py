"""Declarative, ATT&CK-mapped detection engine.

Rules are data (strict YAML validated by :mod:`sentinel.detection.schema`),
evaluated by an allowlisted interpreter (:mod:`sentinel.detection.evaluator`)
and run over normalized events by :class:`~sentinel.detection.engine.DetectionEngine`.
Loading is fail-closed (:func:`~sentinel.detection.loader.load_rules`).
"""

from __future__ import annotations

from sentinel.detection.engine import Detection, DetectionEngine
from sentinel.detection.evaluator import evaluate_condition, resolve_field
from sentinel.detection.loader import RuleLoadError, load_rules
from sentinel.detection.schema import (
    Condition,
    Operator,
    Rule,
    Threshold,
    Throttle,
)

__all__ = [
    "Condition",
    "Detection",
    "DetectionEngine",
    "Operator",
    "Rule",
    "RuleLoadError",
    "Threshold",
    "Throttle",
    "evaluate_condition",
    "load_rules",
    "resolve_field",
]
