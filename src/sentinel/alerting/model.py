"""The Alert — a detection promoted to a deliverable notification.

An :class:`Alert` is the immutable thing the sinks render and send. It carries
the detection's framework mappings plus a ``dedup_key`` (the identity the alert
manager deduplicates on) and a one-line ``summary``. Building it from a
:class:`~sentinel.detection.engine.Detection` is the only supported path, so an
alert always traces back to a real, rule-mapped detection.
"""

from __future__ import annotations

from datetime import datetime
from typing import Final

from pydantic import BaseModel, ConfigDict, Field

from sentinel.detection.engine import Detection

_FROZEN: Final[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

# ECS severity (0-7) -> short human label, shared by every sink's renderer.
_SEVERITY_LABELS: Final[dict[int, str]] = {
    0: "INFO",
    1: "INFO",
    2: "LOW",
    3: "LOW",
    4: "MEDIUM",
    5: "MEDIUM",
    6: "HIGH",
    7: "CRITICAL",
}


def severity_label(severity: int) -> str:
    """Map an ECS 0-7 severity to a short label (INFO/LOW/MEDIUM/HIGH/CRITICAL)."""
    return _SEVERITY_LABELS.get(severity, "INFO")


class Alert(BaseModel):
    """An immutable, deliverable alert derived from one detection."""

    model_config = _FROZEN

    dedup_key: str = Field(
        min_length=1,
        description="Identity the manager dedups on: the same rule firing on the same event.",
    )
    rule_id: str
    title: str
    severity: int = Field(ge=0, le=7)
    attack: tuple[str, ...]
    nist_csf: tuple[str, ...]
    event_id: str
    host: str
    timestamp: datetime
    summary: str

    @classmethod
    def from_detection(cls, detection: Detection) -> Alert:
        """Promote a detection to an alert, deriving its dedup key."""
        return cls(
            dedup_key=f"{detection.rule_id}|{detection.event_id}",
            rule_id=detection.rule_id,
            title=detection.title,
            severity=detection.severity,
            attack=detection.attack,
            nist_csf=detection.nist_csf,
            event_id=detection.event_id,
            host=detection.host,
            timestamp=detection.timestamp,
            summary=detection.message,
        )
