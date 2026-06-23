"""Shared pytest fixtures and test helpers."""

from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import UTC, datetime

import pytest

from sentinel import Settings
from sentinel.alerting.model import Alert
from sentinel.detection.engine import Detection
from sentinel.events import Event
from sentinel.normalizer import Normalizer, RawEvent

_FIXED_TS = datetime(2026, 6, 22, 12, 0, 0, tzinfo=UTC)


def make_detection(
    *,
    rule_id: str = "reverse-shell-process",
    severity: int = 5,
    attack: tuple[str, ...] = ("T1059.004",),
    nist_csf: tuple[str, ...] = ("DE.CM",),
    event_id: str = "0" * 64,
    host: str = "host1",
    message: str = "reverse shell detected",
) -> Detection:
    """Build a Detection for alerting tests."""
    return Detection(
        rule_id=rule_id,
        title="Test rule",
        severity=severity,
        attack=attack,
        nist_csf=nist_csf,
        d3fend=(),
        event_id=event_id,
        host=host,
        timestamp=_FIXED_TS,
        message=message,
    )


def make_alert(**overrides: object) -> Alert:
    """Build an Alert from a (possibly customized) Detection."""
    return Alert.from_detection(make_detection(**overrides))  # type: ignore[arg-type]


class DeadLetterNormalizer(Normalizer):
    """A normalizer that dead-letters every record.

    Injected into a collector to exercise its fail-closed skip path: an
    unmappable record must be dropped (not enqueued, not crashing the producer).
    """

    def normalize(self, raw: RawEvent) -> Event | None:
        return None


@pytest.fixture(autouse=True)
def _isolate_sentinel_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Clear all `SENTINEL_*` env vars before each test.

    Settings are env-driven, so test determinism requires that the OS
    environment cannot leak state between tests or from the developer's shell.
    """
    for key in list(os.environ):
        if key.startswith("SENTINEL_"):
            monkeypatch.delenv(key, raising=False)
    yield


def settings_no_env_file() -> Settings:
    """Construct `Settings` while ignoring any local `.env` file.

    `_env_file` is an undocumented underscore kwarg in pydantic-settings v2 —
    real but not in the public stubs, hence the single targeted ignore.
    """
    return Settings(_env_file=None)  # type: ignore[call-arg]
