"""Tests for the AlertSink base contract (name/severity validation, routing)."""

from __future__ import annotations

import pytest

from sentinel.alerting.model import Alert
from sentinel.alerting.sinks.base import AlertSink
from tests.conftest import make_alert


class _MiniSink(AlertSink):
    """A bare concrete sink (no class-level `name`) for exercising the base."""

    async def emit(self, alert: Alert) -> None:
        self.last = alert


class TestSinkBase:
    def test_empty_name_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="name"):
            _MiniSink()  # inherits name="" → must be rejected

    def test_name_override_is_accepted(self) -> None:
        assert _MiniSink(name="mini").name == "mini"

    def test_min_severity_out_of_range_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="0-7"):
            _MiniSink(name="mini", min_severity=8)

    def test_min_severity_property(self) -> None:
        assert _MiniSink(name="mini", min_severity=5).min_severity == 5

    def test_accepts_respects_the_severity_floor(self) -> None:
        sink = _MiniSink(name="mini", min_severity=5)
        assert sink.accepts(make_alert(severity=6)) is True
        assert sink.accepts(make_alert(severity=2)) is False
