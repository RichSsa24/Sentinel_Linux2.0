"""Tests for the console sink."""

from __future__ import annotations

import io

import pytest

from sentinel.alerting.sinks.console import ConsoleSink
from tests.conftest import make_alert


class TestConsoleSink:
    @pytest.mark.asyncio
    async def test_emit_writes_one_line(self) -> None:
        stream = io.StringIO()
        sink = ConsoleSink(stream=stream)

        await sink.emit(make_alert(rule_id="reverse-shell-process", severity=7, host="web-01"))

        output = stream.getvalue()
        assert output.endswith("\n")
        assert output.count("\n") == 1
        assert "CRITICAL" in output
        assert "reverse-shell-process" in output
        assert "web-01" in output

    def test_render_includes_attack_techniques(self) -> None:
        line = ConsoleSink.render(make_alert(attack=("T1059.004", "T1071")))
        assert "T1059.004,T1071" in line

    def test_min_severity_routing(self) -> None:
        sink = ConsoleSink(min_severity=6)
        assert sink.accepts(make_alert(severity=7)) is True
        assert sink.accepts(make_alert(severity=3)) is False
