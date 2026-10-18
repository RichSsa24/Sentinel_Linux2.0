"""Tests for the console sink."""

from __future__ import annotations

import io
import json

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

    @pytest.mark.security
    def test_control_characters_from_the_host_cannot_reach_the_terminal(self) -> None:
        # The host name is copied from a syslog line, which rsyslog may accept
        # from the network: an ESC sequence would drive the operator's terminal.
        line = ConsoleSink.render(make_alert(host="web\x1b]0;pwned\x07\x1b[2J", message="a\x9bb"))
        assert not any(ord(char) < 0x20 or 0x7F <= ord(char) < 0xA0 for char in line)
        assert "host=web\\x1b]0;pwned\\x07\\x1b[2J" in line
        assert "a\\x9bb" in line

    async def test_json_lines_emit_one_object_per_alert(self) -> None:
        stream = io.StringIO()
        sink = ConsoleSink(stream=stream, json_lines=True)
        await sink.emit(make_alert(rule_id="reverse-shell-process", severity=7, host="web\x1b"))
        lines = stream.getvalue().splitlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["event"] == "alert"
        assert record["level"] == "critical"
        assert record["rule_id"] == "reverse-shell-process"
        assert record["host"] == "web\x1b"  # carried exactly, escaped on the wire
        assert "\x1b" not in lines[0]
