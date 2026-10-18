"""Tests for `sentinel.logging`.

Covers the §3.3 invariants:
- Sensitive-key redaction works top-level, case-insensitive, and recursively.
- Control-character stripping defends against CWE-117 log injection.
- The configured pipeline emits valid JSON with both controls applied.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator

import pytest
import structlog

from sentinel.logging import (
    REDACTED_PLACEHOLDER,
    SENSITIVE_KEY_PATTERNS,
    configure_logging,
    get_logger,
    redact_sensitive_processor,
    strip_control_chars_processor,
)
from tests.conftest import settings_no_env_file


class TestRedactSensitiveProcessor:
    def test_redacts_top_level_password(self) -> None:
        result = redact_sensitive_processor(None, "info", {"password": "hunter2", "user": "alice"})
        assert result["password"] == REDACTED_PLACEHOLDER
        assert result["user"] == "alice"

    def test_redacts_case_insensitive(self) -> None:
        result = redact_sensitive_processor(None, "info", {"Authorization": "Bearer xyz"})
        assert result["Authorization"] == REDACTED_PLACEHOLDER

    def test_redacts_partial_match(self) -> None:
        result = redact_sensitive_processor(
            None,
            "info",
            {"db_password": "x", "api_key_id": "y", "session_id": "z"},
        )
        assert result["db_password"] == REDACTED_PLACEHOLDER
        assert result["api_key_id"] == REDACTED_PLACEHOLDER
        assert result["session_id"] == REDACTED_PLACEHOLDER

    def test_redacts_nested_in_dict(self) -> None:
        result = redact_sensitive_processor(
            None,
            "info",
            {"user": {"name": "alice", "password": "x"}},
        )
        assert result["user"]["name"] == "alice"
        assert result["user"]["password"] == REDACTED_PLACEHOLDER

    def test_redacts_nested_in_list(self) -> None:
        result = redact_sensitive_processor(
            None,
            "info",
            {"creds": [{"token": "a"}, {"token": "b"}]},
        )
        assert result["creds"][0]["token"] == REDACTED_PLACEHOLDER
        assert result["creds"][1]["token"] == REDACTED_PLACEHOLDER

    @pytest.mark.parametrize("pattern", SENSITIVE_KEY_PATTERNS)
    def test_each_pattern_redacted(self, pattern: str) -> None:
        result = redact_sensitive_processor(None, "info", {pattern: "real-secret-value"})
        assert result[pattern] == REDACTED_PLACEHOLDER
        assert "real-secret-value" not in str(result)

    def test_leaves_non_sensitive_fields_untouched(self) -> None:
        result = redact_sensitive_processor(
            None,
            "info",
            {"event": "auth.login", "user_id": "42", "ip": "10.0.0.1"},
        )
        assert result == {"event": "auth.login", "user_id": "42", "ip": "10.0.0.1"}


class TestStripControlCharsProcessor:
    def test_strips_null_byte(self) -> None:
        result = strip_control_chars_processor(None, "info", {"msg": "foo\x00bar"})
        assert result["msg"] == "foo?bar"

    def test_strips_carriage_return(self) -> None:
        # CR enables log-line forging on terminals and naive parsers.
        result = strip_control_chars_processor(None, "info", {"msg": "ok\r\nINJECTED user=evil"})
        assert "\r" not in result["msg"]

    def test_strips_terminal_escape(self) -> None:
        # ESC (\x1b) is the start of ANSI escape sequences — strip it.
        result = strip_control_chars_processor(None, "info", {"msg": "\x1b[31mRED\x1b[0m"})
        assert "\x1b" not in result["msg"]

    def test_strips_del_byte(self) -> None:
        result = strip_control_chars_processor(None, "info", {"msg": "x\x7fy"})
        assert "\x7f" not in result["msg"]

    def test_preserves_tab_and_newline(self) -> None:
        result = strip_control_chars_processor(None, "info", {"msg": "line1\nline2\t"})
        assert result["msg"] == "line1\nline2\t"

    def test_strips_recursively_in_dict(self) -> None:
        result = strip_control_chars_processor(None, "info", {"meta": {"line": "evil\x00ish"}})
        assert "\x00" not in result["meta"]["line"]

    def test_strips_recursively_in_list(self) -> None:
        result = strip_control_chars_processor(None, "info", {"items": ["a\x00", "b\x01"]})
        assert "\x00" not in result["items"][0]
        assert "\x01" not in result["items"][1]

    def test_leaves_safe_strings_untouched(self) -> None:
        result = strip_control_chars_processor(None, "info", {"msg": "hello world 123"})
        assert result["msg"] == "hello world 123"


class TestConfiguredPipeline:
    """End-to-end: configure with JSON renderer, emit a log, parse the line."""

    def test_emits_valid_json_with_both_controls_applied(
        self,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "test")
        configure_logging(settings_no_env_file())

        logger = get_logger("test")
        logger.info(
            "auth.login",
            user="alice",
            password="hunter2",  # pragma: allowlist secret -- redaction fixture
            note="ok\x00bad\r\nINJECTED",  # must be stripped
        )

        captured = capsys.readouterr().out
        json_lines = [line for line in captured.splitlines() if line.startswith("{")]
        assert json_lines, f"expected JSON output, got: {captured!r}"
        payload = json.loads(json_lines[-1])
        assert payload["event"] == "auth.login"
        assert payload["user"] == "alice"
        assert payload["password"] == REDACTED_PLACEHOLDER
        assert payload["level"] == "info"
        assert "\x00" not in payload["note"]
        assert "\r" not in payload["note"]
        assert "INJECTED" in payload["note"]  # content remains, only bytes stripped
        # Timestamp present, UTC ISO-8601.
        assert "timestamp" in payload
        assert payload["timestamp"].endswith("Z") or "+00:00" in payload["timestamp"]


@pytest.fixture
def _restore_logging() -> Iterator[None]:
    """Undo configure_logging: its root handler writes to this test's captured stdout."""
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.NOTSET)
    structlog.reset_defaults()


@pytest.mark.usefixtures("_restore_logging")
class TestLibraryLogsAndExceptions:
    """Regressions: stdlib loggers bypassed the controls; exceptions were not stripped."""

    @pytest.mark.security
    def test_library_logs_get_the_same_controls_and_format(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "test")
        configure_logging(settings_no_env_file())

        logging.getLogger("uvicorn.error").warning("bad request\x1b[2J\r\nFORGED line")

        payload = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
        assert payload["logger"] == "uvicorn.error"
        assert payload["level"] == "warning"
        assert "\x1b" not in payload["event"]
        assert "\r" not in payload["event"]

    @pytest.mark.security
    def test_outbound_request_urls_are_not_logged(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # httpx logs each request URL at INFO; a Slack-style webhook URL is the secret.
        monkeypatch.setenv("SENTINEL_ENV", "test")
        configure_logging(settings_no_env_file())

        url = "https://hooks.example.com/services/T0/B0/webhook-secret"
        logging.getLogger("httpx").info('HTTP Request: POST %s "HTTP/1.1 200 OK"', url)
        logging.getLogger("httpx").warning("connection pool exhausted")

        out = capsys.readouterr().out
        assert "webhook-secret" not in out
        assert "connection pool exhausted" in out  # warnings still surface

    @pytest.mark.security
    def test_exception_text_is_stripped_in_console_format(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "test")
        monkeypatch.setenv("SENTINEL_LOG_FORMAT", "console")
        configure_logging(settings_no_env_file())

        def fail() -> None:
            raise ValueError("boom\x1b[2J\rINJECTED 2026 [critical] forged.event")

        try:
            fail()
        except ValueError:
            get_logger("test").exception("op.failed")

        out = capsys.readouterr().out
        assert "op.failed" in out
        assert "\x1b" not in out
        assert "\r" not in out
