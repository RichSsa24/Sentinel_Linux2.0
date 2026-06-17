"""Tests for `sentinel.settings`.

Covers the §3.3 invariants:
- Required values fail closed when missing.
- Unknown prefixed variables are rejected (no silent typo fall-through).
- Defaults are safe and explicit.
- Settings are immutable after construction.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from sentinel import Environment, LogFormat, LogLevel
from tests.conftest import settings_no_env_file


class TestSettingsValidation:
    def test_rejects_missing_required_env(self) -> None:
        # The autouse `_isolate_sentinel_env` fixture has already cleared
        # SENTINEL_*. Without SENTINEL_ENV the settings must fail closed.
        with pytest.raises(ValidationError) as exc_info:
            settings_no_env_file()
        assert any(
            err["loc"] == ("env",) and err["type"] == "missing" for err in exc_info.value.errors()
        ), f"expected missing-field error on `env`, got: {exc_info.value.errors()}"

    def test_rejects_invalid_environment_value(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "staging")  # not in the Environment enum
        with pytest.raises(ValidationError):
            settings_no_env_file()

    def test_rejects_unknown_prefixed_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "development")
        monkeypatch.setenv("SENTINEL_NOT_A_REAL_FIELD", "x")
        with pytest.raises(ValidationError) as exc_info:
            settings_no_env_file()
        # Our model_validator raises ValueError, which pydantic wraps into
        # a ValidationError whose error type is `value_error`.
        assert any(
            "SENTINEL_NOT_A_REAL_FIELD" in str(err.get("msg", ""))
            for err in exc_info.value.errors()
        )


class TestSettingsDefaults:
    def test_loads_with_required_env_and_safe_defaults(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "development")
        settings = settings_no_env_file()
        assert settings.env is Environment.DEVELOPMENT
        assert settings.log_level is LogLevel.INFO
        assert settings.log_format is LogFormat.JSON
        assert settings.is_production is False

    def test_is_production_when_env_is_production(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "production")
        assert settings_no_env_file().is_production is True

    def test_log_level_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "development")
        monkeypatch.setenv("SENTINEL_LOG_LEVEL", "DEBUG")
        assert settings_no_env_file().log_level is LogLevel.DEBUG

    def test_log_format_override(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "development")
        monkeypatch.setenv("SENTINEL_LOG_FORMAT", "console")
        assert settings_no_env_file().log_format is LogFormat.CONSOLE


class TestSettingsImmutability:
    def test_settings_is_frozen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "development")
        settings = settings_no_env_file()
        with pytest.raises(ValidationError):
            settings.env = Environment.PRODUCTION
