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

from sentinel import BackpressurePolicy, Environment, LogFormat, LogLevel
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


class TestPipelineSettings:
    def test_safe_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "development")
        s = settings_no_env_file()
        assert s.queue_maxsize == 10_000
        assert s.queue_backpressure is BackpressurePolicy.BLOCK
        assert s.dedup_window_seconds == 60.0
        assert s.dedup_max_entries == 100_000

    def test_overrides_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("SENTINEL_QUEUE_MAXSIZE", "256")
        monkeypatch.setenv("SENTINEL_QUEUE_BACKPRESSURE", "drop_newest")
        monkeypatch.setenv("SENTINEL_DEDUP_WINDOW_SECONDS", "30")
        monkeypatch.setenv("SENTINEL_DEDUP_MAX_ENTRIES", "5000")
        s = settings_no_env_file()
        assert s.queue_maxsize == 256
        assert s.queue_backpressure is BackpressurePolicy.DROP_NEWEST
        assert s.dedup_window_seconds == 30.0
        assert s.dedup_max_entries == 5000

    def test_rejects_zero_queue_maxsize(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "development")
        monkeypatch.setenv("SENTINEL_QUEUE_MAXSIZE", "0")
        with pytest.raises(ValidationError):
            settings_no_env_file()

    def test_rejects_negative_dedup_window(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "development")
        monkeypatch.setenv("SENTINEL_DEDUP_WINDOW_SECONDS", "-1")
        with pytest.raises(ValidationError):
            settings_no_env_file()

    def test_rejects_invalid_backpressure_policy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "development")
        monkeypatch.setenv("SENTINEL_QUEUE_BACKPRESSURE", "panic")
        with pytest.raises(ValidationError):
            settings_no_env_file()


class TestAlertingSettings:
    def test_secrets_are_absent_by_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "development")
        s = settings_no_env_file()
        assert s.webhook_url is None
        assert s.webhook_hmac_secret is None
        assert s.smtp_password is None
        assert s.webhook_allow_private is False  # SSRF guard on by default
        assert s.alert_min_severity == 0

    @pytest.mark.security
    def test_secrets_load_from_env_and_do_not_leak(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("SENTINEL_WEBHOOK_HMAC_SECRET", "hmac-shhh")  # pragma: allowlist secret
        monkeypatch.setenv("SENTINEL_SMTP_PASSWORD", "smtp-shhh")  # pragma: allowlist secret
        s = settings_no_env_file()

        assert s.webhook_hmac_secret is not None
        assert s.webhook_hmac_secret.get_secret_value() == "hmac-shhh"
        assert s.smtp_password is not None
        assert s.smtp_password.get_secret_value() == "smtp-shhh"
        # SecretStr must mask the value in any string/repr rendering.
        assert "hmac-shhh" not in repr(s)
        assert "smtp-shhh" not in str(s.smtp_password)

    def test_alerting_overrides_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("SENTINEL_ALERT_MIN_SEVERITY", "4")
        monkeypatch.setenv("SENTINEL_ALERT_THROTTLE_MAX", "3")
        s = settings_no_env_file()
        assert s.alert_min_severity == 4
        assert s.alert_throttle_max == 3
