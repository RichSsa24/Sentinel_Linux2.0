"""Tests for `sentinel.settings`.

Covers the §3.3 invariants:
- Required values fail closed when missing.
- Unknown prefixed variables are rejected (no silent typo fall-through).
- Defaults are safe and explicit.
- Settings are immutable after construction.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel import BackpressurePolicy, Environment, LogFormat, LogLevel
from sentinel.settings import API_KEY_PLACEHOLDER, Settings
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

    @pytest.mark.security
    def test_validation_errors_never_echo_secret_values(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        # Regression: pydantic printed the offending input, so a misspelled
        # variable next to a secret, or any model-level error (which shows the
        # whole input), wrote the secret to the startup log.
        monkeypatch.chdir(tmp_path)
        (tmp_path / ".env").write_text(
            "SENTINEL_ENV=production\n"
            "SENTINEL_SMTP_PASSWRD=typo-smtp-secret-value\n",  # pragma: allowlist secret
            encoding="utf-8",
        )
        with pytest.raises(ValidationError) as from_file:
            Settings()
        assert "typo-smtp-secret-value" not in str(from_file.value)

        monkeypatch.setenv("SENTINEL_API_KEY", "a-real-looking-api-key-0123456789-abcdef")
        monkeypatch.setenv("SENTINEL_LOG_LEVL", "DEBUG")  # typo -> model-level error
        with pytest.raises(ValidationError) as from_env:
            settings_no_env_file()
        assert "0123456789-abcdef" not in str(from_env.value)

    @pytest.mark.security
    @pytest.mark.parametrize(
        "key",
        ["short-key", API_KEY_PLACEHOLDER],
        ids=["shorter-than-32", "env-example-placeholder"],
    )
    def test_rejects_weak_api_keys(self, monkeypatch: pytest.MonkeyPatch, key: str) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("SENTINEL_API_KEY", key)
        with pytest.raises(ValidationError):
            settings_no_env_file()

    @pytest.mark.security
    def test_rejects_a_short_webhook_hmac_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("SENTINEL_WEBHOOK_HMAC_SECRET", "x")  # pragma: allowlist secret
        with pytest.raises(ValidationError):
            settings_no_env_file()

    @pytest.mark.security
    @pytest.mark.parametrize(
        ("url", "reason"),
        [
            ("postgresql://u:dbsecret@db/x", "postgresql://"),  # pragma: allowlist secret
            ("sqlite:///./sentinel.db", "sqlite://"),
            ("not a url ://dbsecret", "not a valid SQLAlchemy URL"),
        ],
    )
    def test_requires_an_async_database_driver(
        self, monkeypatch: pytest.MonkeyPatch, url: str, reason: str
    ) -> None:
        # Regression: a sync URL passed validation and the service died at
        # start-up with a driver traceback (ModuleNotFoundError: psycopg2).
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("SENTINEL_DATABASE_URL", url)
        with pytest.raises(ValidationError) as excinfo:
            settings_no_env_file()
        message = str(excinfo.value)
        assert reason in message
        assert "dbsecret" not in message  # the URL may carry the password

    @pytest.mark.parametrize(
        "url", ["sqlite+aiosqlite:///./sentinel.db", "postgresql+asyncpg://u@db/sentinel"]
    )
    def test_accepts_the_async_drivers(self, monkeypatch: pytest.MonkeyPatch, url: str) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("SENTINEL_DATABASE_URL", url)
        assert settings_no_env_file().database_url.get_secret_value() == url

    @pytest.mark.security
    def test_rejects_a_wildcard_cors_origin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("SENTINEL_API_CORS_ORIGINS", "https://a.test, *")
        with pytest.raises(ValidationError):
            settings_no_env_file()


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
            # Deliberate write to a frozen field: proves the runtime guard.
            settings.env = Environment.PRODUCTION  # type: ignore[misc]


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
        hmac_secret = "hmac-shhh-0123456789abcdef0123456789"  # pragma: allowlist secret
        monkeypatch.setenv("SENTINEL_WEBHOOK_HMAC_SECRET", hmac_secret)
        monkeypatch.setenv("SENTINEL_SMTP_PASSWORD", "smtp-shhh")  # pragma: allowlist secret
        s = settings_no_env_file()

        assert s.webhook_hmac_secret is not None
        assert s.webhook_hmac_secret.get_secret_value() == "hmac-shhh-0123456789abcdef0123456789"
        assert s.smtp_password is not None
        assert s.smtp_password.get_secret_value() == "smtp-shhh"
        # SecretStr must mask the value in any string/repr rendering.
        assert "hmac-shhh-0123456789abcdef0123456789" not in repr(s)
        assert "smtp-shhh" not in str(s.smtp_password)

    @pytest.mark.security
    def test_urls_that_can_carry_credentials_are_masked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A Slack/Teams webhook URL is the credential; a PostgreSQL URL embeds one.
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("SENTINEL_WEBHOOK_URL", "https://hooks.example.com/T0/B0/hooksecret")
        monkeypatch.setenv(
            "SENTINEL_DATABASE_URL",
            "postgresql+asyncpg://sentinel:dbsecret@db/sentinel",  # pragma: allowlist secret
        )
        s = settings_no_env_file()

        assert "hooksecret" not in repr(s)
        assert "dbsecret" not in repr(s)
        assert s.database_url.get_secret_value().endswith("@db/sentinel")

    def test_alerting_overrides_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "production")
        monkeypatch.setenv("SENTINEL_ALERT_MIN_SEVERITY", "4")
        monkeypatch.setenv("SENTINEL_ALERT_THROTTLE_MAX", "3")
        s = settings_no_env_file()
        assert s.alert_min_severity == 4
        assert s.alert_throttle_max == 3


class TestCollectorSettings:
    def test_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "test")
        s = settings_no_env_file()
        assert s.enabled_collectors == ("auth-log", "file-integrity", "process", "network")
        assert str(s.host_root) == "/"
        assert s.fim_path_list == ("/etc", "/var/spool/cron")  # user crontabs too

    def test_csv_lists_are_trimmed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "test")
        monkeypatch.setenv("SENTINEL_FIM_PATHS", " /etc , /usr/local/bin ,")
        monkeypatch.setenv("SENTINEL_EMAIL_RECIPIENTS", "a@x.test, b@x.test")
        monkeypatch.setenv("SENTINEL_API_CORS_ORIGINS", "https://a.test,")
        s = settings_no_env_file()
        assert s.fim_path_list == ("/etc", "/usr/local/bin")
        assert s.email_recipient_list == ("a@x.test", "b@x.test")
        assert s.cors_origin_list == ("https://a.test",)

    @pytest.mark.parametrize(
        ("key", "value", "match"),
        [
            ("SENTINEL_COLLECTORS", "auth-log,keylogger", "unknown collectors"),
            ("SENTINEL_COLLECTORS", " , ", "at least one collector"),
            ("SENTINEL_FIM_PATHS", "/etc,relative/dir", "absolute"),
            ("SENTINEL_HOST_ROOT", "host", "absolute"),
            ("SENTINEL_AUTH_LOG_PATH", "auth.log", "absolute"),
            ("SENTINEL_PERSIST_MAX_BUFFERED", "10", "persist_max_buffered"),
        ],
    )
    def test_invalid_values_fail_closed(
        self, monkeypatch: pytest.MonkeyPatch, key: str, value: str, match: str
    ) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "test")
        monkeypatch.setenv(key, value)
        with pytest.raises(ValidationError, match=match):
            settings_no_env_file()
