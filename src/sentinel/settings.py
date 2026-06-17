"""Typed application settings.

Loaded from environment variables prefixed `SENTINEL_`, with strict validation
that fails closed on missing or invalid required values (NIST SP 800-207 — no
implicit trust in configuration; OWASP ASVS V14 — secure default config).

Sensitive values (DB URLs, API keys, SMTP credentials) MUST NOT have hard-coded
defaults. They are introduced in later phases and remain required-or-absent.
"""

from __future__ import annotations

import os
from enum import StrEnum
from typing import Final

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(StrEnum):
    """Deployment environment."""

    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class LogLevel(StrEnum):
    """Standard Python logging levels."""

    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class LogFormat(StrEnum):
    """Renderer for the structured log pipeline."""

    JSON = "json"
    CONSOLE = "console"


ENV_PREFIX: Final[str] = "SENTINEL_"


class Settings(BaseSettings):
    """Application settings.

    Configuration is loaded from environment variables (and optionally a
    git-ignored `.env` file in development). Unknown prefixed variables are
    rejected (`extra="forbid"`) so a typo cannot silently fall through.
    """

    model_config = SettingsConfigDict(
        env_prefix=ENV_PREFIX,
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="forbid",
        frozen=True,
    )

    env: Environment = Field(
        description="Deployment environment. Required; no default.",
    )
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Minimum log severity to emit.",
    )
    log_format: LogFormat = Field(
        default=LogFormat.JSON,
        description="Renderer for the structlog pipeline. Use json in production.",
    )

    @model_validator(mode="after")
    def _reject_unknown_prefixed_env(self) -> Settings:
        """Refuse to start when unknown `SENTINEL_*` env vars are set.

        pydantic-settings filters env vars by prefix at the source layer, so
        an unknown `SENTINEL_LOG_LEVL` (typo) is silently dropped and the
        default for `log_level` wins. That violates §3.3 ("reject, don't
        coerce, malformed input"). This validator catches every typo at
        construction time so a misnamed variable never silently disables a
        security control in production.
        """
        valid_keys = {f"{ENV_PREFIX}{name.upper()}" for name in type(self).model_fields}
        unknown = sorted(
            key
            for key in os.environ
            if key.upper().startswith(ENV_PREFIX) and key.upper() not in valid_keys
        )
        if unknown:
            msg = (
                f"Unknown {ENV_PREFIX}* environment variables: {unknown}. "
                "Remove them or add them to `Settings`. Refusing to start."
            )
            raise ValueError(msg)
        return self

    @property
    def is_production(self) -> bool:
        """True when running in the production environment."""
        return self.env is Environment.PRODUCTION
