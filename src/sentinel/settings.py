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


class BackpressurePolicy(StrEnum):
    """How the bounded event queue behaves when a producer outpaces the consumer.

    `BLOCK` is the safe default: the producer awaits a free slot and slows down
    to match consumer throughput (lossless). `DROP_NEWEST` is for hard-real-time
    paths where falling behind is preferable to blocking the producer — a
    counter records how many events were dropped so the loss is observable
    rather than silent (OWASP A09 — log everything that matters).
    """

    BLOCK = "block"
    DROP_NEWEST = "drop_newest"


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
    queue_maxsize: int = Field(
        default=10_000,
        ge=1,
        le=1_000_000,
        description=(
            "Bounded asyncio.Queue capacity for the pipeline spine. "
            "Caps memory under flood (no unbounded growth)."
        ),
    )
    queue_backpressure: BackpressurePolicy = Field(
        default=BackpressurePolicy.BLOCK,
        description=(
            "Policy when the queue is full. BLOCK is lossless and applies "
            "backpressure to the producer; DROP_NEWEST is lossy but bounded."
        ),
    )
    dedup_window_seconds: float = Field(
        default=60.0,
        gt=0.0,
        le=86_400.0,
        description=(
            "TTL for the dedup window. Two events with the same content-hash "
            "inside this window are treated as the same event (the v1 "
            "race-condition kill)."
        ),
    )
    dedup_max_entries: int = Field(
        default=100_000,
        ge=1,
        le=10_000_000,
        description=(
            "Hard cap on dedup window size. Memory bound — oldest entries are "
            "evicted first when the cap is hit."
        ),
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
