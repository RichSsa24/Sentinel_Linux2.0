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
from pathlib import Path
from typing import Final

from pydantic import Field, SecretStr, field_validator, model_validator
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

# Collector names accepted by `SENTINEL_COLLECTORS` (each is a collector's `name`).
KNOWN_COLLECTORS: Final[tuple[str, ...]] = ("auth-log", "file-integrity", "process", "network")


def split_csv(value: str) -> tuple[str, ...]:
    """Split a comma-separated setting into its non-empty, stripped items."""
    return tuple(item.strip() for item in value.split(",") if item.strip())


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

    # --- Alerting ------------------------------------------------------------
    alert_min_severity: int = Field(
        default=0, ge=0, le=7, description="Drop alerts below this ECS severity."
    )
    alert_dedup_window_seconds: float = Field(
        default=300.0,
        gt=0.0,
        le=86_400.0,
        description="Collapse identical alerts (same rule+event) within this TTL.",
    )
    alert_throttle_max: int = Field(
        default=10, ge=1, le=10_000, description="Max alerts per rule per throttle window."
    )
    alert_throttle_window_seconds: float = Field(default=60.0, gt=0.0, le=86_400.0)

    # --- Webhook sink (optional; secret from env only, never a default) ------
    webhook_url: str | None = Field(
        default=None, description="HTTPS webhook endpoint. None disables the sink."
    )
    webhook_hmac_secret: SecretStr | None = Field(
        default=None, description="Shared secret for HMAC-signing webhook payloads."
    )
    webhook_allow_private: bool = Field(
        default=False,
        description="Allow webhook delivery to private/loopback targets (SSRF guard off). "
        "Keep False in production.",
    )

    # --- Email sink (optional; credentials from env only) --------------------
    smtp_host: str | None = Field(
        default=None, description="SMTP host. None disables the email sink."
    )
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str | None = None
    smtp_password: SecretStr | None = Field(
        default=None, description="SMTP password — sourced from env, never logged."
    )
    email_from: str | None = None
    email_recipients: str | None = Field(
        default=None, description="Comma-separated alert recipient addresses."
    )
    smtp_starttls: bool = True

    # --- Persistence ---------------------------------------------------------
    database_url: str = Field(
        default="sqlite+aiosqlite:///./sentinel.db",
        min_length=1,
        description="Async SQLAlchemy URL. SQLite by default; PostgreSQL via env.",
    )
    persist_batch_size: int = Field(
        default=256,
        ge=1,
        le=10_000,
        description="Events buffered before a write. 1 = one transaction per event.",
    )
    persist_flush_interval_seconds: float = Field(
        default=0.5,
        gt=0.0,
        le=60.0,
        description="Upper bound on how long a buffered event waits to be written.",
    )

    # --- Read API ------------------------------------------------------------
    api_key: SecretStr | None = Field(
        default=None,
        description="Bearer key for the read API. Unset = the API denies every "
        "request (default-deny / fail-closed).",
    )
    api_cors_origins: str = Field(
        default="",
        description="Comma-separated exact CORS origins. Empty = none (no wildcard).",
    )
    api_rate_limit: int = Field(
        default=100, ge=1, le=100_000, description="Max requests per window per client."
    )
    api_rate_window_seconds: float = Field(default=60.0, gt=0.0, le=3_600.0)
    api_max_page_size: int = Field(default=100, ge=1, le=1_000)

    # --- Collectors ----------------------------------------------------------
    collectors: str = Field(
        default=",".join(KNOWN_COLLECTORS),
        description=f"Comma-separated collectors to run; any of {', '.join(KNOWN_COLLECTORS)}.",
    )
    host_root: Path = Field(
        default=Path("/"),
        description="Where the monitored host's filesystem is visible. '/' on bare metal; "
        "'/host' in a container with the host's /etc, /var/log and /proc bind-mounted "
        "read-only beneath it (the Falco/osquery HOST_ROOT convention). Collectors read "
        "under this root but always report host-native paths.",
    )
    host_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=253,
        description="host.name for collected events. Default: the monitored host's "
        "/etc/hostname under host_root (so a container reports the host, not itself), "
        "else this machine's hostname.",
    )
    auth_log_path: Path = Field(
        default=Path("/var/log/auth.log"), description="Host path of the sshd auth log."
    )
    fim_paths: str = Field(
        default="/etc",
        description="Comma-separated absolute host paths watched for file integrity.",
    )
    rules_dir: Path = Field(
        default=Path("rules"),
        description="Directory of YAML detection rules (relative to the working directory).",
    )

    @field_validator("host_root", "auth_log_path")
    @classmethod
    def _require_absolute(cls, value: Path) -> Path:
        if not value.is_absolute():
            msg = f"must be an absolute path; got {str(value)!r}"
            raise ValueError(msg)
        return value

    @field_validator("collectors")
    @classmethod
    def _check_collectors(cls, value: str) -> str:
        names = split_csv(value)
        if not names:
            msg = "at least one collector must be enabled"
            raise ValueError(msg)
        unknown = sorted(set(names) - set(KNOWN_COLLECTORS))
        if unknown:
            msg = f"unknown collectors {unknown}; expected any of {list(KNOWN_COLLECTORS)}"
            raise ValueError(msg)
        return value

    @field_validator("fim_paths")
    @classmethod
    def _check_fim_paths(cls, value: str) -> str:
        relative = [path for path in split_csv(value) if not Path(path).is_absolute()]
        if relative:
            msg = f"fim_paths entries must be absolute host paths; got {relative}"
            raise ValueError(msg)
        return value

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

    @property
    def enabled_collectors(self) -> tuple[str, ...]:
        """The validated collector names from `collectors`."""
        return split_csv(self.collectors)

    @property
    def fim_path_list(self) -> tuple[str, ...]:
        """The validated FIM watch paths from `fim_paths`."""
        return split_csv(self.fim_paths)

    @property
    def email_recipient_list(self) -> tuple[str, ...]:
        """The alert recipients from `email_recipients`."""
        return split_csv(self.email_recipients or "")

    @property
    def cors_origin_list(self) -> tuple[str, ...]:
        """The exact CORS origins from `api_cors_origins`."""
        return split_csv(self.api_cors_origins)
