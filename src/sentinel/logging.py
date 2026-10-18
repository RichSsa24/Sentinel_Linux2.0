"""Structured logging pipeline.

Pipeline order: contextvars merge -> level tag -> UTC ISO-8601 timestamp ->
stack/exception rendering -> control-character stripping -> sensitive-key
redaction -> renderer. Exceptions are rendered to text *before* stripping, so
attacker bytes in an exception message are cleaned like any other field.

Standard-library loggers (uvicorn, httpx, SQLAlchemy, ...) are routed through
the same chain via ``structlog.stdlib.ProcessorFormatter``: their records get
the same stripping and format as Sentinel's own, instead of bypassing both.

Security rationale:
- **Control-char stripping (CWE-117 — log injection):** every string in the
  event dict has ASCII control characters replaced with `?` before the
  renderer sees them. This prevents attacker-controlled bytes from injecting
  fake log lines, terminal escape sequences, or breaking downstream JSON
  consumers.
- **Sensitive-key redaction (OWASP A09 — security logging; NIST AU):**
  values are redacted (top-level and recursive) for any key whose name
  matches a known-sensitive pattern (`password`, `token`, `secret`, ...).
  Redaction runs after control-char stripping so that no sensitive
  byte sequence ever reaches the renderer.
- **UTC ISO-8601 timestamps:** correlate logs across time zones and tools.
"""

from __future__ import annotations

import logging
import re
import sys
from collections.abc import Mapping
from typing import Any, Final, cast

import structlog
from structlog.types import EventDict, Processor, WrappedLogger

from sentinel.settings import LogFormat, Settings

# Case-insensitive substring patterns. Any event-dict key whose lowercased
# name contains one of these patterns has its value replaced with the
# placeholder. Keep the list narrow and security-focused.
SENSITIVE_KEY_PATTERNS: Final[tuple[str, ...]] = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "auth_header",
    "cookie",
    "session",
    "credential",
    "private_key",
    "hmac",
    "smtp_pass",
)
REDACTED_PLACEHOLDER: Final[str] = "***REDACTED***"

# Strip ASCII control characters EXCEPT \t (0x09) and \n (0x0a) to defend
# against log-injection. \r (0x0d) IS stripped — it can be used to forge
# new log records on naive terminal/log parsers.
_CONTROL_CHARS_RE: Final[re.Pattern[str]] = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _is_sensitive(key: object) -> bool:
    """True if `key` looks like a credential or secret-bearing field name."""
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    return any(pattern in lowered for pattern in SENSITIVE_KEY_PATTERNS)


def _redact_value(value: Any) -> Any:
    """Recursively redact sensitive keys inside mappings and sequences."""
    if isinstance(value, Mapping):
        return {
            k: (REDACTED_PLACEHOLDER if _is_sensitive(k) else _redact_value(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item) for item in value)
    return value


def _strip_value(value: Any) -> Any:
    """Recursively strip control characters from every string in the structure."""
    if isinstance(value, str):
        return _CONTROL_CHARS_RE.sub("?", value)
    if isinstance(value, Mapping):
        return {k: _strip_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_strip_value(item) for item in value)
    return value


def redact_sensitive_processor(
    _logger: WrappedLogger,
    _method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Structlog processor: redact values under sensitive keys."""
    return {
        k: (REDACTED_PLACEHOLDER if _is_sensitive(k) else _redact_value(v))
        for k, v in event_dict.items()
    }


def strip_control_chars_processor(
    _logger: WrappedLogger,
    _method_name: str,
    event_dict: EventDict,
) -> EventDict:
    """Structlog processor: replace ASCII control chars with `?` everywhere."""
    return {k: _strip_value(v) for k, v in event_dict.items()}


# Libraries that log every outbound request URL at INFO. A webhook URL can be
# the credential itself (Slack, Teams, Discord), so they log warnings only.
_URL_LOGGING_LIBRARIES: Final[tuple[str, ...]] = ("httpx", "httpcore")


def _shared_processors() -> list[Processor]:
    """Everything before rendering; applied to structlog and stdlib records alike."""
    return [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        strip_control_chars_processor,
        redact_sensitive_processor,
    ]


def _renderer(log_format: LogFormat) -> Processor:
    if log_format is LogFormat.JSON:
        return structlog.processors.JSONRenderer()
    return structlog.dev.ConsoleRenderer(colors=False)


def build_processors(log_format: LogFormat) -> list[Processor]:
    """Return the configured processor chain for the given renderer."""
    return [*_shared_processors(), _renderer(log_format)]


def configure_logging(settings: Settings) -> None:
    """Configure stdlib `logging` and structlog from `Settings`.

    Safe to call multiple times — subsequent calls reconfigure.
    """
    numeric_level = logging.getLevelNamesMapping()[settings.log_level.value]
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            foreign_pre_chain=[structlog.stdlib.add_logger_name, *_shared_processors()],
            processors=[
                structlog.stdlib.ProcessorFormatter.remove_processors_meta,
                _renderer(settings.log_format),
            ],
        )
    )
    logging.basicConfig(handlers=[handler], level=numeric_level, force=True)
    for name in _URL_LOGGING_LIBRARIES:
        logging.getLogger(name).setLevel(max(numeric_level, logging.WARNING))
    structlog.configure(
        processors=build_processors(settings.log_format),
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Return a bound structlog logger, optionally tagged with `name`."""
    # `structlog.get_logger` is typed as returning `Any` in the upstream stubs;
    # cast to the concrete bound logger so callers get IDE/mypy completion.
    return cast("structlog.stdlib.BoundLogger", structlog.get_logger(name))
