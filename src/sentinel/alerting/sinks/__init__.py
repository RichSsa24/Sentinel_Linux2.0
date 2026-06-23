"""Alert delivery channels: console, webhook (hardened), and email (TLS)."""

from __future__ import annotations

from sentinel.alerting.sinks.base import AlertSink
from sentinel.alerting.sinks.console import ConsoleSink
from sentinel.alerting.sinks.email import EmailSink, SmtpClient
from sentinel.alerting.sinks.webhook import (
    DestinationBlockedError,
    WebhookError,
    WebhookSink,
    validate_destination,
)

__all__ = [
    "AlertSink",
    "ConsoleSink",
    "DestinationBlockedError",
    "EmailSink",
    "SmtpClient",
    "WebhookError",
    "WebhookSink",
    "validate_destination",
]
