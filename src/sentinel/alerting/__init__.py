"""Alerting layer — detections become deduplicated, throttled, multi-sink alerts."""

from __future__ import annotations

from sentinel.alerting.manager import AlertManager
from sentinel.alerting.model import Alert, severity_label
from sentinel.alerting.sinks import (
    AlertSink,
    ConsoleSink,
    DestinationBlockedError,
    EmailSink,
    WebhookError,
    WebhookSink,
    resolve_destination,
    validate_destination,
)

__all__ = [
    "Alert",
    "AlertManager",
    "AlertSink",
    "ConsoleSink",
    "DestinationBlockedError",
    "EmailSink",
    "WebhookError",
    "WebhookSink",
    "resolve_destination",
    "severity_label",
    "validate_destination",
]
