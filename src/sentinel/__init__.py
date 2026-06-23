"""Sentinel-Linux 2.0 — host-based security monitoring framework."""

from __future__ import annotations

from sentinel.alerting import (
    Alert,
    AlertManager,
    AlertSink,
    ConsoleSink,
    EmailSink,
    WebhookSink,
)
from sentinel.collectors.authlog import AuthLogCollector, parse_auth_line
from sentinel.collectors.base import AbstractCollector
from sentinel.collectors.integrity import FileIntegrityCollector
from sentinel.collectors.netparse import parse_net_line
from sentinel.collectors.network import NetworkCollector
from sentinel.collectors.process import ProcessCollector, parse_stat
from sentinel.detection import (
    Detection,
    DetectionEngine,
    Rule,
    RuleLoadError,
    load_rules,
)
from sentinel.events import (
    Destination,
    Event,
    EventCategory,
    EventKind,
    EventMeta,
    EventOutcome,
    File,
    FileHash,
    Host,
    Process,
    Source,
)
from sentinel.normalizer import Normalizer, RawEvent, RawSource
from sentinel.pipeline import BoundedEventQueue, DedupWindow, EventConsumer, Pipeline
from sentinel.settings import (
    BackpressurePolicy,
    Environment,
    LogFormat,
    LogLevel,
    Settings,
)

__version__ = "0.1.0.dev0"
__all__ = [
    "AbstractCollector",
    "Alert",
    "AlertManager",
    "AlertSink",
    "AuthLogCollector",
    "BackpressurePolicy",
    "BoundedEventQueue",
    "ConsoleSink",
    "DedupWindow",
    "Destination",
    "Detection",
    "DetectionEngine",
    "EmailSink",
    "Environment",
    "Event",
    "EventCategory",
    "EventConsumer",
    "EventKind",
    "EventMeta",
    "EventOutcome",
    "File",
    "FileHash",
    "FileIntegrityCollector",
    "Host",
    "LogFormat",
    "LogLevel",
    "NetworkCollector",
    "Normalizer",
    "Pipeline",
    "Process",
    "ProcessCollector",
    "RawEvent",
    "RawSource",
    "Rule",
    "RuleLoadError",
    "Settings",
    "Source",
    "WebhookSink",
    "__version__",
    "load_rules",
    "parse_auth_line",
    "parse_net_line",
    "parse_stat",
]
