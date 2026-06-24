"""Prometheus instrumentation for the pipeline and detection path.

A :class:`Metrics` owns its own ``CollectorRegistry`` (not the process-global
default), so multiple instances — notably one per test — never collide. The API
exposes ``render()`` at ``/metrics`` in the standard text exposition format.
"""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

# Buckets for detection-to-alert latency: sub-millisecond to a few seconds.
_LATENCY_BUCKETS = (0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0)


class Metrics:
    """The framework's Prometheus metrics, scoped to one registry."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()
        self.events_ingested = Counter(
            "sentinel_events_ingested_total",
            "Events ingested by the pipeline.",
            registry=self.registry,
        )
        self.events_dropped = Counter(
            "sentinel_events_dropped_total",
            "Events dropped or dead-lettered.",
            ["reason"],
            registry=self.registry,
        )
        self.detections_fired = Counter(
            "sentinel_detections_fired_total",
            "Detections fired, labelled by rule and severity.",
            ["rule_id", "severity"],
            registry=self.registry,
        )
        self.alerts_emitted = Counter(
            "sentinel_alerts_emitted_total",
            "Alerts delivered, labelled by sink.",
            ["sink"],
            registry=self.registry,
        )
        self.queue_depth = Gauge(
            "sentinel_queue_depth",
            "Current depth of the bounded pipeline queue.",
            registry=self.registry,
        )
        self.alert_latency = Histogram(
            "sentinel_alert_latency_seconds",
            "Latency from detection to alert delivery.",
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )

    def render(self) -> bytes:
        """Serialize the registry in Prometheus text exposition format."""
        return generate_latest(self.registry)

    @property
    def content_type(self) -> str:
        """The Content-Type for the exposition format."""
        return CONTENT_TYPE_LATEST
