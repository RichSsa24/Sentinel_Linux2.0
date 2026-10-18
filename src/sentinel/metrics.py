"""Prometheus instrumentation for the pipeline and detection path.

A :class:`Metrics` owns its own ``CollectorRegistry`` (not the process-global
default), so multiple instances — notably one per test — never collide. The API
exposes ``render()`` at ``/metrics`` in the standard text exposition format.

Two kinds of series live here:

- **Event-time instruments** (counters/histograms the consumer updates as it
  works): events ingested, detections fired, alert latency.
- **Scrape-time mirrors** of counters the domain objects already keep (queue
  depth, drops, alert gate outcomes, per-sink deliveries). Rather than
  double-booking every increment, :meth:`Metrics.observe_runtime` registers a
  custom collector that reads one :class:`RuntimeSnapshot` per scrape — the
  domain code stays free of Prometheus, and the exported values can never drift
  from the source of truth.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, Metric
from prometheus_client.registry import Collector

# Buckets for detection-to-alert latency: sub-millisecond to a few seconds.
_LATENCY_BUCKETS = (0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0)


@dataclass(frozen=True)
class RuntimeSnapshot:
    """Point-in-time counters from the running pipeline and alert manager."""

    queue_depth: int = 0
    dropped: Mapping[str, int] = field(default_factory=dict)
    alerts_delivered: Mapping[str, int] = field(default_factory=dict)
    alerts_suppressed: Mapping[str, int] = field(default_factory=dict)
    sink_errors: int = 0
    alerts_unpersisted: int = 0
    pipeline_up: bool = False
    collector_restarts: Mapping[str, int] = field(default_factory=dict)


class _RuntimeCollector(Collector):
    """Exports a :class:`RuntimeSnapshot` as Prometheus families at scrape time."""

    def __init__(self, source: Callable[[], RuntimeSnapshot]) -> None:
        self._source = source

    def collect(self) -> Iterable[Metric]:
        snap = self._source()
        yield GaugeMetricFamily(
            "sentinel_pipeline_up",
            "1 while the detection pipeline runs; 0 means nothing is being analyzed.",
            value=int(snap.pipeline_up),
        )
        yield _labelled_counter(
            "sentinel_collector_restarts",
            "Collectors that crashed and were restarted, by collector.",
            "collector",
            snap.collector_restarts,
        )
        yield GaugeMetricFamily(
            "sentinel_queue_depth",
            "Current depth of the bounded pipeline queue.",
            value=snap.queue_depth,
        )
        yield _labelled_counter(
            "sentinel_events_dropped",
            "Events dropped before detection or never persisted, by reason.",
            "reason",
            snap.dropped,
        )
        yield _labelled_counter(
            "sentinel_alerts_emitted",
            "Alerts successfully delivered, by sink.",
            "sink",
            snap.alerts_delivered,
        )
        yield _labelled_counter(
            "sentinel_alerts_suppressed",
            "Detections that did not become alerts, by gate.",
            "reason",
            snap.alerts_suppressed,
        )
        errors = CounterMetricFamily(
            "sentinel_alert_sink_errors", "Alert deliveries that raised in a sink."
        )
        errors.add_metric([], snap.sink_errors)
        yield errors
        unpersisted = CounterMetricFamily(
            "sentinel_alerts_unpersisted",
            "Delivered alerts that could not be written to the database.",
        )
        unpersisted.add_metric([], snap.alerts_unpersisted)
        yield unpersisted


def _labelled_counter(
    name: str, documentation: str, label: str, values: Mapping[str, int]
) -> CounterMetricFamily:
    family = CounterMetricFamily(name, documentation, labels=[label])
    for key in sorted(values):
        family.add_metric([key], values[key])
    return family


class Metrics:
    """The framework's Prometheus metrics, scoped to one registry."""

    def __init__(self, registry: CollectorRegistry | None = None) -> None:
        self.registry = registry if registry is not None else CollectorRegistry()
        self.events_ingested = Counter(
            "sentinel_events_ingested_total",
            "Events ingested by the pipeline.",
            registry=self.registry,
        )
        self.detections_fired = Counter(
            "sentinel_detections_fired_total",
            "Detections fired, labelled by rule and severity.",
            ["rule_id", "severity"],
            registry=self.registry,
        )
        self.alert_latency = Histogram(
            "sentinel_alert_latency_seconds",
            "Latency from detection to alert delivery.",
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self._runtime_collector: _RuntimeCollector | None = None

    def observe_runtime(self, source: Callable[[], RuntimeSnapshot]) -> None:
        """Export `source()` on every scrape. Re-binding replaces the previous source."""
        if self._runtime_collector is not None:
            self.registry.unregister(self._runtime_collector)
        self._runtime_collector = _RuntimeCollector(source)
        self.registry.register(self._runtime_collector)

    def render(self) -> bytes:
        """Serialize the registry in Prometheus text exposition format."""
        return generate_latest(self.registry)

    @property
    def content_type(self) -> str:
        """The Content-Type for the exposition format."""
        return CONTENT_TYPE_LATEST
