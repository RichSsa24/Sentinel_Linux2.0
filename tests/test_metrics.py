"""Tests for the Prometheus metrics layer."""

from __future__ import annotations

from prometheus_client.parser import text_string_to_metric_families

from sentinel.metrics import Metrics


class TestMetrics:
    def test_counter_increments_render(self) -> None:
        metrics = Metrics()
        metrics.events_ingested.inc()
        metrics.events_ingested.inc()
        body = metrics.render().decode()
        assert "sentinel_events_ingested_total 2.0" in body

    def test_labelled_counter(self) -> None:
        metrics = Metrics()
        metrics.detections_fired.labels(rule_id="reverse-shell", severity="5").inc()
        body = metrics.render().decode()
        assert 'sentinel_detections_fired_total{rule_id="reverse-shell",severity="5"} 1.0' in body

    def test_histogram_observes(self) -> None:
        metrics = Metrics()
        metrics.alert_latency.observe(0.02)
        body = metrics.render().decode()
        assert "sentinel_alert_latency_seconds_count 1.0" in body

    def test_render_is_valid_exposition_format(self) -> None:
        metrics = Metrics()
        metrics.events_ingested.inc()
        # The official parser must accept the output (scrape-valid).
        families = list(text_string_to_metric_families(metrics.render().decode()))
        names = {family.name for family in families}
        assert "sentinel_events_ingested" in names

    def test_registries_are_isolated(self) -> None:
        first, second = Metrics(), Metrics()
        first.events_ingested.inc()
        # The second instance has its own registry — unaffected by the first.
        assert "sentinel_events_ingested_total 0.0" in second.render().decode()

    def test_content_type_is_prometheus(self) -> None:
        assert "text/plain" in Metrics().content_type
