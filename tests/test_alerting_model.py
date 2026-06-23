"""Tests for the Alert model and severity labelling."""

from __future__ import annotations

import pytest

from sentinel.alerting.model import Alert, severity_label
from tests.conftest import make_detection


class TestFromDetection:
    def test_carries_detection_fields(self) -> None:
        detection = make_detection(severity=7, host="web-01", message="boom")
        alert = Alert.from_detection(detection)

        assert alert.rule_id == detection.rule_id
        assert alert.severity == 7
        assert alert.attack == detection.attack
        assert alert.nist_csf == detection.nist_csf
        assert alert.event_id == detection.event_id
        assert alert.host == "web-01"
        assert alert.timestamp == detection.timestamp
        assert alert.summary == "boom"

    def test_dedup_key_is_rule_and_event(self) -> None:
        alert = Alert.from_detection(make_detection(rule_id="r1", event_id="a" * 64))
        assert alert.dedup_key == f"r1|{'a' * 64}"

    def test_same_rule_and_event_share_dedup_key(self) -> None:
        a = Alert.from_detection(make_detection(rule_id="r1", event_id="a" * 64))
        b = Alert.from_detection(make_detection(rule_id="r1", event_id="a" * 64))
        assert a.dedup_key == b.dedup_key

    def test_different_event_yields_different_dedup_key(self) -> None:
        a = Alert.from_detection(make_detection(rule_id="r1", event_id="a" * 64))
        b = Alert.from_detection(make_detection(rule_id="r1", event_id="b" * 64))
        assert a.dedup_key != b.dedup_key


class TestSeverityLabel:
    @pytest.mark.parametrize(
        ("severity", "label"),
        [
            (0, "INFO"),
            (1, "INFO"),
            (2, "LOW"),
            (3, "LOW"),
            (4, "MEDIUM"),
            (5, "MEDIUM"),
            (6, "HIGH"),
            (7, "CRITICAL"),
        ],
    )
    def test_known_severities(self, severity: int, label: str) -> None:
        assert severity_label(severity) == label
