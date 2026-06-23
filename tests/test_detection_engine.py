"""Tests for the detection engine: threshold state, bounds, and safety."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta

import pytest

from sentinel.detection.engine import DetectionEngine
from sentinel.detection.schema import Rule
from sentinel.events import (
    Event,
    EventCategory,
    EventKind,
    EventMeta,
    EventOutcome,
    Host,
    Process,
    Source,
)

BASE_TS = datetime(2026, 6, 22, 12, 0, 0, tzinfo=UTC)


def _event(
    action: str, *, ip: str | None = None, cmd: str | None = None, ts: datetime | None = None
) -> Event:
    category = EventCategory.AUTHENTICATION if action.startswith("ssh") else EventCategory.PROCESS
    return Event(
        timestamp=ts or BASE_TS,
        event=EventMeta(
            id="0" * 64,
            kind=EventKind.EVENT,
            category=category,
            action=action,
            outcome=EventOutcome.SUCCESS,
            severity=3,
        ),
        host=Host(name="host1"),
        source=Source(ip=ip),
        process=Process(command_line=cmd),
        message="event",
    )


def _brute_rule(**overrides: object) -> Rule:
    body = {
        "id": "ssh-brute-force",
        "title": "SSH brute force",
        "description": "d",
        "severity": 6,
        "attack": ["T1110"],
        "nist_csf": ["DE.CM"],
        "condition": {
            "threshold": {
                "match": {"field": "event.action", "op": "equals", "value": "ssh_login_failed"},
                "window_seconds": 60,
                "count": 3,
                "group_by": "source.ip",
            }
        },
    }
    body.update(overrides)
    return Rule.model_validate(body)


def _simple_rule() -> Rule:
    return Rule.model_validate(
        {
            "id": "reverse-shell-process",
            "title": "Reverse shell",
            "description": "d",
            "severity": 7,
            "attack": ["T1059.004"],
            "nist_csf": ["DE.CM"],
            "d3fend": ["D3-PSA"],
            "condition": {"field": "process.command_line", "op": "contains", "value": "nc -e"},
        }
    )


class TestSimpleRule:
    def test_fires_and_builds_detection(self) -> None:
        engine = DetectionEngine([_simple_rule()])
        detections = engine.evaluate(_event("process_started", cmd="nc -e /bin/sh"))

        assert len(detections) == 1
        det = detections[0]
        assert det.rule_id == "reverse-shell-process"
        assert det.attack == ("T1059.004",)
        assert det.nist_csf == ("DE.CM",)
        assert det.d3fend == ("D3-PSA",)
        assert det.severity == 7
        assert det.event_id == "0" * 64
        assert det.timestamp == BASE_TS

    def test_no_detection_when_silent(self) -> None:
        engine = DetectionEngine([_simple_rule()])
        assert engine.evaluate(_event("process_started", cmd="ls")) == []

    def test_disabled_rule_is_skipped(self) -> None:
        engine = DetectionEngine([_simple_rule(), _brute_rule(enabled=False)])
        assert [r.id for r in engine.rules] == ["reverse-shell-process"]


class TestThreshold:
    def _feed(self, engine: DetectionEngine, n: int, *, ip: str, start: int = 0) -> int:
        fires = 0
        for i in range(n):
            ts = BASE_TS + timedelta(seconds=start + i)
            fires += len(engine.evaluate(_event("ssh_login_failed", ip=ip, ts=ts)))
        return fires

    def test_fires_only_on_reaching_count(self) -> None:
        engine = DetectionEngine([_brute_rule()])
        assert self._feed(engine, 2, ip="1.1.1.1") == 0  # below threshold
        assert (
            len(
                engine.evaluate(
                    _event("ssh_login_failed", ip="1.1.1.1", ts=BASE_TS + timedelta(seconds=2))
                )
            )
            == 1
        )

    def test_clears_after_firing(self) -> None:
        engine = DetectionEngine([_brute_rule()])
        assert self._feed(engine, 3, ip="2.2.2.2") == 1  # fires once at the 3rd
        # window cleared: two more do not re-fire, a third does
        assert self._feed(engine, 2, ip="2.2.2.2", start=3) == 0
        assert self._feed(engine, 1, ip="2.2.2.2", start=5) == 1

    def test_groups_are_isolated(self) -> None:
        engine = DetectionEngine([_brute_rule()])
        assert self._feed(engine, 2, ip="3.3.3.3") == 0
        assert self._feed(engine, 2, ip="4.4.4.4") == 0  # different IP, own counter
        assert engine.stats["threshold_groups"] == 2

    def test_events_outside_window_do_not_accumulate(self) -> None:
        engine = DetectionEngine([_brute_rule()])
        # Two attempts, then a third more than window_seconds later → no fire.
        engine.evaluate(_event("ssh_login_failed", ip="5.5.5.5", ts=BASE_TS))
        engine.evaluate(_event("ssh_login_failed", ip="5.5.5.5", ts=BASE_TS + timedelta(seconds=1)))
        late = engine.evaluate(
            _event("ssh_login_failed", ip="5.5.5.5", ts=BASE_TS + timedelta(seconds=120))
        )
        assert late == []

    def test_missing_group_field_does_not_fire(self) -> None:
        engine = DetectionEngine([_brute_rule()])
        # No source.ip on these events → cannot bucket → never fires.
        fires = sum(
            len(engine.evaluate(_event("ssh_login_failed", ts=BASE_TS + timedelta(seconds=i))))
            for i in range(5)
        )
        assert fires == 0

    def test_threshold_groups_are_bounded(self) -> None:
        engine = DetectionEngine([_brute_rule()], max_threshold_groups=2)
        for i in range(5):
            engine.evaluate(_event("ssh_login_failed", ip=f"10.0.0.{i}", ts=BASE_TS))
        assert engine.stats["threshold_groups"] <= 2


class TestSafetyAndStats:
    def test_malformed_event_does_not_raise(self) -> None:
        # An event with none of the fields the rules look at must be handled.
        engine = DetectionEngine([_simple_rule(), _brute_rule()])
        assert engine.evaluate(_event("something_unmodelled")) == []

    def test_stats_track_evaluations_and_fires(self) -> None:
        engine = DetectionEngine([_simple_rule()])
        engine.evaluate(_event("process_started", cmd="nc -e x"))
        engine.evaluate(_event("process_started", cmd="ls"))
        stats = engine.stats
        assert stats["rules"] == 1
        assert stats["evaluations"] == 2
        assert stats["fired"] == 1

    @pytest.mark.slow
    def test_throughput_is_reasonable(self) -> None:
        # Sanity check: 5k events across a handful of rules in well under a second.
        engine = DetectionEngine([_simple_rule(), _brute_rule()])
        events = [_event("process_started", cmd=f"job-{i}") for i in range(5000)]
        start = time.perf_counter()
        for event in events:
            engine.evaluate(event)
        elapsed = time.perf_counter() - start
        assert elapsed < 2.0, f"5k events took {elapsed:.2f}s"
        assert engine.stats["evaluations"] == 5000
