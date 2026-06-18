"""Tests for `sentinel.events`.

Covers the §3.3 invariants for the event schema:
- Required fields fail closed when missing.
- Naive or non-UTC timestamps are rejected.
- `event.id` must be a 64-char lowercase SHA-256 hex digest.
- Models are frozen after construction.
- `compute_id` is deterministic and content-derived.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

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


def _good_event_meta(event_id: str | None = None) -> EventMeta:
    return EventMeta(
        id=event_id or Event.compute_id("test", 1),
        kind=EventKind.EVENT,
        category=EventCategory.AUTHENTICATION,
        action="user_login_failed",
        outcome=EventOutcome.FAILURE,
        severity=3,
    )


def _good_event(event_id: str | None = None) -> Event:
    return Event(
        timestamp=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
        event=_good_event_meta(event_id),
        host=Host(name="sentinel-host-01"),
        source=Source(ip="10.0.0.5", port=22, user="alice"),
        process=Process(pid=4242, name="sshd"),
        message="failed password for alice from 10.0.0.5",
    )


class TestEventIdFormat:
    def test_accepts_valid_sha256_digest(self) -> None:
        digest = hashlib.sha256(b"hello").hexdigest()
        meta = _good_event_meta(event_id=digest)
        assert meta.id == digest

    @pytest.mark.parametrize(
        "bad_id",
        [
            "",
            "tooshort",
            "G" * 64,  # not hex
            "A" * 64,  # uppercase hex — rejected (we require lowercase)
            "a" * 63,  # one char short
            "a" * 65,  # one char long
        ],
    )
    def test_rejects_malformed_id(self, bad_id: str) -> None:
        with pytest.raises(ValidationError) as exc_info:
            EventMeta(
                id=bad_id,
                kind=EventKind.EVENT,
                category=EventCategory.AUTHENTICATION,
                action="x",
            )
        assert any("event.id" in str(e.get("msg", "")) for e in exc_info.value.errors())


class TestEventTimestampValidation:
    def test_rejects_naive_datetime(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            Event(
                timestamp=datetime(2026, 6, 16, 12, 0, 0),  # noqa: DTZ001 — exercising rejection
                event=_good_event_meta(),
                host=Host(name="h"),
                message="x",
            )
        assert any("timezone-aware" in str(e.get("msg", "")) for e in exc_info.value.errors())

    def test_rejects_non_utc_offset(self) -> None:
        tz_plus_5 = timezone(timedelta(hours=5))
        with pytest.raises(ValidationError) as exc_info:
            Event(
                timestamp=datetime(2026, 6, 16, 12, 0, 0, tzinfo=tz_plus_5),
                event=_good_event_meta(),
                host=Host(name="h"),
                message="x",
            )
        assert any("UTC" in str(e.get("msg", "")) for e in exc_info.value.errors())

    def test_accepts_utc_datetime(self) -> None:
        event = _good_event()
        assert event.timestamp.utcoffset() == timedelta(0)


class TestEventImmutability:
    def test_event_is_frozen(self) -> None:
        event = _good_event()
        with pytest.raises(ValidationError):
            event.message = "tampered"

    def test_event_meta_is_frozen(self) -> None:
        meta = _good_event_meta()
        with pytest.raises(ValidationError):
            meta.severity = 7


class TestEventExtraForbidden:
    def test_unknown_top_level_field_rejected(self) -> None:
        with pytest.raises(ValidationError) as exc_info:
            Event(
                timestamp=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
                event=_good_event_meta(),
                host=Host(name="h"),
                message="x",
                attacker_controlled="payload",  # type: ignore[call-arg]
            )
        assert any(
            "attacker_controlled" in str(e.get("loc", ())) or "extra" in e.get("type", "")
            for e in exc_info.value.errors()
        )

    def test_unknown_nested_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Host(name="h", extra_field="x")  # type: ignore[call-arg]


class TestComputeId:
    def test_compute_id_returns_lowercase_hex_sha256(self) -> None:
        digest = Event.compute_id("source", "alice", 42)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_compute_id_is_deterministic(self) -> None:
        a = Event.compute_id("source", "alice", 42)
        b = Event.compute_id("source", "alice", 42)
        assert a == b

    def test_compute_id_differs_for_different_inputs(self) -> None:
        a = Event.compute_id("source", "alice", 42)
        b = Event.compute_id("source", "bob", 42)
        assert a != b

    def test_compute_id_separator_prevents_collision(self) -> None:
        # Without a delimiter, ("ab", "c") and ("a", "bc") would collide.
        # The 0x1f unit separator keeps them distinct.
        a = Event.compute_id("ab", "c")
        b = Event.compute_id("a", "bc")
        assert a != b


class TestDedupKeyMatchesEventId:
    def test_dedup_key_is_event_id(self) -> None:
        event = _good_event()
        assert event.dedup_key == event.event.id

    def test_two_events_with_same_id_share_dedup_key(self) -> None:
        same_id = Event.compute_id("auth", "alice", 12345)
        e1 = _good_event(event_id=same_id)
        # Build a second event with different non-id content but same id —
        # dedup_key MUST be the id, not the content of the event.
        e2 = Event(
            timestamp=datetime(2026, 6, 16, 13, 0, 0, tzinfo=UTC),
            event=EventMeta(
                id=same_id,
                kind=EventKind.EVENT,
                category=EventCategory.AUTHENTICATION,
                action="user_login_failed",
            ),
            host=Host(name="other-host"),
            message="different message",
        )
        assert e1.dedup_key == e2.dedup_key
