"""Tests for `sentinel.pipeline.dedup.DedupWindow`.

The dedup window is the structural kill of the v1 race condition; these
tests pin down the contract:
- Idempotent: same key inside the window -> True (duplicate).
- TTL eviction: same key outside the window -> False (fresh).
- Bounded memory: never grows beyond `max_entries`; oldest evicted first.
- Counters (`hits`, `misses`, `evictions_ttl`, `evictions_cap`) monotonic.
- Membership check (`in`) does NOT count as a hit.
- Constructor rejects invalid configuration.
"""

from __future__ import annotations

import pytest

from sentinel.pipeline.dedup import DedupWindow


class FakeClock:
    """Deterministic monotonic-ish clock for tests."""

    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


class TestConstruction:
    def test_rejects_non_positive_ttl(self) -> None:
        with pytest.raises(ValueError, match="ttl_seconds"):
            DedupWindow(ttl_seconds=0, max_entries=10)

    def test_rejects_negative_ttl(self) -> None:
        with pytest.raises(ValueError, match="ttl_seconds"):
            DedupWindow(ttl_seconds=-1, max_entries=10)

    def test_rejects_zero_max_entries(self) -> None:
        with pytest.raises(ValueError, match="max_entries"):
            DedupWindow(ttl_seconds=1, max_entries=0)


class TestIdempotency:
    def test_first_seen_returns_false(self) -> None:
        w = DedupWindow(ttl_seconds=10, max_entries=10, time_source=FakeClock())
        assert w.seen("a") is False
        assert w.hits == 0
        assert w.misses == 1

    def test_repeat_within_window_returns_true(self) -> None:
        clock = FakeClock()
        w = DedupWindow(ttl_seconds=10, max_entries=10, time_source=clock)
        w.seen("a")
        clock.advance(5)
        assert w.seen("a") is True
        assert w.hits == 1
        assert w.misses == 1

    def test_distinct_keys_never_dedup(self) -> None:
        w = DedupWindow(ttl_seconds=10, max_entries=10, time_source=FakeClock())
        assert w.seen("a") is False
        assert w.seen("b") is False
        assert w.seen("c") is False
        assert w.hits == 0
        assert w.misses == 3


class TestTtlEviction:
    def test_key_can_be_seen_again_after_ttl(self) -> None:
        clock = FakeClock()
        w = DedupWindow(ttl_seconds=10, max_entries=10, time_source=clock)
        w.seen("a")
        clock.advance(11)  # past TTL
        # Now "a" should be fresh again.
        assert w.seen("a") is False
        assert w.evictions_ttl >= 1

    def test_partial_window_keeps_live_entries(self) -> None:
        clock = FakeClock()
        w = DedupWindow(ttl_seconds=10, max_entries=10, time_source=clock)
        w.seen("a")
        clock.advance(5)
        w.seen("b")
        clock.advance(6)  # a is now 11s old -> expired; b is 6s old -> live
        # Insert a new key — should evict "a" but keep "b".
        w.seen("c")
        assert "a" not in w
        assert "b" in w
        assert "c" in w


class TestMaxEntriesCap:
    def test_oldest_evicted_first_at_cap(self) -> None:
        w = DedupWindow(ttl_seconds=1000, max_entries=3, time_source=FakeClock())
        w.seen("a")
        w.seen("b")
        w.seen("c")
        assert len(w) == 3
        w.seen("d")  # cap evict
        assert len(w) == 3
        assert "a" not in w
        assert "b" in w
        assert "c" in w
        assert "d" in w
        assert w.evictions_cap == 1

    def test_size_never_exceeds_cap_under_flood(self) -> None:
        w = DedupWindow(ttl_seconds=1000, max_entries=100, time_source=FakeClock())
        for i in range(10_000):
            w.seen(f"key-{i}")
        assert len(w) == 100


class TestMembershipDoesNotMutateCounters:
    def test_in_does_not_count_as_hit(self) -> None:
        w = DedupWindow(ttl_seconds=10, max_entries=10, time_source=FakeClock())
        w.seen("a")
        _ = "a" in w
        _ = "b" in w
        assert w.hits == 0
        assert w.misses == 1

    def test_in_returns_false_for_non_string(self) -> None:
        w = DedupWindow(ttl_seconds=10, max_entries=10, time_source=FakeClock())
        w.seen("a")
        assert 42 not in w
        assert None not in w
