"""Idempotent dedup window — the structural kill of the v1 race condition.

A TTL- and size-bounded set of `event.id` hashes. The pipeline's single
consumer task calls `seen()` on each event it pops from the queue;
duplicates inside the window are dropped silently and counted.

This is the load-bearing claim:

> Even if a misbehaving collector emits the same event twice — because of
> a producer race, a log-file rotation re-read, or a retry of a
> partially-acked batch — the consumer sees it exactly once.

Properties:

- **Bounded memory.** `max_entries` is a hard cap. The oldest entry is
  evicted first when the cap is reached.
- **Bounded staleness.** Every entry expires `ttl_seconds` after insert,
  so the dedup window slides with time. Two events with the same content
  separated by more than the TTL are NOT treated as duplicates — that
  matches the security intent (a repeat login failure five minutes apart
  is a real second event, not a duplicate).
- **Single owner.** The runtime calls `seen()` from exactly one consumer
  task. No locks needed.
- **Deterministic in tests.** The clock is injectable via `time_source`.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Final

DEFAULT_TIME_SOURCE: Final[Callable[[], float]] = time.monotonic


class DedupWindow:
    """TTL- and size-bounded set of seen `event.id` hashes."""

    def __init__(
        self,
        ttl_seconds: float,
        max_entries: int,
        *,
        time_source: Callable[[], float] = DEFAULT_TIME_SOURCE,
    ) -> None:
        if ttl_seconds <= 0:
            msg = f"ttl_seconds must be > 0; got {ttl_seconds}"
            raise ValueError(msg)
        if max_entries < 1:
            msg = f"max_entries must be >= 1; got {max_entries}"
            raise ValueError(msg)
        self._ttl = ttl_seconds
        self._max_entries = max_entries
        self._now = time_source
        # `dict` preserves insertion order, and we always insert with a
        # monotonically-increasing expiry — so the oldest entry is the
        # first one yielded by `iter()`. That makes both expiry-eviction
        # and cap-eviction O(k) where k is the number of stale entries.
        self._entries: dict[str, float] = {}
        self._hits = 0
        self._misses = 0
        self._evictions_ttl = 0
        self._evictions_cap = 0

    @property
    def hits(self) -> int:
        """Total duplicates caught (events the consumer would have re-processed)."""
        return self._hits

    @property
    def misses(self) -> int:
        """Total fresh events admitted."""
        return self._misses

    @property
    def evictions_ttl(self) -> int:
        """Total entries removed because their TTL expired."""
        return self._evictions_ttl

    @property
    def evictions_cap(self) -> int:
        """Total entries removed because the size cap was hit."""
        return self._evictions_cap

    def __len__(self) -> int:
        """Current live-entry count (after lazy TTL eviction)."""
        return len(self._entries)

    def seen(self, key: str) -> bool:
        """Atomic check-and-record.

        Returns True if `key` is a duplicate (already in the window),
        False if it is fresh (newly inserted).
        """
        now = self._now()
        self._evict_expired(now)
        if key in self._entries:
            self._hits += 1
            return True
        # Hard cap: never let the window grow beyond max_entries.
        if len(self._entries) >= self._max_entries:
            self._evict_to_cap()
        self._entries[key] = now + self._ttl
        self._misses += 1
        return False

    def __contains__(self, key: object) -> bool:
        """Non-mutating membership check (does NOT count as a hit)."""
        if not isinstance(key, str):
            return False
        self._evict_expired(self._now())
        return key in self._entries

    def _evict_expired(self, now: float) -> None:
        """Drop entries whose TTL has passed. O(k) in number of stale entries."""
        # Snapshot the iterator keys we want to drop — mutating the dict
        # while iterating is undefined behaviour.
        to_drop: list[str] = []
        for key, expiry in self._entries.items():
            if expiry > now:
                # `dict` is insertion-ordered and expiries are monotonic,
                # so once we see a live entry, every later entry is also
                # live. Stop walking.
                break
            to_drop.append(key)
        for key in to_drop:
            del self._entries[key]
        self._evictions_ttl += len(to_drop)

    def _evict_to_cap(self) -> None:
        """Drop the oldest entry to make room for one new one."""
        oldest_key = next(iter(self._entries))
        del self._entries[oldest_key]
        self._evictions_cap += 1
