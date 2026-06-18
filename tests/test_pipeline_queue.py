"""Tests for `sentinel.pipeline.queue.BoundedEventQueue`.

Verifies the §3.1 invariants:
- Bounded — `qsize() <= maxsize` always holds.
- BLOCK policy applies backpressure (producer waits when full).
- DROP_NEWEST policy refuses without blocking, increments the counter.
- Counters (`accepted`, `dropped`) are monotonic.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest

from sentinel.events import (
    Event,
    EventCategory,
    EventKind,
    EventMeta,
    Host,
)
from sentinel.pipeline.queue import BoundedEventQueue
from sentinel.settings import BackpressurePolicy


def make_event(seed: int) -> Event:
    return Event(
        timestamp=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
        event=EventMeta(
            id=Event.compute_id("test", seed),
            kind=EventKind.EVENT,
            category=EventCategory.HOST,
            action="probe",
        ),
        host=Host(name="h"),
        message=f"msg-{seed}",
    )


class TestQueueConstruction:
    def test_rejects_maxsize_zero(self) -> None:
        with pytest.raises(ValueError, match="maxsize"):
            BoundedEventQueue(maxsize=0)

    def test_rejects_negative_maxsize(self) -> None:
        with pytest.raises(ValueError, match="maxsize"):
            BoundedEventQueue(maxsize=-1)

    def test_default_policy_is_block(self) -> None:
        q = BoundedEventQueue(maxsize=10)
        assert q.policy is BackpressurePolicy.BLOCK


class TestBlockPolicy:
    async def test_put_then_get_round_trips(self) -> None:
        q = BoundedEventQueue(maxsize=10)
        e = make_event(1)
        assert await q.put(e) is True
        got = await q.get()
        assert got.event.id == e.event.id

    async def test_put_blocks_when_full(self) -> None:
        q = BoundedEventQueue(maxsize=2, policy=BackpressurePolicy.BLOCK)
        # Fill the queue
        await q.put(make_event(1))
        await q.put(make_event(2))
        assert q.qsize() == 2

        # Third put should block — wrap with a timeout that we expect to hit.
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(q.put(make_event(3)), timeout=0.05)

        # No event was dropped — policy is BLOCK.
        assert q.dropped == 0

    async def test_put_unblocks_after_get(self) -> None:
        q = BoundedEventQueue(maxsize=1, policy=BackpressurePolicy.BLOCK)
        await q.put(make_event(1))

        # Concurrent put waits, then proceeds once we drain.
        async def producer() -> bool:
            return await q.put(make_event(2))

        producer_task = asyncio.create_task(producer())
        await asyncio.sleep(0.01)
        assert not producer_task.done()  # still waiting

        await q.get()  # frees a slot
        assert await producer_task is True


class TestDropNewestPolicy:
    async def test_drops_when_full_without_blocking(self) -> None:
        q = BoundedEventQueue(maxsize=2, policy=BackpressurePolicy.DROP_NEWEST)
        assert await q.put(make_event(1)) is True
        assert await q.put(make_event(2)) is True
        # Third put returns False instantly, not blocking.
        assert await q.put(make_event(3)) is False
        assert q.dropped == 1
        assert q.accepted == 2
        assert q.qsize() == 2

    async def test_resumes_accepting_after_drain(self) -> None:
        q = BoundedEventQueue(maxsize=1, policy=BackpressurePolicy.DROP_NEWEST)
        assert await q.put(make_event(1)) is True
        assert await q.put(make_event(2)) is False  # full -> dropped
        await q.get()  # drain
        assert await q.put(make_event(3)) is True
        assert q.dropped == 1
        assert q.accepted == 2


class TestCounters:
    async def test_accepted_and_dropped_are_monotonic(self) -> None:
        q = BoundedEventQueue(maxsize=2, policy=BackpressurePolicy.DROP_NEWEST)
        previous_accepted = 0
        previous_dropped = 0
        for i in range(10):
            await q.put(make_event(i))
            assert q.accepted >= previous_accepted
            assert q.dropped >= previous_dropped
            previous_accepted = q.accepted
            previous_dropped = q.dropped
        assert q.accepted + q.dropped == 10
