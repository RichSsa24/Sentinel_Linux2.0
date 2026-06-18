"""KEYSTONE TEST — Phase 1 race-condition kill, executable.

The single most load-bearing claim in this project is the §3.1 invariant:

> Even if a misbehaving collector emits the same event twice — because of
> a producer race, a log-file rotation re-read, or a retry of a
> partially-acked batch — the consumer sees it exactly once.

This test makes that claim falsifiable. It stands up the real pipeline
with N concurrent producer tasks, has them race to emit M events each
with substantial overlap, drains the pipeline, and asserts:

1. **Exactly-once delivery**: every distinct `event.id` produced reaches
   the consumer exactly one time — no duplicates, no losses.
2. **No crashes**: gather completes normally; no producer or consumer
   task raised.
3. **Queue is empty at shutdown**: every put() was matched by a get()
   + task_done().
4. **Bounded memory**: the dedup window never exceeds its cap.
5. **Accounting balances**: stats.processed + stats.deduped equals the
   total events accepted by the queue.

If any of those fail, the v1 race is back and the rest of the framework
is built on sand. The whole point of Phase 1 is this test passing.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime

import pytest

from sentinel.collectors.base import AbstractCollector
from sentinel.events import (
    Event,
    EventCategory,
    EventKind,
    EventMeta,
    Host,
)
from sentinel.pipeline.queue import BoundedEventQueue
from sentinel.pipeline.runner import Pipeline
from sentinel.settings import BackpressurePolicy
from tests.conftest import settings_no_env_file

NUM_PRODUCERS = 8
EVENTS_PER_PRODUCER = 1_000
# Each producer emits 500 events with private seeds (unique to it) and 500
# with seeds drawn from a shared duplicate pool. Total events emitted by
# the producers is NUM_PRODUCERS * EVENTS_PER_PRODUCER = 8_000.
# Distinct event.ids: NUM_PRODUCERS * 500 (private) + 500 (shared) = 4_500.
PRIVATE_SEEDS_PER_PRODUCER = EVENTS_PER_PRODUCER // 2
SHARED_DUPLICATE_POOL = 500
EXPECTED_UNIQUE_EVENT_IDS = (NUM_PRODUCERS * PRIVATE_SEEDS_PER_PRODUCER) + SHARED_DUPLICATE_POOL
EXPECTED_TOTAL_EMITTED = NUM_PRODUCERS * EVENTS_PER_PRODUCER


def _make_event(seed: str) -> Event:
    """Construct an event whose `event.id` depends only on `seed`.

    Two producers using the same seed will produce events with identical
    `event.id` — that is the duplicate condition the dedup window must
    eliminate.
    """
    return Event(
        timestamp=datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC),
        event=EventMeta(
            id=Event.compute_id(seed),
            kind=EventKind.EVENT,
            category=EventCategory.AUTHENTICATION,
            action="probe",
        ),
        host=Host(name="keystone-host"),
        message=f"event-{seed}",
    )


class SeedProducer(AbstractCollector):
    """Test collector that emits an event for each seed in `seeds`.

    Yields between every put so we get real interleaving on the event
    loop — without that, the BLOCK policy could complete every producer
    in turn rather than racing them.
    """

    def __init__(self, name: str, seeds: list[str]) -> None:
        super().__init__(name=name)
        self._seeds = seeds

    async def run(self, queue: BoundedEventQueue) -> None:
        for seed in self._seeds:
            if self.stopping:
                return
            await queue.put(_make_event(seed))
            # Tiny yield so other producers actually get scheduling slots.
            # Without this, the BLOCK policy would let one producer drain
            # in a tight loop before another runs, defeating the race.
            await asyncio.sleep(0)


def _seed_plan() -> list[list[str]]:
    """Build the seed assignment for each of NUM_PRODUCERS producers.

    Returns a list of `NUM_PRODUCERS` lists, each `EVENTS_PER_PRODUCER` long.
    Each producer's list contains:
    - PRIVATE_SEEDS_PER_PRODUCER unique-to-this-producer seeds
    - SHARED_DUPLICATE_POOL seeds drawn from a shared pool — every other
      producer will emit these same seeds, producing duplicates.
    """
    shared_seeds = [f"shared-{i}" for i in range(SHARED_DUPLICATE_POOL)]
    plan: list[list[str]] = []
    for p in range(NUM_PRODUCERS):
        private = [f"p{p}-private-{i}" for i in range(PRIVATE_SEEDS_PER_PRODUCER)]
        plan.append(private + shared_seeds)
    return plan


@pytest.mark.asyncio
async def test_keystone_exactly_once_under_concurrent_producers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENTINEL_ENV", "test")
    # Smaller queue + dedup window to keep the test reasonable in memory but
    # still bounded enough to exercise backpressure on the producers.
    monkeypatch.setenv("SENTINEL_QUEUE_MAXSIZE", "256")
    monkeypatch.setenv("SENTINEL_QUEUE_BACKPRESSURE", "block")
    monkeypatch.setenv("SENTINEL_DEDUP_WINDOW_SECONDS", "300")  # well over test duration
    monkeypatch.setenv("SENTINEL_DEDUP_MAX_ENTRIES", "10000")
    settings = settings_no_env_file()
    assert settings.queue_backpressure is BackpressurePolicy.BLOCK

    received_ids: list[str] = []
    consumer_calls = 0

    async def consumer(event: Event) -> None:
        nonlocal consumer_calls
        consumer_calls += 1
        received_ids.append(event.event.id)

    pipeline = Pipeline(settings)
    pipeline.set_consumer(consumer)

    plan = _seed_plan()
    producers = [SeedProducer(name=f"producer-{i}", seeds=plan[i]) for i in range(NUM_PRODUCERS)]
    for p in producers:
        pipeline.register(p)

    run_task = asyncio.create_task(pipeline.run())
    # Let producers finish their seed lists, then stop.
    # All producers complete in O(seconds); allow a generous ceiling.
    deadline = asyncio.get_event_loop().time() + 30.0
    while asyncio.get_event_loop().time() < deadline:
        stats = pipeline.stats
        # Producers finish when accepted_count == EXPECTED_TOTAL_EMITTED
        # AND the queue is drained.
        if stats["queue_accepted"] >= EXPECTED_TOTAL_EMITTED and stats["queue_size"] == 0:
            break
        await asyncio.sleep(0.01)

    await pipeline.stop()
    # run_task should now complete cleanly.
    with contextlib.suppress(asyncio.CancelledError):
        await asyncio.wait_for(run_task, timeout=5.0)

    stats = pipeline.stats

    # --- The five load-bearing assertions -------------------------------

    # (1) Exactly-once delivery.
    assert len(received_ids) == EXPECTED_UNIQUE_EVENT_IDS, (
        f"consumer should have received exactly {EXPECTED_UNIQUE_EVENT_IDS} events; "
        f"got {len(received_ids)}"
    )
    assert len(set(received_ids)) == EXPECTED_UNIQUE_EVENT_IDS, (
        "consumer received duplicate event.ids — dedup leaked"
    )

    # (2) No producer or consumer crashes.
    assert stats["consumer_errors"] == 0, (
        f"consumer raised {stats['consumer_errors']} times during the run"
    )

    # (3) Queue empty at shutdown.
    assert stats["queue_size"] == 0, "queue not fully drained at shutdown"

    # (4) Bounded memory: dedup window never exceeded its cap.
    assert stats["dedup_window_size"] <= settings.dedup_max_entries, (
        f"dedup window grew to {stats['dedup_window_size']}, cap {settings.dedup_max_entries}"
    )

    # (5) Accounting balances.
    assert stats["queue_accepted"] == EXPECTED_TOTAL_EMITTED, (
        f"queue accepted {stats['queue_accepted']}, expected {EXPECTED_TOTAL_EMITTED}"
    )
    assert stats["queue_dropped"] == 0, "BLOCK policy must not drop"
    assert stats["processed"] + stats["deduped"] == EXPECTED_TOTAL_EMITTED, (
        f"processed ({stats['processed']}) + deduped ({stats['deduped']}) != "
        f"emitted ({EXPECTED_TOTAL_EMITTED})"
    )
    assert stats["processed"] == EXPECTED_UNIQUE_EVENT_IDS
    assert stats["deduped"] == EXPECTED_TOTAL_EMITTED - EXPECTED_UNIQUE_EVENT_IDS


@pytest.mark.asyncio
async def test_register_duplicate_name_is_startup_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """One-producer-per-source is enforced at registration time."""
    monkeypatch.setenv("SENTINEL_ENV", "test")
    settings = settings_no_env_file()
    pipeline = Pipeline(settings)

    pipeline.register(SeedProducer(name="auth", seeds=["x"]))
    with pytest.raises(ValueError, match="already registered"):
        pipeline.register(SeedProducer(name="auth", seeds=["y"]))


@pytest.mark.asyncio
async def test_run_without_consumer_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_ENV", "test")
    pipeline = Pipeline(settings_no_env_file())
    pipeline.register(SeedProducer(name="x", seeds=["a"]))
    with pytest.raises(RuntimeError, match="set_consumer"):
        await pipeline.run()


@pytest.mark.asyncio
async def test_run_without_collectors_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTINEL_ENV", "test")
    pipeline = Pipeline(settings_no_env_file())

    async def noop(_event: Event) -> None:
        return None

    pipeline.set_consumer(noop)
    with pytest.raises(RuntimeError, match="collector"):
        await pipeline.run()


@pytest.mark.asyncio
async def test_consumer_exception_is_isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    """A raising consumer callback must not crash the pipeline."""
    monkeypatch.setenv("SENTINEL_ENV", "test")
    monkeypatch.setenv("SENTINEL_QUEUE_MAXSIZE", "16")
    settings = settings_no_env_file()
    pipeline = Pipeline(settings)

    seen = 0

    async def raising_consumer(_event: Event) -> None:
        nonlocal seen
        seen += 1
        raise RuntimeError("intentional")

    pipeline.set_consumer(raising_consumer)
    pipeline.register(SeedProducer(name="p", seeds=[f"k{i}" for i in range(5)]))

    task = asyncio.create_task(pipeline.run())
    # Wait until all events have been accepted and drained.
    for _ in range(500):
        s = pipeline.stats
        if s["queue_accepted"] >= 5 and s["queue_size"] == 0:
            break
        await asyncio.sleep(0.01)

    await pipeline.stop()
    with contextlib.suppress(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=2.0)

    stats = pipeline.stats
    assert seen == 5
    assert stats["consumer_errors"] == 5
    assert stats["processed"] == 0
    # Pipeline survived: queue is empty and we never raised at the top.
    assert stats["queue_size"] == 0
