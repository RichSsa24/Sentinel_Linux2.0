# ruff: noqa
"""Synthetic soak test for Sentinel pipeline idempotency and throughput.

High-throughput simulator to prove S4 (Idempotency and Concurrency).

Proves Zero Duplicate Events and no crashes under high load.
"""

import asyncio
import time
from datetime import UTC, datetime

from sentinel.collectors.base import AbstractCollector
from sentinel.events import (
    Event,
    EventCategory,
    EventKind,
    EventMeta,
    EventOutcome,
    Host,
)
from sentinel.pipeline.runner import Pipeline
from sentinel.settings import Settings


class FirehoseCollector(AbstractCollector):
    def __init__(self, name: str, count: int):
        super().__init__(name=name)
        self.count = count

    async def run(self, queue) -> None:
        import hashlib

        now = datetime.now(UTC)
        for i in range(self.count):
            base_id = hashlib.sha256(f"evt_{i}_{self.name}".encode()).hexdigest()
            for _ in range(5):
                evt = Event(
                    timestamp=now,
                    event=EventMeta(
                        id=base_id,
                        kind=EventKind.EVENT,
                        category=EventCategory.HOST,
                        action="test_action",
                        outcome=EventOutcome.SUCCESS,
                        severity=1,
                    ),
                    host=Host(name="soak_host"),
                    message="soak test event",
                )
                await queue.put(evt)
            if await self.wait_stop(timeout=0):
                return


async def main():
    settings = Settings(env="test")
    pipeline = Pipeline(settings)

    # Register 3 concurrent producers, each emitting 20k unique events, each duplicated 5 times
    # Total events emitted = 3 * 20k * 5 = 300,000
    # Expected unique events = 60,000
    pipeline.register(FirehoseCollector("firehose_1", 20000))
    pipeline.register(FirehoseCollector("firehose_2", 20000))
    pipeline.register(FirehoseCollector("firehose_3", 20000))

    received = set()

    async def consumer(event: Event) -> None:
        if event.event.id in received:
            print(f"FATAL: Duplicate event reached consumer: {event.event.id}")
            import sys

            sys.exit(1)
        received.add(event.event.id)

    pipeline.set_consumer(consumer)

    async def monitor():
        while len(received) < 60000:
            await asyncio.sleep(0.1)
        await pipeline.stop()

    print("Starting soak test... emitting 300,000 events with 80% duplicates.")
    t0 = time.perf_counter()
    asyncio.create_task(monitor())
    try:
        await pipeline.run()
    except asyncio.CancelledError:
        pass
    t1 = time.perf_counter()

    stats = pipeline.stats
    print(f"Completed in {t1 - t0:.2f} seconds.")
    print(f"Stats: {stats}")
    assert stats["processed"] == 60000, "Did not process exactly 60000 unique events"
    assert stats["deduped"] == 240000, "Did not dedup exactly 240000 events"
    print("SOAK TEST PASSED: Zero crashes, zero duplicate events, 100% throughput achieved.")


if __name__ == "__main__":
    asyncio.run(main())
