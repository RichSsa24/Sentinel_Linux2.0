"""Pipeline orchestrator — wires collectors -> queue -> dedup -> consumer.

The orchestrator owns the topology that makes the race-condition kill
real:

1. **Registry of collectors keyed by `name`.** Re-registering a name is
   a startup error, so two producers can never own the same source.
2. **One bounded queue.** All collectors push to it. Capacity and
   backpressure policy come from Settings.
3. **One consumer task.** Single owner of the dedup window, so no lock
   is needed and the "single ownership" invariant cannot be violated by
   adding more consumers.
4. **`event.id`-keyed dedup.** Duplicates inside the TTL window are
   counted and dropped — the consumer's user-callback sees each
   `event.id` exactly once.

Failure isolation: a user-supplied consumer callback that raises does
NOT crash the pipeline. The exception is logged with the offending
`event.id` and processing continues. Producer crashes DO propagate —
they are framework bugs and should fail loud.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from typing import Final

from sentinel.collectors.base import AbstractCollector
from sentinel.events import Event
from sentinel.logging import get_logger
from sentinel.pipeline.dedup import DedupWindow
from sentinel.pipeline.queue import BoundedEventQueue
from sentinel.settings import Settings

EventConsumer = Callable[[Event], Awaitable[None]]

_COLLECTOR_TASK_PREFIX: Final[str] = "sentinel.collector:"
_CONSUMER_TASK_NAME: Final[str] = "sentinel.consumer"


class Pipeline:
    """Producer -> bounded queue -> dedup -> single consumer."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._queue = BoundedEventQueue(
            maxsize=settings.queue_maxsize,
            policy=settings.queue_backpressure,
        )
        self._dedup = DedupWindow(
            ttl_seconds=settings.dedup_window_seconds,
            max_entries=settings.dedup_max_entries,
        )
        self._collectors: dict[str, AbstractCollector] = {}
        self._consumer: EventConsumer | None = None
        self._log = get_logger("sentinel.pipeline")
        self._tasks: list[asyncio.Task[None]] = []
        self._processed = 0
        self._deduped = 0
        self._consumer_errors = 0

    # ------------------------------------------------------------------ wiring

    def register(self, collector: AbstractCollector) -> None:
        """Register a collector. Re-registering its `name` is a startup error."""
        if collector.name in self._collectors:
            msg = f"collector name {collector.name!r} already registered — one producer per source"
            raise ValueError(msg)
        self._collectors[collector.name] = collector

    def set_consumer(self, consumer: EventConsumer) -> None:
        """Install the single user-callback that receives deduped events."""
        self._consumer = consumer

    # ----------------------------------------------------------------- runtime

    async def run(self) -> None:
        """Start all collectors and the single consumer task.

        Returns when every collector task has completed *and* the queue
        has been fully drained by the consumer. To stop, call `stop()`
        from another task.
        """
        if self._consumer is None:
            msg = "set_consumer() must be called before run()"
            raise RuntimeError(msg)
        if not self._collectors:
            msg = "at least one collector must be registered before run()"
            raise RuntimeError(msg)

        # Spin up exactly one task per collector and one consumer task.
        # Collector task names are prefixed so stop() can find them.
        for collector in self._collectors.values():
            task = asyncio.create_task(
                collector.run(self._queue),
                name=f"{_COLLECTOR_TASK_PREFIX}{collector.name}",
            )
            self._tasks.append(task)
        consumer_task = asyncio.create_task(self._consume(), name=_CONSUMER_TASK_NAME)
        self._tasks.append(consumer_task)

        self._log.info(
            "pipeline.started",
            collectors=list(self._collectors),
            queue_maxsize=self._queue.maxsize,
            backpressure=str(self._queue.policy),
        )

        # If a collector raises, the gather propagates it — we want loud
        # failures for framework bugs. Consumer errors are caught inside
        # `_consume`, so the consumer task itself only ends via cancel.
        # `CancelledError` propagates naturally so callers using
        # `asyncio.run(pipeline.run())` see a clean exit after stop().
        await asyncio.gather(*self._tasks)

    async def stop(self) -> None:
        """Graceful shutdown.

        1. Signal every collector to stop.
        2. Wait for collectors to finish their current cycle.
        3. Drain the queue (wait for every queued event to be task_done'd).
        4. Cancel the consumer.
        """
        for collector in self._collectors.values():
            await collector.stop()

        collector_tasks = [
            t for t in self._tasks if t.get_name().startswith(_COLLECTOR_TASK_PREFIX)
        ]
        if collector_tasks:
            await asyncio.gather(*collector_tasks, return_exceptions=True)

        # Drain: every put() that has happened must be task_done()'d.
        await self._queue.join()

        consumer_task = next(
            (t for t in self._tasks if t.get_name() == _CONSUMER_TASK_NAME),
            None,
        )
        if consumer_task is not None and not consumer_task.done():
            consumer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await consumer_task

        self._log.info(
            "pipeline.stopped",
            processed=self._processed,
            deduped=self._deduped,
            consumer_errors=self._consumer_errors,
        )

    # ----------------------------------------------------------------- consume

    async def _consume(self) -> None:
        """Single consumer loop: dedup then dispatch."""
        assert self._consumer is not None  # noqa: S101  # nosec B101 — guaranteed by run()
        while True:
            event = await self._queue.get()
            try:
                if self._dedup.seen(event.dedup_key):
                    self._deduped += 1
                    continue
                try:
                    await self._consumer(event)
                except Exception:
                    # User-callback firewall: a raising consumer must not
                    # crash the framework. Count, log, continue.
                    self._consumer_errors += 1
                    self._log.exception(
                        "pipeline.consumer.error",
                        event_id=event.event.id,
                    )
                else:
                    self._processed += 1
            finally:
                self._queue.task_done()

    # ----------------------------------------------------------------- introspection

    @property
    def stats(self) -> dict[str, int]:
        """Snapshot counters for observability and tests."""
        return {
            "queue_size": self._queue.qsize(),
            "queue_accepted": self._queue.accepted,
            "queue_dropped": self._queue.dropped,
            "processed": self._processed,
            "deduped": self._deduped,
            "consumer_errors": self._consumer_errors,
            "dedup_hits": self._dedup.hits,
            "dedup_misses": self._dedup.misses,
            "dedup_window_size": len(self._dedup),
        }
