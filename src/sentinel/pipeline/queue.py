"""Bounded event queue — the producer/consumer choke point.

A thin wrapper around `asyncio.Queue[Event]` that enforces two §3.1
invariants:

- **Bounded memory.** `maxsize` is mandatory; no producer can grow the
  queue without bound, so a flood from a misbehaving source cannot OOM
  the process.
- **Explicit backpressure policy.** When the queue is full the behaviour
  is one of `BackpressurePolicy.BLOCK` (await a free slot, lossless) or
  `BackpressurePolicy.DROP_NEWEST` (reject the new event and bump the
  `dropped` counter, lossy but bounded). There is no third option: every
  collision must be either survived or counted.
"""

from __future__ import annotations

import asyncio

from sentinel.events import Event
from sentinel.settings import BackpressurePolicy


class BoundedEventQueue:
    """Bounded asyncio queue with an explicit backpressure policy."""

    def __init__(
        self,
        maxsize: int,
        policy: BackpressurePolicy = BackpressurePolicy.BLOCK,
    ) -> None:
        if maxsize < 1:
            msg = f"maxsize must be >= 1; got {maxsize}"
            raise ValueError(msg)
        self._maxsize = maxsize
        self._policy = policy
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=maxsize)
        self._dropped = 0
        self._accepted = 0

    @property
    def maxsize(self) -> int:
        """The configured upper bound on queued events."""
        return self._maxsize

    @property
    def policy(self) -> BackpressurePolicy:
        """The configured backpressure policy."""
        return self._policy

    @property
    def dropped(self) -> int:
        """Total events refused under DROP_NEWEST since start. Monotonic."""
        return self._dropped

    @property
    def accepted(self) -> int:
        """Total events successfully enqueued since start. Monotonic."""
        return self._accepted

    def qsize(self) -> int:
        """Current number of events buffered."""
        return self._queue.qsize()

    def empty(self) -> bool:
        """True if no events are buffered."""
        return self._queue.empty()

    async def put(self, event: Event) -> bool:
        """Enqueue an event according to the configured policy.

        Returns True if the event was accepted, False if it was dropped
        (DROP_NEWEST only; BLOCK never drops).
        """
        if self._policy is BackpressurePolicy.BLOCK:
            await self._queue.put(event)
            self._accepted += 1
            return True

        # DROP_NEWEST: refuse rather than block.
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._dropped += 1
            return False
        self._accepted += 1
        return True

    async def get(self) -> Event:
        """Block until an event is available, then return it."""
        return await self._queue.get()

    def task_done(self) -> None:
        """Mark the most recently fetched event as processed."""
        self._queue.task_done()

    async def join(self) -> None:
        """Wait until every event passed through `put` has been `task_done`'d."""
        await self._queue.join()
