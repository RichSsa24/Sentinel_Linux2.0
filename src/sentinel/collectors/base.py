"""Collector contract: one producer per source.

A `Collector` owns the producer loop for exactly one event source — the
auth log, file-integrity monitor, audit subsystem, network flows, etc.
The pipeline orchestrator creates each collector once, starts it as one
task, and registers its `name` in a `name -> collector` map. Registering
two collectors with the same name is a startup error.

That is the structural fix for the v1 race condition: the framework
gives every source a single owning producer. There is no place in the
public API where a caller can spawn a second producer for the same
source, because the orchestrator's registry rejects it.

Subclasses implement `run(queue)` — the producer loop. They MUST exit
cleanly when either:

- `self.stopping` becomes True (graceful, polled), or
- `asyncio.CancelledError` is raised inside the loop (hard).

The `wait_stop(timeout)` helper lets poll-based collectors sleep in
between cycles while still being responsive to shutdown.
"""

from __future__ import annotations

import abc
import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Imported only for type hints — runtime would cycle through
    # sentinel.pipeline.runner -> AbstractCollector.
    from sentinel.pipeline.queue import BoundedEventQueue


class AbstractCollector(abc.ABC):
    """Base class for every event source.

    Subclasses set `name` (a ClassVar identifying the source) and
    implement `run(queue)`.
    """

    # Subclasses may set a class-level default; instances may also pass
    # `name=...` to __init__ (useful for tests or multi-instance sources
    # like "tail this file" vs "tail that file").
    name: str = ""

    def __init__(self, *, name: str | None = None) -> None:
        if name is not None:
            self.name = name
        if not self.name:
            msg = (
                f"{type(self).__name__} must set `name` (class attribute or "
                "`name=` argument) to a non-empty source identifier"
            )
            raise ValueError(msg)
        self._stop_event = asyncio.Event()

    @abc.abstractmethod
    async def run(self, queue: BoundedEventQueue) -> None:
        """Produce events from the source, pushing each onto `queue`.

        Implementations MUST periodically check `self.stopping` (or await
        `self.wait_stop(...)`) and exit cleanly when set. They MUST also
        propagate `asyncio.CancelledError` after releasing any resources
        held — the orchestrator uses cancellation for hard shutdown.
        """

    async def stop(self) -> None:
        """Signal a graceful stop. Idempotent."""
        self._stop_event.set()

    @property
    def stopping(self) -> bool:
        """True once `stop()` has been called."""
        return self._stop_event.is_set()

    async def wait_stop(self, timeout: float | None = None) -> bool:  # noqa: ASYNC109 — bool return; not an `asyncio.timeout()` block
        """Wait up to `timeout` seconds for `stop()` to be called.

        Returns True if stop was signalled, False if the timeout elapsed
        first. With `timeout=None`, waits indefinitely and always returns
        True. Useful pattern for a poll-and-sleep collector:

            while not self.stopping:
                for event in self._read_batch():
                    await queue.put(event)
                if await self.wait_stop(timeout=POLL_INTERVAL_S):
                    return
        """
        if timeout is None:
            await self._stop_event.wait()
            return True
        try:
            await asyncio.wait_for(self._stop_event.wait(), timeout=timeout)
        except TimeoutError:
            return False
        return True
