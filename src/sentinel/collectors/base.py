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
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from sentinel.logging import get_logger

if TYPE_CHECKING:
    # Imported only for type hints — runtime would cycle through
    # sentinel.pipeline.runner -> AbstractCollector.
    from sentinel.pipeline.queue import BoundedEventQueue


def under_host_root(host_root: Path, host_path: Path) -> Path:
    """Where a host-native path is visible to this process.

    With ``host_root`` ``/`` (bare metal) paths are returned unchanged; in a
    container the host is mounted beneath e.g. ``/host``, so ``/etc/passwd``
    maps to ``/host/etc/passwd``. Relative paths are not host paths and pass
    through untouched. Every collector resolves host paths through this one
    function.
    """
    if host_root == Path("/") or not host_path.is_absolute():
        return host_path
    return host_root / host_path.relative_to(host_path.anchor)


def os_text(value: str) -> str:
    """Make a string that came from the OS (a file name, a symlink target) valid UTF-8.

    Linux names are bytes. Python decodes bytes that are not UTF-8 to lone
    surrogates, which strict consumers (event validation, JSON, the database)
    reject, so a file or binary named with such bytes would crash a collector,
    and with it the pipeline. They are rewritten as ``\\xNN`` escapes instead.
    """
    try:
        raw = value.encode("utf-8", "surrogateescape")
    except UnicodeEncodeError:  # a lone surrogate the OS layer did not produce
        raw = value.encode("utf-8", "surrogatepass")
    return raw.decode("utf-8", "backslashreplace")


_CLIP_MARKER = " ... "


def clip(text: str, limit: int) -> str:
    """Shorten ``text`` to at most ``limit`` characters, keeping head and tail.

    Both ends survive because an attacker can pad either side of what matters
    (argv padding before or after a payload); the middle becomes a marker.
    """
    if len(text) <= limit:
        return text
    keep = max(limit - len(_CLIP_MARKER), 0)
    tail = keep // 2
    return text[: keep - tail] + _CLIP_MARKER + (text[-tail:] if tail else "")


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
        self._source_available = True

    @abc.abstractmethod
    async def run(self, queue: BoundedEventQueue) -> None:
        """Produce events from the source, pushing each onto `queue`.

        Implementations MUST periodically check `self.stopping` (or await
        `self.wait_stop(...)`) and exit cleanly when set. They MUST also
        propagate `asyncio.CancelledError` after releasing any resources
        held — the orchestrator uses cancellation for hard shutdown.
        """

    @property
    def stats(self) -> Mapping[str, int]:
        """Snapshot counters for observability (subclasses extend this)."""
        return {}

    @property
    def source_available(self) -> bool:
        """False while the collector cannot read its source (exported as a gauge).

        A collector that cannot see its source produces no events, which
        looks exactly like a quiet host; this is how the two are told apart.
        """
        return self._source_available

    def _mark_source(self, available: bool, **context: object) -> None:
        """Record whether the source could be read, logging only the changes."""
        if available == self._source_available:
            return
        self._source_available = available
        log = get_logger("sentinel.collectors")
        if available:
            log.info("collector.source_available", collector=self.name, **context)
        else:
            log.warning("collector.source_unavailable", collector=self.name, **context)

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
