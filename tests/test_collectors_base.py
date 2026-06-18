"""Tests for `sentinel.collectors.base.AbstractCollector`.

The base collector encodes the "one producer per source" contract. These
tests pin down the parts not already exercised by the keystone pipeline
test:

- A collector must have a non-empty `name` (class attribute or `name=`
  argument); construction fails loudly otherwise.
- `stop()` / `stopping` form an idempotent latch.
- `wait_stop(timeout)` returns False on timeout, True once stop is
  signalled, and waits indefinitely when `timeout is None`.
"""

from __future__ import annotations

import asyncio

import pytest

from sentinel.collectors.base import AbstractCollector
from sentinel.pipeline.queue import BoundedEventQueue


class _NoopCollector(AbstractCollector):
    """Minimal concrete collector — its `run` loop does nothing.

    `name` is supplied per-instance via `name=` so the class itself carries
    no default, letting us exercise the missing-name validation path.
    """

    async def run(self, queue: BoundedEventQueue) -> None:
        await self.wait_stop()


class _NamedCollector(AbstractCollector):
    """Collector whose `name` comes from a class-level default."""

    name = "auth-log"

    async def run(self, queue: BoundedEventQueue) -> None:
        await self.wait_stop()


class TestName:
    def test_uses_class_level_name(self) -> None:
        collector = _NamedCollector()
        assert collector.name == "auth-log"

    def test_name_argument_overrides_class_default(self) -> None:
        collector = _NamedCollector(name="auth-log-shadow")
        assert collector.name == "auth-log-shadow"

    def test_missing_name_is_construction_error(self) -> None:
        with pytest.raises(ValueError, match="must set `name`"):
            _NoopCollector()

    def test_empty_name_argument_is_construction_error(self) -> None:
        with pytest.raises(ValueError, match="must set `name`"):
            _NoopCollector(name="")


class TestStopLatch:
    def test_starts_not_stopping(self) -> None:
        assert _NoopCollector(name="x").stopping is False

    @pytest.mark.asyncio
    async def test_stop_sets_stopping(self) -> None:
        collector = _NoopCollector(name="x")

        await collector.stop()

        assert collector.stopping is True

    @pytest.mark.asyncio
    async def test_stop_is_idempotent(self) -> None:
        collector = _NoopCollector(name="x")

        await collector.stop()
        await collector.stop()

        assert collector.stopping is True


class TestWaitStop:
    @pytest.mark.asyncio
    async def test_returns_false_when_timeout_elapses(self) -> None:
        collector = _NoopCollector(name="x")

        signalled = await collector.wait_stop(timeout=0.01)

        assert signalled is False
        assert collector.stopping is False

    @pytest.mark.asyncio
    async def test_returns_true_when_stop_signalled_before_timeout(self) -> None:
        collector = _NoopCollector(name="x")

        async def _signal() -> None:
            await collector.stop()

        _, signalled = await asyncio.gather(_signal(), collector.wait_stop(timeout=5.0))

        assert signalled is True

    @pytest.mark.asyncio
    async def test_waits_indefinitely_when_timeout_none(self) -> None:
        collector = _NoopCollector(name="x")
        waiter = asyncio.create_task(collector.wait_stop(timeout=None))

        # Give the waiter a scheduling slot; it must still be pending because
        # stop() has not been called.
        await asyncio.sleep(0)
        assert not waiter.done()

        await collector.stop()
        assert await asyncio.wait_for(waiter, timeout=5.0) is True
