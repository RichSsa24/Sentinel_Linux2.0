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
import os
from pathlib import Path

import pytest

from sentinel.collectors.base import AbstractCollector, clip, os_text, under_host_root
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


class TestUnderHostRoot:
    def test_bare_metal_is_identity(self) -> None:
        assert under_host_root(Path("/"), Path("/etc/passwd")) == Path("/etc/passwd")

    def test_container_maps_beneath_the_mount(self) -> None:
        assert under_host_root(Path("/host"), Path("/etc/passwd")) == Path("/host/etc/passwd")

    def test_relative_paths_pass_through(self) -> None:
        assert under_host_root(Path("/host"), Path("local/dir")) == Path("local/dir")


class TestOsText:
    @pytest.mark.parametrize("name", ["/etc/passwd", "/srv/año/café", "/tmp/emoji-\U0001f600"])
    def test_valid_names_are_unchanged(self, name: str) -> None:
        assert os_text(name) == name

    def test_undecodable_bytes_become_escapes(self) -> None:
        name = os.fsdecode(b"/tmp/evil\xff\xfe")  # how Python hands such a name over
        assert os_text(name) == "/tmp/evil\\xff\\xfe"

    @pytest.mark.parametrize("name", [os.fsdecode(b"/x/\xff"), "/x/\ud800", "/x/\udfff\ud83d"])
    def test_result_is_always_valid_utf8(self, name: str) -> None:
        os_text(name).encode("utf-8")  # strict: raises on any lone surrogate


class TestClip:
    def test_short_text_is_unchanged(self) -> None:
        assert clip("bash -i", 100) == "bash -i"

    def test_keeps_head_and_tail_within_the_limit(self) -> None:
        # An attacker can pad either side of a payload; both ends must survive.
        text = "PAYLOAD-HEAD " + "x" * 50_000 + " PAYLOAD-TAIL"
        clipped = clip(text, 100)
        assert len(clipped) == 100
        assert clipped.startswith("PAYLOAD-HEAD")
        assert clipped.endswith("PAYLOAD-TAIL")

    @pytest.mark.parametrize("limit", [0, 1, 3, 5, 6])
    def test_never_exceeds_tiny_limits(self, limit: int) -> None:
        assert len(clip("y" * 100, limit)) <= max(limit, len(" ... "))
