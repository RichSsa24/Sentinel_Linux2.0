"""Tests for `sentinel.collectors.authlog`.

Three layers:

1. **Parser** — `parse_auth_line` is pure, so its contract (which lines are
   recognised, what fields they map to, what gets rejected) is pinned with
   plain table-style unit tests.
2. **Tailer** — the collector reads a real file: new lines, partial-line
   buffering, and safe behaviour on a missing file.
3. **Rotation re-read (the payoff)** — drives the collector through the real
   `Pipeline` and proves that re-reading the file after a truncation re-emits
   every line, yet the consumer still sees each auth event exactly once. This
   is the Phase 1 race-condition kill demonstrated end-to-end with a real
   source.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

from sentinel.collectors.authlog import AuthLogCollector, parse_auth_line
from sentinel.events import Event, EventCategory, EventOutcome
from sentinel.pipeline.queue import BoundedEventQueue
from sentinel.pipeline.runner import Pipeline
from tests.conftest import settings_no_env_file

YEAR = 2026

_FAILED = "Failed password for bob from 10.0.0.9 port 4242 ssh2"


def _line(
    body: str = _FAILED,
    *,
    month: str = "Jun",
    day: str = "16",
    clock: str = "12:00:00",
    host: str = "testhost",
    proc: str = "sshd",
    pid: str = "1001",
) -> str:
    """Build a syslog-formatted auth line."""
    return f"{month} {day} {clock} {host} {proc}[{pid}]: {body}"


async def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:  # noqa: ASYNC109 — poll loop, not an `asyncio.timeout()` block
    """Poll `predicate` until true or `timeout` elapses."""
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


class TestParseRecognised:
    def test_failed_password(self) -> None:
        event = parse_auth_line(_line(), year=YEAR)

        assert event is not None
        assert event.event.category is EventCategory.AUTHENTICATION
        assert event.event.action == "ssh_login_failed"
        assert event.event.outcome is EventOutcome.FAILURE
        assert event.event.severity == 4
        assert event.source.ip == "10.0.0.9"
        assert event.source.port == 4242
        assert event.source.user == "bob"
        assert event.host.name == "testhost"
        assert event.timestamp == datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)

    def test_failed_password_invalid_user_is_louder(self) -> None:
        body = "Failed password for invalid user root from 1.2.3.4 port 22 ssh2"
        event = parse_auth_line(_line(body), year=YEAR)

        assert event is not None
        assert event.event.action == "ssh_login_failed"
        assert event.event.severity == 5
        assert event.source.user == "root"

    def test_accepted_password(self) -> None:
        body = "Accepted password for alice from 192.168.1.5 port 51000 ssh2"
        event = parse_auth_line(_line(body), year=YEAR)

        assert event is not None
        assert event.event.action == "ssh_login_succeeded"
        assert event.event.outcome is EventOutcome.SUCCESS
        assert event.event.severity == 2
        assert event.source.user == "alice"

    def test_accepted_publickey(self) -> None:
        body = "Accepted publickey for carol from 10.1.1.1 port 40000 ssh2: RSA SHA256:abc"
        event = parse_auth_line(_line(body), year=YEAR)

        assert event is not None
        assert event.event.action == "ssh_login_succeeded"
        assert event.source.user == "carol"

    def test_invalid_user_standalone(self) -> None:
        body = "Invalid user admin from 203.0.113.7 port 5000"
        event = parse_auth_line(_line(body), year=YEAR)

        assert event is not None
        assert event.event.action == "ssh_login_failed"
        assert event.event.severity == 5
        assert event.source.user == "admin"

    def test_double_space_day_field(self) -> None:
        event = parse_auth_line(_line(day=" 6"), year=YEAR)

        assert event is not None
        assert event.timestamp == datetime(2026, 6, 6, 12, 0, 0, tzinfo=UTC)

    def test_non_utc_timezone_is_converted(self) -> None:
        # 12:00 at a -04:00 offset is 16:00 UTC. A fixed offset keeps the test
        # independent of whether an IANA tz database is installed.
        event = parse_auth_line(_line(), year=YEAR, tz=timezone(timedelta(hours=-4)))

        assert event is not None
        assert event.timestamp == datetime(2026, 6, 16, 16, 0, 0, tzinfo=UTC)

    def test_host_override_wins(self) -> None:
        event = parse_auth_line(_line(), year=YEAR, host_override="canonical-host")

        assert event is not None
        assert event.host.name == "canonical-host"


class TestParseRejected:
    @pytest.mark.parametrize(
        "line",
        [
            "",
            "   ",
            "not a syslog line at all",
            # sudo, not sshd — out of this collector's scope.
            _line("session opened for user root", proc="sudo"),
            # sshd noise we do not model.
            _line("Connection closed by 10.0.0.9 port 4242"),
            # auth-shaped but port out of range → reject, don't coerce.
            _line("Failed password for bob from 10.0.0.9 port 99999 ssh2"),
            # bogus month.
            _line(month="Zzz"),
        ],
    )
    def test_unrecognised_lines_return_none(self, line: str) -> None:
        assert parse_auth_line(line, year=YEAR) is None

    def test_overlong_line_is_rejected_before_parsing(self) -> None:
        huge = _line() + "A" * 9_000
        assert parse_auth_line(huge, year=YEAR) is None

    def test_out_of_range_clock_is_rejected(self) -> None:
        # Auth-shaped, well-formed syslog framing, but an impossible hour.
        assert parse_auth_line(_line(clock="99:00:00"), year=YEAR) is None


class TestDeterministicId:
    def test_same_line_yields_same_event_id(self) -> None:
        first = parse_auth_line(_line(), year=YEAR)
        second = parse_auth_line(_line(), year=YEAR)

        assert first is not None
        assert second is not None
        assert first.event.id == second.event.id

    def test_different_source_yields_different_id(self) -> None:
        a = parse_auth_line(_line(), year=YEAR)
        b = parse_auth_line(
            _line("Failed password for bob from 10.0.0.10 port 4242 ssh2"),
            year=YEAR,
        )

        assert a is not None
        assert b is not None
        assert a.event.id != b.event.id


async def _collect_events(
    collector: AuthLogCollector,
    *,
    expected: int,
) -> list[Event]:
    """Run `collector` against a fresh queue until `expected` events arrive."""
    queue = BoundedEventQueue(maxsize=64)
    received: list[Event] = []
    task = asyncio.create_task(collector.run(queue))
    try:
        await _wait_for(lambda: collector.stats["parsed"] >= expected)
        while not queue.empty():
            received.append(await queue.get())
            queue.task_done()
    finally:
        await collector.stop()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2.0)
    return received


class TestConstruction:
    def test_rejects_non_positive_poll_interval(self) -> None:
        with pytest.raises(ValueError, match="poll_interval"):
            AuthLogCollector("/var/log/auth.log", poll_interval=0)


class TestTailer:
    @pytest.mark.asyncio
    async def test_read_error_is_logged_not_fatal(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        collector = AuthLogCollector(tmp_path / "auth.log", poll_interval=0.02, year=YEAR)

        def _boom() -> list[str]:
            raise OSError("permission denied")

        monkeypatch.setattr(collector, "_read_new_lines", _boom)

        # A read failure must be swallowed: no exception, nothing parsed.
        await collector._drain_once(BoundedEventQueue(maxsize=4))

        assert collector.stats["parsed"] == 0

    @pytest.mark.asyncio
    async def test_reads_existing_lines(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        log.write_text(_line() + "\n" + _line(host="other") + "\n", encoding="utf-8")
        collector = AuthLogCollector(log, poll_interval=0.02, year=YEAR)

        events = await _collect_events(collector, expected=2)

        assert len(events) == 2
        assert collector.stats["parsed"] == 2
        assert collector.stats["skipped"] == 0

    @pytest.mark.asyncio
    async def test_partial_line_is_buffered_until_newline(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        log.write_text(_line(), encoding="utf-8")  # no trailing newline yet
        collector = AuthLogCollector(log, poll_interval=0.02, year=YEAR)
        queue = BoundedEventQueue(maxsize=16)
        task = asyncio.create_task(collector.run(queue))
        try:
            # Without a newline the line must not be emitted.
            await asyncio.sleep(0.1)
            assert collector.stats["parsed"] == 0

            log.write_text(_line() + "\n", encoding="utf-8")
            assert await _wait_for(lambda: collector.stats["parsed"] == 1)
        finally:
            await collector.stop()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=2.0)

    @pytest.mark.asyncio
    async def test_missing_file_is_not_fatal(self, tmp_path: Path) -> None:
        collector = AuthLogCollector(tmp_path / "does-not-exist.log", poll_interval=0.02, year=YEAR)
        queue = BoundedEventQueue(maxsize=16)
        task = asyncio.create_task(collector.run(queue))

        await asyncio.sleep(0.1)
        assert not task.done()  # survived a missing source
        assert collector.stats["parsed"] == 0

        await collector.stop()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2.0)

    @pytest.mark.asyncio
    async def test_garbage_lines_are_skipped_not_fatal(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        log.write_text("garbage\n" + _line() + "\nmore garbage\n", encoding="utf-8")
        collector = AuthLogCollector(log, poll_interval=0.02, year=YEAR)

        events = await _collect_events(collector, expected=1)

        assert len(events) == 1
        assert collector.stats["parsed"] == 1
        assert collector.stats["skipped"] == 2


class TestRotationReReadExactlyOnce:
    @pytest.mark.asyncio
    async def test_post_rotation_reread_is_deduped_to_exactly_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "test")
        monkeypatch.setenv("SENTINEL_DEDUP_WINDOW_SECONDS", "300")
        settings = settings_no_env_file()

        lines = [_line(f"Failed password for bob from 10.0.0.{i} port 4242 ssh2") for i in range(5)]
        content = "\n".join(lines) + "\n"
        log = tmp_path / "auth.log"
        log.write_text(content, encoding="utf-8")

        received: list[str] = []

        async def consumer(event: Event) -> None:
            received.append(event.event.id)

        collector = AuthLogCollector(log, poll_interval=0.02, year=YEAR)
        pipeline = Pipeline(settings)
        pipeline.set_consumer(consumer)
        pipeline.register(collector)

        run_task = asyncio.create_task(pipeline.run())
        try:
            # First pass: all five lines parsed and drained.
            assert await _wait_for(
                lambda: collector.stats["parsed"] == 5 and pipeline.stats["queue_size"] == 0
            )

            # Rotate in place: truncate, let the collector observe the reset,
            # then rewrite the identical content (the post-rotation re-read).
            log.write_text("", encoding="utf-8")
            assert await _wait_for(lambda: collector.stats["position"] == 0)
            log.write_text(content, encoding="utf-8")

            # Second pass: the collector re-emits all five lines...
            assert await _wait_for(
                lambda: collector.stats["parsed"] == 10 and pipeline.stats["queue_size"] == 0
            )
        finally:
            await pipeline.stop()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.wait_for(run_task, timeout=5.0)

        # ...but the consumer saw each of the five exactly once.
        assert collector.stats["parsed"] == 10
        assert len(received) == 5
        assert len(set(received)) == 5
        assert pipeline.stats["processed"] == 5
        assert pipeline.stats["deduped"] == 5
