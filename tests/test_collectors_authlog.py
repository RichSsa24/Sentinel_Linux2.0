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
from structlog.testing import capture_logs

from sentinel.collectors.authlog import AuthLogCollector, parse_auth_line, parse_auth_records
from sentinel.events import Event
from sentinel.normalizer import Normalizer, RawAuthEvent, RawEvent, RawSource
from sentinel.pipeline.queue import BoundedEventQueue
from sentinel.pipeline.runner import Pipeline
from tests.conftest import DeadLetterNormalizer, settings_no_env_file

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
        raw = parse_auth_line(_line(), year=YEAR)

        assert raw is not None
        assert raw.source is RawSource.AUTH
        assert raw.action == "ssh_login_failed"
        assert raw.outcome == "failure"
        assert raw.severity == 4
        assert raw.ip == "10.0.0.9"
        assert raw.port == 4242
        assert raw.user == "bob"
        assert raw.host == "testhost"
        assert raw.occurred_at == datetime(2026, 6, 16, 12, 0, 0, tzinfo=UTC)

    def test_failed_password_invalid_user_is_louder(self) -> None:
        body = "Failed password for invalid user root from 1.2.3.4 port 22 ssh2"
        raw = parse_auth_line(_line(body), year=YEAR)

        assert raw is not None
        assert raw.action == "ssh_login_failed"
        assert raw.severity == 5
        assert raw.user == "root"

    def test_accepted_password(self) -> None:
        body = "Accepted password for alice from 192.168.1.5 port 51000 ssh2"
        raw = parse_auth_line(_line(body), year=YEAR)

        assert raw is not None
        assert raw.action == "ssh_login_succeeded"
        assert raw.outcome == "success"
        assert raw.severity == 2
        assert raw.user == "alice"

    def test_accepted_publickey(self) -> None:
        body = "Accepted publickey for carol from 10.1.1.1 port 40000 ssh2: RSA SHA256:abc"
        raw = parse_auth_line(_line(body), year=YEAR)

        assert raw is not None
        assert raw.action == "ssh_login_succeeded"
        assert raw.user == "carol"

    def test_invalid_user_standalone(self) -> None:
        body = "Invalid user admin from 203.0.113.7 port 5000"
        raw = parse_auth_line(_line(body), year=YEAR)

        assert raw is not None
        assert raw.action == "ssh_login_failed"
        assert raw.severity == 5
        assert raw.user == "admin"

    def test_double_space_day_field(self) -> None:
        raw = parse_auth_line(_line(day=" 6"), year=YEAR)

        assert raw is not None
        assert raw.occurred_at == datetime(2026, 6, 6, 12, 0, 0, tzinfo=UTC)

    def test_non_utc_timezone_is_converted(self) -> None:
        # 12:00 at a -04:00 offset is 16:00 UTC. A fixed offset keeps the test
        # independent of whether an IANA tz database is installed.
        raw = parse_auth_line(_line(), year=YEAR, tz=timezone(timedelta(hours=-4)))

        assert raw is not None
        assert raw.occurred_at == datetime(2026, 6, 16, 16, 0, 0, tzinfo=UTC)

    def test_host_override_wins(self) -> None:
        raw = parse_auth_line(_line(), year=YEAR, host_override="canonical-host")

        assert raw is not None
        assert raw.host == "canonical-host"


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

    @pytest.mark.security
    def test_a_huge_port_number_is_rejected_not_raised(self) -> None:
        # Regression: int() raises ValueError past 4300 digits, which escaped
        # the parser and stopped the auth-log collector for good. sshd lines
        # can be forged by any local user (logger -p auth.info -t sshd ...).
        line = _line("Failed password for bob from 10.0.0.9 port " + "9" * 5_000 + " ssh2")
        assert parse_auth_line(line, year=YEAR) is None

    def test_overlong_line_is_rejected_before_parsing(self) -> None:
        huge = _line() + "A" * 9_000
        assert parse_auth_line(huge, year=YEAR) is None

    def test_out_of_range_clock_is_rejected(self) -> None:
        # Auth-shaped, well-formed syslog framing, but an impossible hour.
        assert parse_auth_line(_line(clock="99:00:00"), year=YEAR) is None


class TestDeterministicId:
    def _id(self, line: str) -> str:
        raw = parse_auth_line(line, year=YEAR)
        assert raw is not None
        event = Normalizer().normalize(raw)
        assert event is not None
        return event.event.id

    def test_same_line_yields_same_event_id(self) -> None:
        # The same line parsed and normalized twice must hash to the same id —
        # this is what collapses a post-rotation re-read in the dedup window.
        assert self._id(_line()) == self._id(_line())

    def test_different_source_yields_different_id(self) -> None:
        other = _line("Failed password for bob from 10.0.0.10 port 4242 ssh2")
        assert self._id(_line()) != self._id(other)


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


class TestDeadLetter:
    @pytest.mark.asyncio
    async def test_dead_lettered_line_is_skipped_not_enqueued(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        log.write_text(_line() + "\n", encoding="utf-8")  # a recognised auth line
        collector = AuthLogCollector(
            log, poll_interval=0.02, year=YEAR, normalizer=DeadLetterNormalizer()
        )
        queue = BoundedEventQueue(maxsize=4)

        await collector._drain_once(queue)
        collector._close()  # run() closes the tailed file; this test bypasses it

        assert queue.empty()
        assert collector.stats["parsed"] == 0


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
        with capture_logs() as logs:
            await collector._drain_once(BoundedEventQueue(maxsize=4))
            await collector._drain_once(BoundedEventQueue(maxsize=4))

        assert collector.stats["parsed"] == 0
        assert not collector.source_available
        # Logged when it starts failing, not on every poll.
        assert [(e["event"], e["error"]) for e in logs] == [
            ("collector.source_unavailable", "OSError")
        ]

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


async def _drain_events(collector: AuthLogCollector) -> list[Event]:
    """One poll's worth of events (the test closes the tailed file afterwards)."""
    queue = BoundedEventQueue(maxsize=4096)
    await collector._drain_once(queue)
    events: list[Event] = []
    while not queue.empty():
        events.append(await queue.get())
        queue.task_done()
    return events


class TestModernSshdFormats:
    """Regressions: lines the parser silently skipped on current distributions."""

    def test_sshd_session_process_name(self) -> None:
        # OpenSSH 9.8+ logs per-connection events as sshd-session.
        raw = parse_auth_line(_line(proc="sshd-session"), year=YEAR)
        assert raw is not None
        assert raw.ip == "10.0.0.9"

    def test_rfc3339_timestamp(self) -> None:
        line = "2026-06-16T14:00:00.123456+02:00 testhost sshd[1001]: " + _FAILED
        raw = parse_auth_line(line)
        assert raw is not None
        assert raw.occurred_at == datetime(2026, 6, 16, 12, 0, 0, 123456, tzinfo=UTC)
        assert raw.syslog_ts == "2026-06-16T14:00:00.123456+02:00"

    def test_rsyslog_repeat_summary_counts_every_attempt(self) -> None:
        line = _line("message repeated 3 times: [ " + _FAILED + "]")
        records = parse_auth_records(line, year=YEAR)
        assert [r.occurrence for r in records] == [0, 1, 2]
        assert {r.message for r in records} == {_FAILED}
        assert len({_event_id(r) for r in records}) == 3

    @pytest.mark.parametrize(
        "method", ["keyboard-interactive/pam", "keyboard-interactive", "hostbased"]
    )
    def test_other_authentication_methods(self, method: str) -> None:
        body = f"Accepted {method} for alice from 192.168.1.5 port 51000 ssh2"
        raw = parse_auth_line(_line(body), year=YEAR)
        assert raw is not None
        assert raw.action == "ssh_login_succeeded"

    def test_the_none_probe_is_not_a_failed_login(self) -> None:
        # Clients try "none" before every real method; counting it would
        # double every brute-force tally.
        body = "Failed none for invalid user x from 10.0.0.9 port 4242 ssh2"
        assert parse_auth_line(_line(body), year=YEAR) is None


@pytest.mark.security
class TestHostileUserNames:
    @pytest.mark.parametrize(
        "body",
        [
            "Invalid user a from 6.6.6.6 port 1 from 203.0.113.9 port 2222",
            "Failed password for invalid user a from 6.6.6.6 port 1"
            " from 203.0.113.9 port 2222 ssh2",
        ],
    )
    def test_a_user_name_cannot_choose_the_source_address(self, body: str) -> None:
        # Regression: the user name is client-chosen and sshd logs it verbatim;
        # a lazy match took the attacker's "from 6.6.6.6" as the source.
        raw = parse_auth_line(_line(body), year=YEAR)
        assert raw is not None
        assert (raw.ip, raw.port) == ("203.0.113.9", 2222)


class TestYearInference:
    def test_a_december_line_read_in_january_is_last_year(self) -> None:
        # Regression: the year was fixed when the collector started.
        now = datetime(2027, 1, 1, 0, 5, tzinfo=UTC)
        raw = parse_auth_line(_line(month="Dec", day="31", clock="23:59:00"), now=now)
        assert raw is not None
        assert raw.occurred_at.year == 2026

    def test_a_current_line_is_this_year(self) -> None:
        now = datetime(2027, 6, 16, 12, 5, tzinfo=UTC)
        raw = parse_auth_line(_line(), now=now)
        assert raw is not None
        assert raw.occurred_at.year == 2027


@pytest.mark.security
class TestIdenticalFailures:
    async def test_repeated_identical_failures_are_distinct_events(self, tmp_path: Path) -> None:
        # Regression: sshd logs one identical line per attempt on a connection
        # (same second, pid and port); their ids collided and the dedup window
        # kept one, so six attempts never reached the brute-force threshold.
        log = tmp_path / "auth.log"
        log.write_text("\n".join([_line()] * 6) + "\n", encoding="utf-8")
        collector = AuthLogCollector(log, year=YEAR)
        first = await _drain_events(collector)
        # A truncation and re-read of the same lines reproduces the same ids,
        # so the dedup window still collapses a post-rotation re-read.
        log.write_text("", encoding="utf-8")
        await _drain_events(collector)
        log.write_text("\n".join([_line()] * 6) + "\n", encoding="utf-8")
        second = await _drain_events(collector)
        collector._close()

        assert len({e.event.id for e in first}) == 6
        assert {e.event.id for e in second} == {e.event.id for e in first}


class TestRotationAndBounds:
    async def test_rename_rotation_loses_no_line_and_cuts_none(self, tmp_path: Path) -> None:
        # Regression: rotation was detected only by a shrinking size. When the
        # new file had already grown past the old offset, its start was skipped
        # (a fragment came out as a line), and lines written to the old file
        # after the last poll were never read.
        log = tmp_path / "auth.log"
        log.write_text(_line(pid="1") + "\n", encoding="utf-8")
        collector = AuthLogCollector(log, year=YEAR)
        assert len(await _drain_events(collector)) == 1

        with log.open("a", encoding="utf-8") as old:
            old.write(_line(pid="2") + "\n")  # lands after the last poll
        log.rename(tmp_path / "auth.log.1")
        log.write_text("\n".join(_line(pid=str(p)) for p in range(3, 6)) + "\n", encoding="utf-8")
        events = await _drain_events(collector)
        collector._close()

        assert [e.message for e in events] == [_FAILED] * 4
        assert collector.stats["skipped"] == 0

    async def test_a_poll_reads_a_bounded_amount(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        noise = (_line("Connection closed by 10.0.0.9 port 4242") + "\n") * 40_000  # ~3 MiB
        log.write_text(noise + _line() + "\n", encoding="utf-8")
        collector = AuthLogCollector(log, year=YEAR)

        await _drain_events(collector)
        assert collector.stats["position"] <= 1 << 20
        events: list[Event] = []
        for _ in range(5):
            events += await _drain_events(collector)
        collector._close()
        assert len(events) == 1

    async def test_a_line_without_newline_cannot_grow_the_buffer(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        log.write_bytes(b"A" * 100_000)
        collector = AuthLogCollector(log, year=YEAR)
        await _drain_events(collector)
        assert len(collector._buf) <= 8_192
        with log.open("a", encoding="utf-8") as handle:
            handle.write("tail of the long line\n" + _line() + "\n")
        events = await _drain_events(collector)
        collector._close()
        assert len(events) == 1


def _event_id(raw: RawAuthEvent) -> str:
    event = Normalizer().normalize(raw)
    assert event is not None
    return event.event.id


class TestStartAtEnd:
    """Regression: every restart re-read the whole file and re-sent its alerts."""

    async def test_history_present_at_start_up_is_skipped(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        log.write_text("".join(_line(host=f"h{p}") + "\n" for p in range(5)), encoding="utf-8")
        collector = AuthLogCollector(log, year=YEAR, start_at_end=True)
        assert await _drain_events(collector) == []
        with log.open("a", encoding="utf-8") as handle:
            handle.write(_line(host="h99") + "\n")
        events = await _drain_events(collector)
        collector._close()
        assert [e.host.name for e in events] == ["h99"]

    async def test_a_line_being_written_at_start_up_is_not_read_as_a_fragment(
        self, tmp_path: Path
    ) -> None:
        log = tmp_path / "auth.log"
        log.write_text(_line(host="h1") + "\n" + _line(host="h2")[:30], encoding="utf-8")
        collector = AuthLogCollector(log, year=YEAR, start_at_end=True)
        assert await _drain_events(collector) == []
        with log.open("a", encoding="utf-8") as handle:
            handle.write(_line(host="h2")[30:] + "\n" + _line(host="h3") + "\n")
        events = await _drain_events(collector)
        collector._close()
        assert [e.host.name for e in events] == ["h3"]
        assert collector.stats["skipped"] == 0  # the tail of line 2 was not parsed

    async def test_a_file_created_after_start_up_is_read_from_its_start(
        self, tmp_path: Path
    ) -> None:
        log = tmp_path / "auth.log"
        collector = AuthLogCollector(log, year=YEAR, start_at_end=True)
        assert await _drain_events(collector) == []  # not there yet
        log.write_text(_line(host="h7") + "\n", encoding="utf-8")
        events = await _drain_events(collector)
        collector._close()
        assert len(events) == 1

    async def test_a_file_rotated_in_after_start_up_is_read_from_its_start(
        self, tmp_path: Path
    ) -> None:
        log = tmp_path / "auth.log"
        log.write_text(_line(host="h1") + "\n", encoding="utf-8")
        collector = AuthLogCollector(log, year=YEAR, start_at_end=True)
        assert await _drain_events(collector) == []
        log.rename(tmp_path / "auth.log.1")
        log.write_text(_line(host="h2") + "\n" + _line(host="h3") + "\n", encoding="utf-8")
        events = await _drain_events(collector)
        collector._close()
        assert [e.host.name for e in events] == ["h2", "h3"]

    async def test_a_restarted_collector_resumes_where_it_stopped(self, tmp_path: Path) -> None:
        # The supervisor restarts a crashed collector's run(): the instance
        # keeps its offset, so neither history nor the lines it read reappear.
        log = tmp_path / "auth.log"
        log.write_text(_line(host="h1") + "\n", encoding="utf-8")
        collector = AuthLogCollector(log, year=YEAR, start_at_end=True)
        assert await _drain_events(collector) == []
        with log.open("a", encoding="utf-8") as handle:
            handle.write(_line(host="h2") + "\n")
        assert len(await _drain_events(collector)) == 1
        collector._close()  # what run()'s finally does when it crashes
        with log.open("a", encoding="utf-8") as handle:
            handle.write(_line(host="h3") + "\n")
        events = await _drain_events(collector)
        collector._close()
        assert [e.host.name for e in events] == ["h3"]


class TestSourceAvailability:
    """Regression: a missing auth log was silent — indistinguishable from a quiet host."""

    async def test_a_missing_log_is_reported_once_with_a_hint_and_its_return_too(
        self, tmp_path: Path
    ) -> None:
        log = tmp_path / "auth.log"
        collector = AuthLogCollector(log, year=YEAR)
        with capture_logs() as logs:
            for _ in range(3):
                await _drain_events(collector)
            available = [collector.source_available]
            log.write_text(_line() + "\n", encoding="utf-8")
            events = await _drain_events(collector)
            available.append(collector.source_available)
        collector._close()
        assert len(events) == 1
        assert available == [False, True]
        assert [e["event"] for e in logs] == [
            "collector.source_unavailable",
            "collector.source_available",
        ]
        assert "SENTINEL_AUTH_LOG_PATH" in logs[0]["hint"]


class _NthRecordDeadLettered(Normalizer):
    """Dead-letters only the n-th record it is given (1-based)."""

    def __init__(self, n: int) -> None:
        super().__init__()
        self._n = n
        self.calls = 0

    def normalize(self, raw: RawEvent) -> Event | None:
        self.calls += 1
        return None if self.calls == self._n else super().normalize(raw)


class TestMutationGaps:
    """Behaviours mutation testing showed no test pinned."""

    async def test_one_dead_letter_does_not_drop_the_rest_of_its_line(self, tmp_path: Path) -> None:
        # rsyslog's repeat summary turns one line into several records.
        log = tmp_path / "auth.log"
        log.write_text(
            _line() + "\n" + _line("message repeated 3 times: [ " + _FAILED + "]") + "\n",
            encoding="utf-8",
        )
        # Record 2 is the first of the repeated line's three.
        collector = AuthLogCollector(log, year=YEAR, normalizer=_NthRecordDeadLettered(2))
        events = await _drain_events(collector)
        collector._close()
        assert len(events) == 3  # 1 + 3 records, one dead-lettered

    async def test_lines_written_just_before_stop_are_read(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        log.write_text("", encoding="utf-8")
        collector = AuthLogCollector(log, year=YEAR, poll_interval=60)
        queue = BoundedEventQueue(maxsize=16)
        task = asyncio.create_task(collector.run(queue))
        assert await _wait_for(lambda: collector._handle is not None)  # first poll done
        log.write_text(_line() + "\n", encoding="utf-8")
        await collector.stop()  # long before the next 60 s poll
        await asyncio.wait_for(task, timeout=2)
        assert queue.qsize() == 1  # the final catch-up read it
