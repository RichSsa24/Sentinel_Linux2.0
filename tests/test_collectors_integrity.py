"""Tests for `sentinel.collectors.integrity`.

Layers, mirroring the auth-log collector's test strategy:

1. **Diff logic** — `_diff` / `_content_changed` are exercised with synthetic
   `_FileState` snapshots, so create/modify/attrs/delete classification is
   pinned deterministically and without relying on OS-specific `chmod`
   semantics (which differ on Windows).
2. **Scanning** — the collector reads real files in `tmp_path`: baseline is
   silent, regular-file creation/modification/deletion is detected, non-regular
   entries and missing paths are skipped safely, and the hashing/scan caps hold.
3. **Exactly-once (the payoff)** — drives the collector through the real
   `Pipeline` and shows that a re-baseline race re-emits an identical change,
   yet the consumer sees it exactly once.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from pathlib import Path

import pytest

from sentinel.collectors.integrity import (
    FileIntegrityCollector,
    _content_changed,
    _FileState,
)
from sentinel.events import Event
from sentinel.pipeline.queue import BoundedEventQueue
from sentinel.pipeline.runner import Pipeline
from tests.conftest import DeadLetterNormalizer, settings_no_env_file

H1 = "a" * 64
H2 = "b" * 64


def _state(
    sha256: str | None = H1,
    *,
    size: int = 10,
    mtime_ns: int = 1_000,
    mode: int = 0o644,
) -> _FileState:
    return _FileState(size=size, mtime_ns=mtime_ns, mode=mode, sha256=sha256)


def _collector(tmp_path: Path, **kwargs: object) -> FileIntegrityCollector:
    """A collector with a deterministic host, watching `tmp_path`."""
    return FileIntegrityCollector([tmp_path], host="testhost", **kwargs)  # type: ignore[arg-type]


async def _wait_for(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:  # noqa: ASYNC109 — poll loop, not an `asyncio.timeout()` block
    loop = asyncio.get_event_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.01)
    return False


class TestConstruction:
    def test_rejects_non_positive_poll_interval(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="poll_interval"):
            FileIntegrityCollector([tmp_path], poll_interval=0)

    def test_rejects_empty_paths(self) -> None:
        with pytest.raises(ValueError, match="watch path"):
            FileIntegrityCollector([])


class TestDiff:
    def test_created(self, tmp_path: Path) -> None:
        records = _collector(tmp_path)._diff({}, {"/etc/x": _state(H1)})

        assert len(records) == 1
        assert records[0].action == "file_created"
        assert records[0].path == "/etc/x"
        assert records[0].sha256 == H1

    def test_modified_on_content_change(self, tmp_path: Path) -> None:
        records = _collector(tmp_path)._diff({"/etc/x": _state(H1)}, {"/etc/x": _state(H2)})

        assert len(records) == 1
        assert records[0].action == "file_modified"
        assert records[0].sha256 == H2

    def test_attributes_modified_on_mode_change_only(self, tmp_path: Path) -> None:
        records = _collector(tmp_path)._diff(
            {"/etc/x": _state(H1, mode=0o644)},
            {"/etc/x": _state(H1, mode=0o600)},
        )

        assert len(records) == 1
        assert records[0].action == "file_attributes_modified"
        assert records[0].mode == "0600"

    def test_content_change_takes_precedence_over_mode(self, tmp_path: Path) -> None:
        records = _collector(tmp_path)._diff(
            {"/etc/x": _state(H1, mode=0o644)},
            {"/etc/x": _state(H2, mode=0o600)},
        )

        assert len(records) == 1
        assert records[0].action == "file_modified"

    def test_deleted(self, tmp_path: Path) -> None:
        records = _collector(tmp_path)._diff({"/etc/x": _state(H1)}, {})

        assert len(records) == 1
        assert records[0].action == "file_deleted"

    def test_unchanged_emits_nothing(self, tmp_path: Path) -> None:
        snap = {"/etc/x": _state(H1)}
        assert _collector(tmp_path)._diff(snap, dict(snap)) == []

    def test_same_change_yields_the_same_id_seed(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path)
        first = collector._diff({}, {"/etc/x": _state(H1)})
        second = collector._diff({}, {"/etc/x": _state(H1)})

        # Same change -> same content fingerprint -> the normalizer derives the
        # same event.id, collapsing a re-baseline race in the dedup window.
        assert first[0].id_seed == second[0].id_seed


class TestContentChanged:
    def test_hash_difference_is_change(self) -> None:
        assert _content_changed(_state(H1), _state(H2)) is True

    def test_identical_hash_is_not_change(self) -> None:
        assert _content_changed(_state(H1), _state(H1)) is False

    def test_unhashable_falls_back_to_size(self) -> None:
        assert _content_changed(_state(None, size=1), _state(None, size=2)) is True

    def test_unhashable_falls_back_to_mtime(self) -> None:
        old = _state(None, mtime_ns=1)
        new = _state(None, mtime_ns=2)
        assert _content_changed(old, new) is True

    def test_unhashable_identical_is_not_change(self) -> None:
        assert _content_changed(_state(None), _state(None)) is False


async def _drain(collector: FileIntegrityCollector) -> list[Event]:
    """Run one scan/diff cycle and return the events it would enqueue."""
    queue = BoundedEventQueue(maxsize=128)
    await collector._drain_once(queue)
    events: list[Event] = []
    while not queue.empty():
        events.append(await queue.get())
        queue.task_done()
    return events


class TestScanning:
    @pytest.mark.asyncio
    async def test_first_scan_is_silent_baseline(self, tmp_path: Path) -> None:
        (tmp_path / "pre-existing.txt").write_text("seed", encoding="utf-8")
        collector = _collector(tmp_path)

        assert await _drain(collector) == []  # baseline seeded, nothing emitted
        assert collector.stats["watched"] == 1

    @pytest.mark.asyncio
    async def test_detects_created(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path)
        await _drain(collector)  # seed empty baseline

        (tmp_path / "new.txt").write_text("hello", encoding="utf-8")
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].event.action == "file_created"
        assert events[0].file is not None
        assert events[0].file.hash.sha256 is not None

    @pytest.mark.asyncio
    async def test_detects_modified(self, tmp_path: Path) -> None:
        target = tmp_path / "watch.txt"
        target.write_text("v1", encoding="utf-8")
        collector = _collector(tmp_path)
        await _drain(collector)  # baseline includes the file

        target.write_text("v2-different", encoding="utf-8")
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].event.action == "file_modified"

    @pytest.mark.asyncio
    async def test_detects_deleted(self, tmp_path: Path) -> None:
        target = tmp_path / "doomed.txt"
        target.write_text("bye", encoding="utf-8")
        collector = _collector(tmp_path)
        await _drain(collector)

        target.unlink()
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].event.action == "file_deleted"

    @pytest.mark.asyncio
    async def test_unhashable_file_has_no_digest(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path, max_hash_bytes=0)  # nothing is hashed
        await _drain(collector)

        (tmp_path / "big.bin").write_text("content", encoding="utf-8")
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].file is not None
        assert events[0].file.hash.sha256 is None

    @pytest.mark.asyncio
    async def test_unhashable_file_modification_detected_by_size(self, tmp_path: Path) -> None:
        target = tmp_path / "big.bin"
        target.write_text("v1", encoding="utf-8")
        collector = _collector(tmp_path, max_hash_bytes=0)  # never hashes
        await _drain(collector)  # baseline (no digest)

        target.write_text("v2-longer", encoding="utf-8")  # size changes
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].event.action == "file_modified"
        assert events[0].file is not None
        assert events[0].file.hash.sha256 is None

    @pytest.mark.asyncio
    async def test_subdirectories_are_not_tracked_as_files(self, tmp_path: Path) -> None:
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "nested.txt").write_text("x", encoding="utf-8")
        collector = _collector(tmp_path)  # recursive by default
        await _drain(collector)

        # The directory entry itself is not a watched file; the nested file is.
        assert collector.stats["watched"] == 1

    @pytest.mark.asyncio
    async def test_non_recursive_ignores_nested_files(self, tmp_path: Path) -> None:
        (tmp_path / "top.txt").write_text("a", encoding="utf-8")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "deep.txt").write_text("b", encoding="utf-8")
        collector = _collector(tmp_path, recursive=False)
        await _drain(collector)

        assert collector.stats["watched"] == 1  # only top.txt

    @pytest.mark.asyncio
    async def test_missing_watch_path_is_not_fatal(self, tmp_path: Path) -> None:
        collector = FileIntegrityCollector([tmp_path / "nope"], host="testhost")
        assert await _drain(collector) == []
        assert collector.stats["watched"] == 0

    @pytest.mark.asyncio
    async def test_max_files_cap_bounds_the_snapshot(self, tmp_path: Path) -> None:
        for i in range(3):
            (tmp_path / f"f{i}.txt").write_text("x", encoding="utf-8")
        collector = _collector(tmp_path, max_files=1)
        await _drain(collector)

        assert collector.stats["watched"] == 1


class TestSafeDegradation:
    """The security-posture claim: a file we cannot read is skipped, not fatal."""

    def test_snapshot_skips_file_whose_lstat_is_denied(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "locked.txt"
        target.write_text("secret", encoding="utf-8")

        def _denied(self: Path) -> object:
            raise PermissionError("EACCES")

        monkeypatch.setattr(Path, "lstat", _denied)
        assert _collector(tmp_path)._snapshot_file(target) is None

    def test_hash_returns_none_when_open_is_denied(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = tmp_path / "locked.bin"
        target.write_text("secret", encoding="utf-8")

        def _denied(self: Path, *args: object, **kwargs: object) -> object:
            raise PermissionError("EACCES")

        monkeypatch.setattr(Path, "open", _denied)
        assert _collector(tmp_path)._hash_file(target) is None


class TestDeadLetter:
    @pytest.mark.asyncio
    async def test_unmappable_record_is_skipped_not_enqueued(self, tmp_path: Path) -> None:
        watched = tmp_path / "f.txt"
        watched.write_text("v1", encoding="utf-8")
        collector = _collector(tmp_path, normalizer=DeadLetterNormalizer())
        await _drain(collector)  # baseline includes f.txt

        watched.write_text("v2-changed-content", encoding="utf-8")
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
            assert await _wait_for(lambda: collector._seeded)  # empty baseline seeded

            (tmp_path / "agent.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            assert await _wait_for(
                lambda: collector.stats["emitted"] == 1 and pipeline.stats["queue_size"] == 0
            )

            # Simulate a re-baseline race: the collector "forgets" the file and
            # re-detects it as created — same path, same content, same event.id.
            collector._baseline = {}
            assert await _wait_for(
                lambda: collector.stats["emitted"] == 2 and pipeline.stats["queue_size"] == 0
            )
        finally:
            await pipeline.stop()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.wait_for(run_task, timeout=5.0)

        # Emitted twice by the collector, delivered once to the consumer.
        assert collector.stats["emitted"] == 2
        assert received == received[:1]  # exactly one id
        assert pipeline.stats["processed"] == 1
        assert pipeline.stats["deduped"] == 1
