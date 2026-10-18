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
import hashlib
import os
import time
from collections.abc import Callable
from pathlib import Path

import pytest
from structlog.testing import capture_logs

from sentinel.collectors.integrity import (
    FileIntegrityCollector,
    _content_changed,
    _FileState,
)
from sentinel.events import Event
from sentinel.normalizer import MAX_PATH
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

    @pytest.mark.security
    def test_content_and_mode_change_in_one_poll_report_both(self, tmp_path: Path) -> None:
        # Regression: content took precedence, so overwriting a binary and making
        # it setuid inside one poll emitted only file_modified, which the
        # new-suid-binary rule (created / attributes_modified) never sees.
        records = _collector(tmp_path)._diff(
            {"/usr/local/bin/helper": _state(H1, mode=0o755)},
            {"/usr/local/bin/helper": _state(H2, mode=0o4755)},
        )

        assert [r.action for r in records] == ["file_modified", "file_attributes_modified"]
        assert records[1].mode == "4755"

    @pytest.mark.parametrize("owner", [{"uid": 1000}, {"gid": 42}], ids=["chown", "chgrp"])
    def test_ownership_change_is_an_attributes_change(
        self, tmp_path: Path, owner: dict[str, int]
    ) -> None:
        # `chown attacker /etc/sudoers` leaves content and mode intact.
        before = _state(H1)
        after = before._replace(uid=owner.get("uid", 0), gid=owner.get("gid", 0))
        records = _collector(tmp_path)._diff({"/etc/sudoers": before}, {"/etc/sudoers": after})

        assert [r.action for r in records] == ["file_attributes_modified"]
        unchanged = _collector(tmp_path)._attrs_modified("/x", before)
        assert unchanged is not None
        assert records[0].id_seed != unchanged.id_seed

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

    @pytest.mark.security
    def test_unhashable_ctime_move_is_change(self) -> None:
        # Unreadable file, same size, mtime restored with `touch -d`: only the
        # kernel-maintained ctime gives the edit away.
        old = _state(None)._replace(ctime_ns=100)
        new = _state(None)._replace(ctime_ns=200)
        assert _content_changed(old, new) is True

    @pytest.mark.security
    @pytest.mark.parametrize(
        "after",
        [
            _state(None, mode=0o600)._replace(ctime_ns=200),
            _state(None)._replace(ctime_ns=200, uid=1000),
            _state(None)._replace(ctime_ns=200, gid=42),
        ],
        ids=["chmod", "chown", "chgrp"],
    )
    def test_unhashable_ctime_move_with_metadata_change_is_still_change(
        self, after: _FileState
    ) -> None:
        # Regression: a ctime move that a metadata change could explain was
        # treated as metadata only, so a forged edit of an unreadable file
        # (same length, mtime restored) followed by `chgrp` emitted nothing.
        # The collector cannot tell the two apart, so it must not stay silent.
        before = _state(None)._replace(ctime_ns=100)
        assert _content_changed(before, after) is True


class TestFingerprint:
    @pytest.mark.security
    def test_repeated_forged_edits_of_an_unhashable_file_get_distinct_ids(
        self, tmp_path: Path
    ) -> None:
        # Two same-length edits with the mtime restored each time: only ctime
        # differs. If it were not in the fingerprint, the second edit would hash
        # to the first one's event.id and the dedup window would swallow it.
        collector = _collector(tmp_path)
        base = _state(None)._replace(ctime_ns=100)
        first = collector._diff({"/etc/shadow": base}, {"/etc/shadow": base._replace(ctime_ns=200)})
        second = collector._diff(
            {"/etc/shadow": base._replace(ctime_ns=200)},
            {"/etc/shadow": base._replace(ctime_ns=300)},
        )
        assert [r.action for r in first + second] == ["file_modified", "file_modified"]
        assert first[0].id_seed != second[0].id_seed

    def test_hashable_fingerprint_leads_with_the_digest(self, tmp_path: Path) -> None:
        records = _collector(tmp_path)._diff({}, {"/etc/x": _state(H1)._replace(ctime_ns=5)})
        assert records[0].id_seed.startswith(H1)


@pytest.mark.security
class TestReturningToAnEarlierState:
    """Regression: ids derived from content or mode alone repeated on A -> B -> A.

    The repeat got the id of the event already reported for A, and the dedup
    window (60 s by default) dropped it: re-adding a reverted backdoor line, or
    setting setuid again, went unreported.
    """

    def test_re_applied_content_gets_a_new_id(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path)
        clean = _state(H1)._replace(ctime_ns=100, inode=7)
        backdoor = _state(H2)._replace(ctime_ns=200, inode=7)
        reverted = clean._replace(ctime_ns=300)
        again = backdoor._replace(ctime_ns=400)
        first = collector._diff({"/etc/sudoers": clean}, {"/etc/sudoers": backdoor})
        collector._diff({"/etc/sudoers": backdoor}, {"/etc/sudoers": reverted})
        second = collector._diff({"/etc/sudoers": reverted}, {"/etc/sudoers": again})
        assert [r.action for r in first + second] == ["file_modified", "file_modified"]
        assert first[0].id_seed != second[0].id_seed

    def test_re_applied_setuid_gets_a_new_id(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path)
        plain = _state(H1, mode=0o755)._replace(ctime_ns=100)
        setuid = _state(H1, mode=0o4755)._replace(ctime_ns=200)
        first = collector._diff({"/usr/bin/x": plain}, {"/usr/bin/x": setuid})
        collector._diff({"/usr/bin/x": setuid}, {"/usr/bin/x": plain._replace(ctime_ns=300)})
        second = collector._diff(
            {"/usr/bin/x": plain._replace(ctime_ns=300)},
            {"/usr/bin/x": setuid._replace(ctime_ns=400)},
        )
        assert first[0].id_seed != second[0].id_seed

    def test_recreating_the_same_bytes_gets_a_new_id(self, tmp_path: Path) -> None:
        # Copy a binary 0755, delete it, recreate the same bytes 4755: the new
        # file has another inode and ctime, so its creation is a new event.
        collector = _collector(tmp_path)
        benign = _state(H1, mode=0o755)._replace(ctime_ns=100, inode=7)
        setuid = _state(H1, mode=0o4755)._replace(ctime_ns=200, inode=8)
        first = collector._diff({}, {"/usr/local/bin/x": benign})
        second = collector._diff({}, {"/usr/local/bin/x": setuid})
        assert first[0].id_seed != second[0].id_seed

    def test_re_observing_one_transition_keeps_its_id(self, tmp_path: Path) -> None:
        collector = _collector(tmp_path)
        before = _state(H1)._replace(ctime_ns=100, inode=7)
        after = _state(H2)._replace(ctime_ns=200, inode=7)
        once = collector._diff({"/etc/x": before}, {"/etc/x": after})
        twice = collector._diff({"/etc/x": before}, {"/etc/x": after})
        assert once[0].id_seed == twice[0].id_seed  # the dedup still collapses this


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
    async def test_the_baseline_is_announced(self, tmp_path: Path) -> None:
        # A restart re-seeds the baseline: changes made while the service was
        # down are invisible, so the moment it happens must be on record.
        (tmp_path / "a.txt").write_text("a", encoding="utf-8")
        (tmp_path / "b.txt").write_text("b", encoding="utf-8")
        with capture_logs() as logs:
            await _drain(_collector(tmp_path))
        assert [(e["event"], e["files"]) for e in logs] == [("integrity.baseline_seeded", 2)]

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

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_forged_edit_of_unhashable_file_is_not_masked_by_a_hard_link(
        self, tmp_path: Path
    ) -> None:
        # Regression: a same-length edit with the mtime restored, plus a hard
        # link (which also moves ctime), was taken for metadata only: no event.
        watched = tmp_path / "etc"
        watched.mkdir()
        target = watched / "shadow"
        target.write_text("root:AAAA\n", encoding="utf-8")
        collector = _collector(watched, max_hash_bytes=0)  # like an unreadable file
        await _drain(collector)
        before = target.stat()
        await asyncio.sleep(0.05)  # past the kernel's coarse timestamp tick, so ctime moves

        target.write_text("root:BBBB\n", encoding="utf-8")
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
        os.link(target, tmp_path / "elsewhere")

        events = await _drain(collector)
        assert [e.event.action for e in events] == ["file_modified"]

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_a_file_with_an_undecodable_name_cannot_crash_the_collector(
        self, tmp_path: Path
    ) -> None:
        # Regression: a file named with non-UTF-8 bytes in a watched path failed
        # event validation; the collector raised and the pipeline stopped.
        collector = _collector(tmp_path)
        await _drain(collector)
        (tmp_path / os.fsdecode(b"evil\xff")).write_bytes(b"x")
        events = await _drain(collector)

        assert [e.event.action for e in events] == ["file_created"]
        assert events[0].file is not None
        assert events[0].file.path.endswith("/evil\\xff")

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_a_long_undecodable_path_is_clipped_not_fatal(self, tmp_path: Path) -> None:
        # Regression: escaping inflates each undecodable byte to four characters,
        # so a ~1,250-byte path of 0xff passed the 4,096-character limit and
        # the collector raised.
        deep = tmp_path
        for _ in range(5):
            deep = deep / os.fsdecode(b"\xff" * 250)
        deep.mkdir(parents=True)
        collector = _collector(tmp_path, recursive=True)
        await _drain(collector)
        (deep / "payload").write_bytes(b"x")
        events = await _drain(collector)

        assert [e.event.action for e in events] == ["file_created"]
        assert events[0].file is not None
        assert len(events[0].file.path) <= MAX_PATH
        assert events[0].file.path.endswith("/payload")

    @pytest.mark.asyncio
    async def test_a_missing_watch_path_is_reported_once(self, tmp_path: Path) -> None:
        # Regression: a missing path (e.g. no /var/spool/cron) logged a warning
        # on every poll, forever.
        missing = tmp_path / "absent"
        collector = FileIntegrityCollector([missing], host="testhost")
        with capture_logs() as logs:
            for _ in range(3):
                await _drain(collector)
            missing.mkdir()
            await _drain(collector)
        events = [entry["event"] for entry in logs]
        assert events.count("integrity.scan_error") == 1
        assert events.count("integrity.path_available") == 1

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

        def _denied(*args: object, **kwargs: object) -> int:
            raise PermissionError("EACCES")

        expected = target.lstat()
        monkeypatch.setattr(os, "open", _denied)
        assert _collector(tmp_path)._hash_file(target, expected) is None


@pytest.mark.security
class TestEntrySwappedAfterLstat:
    """Regression: the scan hashed with a plain open() after classifying with lstat.

    Whoever can write to a watched directory could swap the entry in between:
    a FIFO blocked the scan thread forever, a symlink to /dev/zero never ended.
    Each case must now return promptly with "unhashable".
    """

    def test_a_fifo_is_refused_without_blocking(self, tmp_path: Path) -> None:
        regular = tmp_path / "f"
        regular.write_bytes(b"x")
        expected = regular.lstat()
        regular.unlink()
        os.mkfifo(regular)
        assert _collector(tmp_path)._hash_file(regular, expected) is None

    def test_a_symlink_is_not_followed(self, tmp_path: Path) -> None:
        regular = tmp_path / "f"
        regular.write_bytes(b"x")
        expected = regular.lstat()
        regular.unlink()
        regular.symlink_to("/dev/zero")
        assert _collector(tmp_path)._hash_file(regular, expected) is None

    def test_a_different_file_is_refused(self, tmp_path: Path) -> None:
        regular = tmp_path / "f"
        regular.write_bytes(b"x")
        expected = regular.lstat()
        replacement = tmp_path / "g"
        replacement.write_bytes(b"x")
        replacement.replace(regular)  # same name, another inode
        assert _collector(tmp_path)._hash_file(regular, expected) is None

    def test_reading_stops_at_the_hash_cap(self, tmp_path: Path) -> None:
        grown = tmp_path / "f"
        grown.write_bytes(b"x" * 64)
        collector = _collector(tmp_path, max_hash_bytes=16)
        assert collector._hash_file(grown, grown.lstat()) is None

    def test_an_unchanged_file_still_hashes(self, tmp_path: Path) -> None:
        regular = tmp_path / "f"
        regular.write_bytes(b"abc")
        digest = _collector(tmp_path)._hash_file(regular, regular.lstat())
        assert digest == hashlib.sha256(b"abc").hexdigest()


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


class TestHostRoot:
    """Containerized FIM: scan beneath a host-root mount, report host-native paths."""

    @pytest.mark.asyncio
    async def test_reports_host_native_paths(self, tmp_path: Path) -> None:
        etc = tmp_path / "etc"
        etc.mkdir()
        collector = FileIntegrityCollector(["/etc"], host="testhost", host_root=tmp_path)
        await _drain(collector)  # seed empty baseline

        (etc / "passwd").write_text("root:x:0:0::/root:/bin/sh\n", encoding="utf-8")
        events = await _drain(collector)

        assert len(events) == 1
        assert events[0].file is not None
        # Rules match `^/etc/...`; the mount prefix must never leak into events.
        assert events[0].file.path == "/etc/passwd"

    @pytest.mark.asyncio
    async def test_relative_watch_path_is_left_untouched(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        (tmp_path / "local").mkdir()
        collector = FileIntegrityCollector(["local"], host="testhost", host_root="/host")
        await _drain(collector)
        (tmp_path / "local" / "f.txt").write_text("x", encoding="utf-8")
        events = await _drain(collector)
        assert [e.file.path for e in events if e.file] == ["local/f.txt"]


class TestStatCache:
    """Unchanged files are not re-hashed — without opening a tampering blind spot."""

    @staticmethod
    def _clock_ahead(monkeypatch: pytest.MonkeyPatch, seconds: float = 30.0) -> None:
        # Files written moments ago would be "racy" (re-hashed every poll); move
        # the scan clock forward so they look settled and become cacheable.
        real = time.time_ns
        monkeypatch.setattr(time, "time_ns", lambda: real() + int(seconds * 1e9))

    def test_settled_unchanged_files_reuse_their_digest(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for i in range(5):
            (tmp_path / f"f{i}").write_text(f"content {i}", encoding="utf-8")
        self._clock_ahead(monkeypatch)
        collector = _collector(tmp_path)
        first = collector._scan()
        second = collector._scan(first)
        assert collector.stats["hashed"] == 5  # first scan only
        assert collector.stats["hash_reused"] == 5
        assert second == first

    def test_racy_entries_are_rehashed(self, tmp_path: Path) -> None:
        # Written "now": the kernel's coarse clock could hide a same-tick rewrite,
        # so the cache must not be trusted yet.
        (tmp_path / "fresh").write_text("v1", encoding="utf-8")
        collector = _collector(tmp_path)
        collector._scan(collector._scan())
        assert collector.stats["hash_reused"] == 0
        assert collector.stats["hashed"] == 2

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_same_size_edit_with_restored_mtime_is_detected(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The classic FIM evasion: same length, then `touch -d` the old mtime back.
        target = tmp_path / "sudoers"
        target.write_text("root ALL=(ALL) ALL\n", encoding="utf-8")
        self._clock_ahead(monkeypatch)
        collector = _collector(tmp_path)
        await _drain(collector)  # baseline, cacheable
        before = target.stat()

        target.write_text("evil ALL=(ALL) ALL\n", encoding="utf-8")  # same length
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
        assert target.stat().st_mtime_ns == before.st_mtime_ns
        assert target.stat().st_size == before.st_size

        events = await _drain(collector)
        assert [e.event.action for e in events] == ["file_modified"]
