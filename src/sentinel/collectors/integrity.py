"""File-integrity monitoring (FIM) collector.

Watches a configured set of paths and emits an :class:`~sentinel.events.Event`
whenever a watched regular file is created, has its content changed, has its
POSIX permission bits changed, or is deleted. This is the AIDE/Tripwire-style
detection surface — tampering with ``/etc/passwd``, dropping a binary into
``/usr/local/bin``, or ``chmod 777`` on a sensitive file all surface here.

How it works: each poll builds a snapshot ``{path -> (size, mtime, mode,
sha256)}`` and diffs it against the previous one. The **first** poll seeds the
baseline silently — pre-existing files are the baseline, not "created" events —
and every later poll emits one event per transition.

Each event's ``event.id`` is a deterministic hash over the path, the action,
and the *new* content fingerprint, so re-observing the same transition (e.g. a
double poll or a re-baseline race) collapses to one event in the dedup window,
while a genuinely new modification (new content, hence new hash) is a new event.

Security posture (per the collector contract in
:mod:`sentinel.collectors.base`):

- **Only regular files are tracked.** ``lstat`` is used and symlinks, devices,
  sockets and directories-as-entries are skipped — the collector never follows
  a symlink, sidestepping traversal/TOCTOU tricks.
- **Bounded work.** Hashing is capped at ``max_hash_bytes`` (larger files fall
  back to size+mtime), and a scan visits at most ``max_files`` entries, so a
  watched directory that explodes in size cannot hang or OOM the process.
- **Degrades safely.** A path that cannot be read (permission denied, vanished
  mid-scan) is logged and skipped, never fatal.
- **Never blocks the event loop.** The whole scan runs in a worker thread via
  :func:`asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple

from sentinel.collectors.base import AbstractCollector
from sentinel.events import (
    Event,
    EventCategory,
    EventKind,
    EventMeta,
    EventOutcome,
    File,
    FileHash,
    Host,
)
from sentinel.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sentinel.pipeline.queue import BoundedEventQueue

_HASH_CHUNK: Final[int] = 1 << 16  # 64 KiB read window for streaming hashes.
_DEFAULT_MAX_HASH_BYTES: Final[int] = 50 * 1024 * 1024  # 50 MiB.
_DEFAULT_MAX_FILES: Final[int] = 50_000

_ACTION_CREATED: Final[str] = "file_created"
_ACTION_MODIFIED: Final[str] = "file_modified"
_ACTION_ATTRS: Final[str] = "file_attributes_modified"
_ACTION_DELETED: Final[str] = "file_deleted"

# ECS severity (0-7). A permission change or deletion on a watched path is the
# loudest; a brand-new file is notable; a content edit sits between.
_SEV_CREATED: Final[int] = 3
_SEV_MODIFIED: Final[int] = 4
_SEV_ATTRS: Final[int] = 5
_SEV_DELETED: Final[int] = 5


class _FileState(NamedTuple):
    """The integrity-relevant fingerprint of one regular file."""

    size: int
    mtime_ns: int
    mode: int
    sha256: str | None  # None when the file exceeds the hashing cap.


class FileIntegrityCollector(AbstractCollector):
    """Polls watched paths and emits an Event per file create/modify/delete."""

    name = "file-integrity"

    def __init__(
        self,
        paths: list[Path | str],
        *,
        recursive: bool = True,
        poll_interval: float = 5.0,
        host: str | None = None,
        max_hash_bytes: int = _DEFAULT_MAX_HASH_BYTES,
        max_files: int = _DEFAULT_MAX_FILES,
        name: str | None = None,
    ) -> None:
        super().__init__(name=name)
        if poll_interval <= 0:
            msg = f"poll_interval must be > 0; got {poll_interval}"
            raise ValueError(msg)
        if not paths:
            msg = "at least one watch path is required"
            raise ValueError(msg)
        self._paths = [Path(p) for p in paths]
        self._recursive = recursive
        self._poll = poll_interval
        self._host = host or socket.gethostname() or "localhost"
        self._max_hash_bytes = max_hash_bytes
        self._max_files = max_files
        self._log = get_logger("sentinel.collectors.integrity")
        self._baseline: dict[str, _FileState] = {}
        self._seeded = False
        self._emitted = 0

    async def run(self, queue: BoundedEventQueue) -> None:
        """Seed a baseline, then emit one event per change until stopped."""
        while not self.stopping:
            await self._drain_once(queue)
            if await self.wait_stop(timeout=self._poll):
                break
        # Final catch-up so a change made just before stop is not lost.
        await self._drain_once(queue)

    async def _drain_once(self, queue: BoundedEventQueue) -> None:
        """Scan, diff against the baseline, and enqueue the resulting events."""
        snapshot = await asyncio.to_thread(self._scan)
        if not self._seeded:
            self._baseline = snapshot
            self._seeded = True
            return
        events = self._diff(self._baseline, snapshot)
        self._baseline = snapshot
        for event in events:
            self._emitted += 1
            await queue.put(event)

    # ------------------------------------------------------------------ scanning

    def _scan(self) -> dict[str, _FileState]:
        """Build a fresh snapshot of every watched regular file (runs in a thread)."""
        snapshot: dict[str, _FileState] = {}
        for root in self._paths:
            for path in self._iter_files(root):
                if len(snapshot) >= self._max_files:
                    self._log.warning("integrity.max_files_reached", max_files=self._max_files)
                    return snapshot
                state = self._snapshot_file(path)
                if state is not None:
                    snapshot[str(path)] = state
        return snapshot

    def _iter_files(self, root: Path) -> Iterator[Path]:
        """Yield regular-file paths under `root` (a file yields itself)."""
        try:
            lst = root.lstat()
        except OSError as exc:
            self._log.warning("integrity.scan_error", path=str(root), error=str(exc))
            return
        if stat.S_ISREG(lst.st_mode):
            yield root
        elif stat.S_ISDIR(lst.st_mode):
            yield from self._walk(root)

    def _walk(self, directory: Path) -> Iterator[Path]:
        """Walk a directory for regular files without following symlinks."""
        # followlinks=False (default) keeps us from chasing symlinked dirs.
        for current, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                yield Path(current) / filename
            if not self._recursive:
                dirnames.clear()  # prune descent: top level only.

    def _snapshot_file(self, path: Path) -> _FileState | None:
        """Fingerprint one path, or None if it is not a readable regular file."""
        try:
            lst = path.lstat()
        except OSError:
            return None
        if not stat.S_ISREG(lst.st_mode):
            return None  # symlink, dir, socket, device — out of scope.
        sha256 = None
        if lst.st_size <= self._max_hash_bytes:
            sha256 = self._hash_file(path)
        return _FileState(
            size=lst.st_size,
            mtime_ns=lst.st_mtime_ns,
            mode=stat.S_IMODE(lst.st_mode),
            sha256=sha256,
        )

    def _hash_file(self, path: Path) -> str | None:
        """Stream a file's SHA-256, or None on read failure."""
        digest = hashlib.sha256()
        try:
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(_HASH_CHUNK), b""):
                    digest.update(chunk)
        except OSError:
            return None
        return digest.hexdigest()

    # ------------------------------------------------------------------ diffing

    def _diff(self, old: dict[str, _FileState], new: dict[str, _FileState]) -> list[Event]:
        """Compute the create/modify/attrs/delete events between two snapshots."""
        events: list[Event] = []
        for path, state in new.items():
            previous = old.get(path)
            if previous is None:
                events.append(self._created(path, state))
            elif _content_changed(previous, state):
                events.append(self._modified(path, state))
            elif previous.mode != state.mode:
                events.append(self._attrs_modified(path, state))
        for path, previous in old.items():
            if path not in new:
                events.append(self._deleted(path, previous))
        return events

    # ------------------------------------------------------------------ builders

    def _created(self, path: str, state: _FileState) -> Event:
        seed = state.sha256 or f"{state.size}:{state.mtime_ns}"
        return self._build(path, state, _ACTION_CREATED, _SEV_CREATED, seed)

    def _modified(self, path: str, state: _FileState) -> Event:
        # Fall back to size+mtime as the fingerprint when the file is unhashable,
        # so a later edit (new mtime) still reads as a distinct modification.
        seed = state.sha256 or f"{state.size}:{state.mtime_ns}"
        return self._build(path, state, _ACTION_MODIFIED, _SEV_MODIFIED, seed)

    def _attrs_modified(self, path: str, state: _FileState) -> Event:
        return self._build(path, state, _ACTION_ATTRS, _SEV_ATTRS, f"{state.mode:04o}")

    def _deleted(self, path: str, state: _FileState) -> Event:
        seed = state.sha256 or f"{state.size}:{state.mtime_ns}"
        return self._build(path, state, _ACTION_DELETED, _SEV_DELETED, seed)

    def _build(self, path: str, state: _FileState, action: str, severity: int, seed: str) -> Event:
        """Assemble an ECS file event with a content-derived, dedup-safe id."""
        return Event(
            timestamp=datetime.now(tz=UTC),
            event=EventMeta(
                id=Event.compute_id(path, action, seed),
                kind=EventKind.EVENT,
                category=EventCategory.FILE,
                action=action,
                outcome=EventOutcome.SUCCESS,
                severity=severity,
            ),
            host=Host(name=self._host),
            file=File(
                path=path,
                size=state.size,
                mode=f"{state.mode:04o}",
                hash=FileHash(sha256=state.sha256),
            ),
            message=f"{action}: {path}",
        )

    @property
    def stats(self) -> dict[str, int]:
        """Snapshot counters for observability and tests."""
        return {"emitted": self._emitted, "watched": len(self._baseline)}


def _content_changed(old: _FileState, new: _FileState) -> bool:
    """True if file content changed between snapshots.

    Prefers the hash; for unhashable files (no digest on either side) falls back
    to size or mtime drift.
    """
    if old.sha256 is not None and new.sha256 is not None:
        return old.sha256 != new.sha256
    return old.size != new.size or old.mtime_ns != new.mtime_ns
