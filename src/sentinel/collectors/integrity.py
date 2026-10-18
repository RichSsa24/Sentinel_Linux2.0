"""File-integrity monitoring (FIM) collector.

Watches a configured set of paths and emits an :class:`~sentinel.events.Event`
whenever a watched regular file is created, has its content changed, has its
POSIX permission bits or ownership changed, or is deleted. This is the AIDE/Tripwire-style
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
- **Hash only what changed (stat cache).** A file whose ``(size, mtime, ctime,
  inode, device)`` is unchanged since the last poll keeps its previous digest
  instead of being re-read. ``mtime`` alone would not be safe — an attacker can
  restore it with ``touch -d`` — but ``ctime`` is updated by the kernel on every
  write, ``chmod`` and ``utimensat`` and cannot be set from userspace (forging
  it means changing the system clock, i.e. ``CAP_SYS_TIME``). Because the
  kernel stamps times from a coarse clock, two writes inside one tick can share
  a ``ctime``; as in Git's "racy clean" handling, an entry whose ``ctime`` is
  within ``_RACY_WINDOW_NS`` of the scan is never trusted from cache and is
  re-hashed on the next poll.
- **Degrades safely.** A path that cannot be read (permission denied, vanished
  mid-scan) is logged and skipped, never fatal.
- **Never blocks the event loop.** The whole scan runs in a worker thread via
  :func:`asyncio.to_thread`.

Containerized deployments mount the host's filesystem read-only under a
``host_root`` (e.g. ``/host``). The collector then scans ``/host/etc`` but keys
and reports every file by its host-native path (``/etc/passwd``), so rules and
investigators never see the mount prefix.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import socket
import stat
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple

from sentinel.collectors.base import AbstractCollector, under_host_root
from sentinel.logging import get_logger
from sentinel.normalizer import Normalizer, RawFileEvent

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sentinel.pipeline.queue import BoundedEventQueue

_HASH_CHUNK: Final[int] = 1 << 16  # 64 KiB read window for streaming hashes.
_DEFAULT_MAX_HASH_BYTES: Final[int] = 50 * 1024 * 1024  # 50 MiB.
_DEFAULT_MAX_FILES: Final[int] = 50_000
# Entries changed this recently (relative to the scan start) are re-hashed next
# poll even if their stat is unchanged: far wider than the kernel's timestamp
# granularity (one jiffy, 1-10 ms) plus ordinary clock jitter.
_RACY_WINDOW_NS: Final[int] = 2_000_000_000

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
    # Stat-cache key beyond size/mtime (see module docstring). `cacheable` is
    # False for entries too recent to trust, forcing a re-hash next poll.
    ctime_ns: int = 0
    inode: int = 0
    device: int = 0
    cacheable: bool = False
    # Ownership: a `chown` is reported as an attributes change, like a `chmod`.
    uid: int = 0
    gid: int = 0

    def same_stat(self, other: _FileState) -> bool:
        """True if `other` has the identical stat fingerprint (content assumed same)."""
        return (
            self.size == other.size
            and self.mtime_ns == other.mtime_ns
            and self.ctime_ns == other.ctime_ns
            and self.inode == other.inode
            and self.device == other.device
        )


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
        host_root: Path | str = "/",
        normalizer: Normalizer | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(name=name)
        if poll_interval <= 0:
            msg = f"poll_interval must be > 0; got {poll_interval}"
            raise ValueError(msg)
        if not paths:
            msg = "at least one watch path is required"
            raise ValueError(msg)
        self._host_root = Path(host_root)
        self._paths = [Path(p) for p in paths]
        self._recursive = recursive
        self._poll = poll_interval
        self._host = host or socket.gethostname() or "localhost"
        self._max_hash_bytes = max_hash_bytes
        self._max_files = max_files
        self._normalizer = normalizer or Normalizer()
        self._log = get_logger("sentinel.collectors.integrity")
        self._baseline: dict[str, _FileState] = {}
        self._seeded = False
        self._emitted = 0
        self._hashed = 0
        self._hash_reused = 0

    async def run(self, queue: BoundedEventQueue) -> None:
        """Seed a baseline, then emit one event per change until stopped."""
        while not self.stopping:
            await self._drain_once(queue)
            if await self.wait_stop(timeout=self._poll):
                break
        # Final catch-up so a change made just before stop is not lost.
        await self._drain_once(queue)

    async def _drain_once(self, queue: BoundedEventQueue) -> None:
        """Scan, diff, normalize each change, and enqueue the resulting events."""
        snapshot = await asyncio.to_thread(self._scan, self._baseline)
        if not self._seeded:
            self._baseline = snapshot
            self._seeded = True
            return
        records = self._diff(self._baseline, snapshot)
        self._baseline = snapshot
        for raw in records:
            event = self._normalizer.normalize(raw)
            if event is None:
                continue  # unmappable record: dead-lettered by the normalizer
            self._emitted += 1
            await queue.put(event)

    # ------------------------------------------------------------------ scanning

    def _scan(self, previous: dict[str, _FileState] | None = None) -> dict[str, _FileState]:
        """Build a fresh snapshot of every watched regular file (runs in a thread).

        `previous` is the last snapshot; its digests are reused for files whose
        stat fingerprint is unchanged (the stat cache).
        """
        previous = previous or {}
        racy_after_ns = time.time_ns() - _RACY_WINDOW_NS
        snapshot: dict[str, _FileState] = {}
        for root in self._paths:
            for path in self._iter_files(under_host_root(self._host_root, root)):
                if len(snapshot) >= self._max_files:
                    self._log.warning("integrity.max_files_reached", max_files=self._max_files)
                    return snapshot
                key = self._host_path(path)
                state = self._snapshot_file(path, previous.get(key), racy_after_ns)
                if state is not None:
                    snapshot[key] = state
        return snapshot

    def _host_path(self, on_disk: Path) -> str:
        """The host-native path reported for a file found under the host root."""
        if self._host_root == Path("/"):
            return str(on_disk)
        try:
            return str(Path("/") / on_disk.relative_to(self._host_root))
        except ValueError:  # a relative watch path that is not under the root
            return str(on_disk)

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

    def _snapshot_file(
        self, path: Path, previous: _FileState | None = None, racy_after_ns: int = 0
    ) -> _FileState | None:
        """Fingerprint one path, or None if it is not a readable regular file."""
        try:
            lst = path.lstat()
        except OSError:
            return None
        if not stat.S_ISREG(lst.st_mode):
            return None  # symlink, dir, socket, device — out of scope.
        state = _FileState(
            size=lst.st_size,
            mtime_ns=lst.st_mtime_ns,
            mode=stat.S_IMODE(lst.st_mode),
            sha256=None,
            ctime_ns=lst.st_ctime_ns,
            inode=lst.st_ino,
            device=lst.st_dev,
            cacheable=lst.st_ctime_ns < racy_after_ns,
            uid=lst.st_uid,
            gid=lst.st_gid,
        )
        if previous is not None and previous.cacheable and previous.same_stat(state):
            self._hash_reused += 1
            return state._replace(sha256=previous.sha256)
        if lst.st_size <= self._max_hash_bytes:
            self._hashed += 1
            return state._replace(sha256=self._hash_file(path))
        return state

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

    def _diff(self, old: dict[str, _FileState], new: dict[str, _FileState]) -> list[RawFileEvent]:
        """Compute create/modify/attrs/delete raw records between two snapshots.

        Content and attribute changes are reported independently: a rewrite plus
        ``chmod u+s`` in one poll yields both events, so the setuid change still
        reaches the rules that match attribute changes.
        """
        records: list[RawFileEvent] = []
        for path, state in new.items():
            previous = old.get(path)
            if previous is None:
                records.append(self._created(path, state))
                continue
            if _content_changed(previous, state):
                records.append(self._modified(path, state))
            if _attributes_changed(previous, state):
                records.append(self._attrs_modified(path, state))
        for path, previous in old.items():
            if path not in new:
                records.append(self._deleted(path, previous))
        return records

    # ------------------------------------------------------------------ builders

    def _created(self, path: str, state: _FileState) -> RawFileEvent:
        return self._raw(path, state, _ACTION_CREATED, _SEV_CREATED, _fingerprint(state))

    def _modified(self, path: str, state: _FileState) -> RawFileEvent:
        return self._raw(path, state, _ACTION_MODIFIED, _SEV_MODIFIED, _fingerprint(state))

    def _attrs_modified(self, path: str, state: _FileState) -> RawFileEvent:
        seed = f"{state.mode:04o}:{state.uid}:{state.gid}"
        return self._raw(path, state, _ACTION_ATTRS, _SEV_ATTRS, seed)

    def _deleted(self, path: str, state: _FileState) -> RawFileEvent:
        return self._raw(path, state, _ACTION_DELETED, _SEV_DELETED, _fingerprint(state))

    def _raw(
        self, path: str, state: _FileState, action: str, severity: int, seed: str
    ) -> RawFileEvent:
        """Build the raw file record the normalizer maps to an ECS Event."""
        return RawFileEvent(
            occurred_at=datetime.now(tz=UTC),
            host=self._host,
            action=action,
            severity=severity,
            path=path,
            size=state.size,
            mode=f"{state.mode:04o}",
            sha256=state.sha256,
            id_seed=seed,
        )

    @property
    def stats(self) -> dict[str, int]:
        """Snapshot counters for observability and tests."""
        return {
            "emitted": self._emitted,
            "watched": len(self._baseline),
            "hashed": self._hashed,
            "hash_reused": self._hash_reused,
            "dead_lettered": self._normalizer.stats["dead_letters"],
        }


def _fingerprint(state: _FileState) -> str:
    """The content fingerprint an event id derives from.

    The digest when there is one. For an unhashable file it is size, mtime *and*
    ctime: two forged edits that restore the same size and mtime still differ in
    ctime, so the second is not mistaken for a re-observation of the first and
    dropped by the dedup window. Re-observing one transition yields one value.
    """
    return state.sha256 or f"{state.size}:{state.mtime_ns}:{state.ctime_ns}"


def _content_changed(old: _FileState, new: _FileState) -> bool:
    """True if file content changed — or, for an unhashable file, may have.

    Prefers the hash. For unhashable files (unreadable — e.g. /etc/shadow for a
    non-root collector — or over the size cap) it falls back to size or mtime
    drift, and then to ctime: size+mtime alone can be forged (a same-length edit
    followed by ``touch -d``), ctime cannot. Any ctime move counts, even one a
    visible ``chmod``, ``chown`` or hard link could explain, because an attacker
    can make that change alongside the edit to mask it. Fail-safe: metadata
    changes to such a file are also reported as possible modifications.
    """
    if old.sha256 is not None and new.sha256 is not None:
        return old.sha256 != new.sha256
    if old.size != new.size or old.mtime_ns != new.mtime_ns:
        return True
    return bool(old.ctime_ns and new.ctime_ns) and old.ctime_ns != new.ctime_ns


def _attributes_changed(old: _FileState, new: _FileState) -> bool:
    """True if permission bits or ownership changed between snapshots."""
    return (old.mode, old.uid, old.gid) != (new.mode, new.uid, new.gid)
