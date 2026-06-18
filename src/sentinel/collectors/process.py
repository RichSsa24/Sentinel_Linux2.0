"""Process-lifecycle collector — observes ``/proc`` for process start/stop.

Enumerates the numeric entries under ``/proc`` each poll, fingerprints every
process, and diffs against the previous scan to emit one
:class:`~sentinel.events.Event` when a process **starts** and one when it
**stops**. This is the execution-monitoring surface: a shell spawned by a web
server, a dropped binary running out of ``/tmp``, or an unexpected child of
``init`` all surface here, ready for the Phase 4 rules to map onto MITRE
ATT&CK execution/persistence techniques.

Process identity is ``(pid, starttime)``, not ``pid`` alone — the kernel
recycles pids, and ``starttime`` (field 22 of ``/proc/<pid>/stat``, in clock
ticks since boot) disambiguates one short-lived ``bash`` from the next that
happens to reuse its pid. A poll that observes the *same* pid with a *different*
starttime therefore emits a stop for the old instance and a start for the new.
Each ``event.id`` is a deterministic hash over ``(pid, starttime, action)``, so
a re-baseline race collapses in the dedup window while a genuinely new process
is a new event.

The proc filesystem root is injectable (``proc_root``) so the collector is
unit-testable against a synthetic tree on any OS — on a host without ``/proc``
it simply observes no processes and never crashes.

Security posture (per the collector contract in
:mod:`sentinel.collectors.base`):

- **Never trusts the bytes it reads.** ``/proc/<pid>/stat`` is parsed defensively
  (the comm field can contain spaces and parentheses), and unparseable or
  vanished entries are skipped, not coerced.
- **Tolerates the inherent TOCTOU of /proc.** A process can exit mid-read; every
  per-pid read is guarded and a disappearing process is simply omitted.
- **Bounded work.** At most ``max_procs`` entries are fingerprinted per scan.
- **Never blocks the event loop.** The scan runs in a worker thread via
  :func:`asyncio.to_thread`.

Known limitation: polling cannot observe a process that starts and exits within
one poll interval. Catching every exec needs a kernel facility (eBPF, the
netlink proc connector) — explicitly out of scope for this poll-based collector.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
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
    Host,
    Process,
)
from sentinel.logging import get_logger

if TYPE_CHECKING:
    from collections.abc import Iterator

    from sentinel.pipeline.queue import BoundedEventQueue

_DEFAULT_PROC_ROOT: Final[Path] = Path("/proc")
_DEFAULT_MAX_PROCS: Final[int] = 100_000
# Fields of /proc/<pid>/stat *after* the "(comm)" field: index 1 is ppid and
# index 19 is starttime (overall fields 4 and 22). Need at least 20 to read it.
_STAT_MIN_FIELDS: Final[int] = 20
_PPID_INDEX: Final[int] = 1
_STARTTIME_INDEX: Final[int] = 19

_ACTION_STARTED: Final[str] = "process_started"
_ACTION_STOPPED: Final[str] = "process_stopped"

_SEV_STARTED: Final[int] = 3
_SEV_STOPPED: Final[int] = 2


class _ProcState(NamedTuple):
    """The lifecycle-relevant fingerprint of one process."""

    pid: int
    ppid: int
    starttime: int
    comm: str
    cmdline: str | None
    executable: str | None


def parse_stat(content: str) -> tuple[int, int] | None:
    """Extract ``(ppid, starttime)`` from ``/proc/<pid>/stat`` content.

    The comm field is wrapped in parentheses and may itself contain spaces and
    parentheses, so we split on the *last* ``)`` rather than on whitespace.
    Returns ``None`` if the line is too short or malformed.
    """
    rparen = content.rfind(")")
    if rparen == -1:
        return None
    fields = content[rparen + 1 :].split()
    if len(fields) < _STAT_MIN_FIELDS:
        return None
    try:
        return int(fields[_PPID_INDEX]), int(fields[_STARTTIME_INDEX])
    except ValueError:
        return None


def _parse_comm_from_stat(content: str) -> str:
    """Pull the comm value out of the ``(...)`` in a stat line (best effort)."""
    lparen = content.find("(")
    rparen = content.rfind(")")
    if lparen != -1 and rparen > lparen:
        return content[lparen + 1 : rparen]
    return ""


class ProcessCollector(AbstractCollector):
    """Polls /proc and emits an Event per process start and stop."""

    name = "process"

    def __init__(
        self,
        *,
        proc_root: Path | str = _DEFAULT_PROC_ROOT,
        poll_interval: float = 1.0,
        host: str | None = None,
        max_procs: int = _DEFAULT_MAX_PROCS,
        name: str | None = None,
    ) -> None:
        super().__init__(name=name)
        if poll_interval <= 0:
            msg = f"poll_interval must be > 0; got {poll_interval}"
            raise ValueError(msg)
        self._proc_root = Path(proc_root)
        self._poll = poll_interval
        self._host = host or socket.gethostname() or "localhost"
        self._max_procs = max_procs
        self._log = get_logger("sentinel.collectors.process")
        self._baseline: dict[int, _ProcState] = {}
        self._seeded = False
        self._emitted = 0

    async def run(self, queue: BoundedEventQueue) -> None:
        """Seed a baseline, then emit one event per start/stop until stopped."""
        while not self.stopping:
            await self._drain_once(queue)
            if await self.wait_stop(timeout=self._poll):
                break
        # Final catch-up so a process that exited just before stop is recorded.
        await self._drain_once(queue)

    async def _drain_once(self, queue: BoundedEventQueue) -> None:
        """Scan /proc, diff against the baseline, and enqueue the events."""
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

    def _scan(self) -> dict[int, _ProcState]:
        """Fingerprint every current process (runs in a worker thread)."""
        snapshot: dict[int, _ProcState] = {}
        for pid in self._iter_pids():
            if len(snapshot) >= self._max_procs:
                self._log.warning("process.max_procs_reached", max_procs=self._max_procs)
                break
            state = self._read_proc(pid)
            if state is not None:
                snapshot[pid] = state
        return snapshot

    def _iter_pids(self) -> Iterator[int]:
        """Yield the numeric pid directories under the proc root."""
        try:
            entries = list(self._proc_root.iterdir())
        except OSError:
            # No /proc (e.g. non-Linux host) or it became unreadable: no procs.
            return
        for entry in entries:
            if entry.name.isdigit():
                yield int(entry.name)

    def _read_proc(self, pid: int) -> _ProcState | None:
        """Read one process's fingerprint, or None if it vanished/is malformed."""
        base = self._proc_root / str(pid)
        try:
            stat_content = (base / "stat").read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None  # process exited between iterdir() and read — fine.
        parsed = parse_stat(stat_content)
        if parsed is None:
            return None
        ppid, starttime = parsed
        return _ProcState(
            pid=pid,
            ppid=ppid,
            starttime=starttime,
            comm=self._read_comm(base, stat_content),
            cmdline=self._read_cmdline(base),
            executable=self._read_exe(base),
        )

    def _read_comm(self, base: Path, stat_content: str) -> str:
        """Prefer /proc/<pid>/comm; fall back to the comm field in stat."""
        try:
            comm = (base / "comm").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            comm = ""
        return comm or _parse_comm_from_stat(stat_content)

    def _read_cmdline(self, base: Path) -> str | None:
        """Read the NUL-separated cmdline; None for kernel threads (empty)."""
        try:
            raw = (base / "cmdline").read_bytes()
        except OSError:
            return None
        text = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
        return text or None

    def _read_exe(self, base: Path) -> str | None:
        """Resolve the /proc/<pid>/exe symlink target, or None if unavailable."""
        with contextlib.suppress(OSError):
            return str((base / "exe").readlink())
        return None

    # ------------------------------------------------------------------ diffing

    def _diff(self, old: dict[int, _ProcState], new: dict[int, _ProcState]) -> list[Event]:
        """Compute start/stop events between two process snapshots."""
        events: list[Event] = []
        for pid, state in new.items():
            previous = old.get(pid)
            if previous is None:
                events.append(self._started(state))
            elif previous.starttime != state.starttime:
                # pid recycled: the old instance ended, a new one began.
                events.append(self._stopped(previous))
                events.append(self._started(state))
        for pid, previous in old.items():
            if pid not in new:
                events.append(self._stopped(previous))
        return events

    def _started(self, state: _ProcState) -> Event:
        return self._build(state, _ACTION_STARTED, _SEV_STARTED)

    def _stopped(self, state: _ProcState) -> Event:
        return self._build(state, _ACTION_STOPPED, _SEV_STOPPED)

    def _build(self, state: _ProcState, action: str, severity: int) -> Event:
        """Assemble an ECS process event with a dedup-safe, identity-derived id."""
        return Event(
            timestamp=datetime.now(tz=UTC),
            event=EventMeta(
                id=Event.compute_id(state.pid, state.starttime, action),
                kind=EventKind.EVENT,
                category=EventCategory.PROCESS,
                action=action,
                outcome=EventOutcome.SUCCESS,
                severity=severity,
            ),
            host=Host(name=self._host),
            process=Process(
                pid=state.pid,
                ppid=state.ppid,
                name=state.comm or None,
                executable=state.executable,
                command_line=state.cmdline,
            ),
            message=f"{action}: pid={state.pid} {state.comm}".rstrip(),
        )

    @property
    def stats(self) -> dict[str, int]:
        """Snapshot counters for observability and tests."""
        return {"emitted": self._emitted, "tracked": len(self._baseline)}
