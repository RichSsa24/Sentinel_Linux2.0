"""Network-socket collector — observes ``/proc/net/tcp`` for socket lifecycle.

Each poll parses ``/proc/net/tcp`` and ``/proc/net/tcp6``, keeps only the
sockets in a security-relevant state — **LISTEN** (a service is accepting
connections) and **ESTABLISHED** (an active connection) — and diffs against the
previous scan to emit one :class:`~sentinel.events.Event` when a socket appears
and one when it disappears. This is the network-visibility surface: a backdoor
binding an unexpected port, a reverse shell's outbound connection, or a beacon's
periodic call-out all surface here for the Phase 4 rules to map onto MITRE
ATT&CK (T1571 non-standard port, T1071 C2 channels, T1059 reverse shells).

Socket identity is ``(proto, local, remote, inode)``. The kernel-assigned
``inode`` uniquely tags one socket instance, so a service that restarts on the
same port is correctly a *close* of the old socket and an *open* of the new one,
not a silent continuation. Each ``event.id`` is a deterministic hash over that
identity plus the action, so a re-baseline race collapses in the dedup window
while a genuinely new socket is a new event — the same exactly-once guarantee
the other collectors share.

The proc filesystem root is injectable (``proc_root``) so the collector is
unit-testable against synthetic ``/proc/net`` fixtures on any OS; on a host
without ``/proc`` it simply observes no sockets and never crashes.

Security posture (per the collector contract in
:mod:`sentinel.collectors.base`):

- **Never trusts the bytes it reads.** Lines are decoded by the pure, bounds-
  checking parser in :mod:`sentinel.collectors.netparse`, which rejects the
  header and any malformed row rather than coercing it (§3.3).
- **Bounded work.** At most ``max_sockets`` entries are tracked per scan, so a
  host under a connection flood cannot grow the snapshot without bound.
- **Degrades safely.** A missing ``/proc/net/tcp6`` (IPv6 disabled) or an
  unreadable file is treated as "no sockets from that source", never fatal.
- **Never blocks the event loop.** The scan runs in a worker thread via
  :func:`asyncio.to_thread`.

Known limitation: polling cannot observe a connection that opens and closes
within one poll interval. Catching every flow needs a kernel facility (eBPF,
conntrack) — out of scope for this poll-based collector.
"""

from __future__ import annotations

import asyncio
import socket
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from sentinel.collectors.base import AbstractCollector
from sentinel.collectors.netparse import (
    STATE_ESTABLISHED,
    STATE_LISTEN,
    Socket,
    SocketKey,
    parse_net_line,
)
from sentinel.events import (
    Destination,
    Event,
    EventCategory,
    EventKind,
    EventMeta,
    EventOutcome,
    Host,
    Source,
)
from sentinel.logging import get_logger

if TYPE_CHECKING:
    from sentinel.pipeline.queue import BoundedEventQueue

_DEFAULT_PROC_ROOT: Final[Path] = Path("/proc")
_DEFAULT_MAX_SOCKETS: Final[int] = 100_000

# Which decoded states the collector acts on. Listening sockets are always
# tracked; established connections are optional (higher volume on a busy host).
_TRACKED_STATES: Final[frozenset[str]] = frozenset({STATE_LISTEN, STATE_ESTABLISHED})
_LISTEN_ONLY: Final[frozenset[str]] = frozenset({STATE_LISTEN})

# (proto label, file name under /proc/net). tcp6 is absent when IPv6 is off.
_SOURCES: Final[tuple[tuple[str, str], ...]] = (("tcp", "tcp"), ("tcp6", "tcp6"))

_ACTION_LISTEN_OPEN: Final[str] = "network_listen_started"
_ACTION_LISTEN_CLOSE: Final[str] = "network_listen_stopped"
_ACTION_CONN_OPEN: Final[str] = "network_connection_opened"
_ACTION_CONN_CLOSE: Final[str] = "network_connection_closed"

# ECS severity (0-7). A new listening service is the loudest network signal;
# connection churn is informational unless a Phase 4 rule escalates it.
_SEV_LISTEN_OPEN: Final[int] = 4
_SEV_LISTEN_CLOSE: Final[int] = 3
_SEV_CONN_OPEN: Final[int] = 2
_SEV_CONN_CLOSE: Final[int] = 1


class NetworkCollector(AbstractCollector):
    """Polls /proc/net/tcp[6] and emits an Event per socket open and close."""

    name = "network"

    def __init__(
        self,
        *,
        proc_root: Path | str = _DEFAULT_PROC_ROOT,
        poll_interval: float = 2.0,
        host: str | None = None,
        max_sockets: int = _DEFAULT_MAX_SOCKETS,
        track_connections: bool = True,
        name: str | None = None,
    ) -> None:
        super().__init__(name=name)
        if poll_interval <= 0:
            msg = f"poll_interval must be > 0; got {poll_interval}"
            raise ValueError(msg)
        self._proc_root = Path(proc_root)
        self._poll = poll_interval
        self._host = host or socket.gethostname() or "localhost"
        self._max_sockets = max_sockets
        # When False, only listening sockets are tracked — far lower volume on a
        # busy host, at the cost of outbound-connection (beaconing) visibility.
        self._tracked_states = _TRACKED_STATES if track_connections else _LISTEN_ONLY
        self._log = get_logger("sentinel.collectors.network")
        self._baseline: dict[SocketKey, Socket] = {}
        self._seeded = False
        self._emitted = 0

    async def run(self, queue: BoundedEventQueue) -> None:
        """Seed a baseline, then emit one event per socket change until stopped."""
        while not self.stopping:
            await self._drain_once(queue)
            if await self.wait_stop(timeout=self._poll):
                break
        # Final catch-up so a socket closed just before stop is recorded.
        await self._drain_once(queue)

    async def _drain_once(self, queue: BoundedEventQueue) -> None:
        """Scan /proc/net, diff against the baseline, and enqueue the events."""
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

    def _scan(self) -> dict[SocketKey, Socket]:
        """Snapshot every tracked socket across IPv4/IPv6 (runs in a thread)."""
        snapshot: dict[SocketKey, Socket] = {}
        for proto, filename in _SOURCES:
            for line in self._read_proc_net(filename).splitlines():
                if len(snapshot) >= self._max_sockets:
                    self._log.warning("network.max_sockets_reached", max_sockets=self._max_sockets)
                    return snapshot
                sock = parse_net_line(line, proto=proto)
                if sock is not None and sock.state in self._tracked_states:
                    snapshot[sock.key] = sock
        return snapshot

    def _read_proc_net(self, filename: str) -> str:
        """Read /proc/net/<filename>, returning '' if it is absent/unreadable."""
        path = self._proc_root / "net" / filename
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            # IPv6 disabled (no tcp6), non-Linux host, or a transient read error:
            # treat as "no sockets from this source" rather than crashing.
            return ""

    # ------------------------------------------------------------------ diffing

    def _diff(self, old: dict[SocketKey, Socket], new: dict[SocketKey, Socket]) -> list[Event]:
        """Compute open/close events between two socket snapshots."""
        events: list[Event] = []
        events.extend(self._appeared(s) for k, s in new.items() if k not in old)
        events.extend(self._disappeared(s) for k, s in old.items() if k not in new)
        return events

    def _appeared(self, sock: Socket) -> Event:
        if sock.state == STATE_LISTEN:
            return self._build(sock, _ACTION_LISTEN_OPEN, _SEV_LISTEN_OPEN)
        return self._build(sock, _ACTION_CONN_OPEN, _SEV_CONN_OPEN)

    def _disappeared(self, sock: Socket) -> Event:
        if sock.state == STATE_LISTEN:
            return self._build(sock, _ACTION_LISTEN_CLOSE, _SEV_LISTEN_CLOSE)
        return self._build(sock, _ACTION_CONN_CLOSE, _SEV_CONN_CLOSE)

    def _build(self, sock: Socket, action: str, severity: int) -> Event:
        """Assemble an ECS network event with a dedup-safe, identity-derived id."""
        event_id = Event.compute_id(
            sock.proto, sock.local_ip, sock.local_port,
            sock.remote_ip, sock.remote_port, sock.inode, action,
        )  # fmt: skip
        return Event(
            timestamp=datetime.now(tz=UTC),
            event=EventMeta(
                id=event_id,
                kind=EventKind.EVENT,
                category=EventCategory.NETWORK,
                action=action,
                outcome=EventOutcome.SUCCESS,
                severity=severity,
            ),
            host=Host(name=self._host),
            source=Source(ip=sock.local_ip, port=sock.local_port),
            destination=self._destination(sock),
            message=self._message(sock, action),
        )

    def _destination(self, sock: Socket) -> Destination:
        """Remote peer for a connection; empty for a listener (no fixed peer)."""
        if sock.state == STATE_LISTEN:
            return Destination()
        return Destination(ip=sock.remote_ip, port=sock.remote_port)

    def _message(self, sock: Socket, action: str) -> str:
        local = f"{sock.local_ip}:{sock.local_port}"
        if sock.state == STATE_LISTEN:
            return f"{action}: {sock.proto} {local} (uid={sock.uid})"
        remote = f"{sock.remote_ip}:{sock.remote_port}"
        return f"{action}: {sock.proto} {local} -> {remote} (uid={sock.uid})"

    @property
    def stats(self) -> dict[str, int]:
        """Snapshot counters for observability and tests."""
        return {"emitted": self._emitted, "tracked": len(self._baseline)}
