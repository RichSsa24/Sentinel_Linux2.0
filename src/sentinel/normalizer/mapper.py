"""Raw -> ECS ``Event`` mapping: the one place a source becomes a common event.

Each ``_map_*`` is a pure function that turns one source-specific raw record
into a fully-populated, schema-valid :class:`~sentinel.events.Event`. The
``event.id`` each computes is byte-for-byte the value the collectors used to
produce inline, so moving the logic here changes *where* an event is built, not
*what* it is — dedup and the exactly-once guarantee are unaffected.

:class:`Normalizer` is the fail-closed front door. It dispatches on the raw
record's ``source`` and, if mapping raises (an out-of-range value the ECS schema
rejects, an unknown outcome), it **dead-letters** the record: a counter is
bumped and a WARNING is logged with the exception *type* only — never the
payload, which may carry attacker-controlled bytes — and ``None`` is returned.
An invalid event therefore can never leave the normalizer.
"""

from __future__ import annotations

from typing import Final, assert_never

from pydantic import ValidationError

from sentinel.collectors.netparse import STATE_LISTEN
from sentinel.events import (
    Destination,
    Event,
    EventCategory,
    EventKind,
    EventMeta,
    EventOutcome,
    File,
    FileHash,
    Process,
    Source,
)
from sentinel.logging import get_logger
from sentinel.normalizer.enrich import clamp_severity, resolve_host
from sentinel.normalizer.raw import (
    RawAuthEvent,
    RawEvent,
    RawFileEvent,
    RawNetworkEvent,
    RawProcessEvent,
)

_SUCCESS: Final[EventOutcome] = EventOutcome.SUCCESS


def _map_auth(raw: RawAuthEvent) -> Event:
    """Map a parsed auth-log line to an ECS authentication event."""
    return Event(
        timestamp=raw.occurred_at,
        event=EventMeta(
            id=Event.compute_id(
                raw.syslog_ts, raw.host, raw.pid, raw.action, raw.user, raw.ip, raw.port
            ),
            kind=EventKind.EVENT,
            category=EventCategory.AUTHENTICATION,
            action=raw.action,
            outcome=EventOutcome(raw.outcome),
            severity=clamp_severity(raw.severity),
        ),
        host=resolve_host(raw.host),
        source=Source(ip=raw.ip, port=raw.port, user=raw.user),
        message=raw.message,
    )


def _map_process(raw: RawProcessEvent) -> Event:
    """Map a /proc lifecycle observation to an ECS process event."""
    return Event(
        timestamp=raw.occurred_at,
        event=EventMeta(
            id=Event.compute_id(raw.pid, raw.starttime, raw.action),
            kind=EventKind.EVENT,
            category=EventCategory.PROCESS,
            action=raw.action,
            outcome=_SUCCESS,
            severity=clamp_severity(raw.severity),
        ),
        host=resolve_host(raw.host),
        process=Process(
            pid=raw.pid,
            ppid=raw.ppid,
            name=raw.comm or None,
            executable=raw.executable,
            command_line=raw.cmdline,
        ),
        message=f"{raw.action}: pid={raw.pid} {raw.comm}".rstrip(),
    )


def _map_file(raw: RawFileEvent) -> Event:
    """Map a file-integrity transition to an ECS file event."""
    return Event(
        timestamp=raw.occurred_at,
        event=EventMeta(
            id=Event.compute_id(raw.path, raw.action, raw.id_seed),
            kind=EventKind.EVENT,
            category=EventCategory.FILE,
            action=raw.action,
            outcome=_SUCCESS,
            severity=clamp_severity(raw.severity),
        ),
        host=resolve_host(raw.host),
        file=File(
            path=raw.path,
            size=raw.size,
            mode=raw.mode,
            hash=FileHash(sha256=raw.sha256),
        ),
        message=f"{raw.action}: {raw.path}",
    )


def _map_network(raw: RawNetworkEvent) -> Event:
    """Map a socket-lifecycle observation to an ECS network event."""
    is_listener = raw.state == STATE_LISTEN
    local = f"{raw.local_ip}:{raw.local_port}"
    if is_listener:
        destination = Destination()
        message = f"{raw.action}: {raw.proto} {local} (uid={raw.uid})"
    else:
        destination = Destination(ip=raw.remote_ip, port=raw.remote_port)
        remote = f"{raw.remote_ip}:{raw.remote_port}"
        message = f"{raw.action}: {raw.proto} {local} -> {remote} (uid={raw.uid})"
    event_id = Event.compute_id(
        raw.proto, raw.local_ip, raw.local_port,
        raw.remote_ip, raw.remote_port, raw.inode, raw.action,
    )  # fmt: skip
    return Event(
        timestamp=raw.occurred_at,
        event=EventMeta(
            id=event_id,
            kind=EventKind.EVENT,
            category=EventCategory.NETWORK,
            action=raw.action,
            outcome=_SUCCESS,
            severity=clamp_severity(raw.severity),
        ),
        host=resolve_host(raw.host),
        source=Source(ip=raw.local_ip, port=raw.local_port),
        destination=destination,
        message=message,
    )


def map_raw(raw: RawEvent) -> Event:
    """Dispatch a raw record to its source mapper (may raise; see Normalizer)."""
    match raw:
        case RawAuthEvent():
            return _map_auth(raw)
        case RawProcessEvent():
            return _map_process(raw)
        case RawFileEvent():
            return _map_file(raw)
        case RawNetworkEvent():
            return _map_network(raw)
        case _:  # pragma: no cover - exhaustiveness guard over the union
            assert_never(raw)


class Normalizer:
    """Fail-closed raw -> Event front door with a dead-letter path."""

    def __init__(self) -> None:
        self._log = get_logger("sentinel.normalizer")
        self._dead_letters = 0
        self._normalized = 0

    def normalize(self, raw: RawEvent) -> Event | None:
        """Return the mapped Event, or ``None`` if the record was dead-lettered.

        A dead-letter is counted and logged (exception *type* only — no payload),
        never raised, so one poisoned record cannot crash a collector or the
        pipeline.
        """
        try:
            event = map_raw(raw)
        except (ValidationError, ValueError) as exc:
            self._dead_letters += 1
            self._log.warning(
                "normalizer.dead_letter",
                source=str(raw.source),
                action=raw.action,
                reason=type(exc).__name__,
            )
            return None
        self._normalized += 1
        return event

    @property
    def stats(self) -> dict[str, int]:
        """Snapshot counters for observability and tests."""
        return {"normalized": self._normalized, "dead_letters": self._dead_letters}
