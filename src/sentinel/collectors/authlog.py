"""SSH/auth-log collector — the canonical first source.

Tails an OpenSSH/syslog auth log (default ``/var/log/auth.log``) and emits one
ECS-aligned :class:`~sentinel.events.Event` per recognised authentication line:
failed/accepted password and publickey, plus "invalid user" failures.

This collector is the headline demonstration of the race-condition kill. Log
files rotate, and a naive re-read after rotation re-emits lines the system has
already processed. Here every emitted ``Event`` carries a deterministic
``event.id`` computed from the line's identity fields, so a re-read produces
duplicates that the pipeline's dedup window drops — the consumer still sees each
auth event exactly once. The integration test exercises exactly this.

Security posture (per the collector contract in
:mod:`sentinel.collectors.base`):

- **Never trusts the bytes it reads.** Lines are length-capped before parsing,
  unparseable lines are counted and skipped (reject, don't coerce — §3.3), and
  the timestamp is parsed with an explicit month table rather than the
  locale-dependent ``%b`` directive so a hostile or unusual ``LANG`` cannot
  change parsing behaviour.
- **Degrades safely.** A missing or unreadable file is logged and retried, not
  fatal — one temporarily-unavailable source must not take the process down.
- **Never blocks the event loop.** File reads run in a worker thread via
  :func:`asyncio.to_thread`, honouring the async-throughout invariant.
"""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime, tzinfo
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple

from pydantic import ValidationError

from sentinel.collectors.base import AbstractCollector
from sentinel.events import (
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

# Defence-in-depth: refuse absurdly long lines before doing regex work on them.
_MAX_LINE_LEN: Final[int] = 8_192

DEFAULT_AUTH_LOG: Final[Path] = Path("/var/log/auth.log")

# ECS severity (0-7) by auth outcome. Failed auth is more interesting than a
# clean login; an attempt against a non-existent account is the loudest.
_SEV_ACCEPTED: Final[int] = 2
_SEV_FAILED: Final[int] = 4
_SEV_INVALID: Final[int] = 5

_ACTION_OK: Final[str] = "ssh_login_succeeded"
_ACTION_FAIL: Final[str] = "ssh_login_failed"

# Locale-independent month lookup — never rely on strptime("%b") here.
_MONTHS: Final[dict[str, int]] = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}  # fmt: skip

# "Jun 16 12:00:00 host sshd[1234]: <msg>" — single- or double-space day field.
_SYSLOG_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s"
    r"(?P<proc>[\w/.-]+?)(?:\[(?P<pid>\d+)\])?:\s"
    r"(?P<msg>.*)$"
)
_FAILED_RE: Final[re.Pattern[str]] = re.compile(
    r"^Failed (?P<method>password|publickey) for (?P<invalid>invalid user )?"
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_ACCEPTED_RE: Final[re.Pattern[str]] = re.compile(
    r"^Accepted (?P<method>password|publickey) for (?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)"
)
_INVALID_RE: Final[re.Pattern[str]] = re.compile(
    r"^Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)


class _Body(NamedTuple):
    """The auth-relevant fields lifted out of an sshd message body."""

    user: str
    ip: str
    port: str
    action: str
    outcome: EventOutcome
    severity: int


def _match_body(msg: str) -> _Body | None:
    """Match one sshd message body against the recognised auth patterns."""
    failed = _FAILED_RE.match(msg)
    if failed is not None:
        severity = _SEV_INVALID if failed["invalid"] else _SEV_FAILED
        return _Body(
            failed["user"], failed["ip"], failed["port"],
            _ACTION_FAIL, EventOutcome.FAILURE, severity,
        )  # fmt: skip
    accepted = _ACCEPTED_RE.match(msg)
    if accepted is not None:
        return _Body(
            accepted["user"], accepted["ip"], accepted["port"],
            _ACTION_OK, EventOutcome.SUCCESS, _SEV_ACCEPTED,
        )  # fmt: skip
    invalid = _INVALID_RE.match(msg)
    if invalid is not None:
        return _Body(
            invalid["user"], invalid["ip"], invalid["port"],
            _ACTION_FAIL, EventOutcome.FAILURE, _SEV_INVALID,
        )  # fmt: skip
    return None


def _parse_timestamp(raw: str, *, year: int, tz: tzinfo) -> datetime | None:
    """Parse a space-normalised syslog timestamp into a UTC datetime.

    Returns ``None`` if the field is not a well-formed ``Mon DD HH:MM:SS``.
    """
    month_name, day, clock = " ".join(raw.split()).split(" ")
    month = _MONTHS.get(month_name)
    if month is None:
        return None
    try:
        hour, minute, second = (int(part) for part in clock.split(":"))
        local = datetime(year, month, int(day), hour, minute, second, tzinfo=tz)
    except ValueError:
        return None
    return local.astimezone(UTC)


def parse_auth_line(
    line: str,
    *,
    year: int,
    tz: tzinfo = UTC,
    host_override: str | None = None,
) -> Event | None:
    """Parse one auth-log line into an :class:`Event`, or ``None`` if unrecognised.

    ``year`` and ``tz`` supply the calendar context that syslog's timestamp
    omits. The resulting ``event.id`` is a deterministic hash over the line's
    identity fields, so the same line parsed twice yields the same id — which is
    exactly what lets the dedup window collapse a post-rotation re-read.
    """
    if len(line) > _MAX_LINE_LEN:
        return None
    syslog = _SYSLOG_RE.match(line.rstrip("\n"))
    if syslog is None or syslog["proc"] != "sshd":
        return None
    body = _match_body(syslog["msg"])
    if body is None:
        return None
    timestamp = _parse_timestamp(syslog["ts"], year=year, tz=tz)
    if timestamp is None:
        return None

    host = host_override or syslog["host"]
    pid = syslog["pid"] or ""
    event_id = Event.compute_id(syslog["ts"], host, pid, body.action, body.user, body.ip, body.port)
    try:
        return Event(
            timestamp=timestamp,
            event=EventMeta(
                id=event_id,
                kind=EventKind.EVENT,
                category=EventCategory.AUTHENTICATION,
                action=body.action,
                outcome=body.outcome,
                severity=body.severity,
            ),
            host=Host(name=host),
            source=Source(ip=body.ip, port=int(body.port), user=body.user),
            message=syslog["msg"],
        )
    except ValidationError:
        # A structurally-auth-shaped but out-of-range line (e.g. port > 65535):
        # reject rather than coerce. The collector counts it as skipped.
        return None


class AuthLogCollector(AbstractCollector):
    """Tails an sshd auth log and emits one Event per recognised line."""

    name = "auth-log"

    def __init__(
        self,
        path: Path | str = DEFAULT_AUTH_LOG,
        *,
        poll_interval: float = 1.0,
        year: int | None = None,
        tz: tzinfo = UTC,
        host_override: str | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(name=name)
        if poll_interval <= 0:
            msg = f"poll_interval must be > 0; got {poll_interval}"
            raise ValueError(msg)
        self._path = Path(path)
        self._poll = poll_interval
        self._year = year if year is not None else datetime.now(tz=UTC).year
        self._tz = tz
        self._host_override = host_override
        self._log = get_logger("sentinel.collectors.authlog")
        # Tail state. `_pos` is the byte offset already consumed; `_buf` holds a
        # trailing partial line (no newline yet) carried to the next read.
        self._pos = 0
        self._buf = ""
        self._parsed = 0
        self._skipped = 0

    async def run(self, queue: BoundedEventQueue) -> None:
        """Poll the file, parsing and enqueuing new complete lines until stopped."""
        while not self.stopping:
            await self._drain_once(queue)
            if await self.wait_stop(timeout=self._poll):
                break
        # Final catch-up so lines written just before stop are not lost.
        await self._drain_once(queue)

    async def _drain_once(self, queue: BoundedEventQueue) -> None:
        """Read whatever is new, parse it, and enqueue the resulting events."""
        try:
            lines = await asyncio.to_thread(self._read_new_lines)
        except OSError as exc:
            self._log.warning("authlog.read_error", path=str(self._path), error=str(exc))
            return
        for line in lines:
            event = parse_auth_line(
                line,
                year=self._year,
                tz=self._tz,
                host_override=self._host_override,
            )
            if event is None:
                self._skipped += 1
                continue
            self._parsed += 1
            await queue.put(event)

    def _read_new_lines(self) -> list[str]:
        """Synchronously read complete new lines since the last call.

        Runs inside a worker thread. Detects truncation/rotation by a shrinking
        file size and restarts from the top. Only newline-terminated lines are
        returned; a trailing partial line is buffered until its newline arrives.
        """
        if not self._path.exists():
            return []
        size = self._path.stat().st_size
        if size < self._pos:
            # File was truncated or rotated in place — start over from the top.
            self._pos = 0
            self._buf = ""
        if size == self._pos:
            return []
        with self._path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(self._pos)
            chunk = handle.read()
            self._pos = handle.tell()
        self._buf += chunk
        *complete, self._buf = self._buf.split("\n")
        return complete

    @property
    def stats(self) -> dict[str, int]:
        """Snapshot counters for observability and tests."""
        return {
            "parsed": self._parsed,
            "skipped": self._skipped,
            "position": self._pos,
        }
