"""SSH/auth-log collector — the canonical first source.

Tails an OpenSSH/syslog auth log (default ``/var/log/auth.log``) and emits one
ECS-aligned :class:`~sentinel.events.Event` per recognised authentication line:
failed/accepted logins (password, publickey, keyboard-interactive/PAM,
hostbased, GSSAPI) plus "invalid user" failures. It understands both
``sshd`` and OpenSSH 9.8+'s ``sshd-session`` process names, BSD and RFC 3339
syslog timestamps, and rsyslog's "message repeated N times" reduction.

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
- **Bounded.** At most ``_MAX_READ`` bytes are read per poll and a partial line
  is never buffered past the line cap, so a huge or newline-free file cannot
  exhaust memory or stall the event loop.
- **Follows rotation like ``tail -F``.** The file stays open between polls; a
  rename (logrotate) is detected by inode and the old file is drained to its
  end before the new one is opened, and an in-place truncation is detected by
  size. No line is skipped or cut in half by a rotation.
- **Never blocks the event loop.** File reads run in a worker thread via
  :func:`asyncio.to_thread`, honouring the async-throughout invariant.
"""

from __future__ import annotations

import asyncio
import os
import re
from datetime import UTC, datetime, timedelta, tzinfo
from pathlib import Path
from typing import IO, TYPE_CHECKING, Final, NamedTuple

from pydantic import ValidationError

from sentinel.collectors.base import AbstractCollector
from sentinel.logging import get_logger
from sentinel.normalizer import Normalizer, RawAuthEvent

if TYPE_CHECKING:
    from sentinel.pipeline.queue import BoundedEventQueue

# Defence-in-depth: refuse absurdly long lines before doing regex work on them.
_MAX_LINE_LEN: Final[int] = 8_192
# Bytes read per poll; the rest waits for the next poll.
_MAX_READ: Final[int] = 1 << 20
# Lines parsed between yields to the event loop.
_YIELD_EVERY: Final[int] = 1_000
# Upper bound on how many events one "message repeated N times" line expands to.
_MAX_REPEAT: Final[int] = 1_000

DEFAULT_AUTH_LOG: Final[Path] = Path("/var/log/auth.log")

# ECS severity (0-7) by auth outcome. Failed auth is more interesting than a
# clean login; an attempt against a non-existent account is the loudest.
_SEV_ACCEPTED: Final[int] = 2
_SEV_FAILED: Final[int] = 4
_SEV_INVALID: Final[int] = 5

_ACTION_OK: Final[str] = "ssh_login_succeeded"
_ACTION_FAIL: Final[str] = "ssh_login_failed"

# ECS event.outcome values. Kept as plain strings here so the collector stays
# decoupled from the event schema; the normalizer maps them onto EventOutcome.
_OUTCOME_OK: Final[str] = "success"
_OUTCOME_FAIL: Final[str] = "failure"

# Locale-independent month lookup — never rely on strptime("%b") here.
_MONTHS: Final[dict[str, int]] = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}  # fmt: skip

# The syslog header: a BSD ("Jun 16 12:00:00", single- or double-space day) or
# RFC 3339 ("2026-06-16T12:00:00.123456+02:00") timestamp, host, process[pid].
_SYSLOG_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?P<bsd>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})"
    r"|(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})))\s"
    r"(?P<host>\S+)\s"
    r"(?P<proc>[\w/.-]+?)(?:\[(?P<pid>\d{1,10})\])?:\s"
    r"(?P<msg>.*)$"
)
# OpenSSH 9.8 moved per-connection logging from "sshd" to "sshd-session".
_SSHD_PROCS: Final[frozenset[str]] = frozenset({"sshd", "sshd-session"})
# rsyslog's duplicate reduction: the first line is logged, then this summary.
_REPEAT_RE: Final[re.Pattern[str]] = re.compile(
    r"^message repeated (?P<count>\d{1,9}) times: \[\s?(?P<inner>.*)\]$"
)
# "none" is deliberately absent: clients probe it before every real method.
_METHODS: Final[str] = (
    r"(?P<method>password|publickey|keyboard-interactive(?:/pam)?|hostbased|gssapi-with-mic)"
)
# The user is greedy and the address is anchored to the end of the message:
# a client-chosen user name can contain " from 6.6.6.6 port 1", and a lazy
# match would take the attacker's address instead of the real one sshd appends.
_TAIL: Final[str] = r" from (?P<ip>\S+) port (?P<port>\d{1,5})(?:\s+ssh2\b.*)?$"
_FAILED_RE: Final[re.Pattern[str]] = re.compile(
    rf"^Failed {_METHODS} for (?P<invalid>invalid user )?(?P<user>.+){_TAIL}"
)
_ACCEPTED_RE: Final[re.Pattern[str]] = re.compile(rf"^Accepted {_METHODS} for (?P<user>.+){_TAIL}")
_INVALID_RE: Final[re.Pattern[str]] = re.compile(rf"^Invalid user (?P<user>.+){_TAIL}")


class _Body(NamedTuple):
    """The auth-relevant fields lifted out of an sshd message body."""

    user: str
    ip: str
    port: str
    action: str
    outcome: str
    severity: int


def _match_body(msg: str) -> _Body | None:
    """Match one sshd message body against the recognised auth patterns."""
    failed = _FAILED_RE.match(msg)
    if failed is not None:
        severity = _SEV_INVALID if failed["invalid"] else _SEV_FAILED
        return _Body(
            failed["user"], failed["ip"], failed["port"],
            _ACTION_FAIL, _OUTCOME_FAIL, severity,
        )  # fmt: skip
    accepted = _ACCEPTED_RE.match(msg)
    if accepted is not None:
        return _Body(
            accepted["user"], accepted["ip"], accepted["port"],
            _ACTION_OK, _OUTCOME_OK, _SEV_ACCEPTED,
        )  # fmt: skip
    invalid = _INVALID_RE.match(msg)
    if invalid is not None:
        return _Body(
            invalid["user"], invalid["ip"], invalid["port"],
            _ACTION_FAIL, _OUTCOME_FAIL, _SEV_INVALID,
        )  # fmt: skip
    return None


def _parse_bsd_timestamp(
    raw: str, *, year: int | None, tz: tzinfo, now: datetime | None
) -> datetime | None:
    """Parse a ``Mon DD HH:MM:SS`` syslog timestamp into a UTC datetime.

    BSD syslog omits the year. Without an explicit ``year`` it is inferred per
    line: the current year, unless that puts the line more than a day in the
    future (a December line read in January), in which case the previous one.
    Returns ``None`` if the field is not a well-formed timestamp.
    """
    month_name, day, clock = " ".join(raw.split()).split(" ")
    month = _MONTHS.get(month_name)
    if month is None:
        return None
    current = (now or datetime.now(tz=UTC)).astimezone(tz)
    try:
        hour, minute, second = (int(part) for part in clock.split(":"))
        local = datetime(year or current.year, month, int(day), hour, minute, second, tzinfo=tz)
        if year is None and local > current + timedelta(days=1):
            local = local.replace(year=current.year - 1)
    except ValueError:
        return None
    return local.astimezone(UTC)


def _parse_iso_timestamp(raw: str) -> datetime | None:
    """Parse an RFC 3339 syslog timestamp (it carries its own offset) into UTC."""
    try:
        return datetime.fromisoformat(raw).astimezone(UTC)
    except ValueError:
        return None


def parse_auth_records(
    line: str,
    *,
    year: int | None = None,
    tz: tzinfo = UTC,
    host_override: str | None = None,
    now: datetime | None = None,
) -> list[RawAuthEvent]:
    """Every auth record one log line stands for.

    One record for a recognised sshd auth line, ``N`` for an rsyslog "message
    repeated N times: [ ... ]" summary of one (capped at ``_MAX_REPEAT``), none
    for anything else. Records carry ``occurrence`` 0..N-1; the collector
    offsets it so that identical lines (same second, same connection) stay
    distinct events. A structurally auth-shaped line carrying an out-of-range
    value (e.g. ``port > 65535``) yields none: the raw model rejects it rather
    than coercing (§3.3). ``year`` (BSD timestamps only) and ``tz`` supply the
    calendar context BSD syslog omits; the raw timestamp is kept so the same
    line always derives the same ``event.id``.
    """
    if len(line) > _MAX_LINE_LEN:
        return []
    syslog = _SYSLOG_RE.match(line.rstrip("\n"))
    if syslog is None or syslog["proc"] not in _SSHD_PROCS:
        return []
    message, count = syslog["msg"], 1
    repeat = _REPEAT_RE.match(message)
    if repeat is not None:
        message, count = repeat["inner"], min(int(repeat["count"]), _MAX_REPEAT)
    body = _match_body(message)
    if body is None:
        return []
    if syslog["bsd"] is not None:
        raw_ts = syslog["bsd"]
        timestamp = _parse_bsd_timestamp(raw_ts, year=year, tz=tz, now=now)
    else:
        raw_ts = syslog["iso"]
        timestamp = _parse_iso_timestamp(raw_ts)
    if timestamp is None:
        return []
    try:
        first = RawAuthEvent(
            occurred_at=timestamp,
            host=host_override or syslog["host"],
            syslog_ts=raw_ts,
            pid=syslog["pid"] or "",
            action=body.action,
            outcome=body.outcome,
            severity=body.severity,
            user=body.user,
            ip=body.ip,
            port=int(body.port),
            message=message,
        )
    except (ValidationError, ValueError):
        return []
    return [first.model_copy(update={"occurrence": n}) for n in range(count)]


def parse_auth_line(
    line: str,
    *,
    year: int | None = None,
    tz: tzinfo = UTC,
    host_override: str | None = None,
    now: datetime | None = None,
) -> RawAuthEvent | None:
    """Parse one auth-log line into its first :class:`RawAuthEvent`, or ``None``."""
    records = parse_auth_records(line, year=year, tz=tz, host_override=host_override, now=now)
    return records[0] if records else None


class AuthLogCollector(AbstractCollector):
    """Tails an sshd auth log and emits one Event per recognised auth record."""

    name = "auth-log"

    def __init__(
        self,
        path: Path | str = DEFAULT_AUTH_LOG,
        *,
        poll_interval: float = 1.0,
        year: int | None = None,
        tz: tzinfo = UTC,
        host_override: str | None = None,
        normalizer: Normalizer | None = None,
        name: str | None = None,
    ) -> None:
        super().__init__(name=name)
        if poll_interval <= 0:
            msg = f"poll_interval must be > 0; got {poll_interval}"
            raise ValueError(msg)
        self._path = Path(path)
        self._poll = poll_interval
        # None: infer the year of each BSD timestamp (see _parse_bsd_timestamp).
        self._year = year
        self._tz = tz
        self._host_override = host_override
        self._normalizer = normalizer or Normalizer()
        self._log = get_logger("sentinel.collectors.authlog")
        # Tail state: the open file, the byte offset consumed from it, and a
        # trailing partial line (no newline yet) carried to the next read.
        self._handle: IO[bytes] | None = None
        self._pos = 0
        self._buf = b""
        self._discarding = False  # inside an over-long line: drop to its newline
        # Occurrences of identical records within the current timestamp, so
        # sshd's repeated identical failures stay distinct events while a
        # re-read of the same lines (after a truncation) reproduces their ids.
        self._seen_ts = ""
        self._seen: dict[tuple[str, str, str, str], int] = {}
        self._parsed = 0
        self._skipped = 0

    async def run(self, queue: BoundedEventQueue) -> None:
        """Poll the file, parsing and enqueuing new complete lines until stopped."""
        try:
            while not self.stopping:
                await self._drain_once(queue)
                if await self.wait_stop(timeout=self._poll):
                    break
            # Final catch-up so lines written just before stop are not lost.
            await self._drain_once(queue)
        finally:
            await asyncio.to_thread(self._close)

    async def _drain_once(self, queue: BoundedEventQueue) -> None:
        """Read whatever is new, parse it, and enqueue the resulting events."""
        try:
            lines = await asyncio.to_thread(self._read_new_lines)
        except OSError as exc:
            self._log.warning("authlog.read_error", path=str(self._path), error=str(exc))
            return
        for index, line in enumerate(lines, start=1):
            records = parse_auth_records(
                line, year=self._year, tz=self._tz, host_override=self._host_override
            )
            if not records:
                self._skipped += 1
            for raw in self._number(records):
                event = self._normalizer.normalize(raw)
                if event is None:
                    continue  # unmappable record: dead-lettered by the normalizer
                self._parsed += 1
                await queue.put(event)
            if index % _YIELD_EVERY == 0:
                await asyncio.sleep(0)  # a large backlog must not starve the loop

    def _number(self, records: list[RawAuthEvent]) -> list[RawAuthEvent]:
        """Offset ``occurrence`` past identical records already seen this second."""
        if not records:
            return records
        first = records[0]
        if first.syslog_ts != self._seen_ts:
            self._seen_ts = first.syslog_ts
            self._seen.clear()
        key = (first.host, first.pid, first.message, first.action)
        base = self._seen.get(key, 0)
        self._seen[key] = base + len(records)
        if base == 0:
            return records
        return [r.model_copy(update={"occurrence": base + r.occurrence}) for r in records]

    def _read_new_lines(self) -> list[str]:
        """Synchronously read complete new lines since the last call (worker thread).

        Reads at most ``_MAX_READ`` bytes. At the end of the open file, a
        different inode at the path means the file was rotated: the old one
        has just been drained, so the new one is opened from its start. A size
        below the read offset on the same inode means it was truncated in place.
        """
        if self._handle is None and not self._open():
            return []
        assert self._handle is not None  # noqa: S101 — narrowed for the type checker
        chunk = self._handle.read(_MAX_READ)
        self._pos = self._handle.tell()
        lines = self._split(chunk)
        if len(chunk) < _MAX_READ:
            lines += self._follow_rotation()
        return lines

    def _open(self) -> bool:
        try:
            self._handle = self._path.open("rb")
        except FileNotFoundError:
            return False
        self._handle.seek(self._pos)
        return True

    def _follow_rotation(self) -> list[str]:
        """At end of file: switch to a rotated-in file or rewind a truncated one."""
        assert self._handle is not None  # noqa: S101 — only called with an open file
        try:
            current = self._path.stat()
        except FileNotFoundError:
            return []  # renamed away, successor not created yet: keep the old one
        opened = os.fstat(self._handle.fileno())
        if (current.st_ino, current.st_dev) != (opened.st_ino, opened.st_dev):
            tail = self._flush_partial()
            self._close()
            self._pos = 0
            return tail + (self._read_new_lines() if self._open() else [])
        if current.st_size < self._pos:
            self._handle.seek(0)
            self._pos = 0
            self._buf = b""
            self._discarding = False
            self._seen.clear()
        return []

    def _split(self, chunk: bytes) -> list[str]:
        """Complete lines out of ``chunk``; a partial line waits for its newline."""
        *complete, rest = (self._buf + chunk).split(b"\n")
        if self._discarding and complete:
            complete = complete[1:]  # the end of an over-long line
            self._discarding = False
        self._buf = rest
        if len(self._buf) > _MAX_LINE_LEN:
            self._buf = b""  # too long to ever parse; drop it up to its newline
            self._discarding = True
            self._skipped += 1
        return [line.decode("utf-8", errors="replace") for line in complete]

    def _flush_partial(self) -> list[str]:
        """A rotated file's last line, even without its newline."""
        tail = [] if self._discarding or not self._buf else [self._buf.decode("utf-8", "replace")]
        self._buf = b""
        self._discarding = False
        return tail

    def _close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None

    @property
    def stats(self) -> dict[str, int]:
        """Snapshot counters for observability and tests."""
        return {
            "parsed": self._parsed,
            "skipped": self._skipped,
            "position": self._pos,
            "dead_lettered": self._normalizer.stats["dead_letters"],
        }
