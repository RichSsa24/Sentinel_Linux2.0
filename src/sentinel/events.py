"""ECS-aligned event schema for the Sentinel pipeline.

Field names map onto the Elastic Common Schema so downstream tooling
(Kibana, OpenSearch, Splunk) ingests them without translation. Every model
is frozen and forbids extras (§3.3 — reject, don't coerce, malformed input).

The `event.id` field is the **idempotency key**: a 64-char lowercase hex
SHA-256 digest that the producer computes deterministically from the
content of the event. Two events with the same `id` are treated as the
same event by the dedup window — this is the structural kill of the v1
race condition where the same source line could be ingested twice and
recorded twice.

Producers MUST compute `event.id` so that semantically-identical events
always hash to the same value. `Event.compute_id` is a small helper for
the common case (joining a tuple of fields with an ASCII unit-separator
before hashing).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EventKind(StrEnum):
    """ECS `event.kind` — top-level classification."""

    EVENT = "event"
    ALERT = "alert"
    METRIC = "metric"
    STATE = "state"
    SIGNAL = "signal"


class EventCategory(StrEnum):
    """ECS `event.category` — coarse-grained category."""

    AUTHENTICATION = "authentication"
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    INTRUSION_DETECTION = "intrusion_detection"
    HOST = "host"
    CONFIGURATION = "configuration"


class EventOutcome(StrEnum):
    """ECS `event.outcome`."""

    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


# Shared frozen+extra-forbid config so every nested model enforces the §3.3
# invariant without restating the boilerplate.
_FROZEN_MODEL: Final[ConfigDict] = ConfigDict(
    frozen=True,
    extra="forbid",
    # Do NOT silently strip whitespace from strings: log-injection defence
    # lives in `sentinel.logging`, not via mutating input here.
    str_strip_whitespace=False,
    validate_assignment=True,
)

# event.id must be a SHA-256 hex digest. 64 lowercase hex chars, exactly.
_HEX_DIGEST_LEN: Final[int] = 64
_HEX_CHARS: Final[frozenset[str]] = frozenset("0123456789abcdef")


class EventMeta(BaseModel):
    """ECS `event.*` metadata."""

    model_config = _FROZEN_MODEL

    id: str = Field(
        description="SHA-256 content hash of the event. Drives dedup.",
    )
    kind: EventKind
    category: EventCategory
    action: str = Field(
        min_length=1,
        max_length=200,
        description="Verb describing what happened (e.g. 'user_login_failed').",
    )
    outcome: EventOutcome = EventOutcome.UNKNOWN
    severity: int = Field(
        default=0,
        ge=0,
        le=7,
        description="ECS 0-7. 0=informational, 7=critical.",
    )

    @field_validator("id")
    @classmethod
    def _check_id_format(cls, value: str) -> str:
        """Reject anything that isn't a 64-char lowercase hex SHA-256 digest."""
        if len(value) != _HEX_DIGEST_LEN or not set(value).issubset(_HEX_CHARS):
            msg = (
                f"event.id must be a {_HEX_DIGEST_LEN}-char lowercase hex "
                f"SHA-256 digest; got {value!r}"
            )
            raise ValueError(msg)
        return value


class Host(BaseModel):
    """ECS `host.*` — origin host of the event."""

    model_config = _FROZEN_MODEL

    name: str = Field(min_length=1, max_length=253)


class Source(BaseModel):
    """ECS `source.*` — network/identity source of the event (optional)."""

    model_config = _FROZEN_MODEL

    ip: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    user: str | None = None


class Destination(BaseModel):
    """ECS `destination.*` — the remote peer of a network event (optional).

    Populated by the network collector for established connections (the local
    side maps to `source.*`, the remote peer to `destination.*`). Left empty for
    listening sockets, which have no fixed peer.
    """

    model_config = _FROZEN_MODEL

    ip: str | None = None
    port: int | None = Field(default=None, ge=0, le=65535)
    user: str | None = None


class Process(BaseModel):
    """ECS `process.*` — process context (optional)."""

    model_config = _FROZEN_MODEL

    pid: int | None = Field(default=None, ge=0, le=2**31 - 1)
    ppid: int | None = Field(
        default=None,
        ge=0,
        le=2**31 - 1,
        description="ECS process.parent.pid — the parent process id.",
    )
    name: str | None = None
    executable: str | None = None
    command_line: str | None = Field(
        default=None,
        max_length=10_000,
        description="Full command line of the process (ECS process.command_line).",
    )


class FileHash(BaseModel):
    """ECS `file.hash.*` — content digests of a file (optional)."""

    model_config = _FROZEN_MODEL

    sha256: str | None = Field(
        default=None,
        description="SHA-256 of file content; None when unhashable (too large/denied).",
    )

    @field_validator("sha256")
    @classmethod
    def _check_sha256_format(cls, value: str | None) -> str | None:
        """When present, enforce the same 64-char lowercase hex shape as event.id."""
        if value is None:
            return value
        if len(value) != _HEX_DIGEST_LEN or not set(value).issubset(_HEX_CHARS):
            msg = f"file.hash.sha256 must be a {_HEX_DIGEST_LEN}-char lowercase hex digest"
            raise ValueError(msg)
        return value


class File(BaseModel):
    """ECS `file.*` — file context for integrity events (optional)."""

    model_config = _FROZEN_MODEL

    path: str = Field(min_length=1, max_length=4096)
    size: int | None = Field(default=None, ge=0)
    mode: str | None = Field(
        default=None,
        description="POSIX permission bits as a zero-padded octal string, e.g. '0644'.",
    )
    hash: FileHash = Field(default_factory=FileHash)


class Event(BaseModel):
    """A single normalised event flowing through the pipeline."""

    model_config = _FROZEN_MODEL

    timestamp: datetime = Field(
        description="When the event happened, in UTC. Naive datetimes rejected.",
    )
    event: EventMeta
    host: Host
    source: Source = Field(default_factory=Source)
    destination: Destination = Field(default_factory=Destination)
    process: Process = Field(default_factory=Process)
    file: File | None = Field(
        default=None,
        description="File context; set by the integrity collector, else None.",
    )
    message: str = Field(
        min_length=1,
        max_length=10_000,
        description="Human-readable event description.",
    )

    @field_validator("timestamp")
    @classmethod
    def _require_utc(cls, value: datetime) -> datetime:
        """Refuse naive or non-UTC datetimes (§3.3 — no time-zone ambiguity)."""
        if value.tzinfo is None:
            msg = "timestamp must be timezone-aware"
            raise ValueError(msg)
        if value.utcoffset() != timedelta(0):
            msg = f"timestamp must be UTC (offset 0); got offset {value.utcoffset()}"
            raise ValueError(msg)
        return value

    @property
    def dedup_key(self) -> str:
        """Stable per-event idempotency key. Equal => duplicate."""
        return self.event.id

    @staticmethod
    def compute_id(*parts: object) -> str:
        """Compute a deterministic SHA-256 event.id from content parts.

        Parts are joined with ASCII Unit Separator (0x1F) — a byte that
        cannot appear in our control-char-stripped log strings, so it is
        unambiguous as a delimiter even when individual parts contain odd
        characters. Strings are used as-is; everything else is stringified
        via `repr` for a stable representation.
        """
        canonical = "\x1f".join(p if isinstance(p, str) else repr(p) for p in parts)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
