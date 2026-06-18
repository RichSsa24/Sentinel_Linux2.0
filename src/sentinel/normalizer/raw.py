"""Raw, pre-normalization records emitted by collectors.

Each collector reads one source and produces a source-specific *raw* record —
the facts it parsed, with no ECS opinion. The normalizer
(:mod:`sentinel.normalizer.mapper`) is the single place those raw records become
the common :class:`~sentinel.events.Event`. Splitting the two — a collector
knows how to *read* a source, the normalizer knows how to *describe* it in ECS —
is the structural seam this phase restores: collection and normalization no
longer live tangled in one method.

The records are frozen, ``extra="forbid"`` Pydantic models, so a structurally
malformed raw record is rejected at construction. A record that is valid yet
cannot be mapped (e.g. a value the ECS schema rejects) is *dead-lettered* by the
normalizer, never silently dropped and never allowed to yield an invalid event.
Every model carries a ``source`` discriminator so the normalizer can dispatch
without ``isinstance`` ladders, and is JSON-serializable so the raw side of a
golden fixture is just ``model_dump_json()``.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from enum import StrEnum
from typing import Annotated, Final, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_validator


class RawSource(StrEnum):
    """Which collector produced a raw record — the normalizer's dispatch key."""

    AUTH = "auth"
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"


_RAW_MODEL: Final[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

_MAX_PORT: Final[int] = 65535
_MAX_PID: Final[int] = 2**31 - 1


def _require_utc(value: datetime) -> datetime:
    """Shared validator: reject naive or non-UTC observation timestamps."""
    if value.tzinfo is None or value.utcoffset() != timedelta(0):
        msg = "occurred_at must be timezone-aware UTC"
        raise ValueError(msg)
    return value


class _RawBase(BaseModel):
    """Common shape: an observation time and a host, validated UTC."""

    model_config = _RAW_MODEL

    occurred_at: datetime = Field(description="When the event was observed, UTC.")
    host: str = Field(min_length=1, max_length=253)

    _check_utc = field_validator("occurred_at")(_require_utc)


class RawAuthEvent(_RawBase):
    """A parsed sshd/auth-log line, pre-ECS."""

    source: Literal[RawSource.AUTH] = RawSource.AUTH
    syslog_ts: str = Field(
        min_length=1, max_length=64, description="Raw syslog timestamp; part of the id."
    )
    pid: str = Field(default="", max_length=20, description="sshd pid as text; may be empty.")
    action: str = Field(min_length=1, max_length=200)
    outcome: str = Field(min_length=1, max_length=20)
    severity: int = Field(ge=0, le=7)
    user: str = Field(min_length=1, max_length=256)
    ip: str = Field(min_length=1, max_length=64)
    port: int = Field(ge=0, le=_MAX_PORT)
    message: str = Field(min_length=1, max_length=10_000)


class RawProcessEvent(_RawBase):
    """A /proc process-lifecycle observation, pre-ECS."""

    source: Literal[RawSource.PROCESS] = RawSource.PROCESS
    action: str = Field(min_length=1, max_length=200)
    severity: int = Field(ge=0, le=7)
    pid: int = Field(ge=0, le=_MAX_PID)
    ppid: int = Field(ge=0, le=_MAX_PID)
    starttime: int = Field(ge=0, description="Field 22 of /proc/<pid>/stat; identity component.")
    comm: str = Field(default="", max_length=256)
    cmdline: str | None = Field(default=None, max_length=10_000)
    executable: str | None = Field(default=None, max_length=4096)


class RawFileEvent(_RawBase):
    """A file-integrity transition, pre-ECS."""

    source: Literal[RawSource.FILE] = RawSource.FILE
    action: str = Field(min_length=1, max_length=200)
    severity: int = Field(ge=0, le=7)
    path: str = Field(min_length=1, max_length=4096)
    size: int = Field(ge=0)
    mode: str = Field(
        min_length=1, max_length=8, description="POSIX bits as octal text, e.g. '0644'."
    )
    sha256: str | None = Field(
        default=None, description="None when the file exceeds the hashing cap."
    )
    id_seed: str = Field(
        min_length=1, max_length=256, description="Content fingerprint the id derives from."
    )


class RawNetworkEvent(_RawBase):
    """A socket-lifecycle observation from /proc/net/tcp[6], pre-ECS."""

    source: Literal[RawSource.NETWORK] = RawSource.NETWORK
    action: str = Field(min_length=1, max_length=200)
    severity: int = Field(ge=0, le=7)
    proto: str = Field(min_length=1, max_length=8)
    local_ip: str = Field(min_length=1, max_length=64)
    local_port: int = Field(ge=0, le=_MAX_PORT)
    remote_ip: str = Field(min_length=1, max_length=64)
    remote_port: int = Field(ge=0, le=_MAX_PORT)
    state: str = Field(min_length=1, max_length=20)
    uid: int = Field(ge=0)
    inode: int = Field(ge=0)


# Discriminated union on `source`: lets Pydantic parse a raw record (e.g. a
# golden-fixture dict) straight into the right model, and lets the normalizer
# dispatch without an isinstance ladder.
RawEvent = Annotated[
    RawAuthEvent | RawProcessEvent | RawFileEvent | RawNetworkEvent,
    Field(discriminator="source"),
]

# Module-level adapter for parsing untyped data (JSON/dict) into a RawEvent.
RAW_EVENT_ADAPTER: Final[TypeAdapter[RawEvent]] = TypeAdapter(RawEvent)
