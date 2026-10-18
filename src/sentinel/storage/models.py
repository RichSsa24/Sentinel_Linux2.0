"""SQLAlchemy 2.0 models for the persisted event and alert tables.

These are append-only audit records: an event or alert is written once and never
mutated, so each table carries an ``id`` and a ``created_at`` (insertion time)
but no ``updated_at`` — an immutable row has nothing to update, and a spurious
``updated_at`` would only mislead an investigator. Timestamps are timezone-aware
(``DateTime(timezone=True)`` → ``timestamptz`` on PostgreSQL), and the
:class:`UTCDateTime` column type reattaches UTC as values are loaded, so
SQLite's tz-naive storage is invisible to callers.

All access goes through the typed ORM, never string-built SQL (OWASP A03).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, Dialect, Index, Integer, String, Text, true
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """``DateTime(timezone=True)`` whose loaded values are always UTC-aware.

    SQLite stores no offset, so values come back naive. Normalizing *as they
    are loaded* matters: patching the attribute on a loaded row instead marks
    it dirty, and the session's next autoflush turned a read into an UPDATE
    (holding SQLite's write lock against the event writer).
    """

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value: datetime | None, dialect: Dialect) -> datetime | None:  # noqa: ARG002 — part of the TypeDecorator signature
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value


class Base(DeclarativeBase):
    """Declarative base for all persisted models."""


class EventRow(Base):
    """A normalized event, persisted for the read API and forensics."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime())
    category: Mapped[str] = mapped_column(String(32))
    action: Mapped[str] = mapped_column(String(200))
    outcome: Mapped[str] = mapped_column(String(16))
    severity: Mapped[int] = mapped_column(Integer)
    host: Mapped[str] = mapped_column(String(253))
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    message: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)

    __table_args__ = (Index("ix_events_occurred_at_id", "occurred_at", "id"),)


class AlertRow(Base):
    """A delivered/processed alert, persisted for the read API and audit."""

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    dedup_key: Mapped[str] = mapped_column(String(256), index=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[int] = mapped_column(Integer)
    attack: Mapped[str] = mapped_column(String(256))
    nist_csf: Mapped[str] = mapped_column(String(256))
    event_id: Mapped[str] = mapped_column(String(64))
    host: Mapped[str] = mapped_column(String(253))
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime())
    summary: Mapped[str] = mapped_column(Text)
    # False when the throttle withheld the notification (the alert is kept).
    notified: Mapped[bool] = mapped_column(Boolean, server_default=true())
    created_at: Mapped[datetime] = mapped_column(UTCDateTime(), default=_utcnow)

    __table_args__ = (Index("ix_alerts_occurred_at_id", "occurred_at", "id"),)
