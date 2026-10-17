"""Repository layer — typed ORM reads and writes, never string-built SQL.

Persists domain objects (:class:`~sentinel.events.Event`,
:class:`~sentinel.alerting.model.Alert`) and serves them back with **keyset**
pagination: results are ordered by descending ``id`` and a cursor is the last id
seen, so paging is O(log n) and stable under concurrent inserts (no OFFSET
scan). Every query is built with SQLAlchemy expressions and bound parameters
(OWASP A03 — no SQL is ever assembled from strings).
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.alerting.model import Alert
from sentinel.events import Event
from sentinel.storage.models import AlertRow, EventRow


def _as_utc(moment: datetime) -> datetime:
    """Reattach UTC to a tz-naive value (SQLite drops tzinfo on round-trip)."""
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)


def _event_row(event: Event) -> EventRow:
    return EventRow(
        event_id=event.event.id,
        occurred_at=event.timestamp,
        category=event.event.category.value,
        action=event.event.action,
        outcome=event.event.outcome.value,
        severity=event.event.severity,
        host=event.host.name,
        source_ip=event.source.ip,
        message=event.message,
    )


def _alert_row(alert: Alert) -> AlertRow:
    return AlertRow(
        dedup_key=alert.dedup_key,
        rule_id=alert.rule_id,
        severity=alert.severity,
        attack=",".join(alert.attack),
        nist_csf=",".join(alert.nist_csf),
        event_id=alert.event_id,
        host=alert.host,
        occurred_at=alert.timestamp,
        summary=alert.summary,
    )


class Repository:
    """Reads and writes for events and alerts over one async session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_event(self, event: Event) -> EventRow:
        row = _event_row(event)
        self._session.add(row)
        await self._session.commit()
        return row

    async def save_alert(self, alert: Alert) -> AlertRow:
        row = _alert_row(alert)
        self._session.add(row)
        await self._session.commit()
        return row

    async def save_batch(
        self, *, events: Iterable[Event] = (), alerts: Iterable[Alert] = ()
    ) -> int:
        """Persist many events and alerts in a single transaction.

        One commit for the whole batch: either every row lands or none does.
        Returns the number of rows written.
        """
        rows: list[EventRow | AlertRow] = [_event_row(event) for event in events]
        rows.extend(_alert_row(alert) for alert in alerts)
        if not rows:
            return 0
        self._session.add_all(rows)
        await self._session.commit()
        return len(rows)

    async def list_events(self, *, limit: int, before_id: int | None = None) -> list[EventRow]:
        stmt = select(EventRow).order_by(EventRow.id.desc()).limit(limit)
        if before_id is not None:
            stmt = stmt.where(EventRow.id < before_id)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        for row in rows:
            row.occurred_at = _as_utc(row.occurred_at)
        return rows

    async def list_alerts(self, *, limit: int, before_id: int | None = None) -> list[AlertRow]:
        stmt = select(AlertRow).order_by(AlertRow.id.desc()).limit(limit)
        if before_id is not None:
            stmt = stmt.where(AlertRow.id < before_id)
        result = await self._session.execute(stmt)
        rows = list(result.scalars().all())
        for row in rows:
            row.occurred_at = _as_utc(row.occurred_at)
        return rows

    async def count_events(self) -> int:
        result = await self._session.execute(select(func.count()).select_from(EventRow))
        return int(result.scalar_one())

    async def count_alerts(self) -> int:
        result = await self._session.execute(select(func.count()).select_from(AlertRow))
        return int(result.scalar_one())
