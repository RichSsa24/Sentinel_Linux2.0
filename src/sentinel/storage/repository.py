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
from datetime import datetime
from typing import Any, cast

from sqlalchemy import CursorResult, delete, func, insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.alerting.model import Alert
from sentinel.events import Event
from sentinel.storage.models import AlertRow, EventRow


def _event_values(event: Event) -> dict[str, object]:
    return {
        "event_id": event.event.id,
        "occurred_at": event.timestamp,
        "category": event.event.category.value,
        "action": event.event.action,
        "outcome": event.event.outcome.value,
        "severity": event.event.severity,
        "host": event.host.name,
        "source_ip": event.source.ip,
        "message": event.message,
    }


def _alert_values(alert: Alert) -> dict[str, object]:
    return {
        "dedup_key": alert.dedup_key,
        "rule_id": alert.rule_id,
        "severity": alert.severity,
        "attack": ",".join(alert.attack),
        "nist_csf": ",".join(alert.nist_csf),
        "event_id": alert.event_id,
        "host": alert.host,
        "occurred_at": alert.timestamp,
        "summary": alert.summary,
        "notified": alert.notified,
    }


class Repository:
    """Reads and writes for events and alerts over one async session."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def save_event(self, event: Event) -> EventRow:
        row = EventRow(**_event_values(event))
        self._session.add(row)
        await self._session.commit()
        return row

    async def save_alert(self, alert: Alert) -> AlertRow:
        row = AlertRow(**_alert_values(alert))
        self._session.add(row)
        await self._session.commit()
        return row

    async def save_batch(
        self, *, events: Iterable[Event] = (), alerts: Iterable[Alert] = ()
    ) -> int:
        """Persist many events and alerts in a single transaction.

        One commit for the whole batch: either every row lands or none does.
        Rows go in as a bulk ``executemany`` INSERT rather than through the ORM
        unit of work: these are append-only audit records, so nothing needs the
        generated primary keys back, and skipping per-row ``RETURNING`` is what
        makes batching pay off (see ``scripts/benchmark.py persist``).
        Returns the number of rows written.
        """
        event_values = [_event_values(event) for event in events]
        alert_values = [_alert_values(alert) for alert in alerts]
        if event_values:
            await self._session.execute(insert(EventRow), event_values)
        if alert_values:
            await self._session.execute(insert(AlertRow), alert_values)
        if not event_values and not alert_values:
            return 0
        await self._session.commit()
        return len(event_values) + len(alert_values)

    async def delete_stored_before(self, cutoff: datetime, *, limit: int) -> tuple[int, int]:
        """Delete up to ``limit`` events and ``limit`` alerts stored before ``cutoff``.

        Returns how many events and alerts were deleted. The bound keeps each
        transaction, and SQLite's write lock, short; callers repeat until a
        batch comes back short. Insertion time, not ``occurred_at``, decides:
        an event's own timestamp comes from the host and can be forged.
        """
        deleted: list[int] = []
        for model in (EventRow, AlertRow):
            expired = select(model.id).where(model.created_at < cutoff).limit(limit)
            result = await self._session.execute(
                delete(model)
                .where(model.id.in_(expired))
                .execution_options(synchronize_session=False)
            )
            deleted.append(cast("CursorResult[Any]", result).rowcount)
        await self._session.commit()
        return deleted[0], deleted[1]

    async def list_events(self, *, limit: int, before_id: int | None = None) -> list[EventRow]:
        stmt = select(EventRow).order_by(EventRow.id.desc()).limit(limit)
        if before_id is not None:
            stmt = stmt.where(EventRow.id < before_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def list_alerts(self, *, limit: int, before_id: int | None = None) -> list[AlertRow]:
        stmt = select(AlertRow).order_by(AlertRow.id.desc()).limit(limit)
        if before_id is not None:
            stmt = stmt.where(AlertRow.id < before_id)
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def count_events(self) -> int:
        result = await self._session.execute(select(func.count()).select_from(EventRow))
        return int(result.scalar_one())

    async def count_alerts(self) -> int:
        result = await self._session.execute(select(func.count()).select_from(AlertRow))
        return int(result.scalar_one())
