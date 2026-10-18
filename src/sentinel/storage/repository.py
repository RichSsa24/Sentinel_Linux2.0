"""Repository layer — typed ORM reads and writes, never string-built SQL.

Persists domain objects (:class:`~sentinel.events.Event`,
:class:`~sentinel.alerting.model.Alert`) and serves them back with **keyset**
pagination: results are ordered by descending ``id`` and a cursor is the last id
seen, so paging is O(log n) and stable under concurrent inserts (no OFFSET
scan). Every query is built with SQLAlchemy expressions and bound parameters
(OWASP A03 — no SQL is ever assembled from strings).
"""

from __future__ import annotations

import itertools
import secrets
from collections.abc import Callable, Iterable, Iterator
from datetime import datetime
from typing import Any, NamedTuple, cast

from sqlalchemy import CursorResult, delete, func, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncSession

from sentinel.alerting.model import Alert
from sentinel.events import Event
from sentinel.storage.models import AlertRow, EventRow


class Pending[R: (Event, Alert)](NamedTuple):
    """A record waiting to be stored, with the write id that makes storing it idempotent.

    A write can commit and still fail for its caller: the acknowledgement is
    lost to a deadline or a dropped connection. The caller must retry (it
    cannot tell), and the database skips a row whose ``write_id`` it already
    holds instead of storing it twice. ``event.id`` cannot serve as that key:
    it identifies content only within the pipeline's dedup window, and the
    same content outside it (a repeated login failure, a pid and start time
    seen again after a reboot) is a real second event.
    """

    write_id: str
    record: R


def write_ids() -> Iterator[str]:
    """Yield unique write ids: a random per-writer prefix and a sequence number.

    The scheme of Kafka's idempotent producer (a producer id and a sequence
    number). Ids stay unique across restarts and across hosts sharing one
    database without coordination (``n`` writers share a 64-bit prefix with
    probability about n²/2⁶⁵), and one writer's ids ascend, so its inserts land
    at one end of their range of the unique index, not at random.
    """
    prefix = secrets.token_hex(8)
    return (f"{prefix}{sequence:016x}" for sequence in itertools.count())


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


def _row[R: (Event, Alert)](
    item: R | Pending[R], values: Callable[[R], dict[str, object]]
) -> dict[str, object]:
    if isinstance(item, Pending):
        return {**values(item.record), "write_id": item.write_id}
    return values(item)


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
        self,
        *,
        events: Iterable[Event | Pending[Event]] = (),
        alerts: Iterable[Alert | Pending[Alert]] = (),
    ) -> int:
        """Persist many events and alerts in a single transaction.

        One commit for the whole batch: either every row lands or none does.
        Rows go in as a bulk ``executemany`` INSERT rather than through the ORM
        unit of work: these are append-only audit records, so nothing needs the
        generated primary keys back, and skipping per-row ``RETURNING`` is what
        makes batching pay off (see ``scripts/benchmark.py persist``).

        A record given as :class:`Pending` is stored at most once: saving it
        again (the retry of a write whose acknowledgement was lost) skips it.
        Returns the number of records submitted.
        """
        event_values = [_row(event, _event_values) for event in events]
        alert_values = [_row(alert, _alert_values) for alert in alerts]
        if event_values:
            await self._session.execute(self._insert_once(EventRow), event_values)
        if alert_values:
            await self._session.execute(self._insert_once(AlertRow), alert_values)
        if not event_values and not alert_values:
            return 0
        await self._session.commit()
        return len(event_values) + len(alert_values)

    def _insert_once(self, model: type[EventRow | AlertRow]) -> sqlite.Insert | postgresql.Insert:
        """An INSERT that skips rows whose ``write_id`` is already stored.

        Settings admit only SQLite and PostgreSQL. A row without a write id
        never conflicts (unique indexes treat NULLs as distinct).
        """
        if self._session.get_bind().dialect.name == "postgresql":
            return postgresql.insert(model).on_conflict_do_nothing(index_elements=["write_id"])
        return sqlite.insert(model).on_conflict_do_nothing(index_elements=["write_id"])

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
