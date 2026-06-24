"""Tests for the async storage layer: models, repository, pagination."""

from __future__ import annotations

import pytest

from sentinel.storage import Database, Repository
from tests.conftest import make_alert, make_event


class TestEventPersistence:
    async def test_save_event_assigns_id(self, database: Database) -> None:
        async with database.session() as session:
            row = await Repository(session).save_event(make_event())
        assert row.id >= 1

    async def test_count_reflects_inserts(self, database: Database) -> None:
        async with database.session() as session:
            repo = Repository(session)
            for i in range(3):
                await repo.save_event(make_event(event_id=f"{i:064d}"))
            assert await repo.count_events() == 3

    async def test_list_returns_newest_first(self, database: Database) -> None:
        async with database.session() as session:
            repo = Repository(session)
            for i in range(3):
                await repo.save_event(make_event(event_id=f"{i:064d}", message=f"evt-{i}"))
            rows = await repo.list_events(limit=10)
        assert [r.message for r in rows] == ["evt-2", "evt-1", "evt-0"]

    async def test_occurred_at_is_timezone_aware(self, database: Database) -> None:
        async with database.session() as session:
            repo = Repository(session)
            await repo.save_event(make_event())
            rows = await repo.list_events(limit=1)
        assert rows[0].occurred_at.tzinfo is not None

    async def test_source_ip_nullable(self, database: Database) -> None:
        async with database.session() as session:
            repo = Repository(session)
            await repo.save_event(make_event(source_ip=None, port=None))
            rows = await repo.list_events(limit=1)
        assert rows[0].source_ip is None


class TestKeysetPagination:
    async def test_cursor_walks_pages_without_overlap(self, database: Database) -> None:
        async with database.session() as session:
            repo = Repository(session)
            for i in range(5):
                await repo.save_event(make_event(event_id=f"{i:064d}"))
            page1 = await repo.list_events(limit=2)
            page2 = await repo.list_events(limit=2, before_id=page1[-1].id)
            page3 = await repo.list_events(limit=2, before_id=page2[-1].id)
        ids = [r.id for r in (*page1, *page2, *page3)]
        assert ids == sorted(ids, reverse=True)
        assert len(set(ids)) == 5  # no duplicates across pages

    async def test_empty_database_returns_empty(self, database: Database) -> None:
        async with database.session() as session:
            rows = await Repository(session).list_events(limit=10)
        assert rows == []


class TestAlertPersistence:
    async def test_save_alert_roundtrips_attack_list(self, database: Database) -> None:
        alert = make_alert(attack=("T1059.004", "T1071"))
        async with database.session() as session:
            repo = Repository(session)
            await repo.save_alert(alert)
            rows = await repo.list_alerts(limit=1)
        assert rows[0].attack == "T1059.004,T1071"
        assert rows[0].rule_id == alert.rule_id

    async def test_count_alerts(self, database: Database) -> None:
        async with database.session() as session:
            repo = Repository(session)
            await repo.save_alert(make_alert())
            assert await repo.count_alerts() == 1


@pytest.mark.security
class TestNoStringSql:
    async def test_message_with_sql_metacharacters_is_stored_literally(
        self, database: Database
    ) -> None:
        # A classic injection payload must be persisted as data, never executed.
        payload = "'; DROP TABLE events;--"
        async with database.session() as session:
            repo = Repository(session)
            await repo.save_event(make_event(message=payload))
            rows = await repo.list_events(limit=1)
            # The table still exists and the payload round-trips verbatim.
            assert rows[0].message == payload
            assert await repo.count_events() == 1
