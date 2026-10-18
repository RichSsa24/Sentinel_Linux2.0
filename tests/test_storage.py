"""Tests for the async storage layer: models, repository, pagination."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import event
from structlog.testing import capture_logs

from sentinel.storage import Database, Repository
from sentinel.storage.database import create_private_sqlite_file
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


class TestBatchPersistence:
    @pytest.mark.asyncio
    async def test_batch_writes_events_and_alerts_in_one_commit(self, database: Database) -> None:
        events = [make_event(event_id=f"{i:064d}") for i in range(3)]
        async with database.session() as session:
            repo = Repository(session)
            written = await repo.save_batch(events=events, alerts=[make_alert()])
            assert written == 4
            assert await repo.count_events() == 3
            assert await repo.count_alerts() == 1

    @pytest.mark.asyncio
    async def test_empty_batch_is_a_noop(self, database: Database) -> None:
        async with database.session() as session:
            assert await Repository(session).save_batch() == 0

    @pytest.mark.asyncio
    async def test_bulk_rows_get_server_side_defaults(self, database: Database) -> None:
        async with database.session() as session:
            repo = Repository(session)
            await repo.save_batch(events=[make_event()], alerts=[make_alert()])
            (event_row,) = await repo.list_events(limit=1)
            (alert_row,) = await repo.list_alerts(limit=1)
        assert event_row.id >= 1
        assert event_row.created_at is not None
        assert alert_row.created_at is not None


class TestSqliteTuning:
    @pytest.mark.asyncio
    async def test_file_database_uses_wal_and_normal_sync(self, database: Database) -> None:
        async with database.engine.connect() as conn:
            journal = (await conn.exec_driver_sql("PRAGMA journal_mode")).scalar()
            sync = (await conn.exec_driver_sql("PRAGMA synchronous")).scalar()
            busy = (await conn.exec_driver_sql("PRAGMA busy_timeout")).scalar()
        assert journal == "wal"
        assert sync == 1  # NORMAL
        assert busy == 5000


@pytest.mark.security
class TestReadsDoNotWrite:
    async def test_listing_then_counting_issues_no_write(self, database: Database) -> None:
        # Regression: list_* reassigned occurred_at on the loaded rows, so the
        # next query's autoflush sent an UPDATE (an "append-only" table written
        # by the read API, holding SQLite's write lock against the event writer).
        async with database.session() as session:
            repo = Repository(session)
            await repo.save_event(make_event())
            await repo.save_alert(make_alert())

        statements: list[str] = []

        def record(_conn: object, _cursor: object, statement: str, *_args: object) -> None:
            statements.append(statement.lstrip().split()[0].upper())

        event.listen(database.engine.sync_engine, "before_cursor_execute", record)
        try:
            async with database.session() as session:
                repo = Repository(session)
                events = await repo.list_events(limit=10)
                await repo.count_events()
                alerts = await repo.list_alerts(limit=10)
                await repo.count_alerts()
                assert not session.dirty
        finally:
            event.remove(database.engine.sync_engine, "before_cursor_execute", record)

        assert set(statements) == {"SELECT"}
        assert events[0].occurred_at.tzinfo is not None  # still UTC-aware on SQLite
        assert alerts[0].occurred_at.tzinfo is not None


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _modes(directory: Path) -> dict[str, int]:
    return {file.name: _mode(file) for file in directory.iterdir()}


@pytest.fixture
def permissive_umask() -> Iterator[None]:
    """The common default umask (022), under which new files are world-readable."""
    previous = os.umask(0o022)
    yield
    os.umask(previous)


@pytest.mark.security
@pytest.mark.usefixtures("permissive_umask")
class TestDatabaseFilePermissions:
    async def test_a_new_database_and_its_wal_files_are_private(self, tmp_path: Path) -> None:
        # Regression: under umask 022 the database, -wal and -shm were 0644,
        # so any local user could read the auth events and command lines.
        path = tmp_path / "sentinel.db"
        database = Database(f"sqlite+aiosqlite:///{path}")
        await database.create_all()
        async with database.session() as session:
            await Repository(session).save_batch(events=[make_event()])
            modes = _modes(tmp_path)  # while open: -wal and -shm still exist
        await database.dispose()
        assert modes == {"sentinel.db": 0o600, "sentinel.db-shm": 0o600, "sentinel.db-wal": 0o600}

    def test_an_existing_readable_database_is_reported_not_changed(self, tmp_path: Path) -> None:
        path = tmp_path / "sentinel.db"
        path.touch(mode=0o640)
        with capture_logs() as logs:
            create_private_sqlite_file(f"sqlite+aiosqlite:///{path}")
        assert _mode(path) == 0o640  # the operator's choice stands
        assert [(e["event"], e["mode"]) for e in logs] == [
            ("storage.database_readable_by_others", "0640")
        ]

    @pytest.mark.parametrize(
        "url",
        [
            "sqlite+aiosqlite://",
            "sqlite+aiosqlite:///:memory:",
            "postgresql+asyncpg://user:pw@db.invalid/sentinel",  # pragma: allowlist secret
        ],
    )
    def test_urls_without_a_database_file_are_left_alone(
        self, url: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        create_private_sqlite_file(url)
        assert list(tmp_path.iterdir()) == []

    def test_an_uncreatable_path_is_left_for_sqlite_to_report(self, tmp_path: Path) -> None:
        create_private_sqlite_file(f"sqlite+aiosqlite:///{tmp_path / 'missing' / 'x.db'}")
        assert not (tmp_path / "missing").exists()
