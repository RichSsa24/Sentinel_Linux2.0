"""Async database engine and session management.

A thin wrapper over an async SQLAlchemy engine: SQLite (``sqlite+aiosqlite``) by
default, PostgreSQL via an env-configured URL — the application code is identical
either way. ``create_all`` is the dev/SQLite convenience; production schema
changes go through the Alembic migrations under ``migrations/``.

SQLite connections are tuned on connect:

- ``journal_mode=WAL`` lets the API read while the pipeline writes (readers
  never block the writer) and turns each commit into a sequential append.
- ``synchronous=NORMAL`` is the setting SQLite recommends with WAL: the
  database cannot be corrupted, but the last transactions before a power loss
  may roll back. Acceptable for telemetry; use PostgreSQL where it is not.
- ``busy_timeout`` makes a briefly-locked database wait instead of erroring.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Final

from sqlalchemy import event
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sentinel.storage.models import Base

_SQLITE_PRAGMAS: Final[tuple[str, ...]] = (
    "PRAGMA journal_mode=WAL",
    "PRAGMA synchronous=NORMAL",
    "PRAGMA busy_timeout=5000",
)


def _tune_sqlite(dbapi_connection: DBAPIConnection, _record: object) -> None:
    cursor = dbapi_connection.cursor()
    try:
        for pragma in _SQLITE_PRAGMAS:
            cursor.execute(pragma)
    finally:
        cursor.close()


class Database:
    """Owns the async engine and hands out sessions."""

    def __init__(self, url: str) -> None:
        self._engine: AsyncEngine = create_async_engine(url)
        if self._engine.dialect.name == "sqlite":
            event.listen(self._engine.sync_engine, "connect", _tune_sqlite)
        self._sessionmaker: async_sessionmaker[AsyncSession] = async_sessionmaker(
            self._engine, expire_on_commit=False
        )

    @property
    def engine(self) -> AsyncEngine:
        """The underlying async engine."""
        return self._engine

    async def create_all(self) -> None:
        """Create every table (SQLite/dev/test convenience; prod uses Alembic)."""
        async with self._engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)

    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """Yield a session, closed on exit."""
        async with self._sessionmaker() as session:
            yield session

    async def dispose(self) -> None:
        """Release the engine's connection pool."""
        await self._engine.dispose()
