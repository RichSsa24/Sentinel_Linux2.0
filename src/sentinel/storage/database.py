"""Async database engine and session management.

A thin wrapper over an async SQLAlchemy engine: SQLite (``sqlite+aiosqlite``) by
default, PostgreSQL via an env-configured URL — the application code is identical
either way. ``create_all`` is the dev/SQLite convenience; production schema
changes go through the Alembic migrations under ``migrations/``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sentinel.storage.models import Base


class Database:
    """Owns the async engine and hands out sessions."""

    def __init__(self, url: str) -> None:
        self._engine: AsyncEngine = create_async_engine(url)
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
