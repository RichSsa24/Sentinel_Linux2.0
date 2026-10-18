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

A new SQLite database file is created owner-only (0600) before SQLite opens
it. Left to SQLite it would follow the process umask — typically 0644, so
every local user could read the auth events, user names and command lines it
holds — and its ``-wal`` and ``-shm`` files copy the database file's mode.
"""

from __future__ import annotations

import os
import stat
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Final

from sqlalchemy import event, make_url
from sqlalchemy.engine.interfaces import DBAPIConnection
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from sentinel.logging import get_logger
from sentinel.storage.models import Base

_log = get_logger("sentinel.storage")
_PRIVATE_MODE: Final[int] = 0o600

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


def create_private_sqlite_file(url: str) -> None:
    """Create a file-backed SQLite database owner-only, before SQLite creates it.

    SQLite takes an empty file as an empty database. An existing file is left
    as the operator set it (a backup user may need to read it), with a warning
    if other users can. Anything but a plain SQLite file path is ignored, and
    a path that cannot be created is left for SQLite to report on connect.
    """
    parsed = make_url(url)
    database = parsed.database
    if parsed.get_backend_name() != "sqlite" or not database or database == ":memory:":
        return
    if database.startswith("file:"):  # a SQLite URI: its own rules apply
        return
    path = Path(database)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    try:
        os.close(os.open(path, flags, _PRIVATE_MODE))
    except FileExistsError:
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            return
        if mode & 0o077:
            _log.warning(
                "storage.database_readable_by_others",
                path=str(path),
                mode=f"{mode:04o}",
                hint=f"chmod 600 {path}",
            )
    except OSError:
        return


class Database:
    """Owns the async engine and hands out sessions."""

    def __init__(self, url: str) -> None:
        create_private_sqlite_file(url)
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
