"""Alembic migration environment.

Migrations run **synchronously** even though the application uses an async
engine — Alembic's runtime is sync, so we strip the async driver from the URL
(``+aiosqlite`` → SQLite sync, ``+asyncpg`` → ``+psycopg``). The URL comes from
the caller's config override (tests) or falls back to ``Settings.database_url``;
nothing is hard-coded here.
"""

from __future__ import annotations

from alembic import context
from sqlalchemy import create_engine, pool

from sentinel.settings import Settings
from sentinel.storage.models import Base

target_metadata = Base.metadata


def _sync_url() -> str:
    configured = context.config.get_main_option("sqlalchemy.url")
    url = configured if configured else Settings().database_url
    return url.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg")


def run_migrations_offline() -> None:
    context.configure(
        url=_sync_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_sync_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
