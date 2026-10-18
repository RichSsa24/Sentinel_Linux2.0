"""Integration tests against PostgreSQL, the production database.

Everything else runs on SQLite; these cover what only PostgreSQL does: its
error classes (a value it refuses arrives from asyncpg as a bare DBAPIError
carrying a SQLSTATE), ``timestamptz``, the migrations on its dialect, and
bulk deletes. Skipped unless SENTINEL_TEST_POSTGRES_URL is a
``postgresql+asyncpg://`` URL of a disposable database — CI runs them against
a postgres:16 service (see the `postgres` job in ci.yml). The schema is built
by the migrations (the production path) and removed afterwards.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, make_url
from structlog.testing import capture_logs

from sentinel.api import create_app
from sentinel.detection.schema import Rule
from sentinel.metrics import Metrics
from sentinel.runtime import Runtime
from sentinel.storage import Database, Repository
from sentinel.storage.models import Base
from tests.conftest import make_alert, make_api_settings, make_event

_URL = os.environ.get("SENTINEL_TEST_POSTGRES_URL", "")
_ROOT = Path(__file__).resolve().parent.parent

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not _URL, reason="SENTINEL_TEST_POSTGRES_URL is not set"),
]


def _sync_url() -> str:
    return _URL.replace("+asyncpg", "+psycopg")


def _alembic() -> Config:
    config = Config(str(_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(_ROOT / "migrations"))
    config.set_main_option("sqlalchemy.url", _sync_url())
    return config


@pytest.fixture
def migrated() -> Iterator[None]:
    command.downgrade(_alembic(), "base")  # a previous run may have been interrupted
    command.upgrade(_alembic(), "head")
    yield
    command.downgrade(_alembic(), "base")


@pytest.fixture
async def pg(migrated: None) -> AsyncIterator[Database]:
    database = Database(_URL)
    yield database
    await database.dispose()


def test_the_migrations_build_exactly_the_orm_schema(migrated: None) -> None:
    engine = create_engine(_sync_url())
    with engine.connect() as connection:
        differences = compare_metadata(MigrationContext.configure(connection), Base.metadata)
    engine.dispose()
    assert differences == []


async def test_records_round_trip_with_utc_timestamps(pg: Database) -> None:
    occurred = datetime(2026, 6, 16, 12, 0, 1, tzinfo=UTC)
    async with pg.session() as session:
        repo = Repository(session)
        await repo.save_batch(
            events=[make_event(event_id="1" * 64, timestamp=occurred)],
            alerts=[make_alert(event_id="1" * 64).model_copy(update={"notified": False})],
        )
        (event,) = await repo.list_events(limit=10)
        (alert,) = await repo.list_alerts(limit=10)
    assert event.occurred_at == occurred
    assert event.occurred_at.tzinfo is not None
    assert alert.notified is False


async def test_retention_deletes_in_bounded_batches(pg: Database) -> None:
    async with pg.session() as session:
        repo = Repository(session)
        await repo.save_batch(events=[make_event(event_id=f"{i:064d}") for i in range(5)])
        later = datetime.now(tz=UTC) + timedelta(days=1)
        assert await repo.delete_stored_before(later, limit=2) == (2, 0)
        assert await repo.delete_stored_before(later, limit=10) == (3, 0)
        assert await repo.count_events() == 0


@pytest.mark.security
async def test_a_row_postgres_refuses_is_isolated_not_retried_forever(
    pg: Database, rules: tuple[Rule, ...]
) -> None:
    # PostgreSQL refuses NUL in text (SQLSTATE 22021); asyncpg's adapter
    # raises a bare DBAPIError for it, which only the SQLSTATE identifies as
    # a rejection rather than an outage. Retrying it would stall every write.
    runtime = Runtime(make_api_settings(), database=pg, metrics=Metrics(), rules=rules, sinks=[])
    for i, message in enumerate(["before", "nul \x00 byte", "after"]):
        await runtime._consume(make_event(event_id=f"{i:064d}", message=message))
    with capture_logs() as logs:
        assert await runtime.flush() is True
    async with pg.session() as session:
        assert await Repository(session).count_events() == 2
    assert runtime.snapshot().dropped["persist_error"] == 1
    assert runtime.persisting
    assert [e["event"] for e in logs] == ["runtime.persist_rejected"]


async def test_the_api_is_ready_on_a_migrated_database(
    pg: Database, rules: tuple[Rule, ...]
) -> None:
    app = create_app(make_api_settings(), database=pg, metrics=Metrics(), rules=rules)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        assert (await client.get("/readyz")).status_code == 200


class _FreezableProxy:
    """A TCP proxy in front of PostgreSQL that can stop forwarding.

    Frozen, it holds every byte without resetting a connection — what a
    network partition (a dropped route, a firewall that drops) looks like to
    the client, as opposed to a refused or reset connection.
    """

    def __init__(self, host: str, port: int) -> None:
        self._upstream = (host, port)
        self._flowing = asyncio.Event()
        self._flowing.set()
        self._server: asyncio.Server | None = None
        self._writers: list[asyncio.StreamWriter] = []

    def freeze(self) -> None:
        self._flowing.clear()

    def thaw(self) -> None:
        self._flowing.set()

    async def start(self) -> int:
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        return int(self._server.sockets[0].getsockname()[1])

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
        for writer in self._writers:
            writer.close()

    async def _handle(self, client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter) -> None:
        server_r, server_w = await asyncio.open_connection(*self._upstream)
        self._writers += [client_w, server_w]
        await asyncio.gather(self._pipe(client_r, server_w), self._pipe(server_r, client_w))

    async def _pipe(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(Exception):
            while data := await reader.read(65536):
                await self._flowing.wait()
                writer.write(data)
                await writer.drain()


async def test_a_network_partition_cannot_hold_writes_readiness_or_shutdown(
    migrated: None, rules: tuple[Rule, ...]
) -> None:
    # Regression: on cancellation SQLAlchemy's asyncpg adapter closes the
    # connection inside asyncio.shield. Over a partition that never ended, so
    # a write with a 1 s deadline was still running after 60 s and stop()
    # with it, and readiness kept reporting writes as healthy.
    target = make_url(_URL)
    proxy = _FreezableProxy(target.host or "127.0.0.1", target.port or 5432)
    port = await proxy.start()
    proxied = target.set(host="127.0.0.1", port=port).render_as_string(hide_password=False)
    database = Database(proxied)
    runtime = Runtime(
        make_api_settings(database_url=proxied, persist_write_timeout_seconds=1.0),
        database=database,
        metrics=Metrics(),
        rules=rules,
        sinks=[],
    )
    loop = asyncio.get_running_loop()
    try:
        await runtime._consume(make_event(event_id="1" * 64))
        assert await runtime.flush() is True  # the connection is pooled and healthy

        proxy.freeze()
        await runtime._consume(make_event(event_id="2" * 64))
        started = loop.time()
        assert await runtime.flush() is False
        assert loop.time() - started < 3  # the 1 s deadline, not the driver's cleanup
        assert not runtime.persisting
        assert runtime.snapshot().persist_buffered["events"] == 1  # kept for the retry

        started = loop.time()
        await runtime.stop()
        await database.dispose(max_wait=1)
        assert loop.time() - started < 5
    finally:
        proxy.thaw()
        await proxy.close()
