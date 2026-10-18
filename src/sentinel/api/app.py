"""The hardened read API (FastAPI).

A factory, :func:`create_app`, wires the database, metrics, and rule library into
an app whose every *data* endpoint is authenticated (default-deny) and whose
responses go through the project envelope. Interactive docs and the OpenAPI
schema are disabled — this is a machine read-API, not a public dev portal, and a
smaller surface is a safer surface. Errors are generic (no stack traces or
internal detail leak); all list endpoints are keyset-paginated with a bounded
page size.

The app's lifespan runs the detection system itself: it starts a
:class:`~sentinel.runtime.Runtime` (built from the same ``Settings``) on startup
and drains it on shutdown. ``/readyz`` reports *not ready* if the pipeline has
died, or the database is unreachable, slow to answer, unmigrated or failing
writes. A crashed collector is restarted by the
pipeline; if the pipeline itself dies, the production app shuts itself down
gracefully so the process supervisor (Docker's restart policy, systemd) starts
a fresh one — neither restarts a process merely for failing a health check.
"""

# NOTE: no `from __future__ import annotations` here — FastAPI must evaluate the
# `Annotated[int, Query(...)]` route-parameter annotations at runtime, which
# stringified (PEP 563) annotations break.

import asyncio
import os
import signal
import time
from collections.abc import AsyncGenerator, Callable, Iterable, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from importlib.metadata import PackageNotFoundError, version
from typing import Annotated

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select, text
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, Response

from sentinel.alerting import AlertSink
from sentinel.api.schemas import AlertOut, EventOut, Page, Pagination, RuleOut
from sentinel.api.security import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    error_response,
    require_api_key,
)
from sentinel.collectors.base import AbstractCollector
from sentinel.detection.loader import load_rules
from sentinel.detection.schema import Rule
from sentinel.logging import configure_logging, get_logger
from sentinel.metrics import Metrics
from sentinel.runtime import Runtime
from sentinel.settings import Settings
from sentinel.storage.database import Database
from sentinel.storage.models import AlertRow, EventRow
from sentinel.storage.repository import Repository

_log = get_logger("sentinel.api")
_DEFAULT_PAGE_SIZE = 50
# Cursors are row ids: a signed 64-bit integer in SQLite and PostgreSQL alike.
_MAX_CURSOR = 2**63 - 1
# A readiness probe must answer before its caller gives up (the image's
# HEALTHCHECK waits 4 s); a database slower than this is not ready.
_READY_TIMEOUT_S = 2.0
# Probes are exempt from the rate limit, so the database round trip behind
# /readyz is shared: at most one per this many seconds, however many callers.
_READY_CACHE_S = 1.0
# Never rate limited (see RateLimitMiddleware); both are cheap to answer.
_PROBE_PATHS = frozenset({"/healthz", "/readyz"})


def _package_version() -> str:
    try:
        return version("sentinel-linux")
    except PackageNotFoundError:  # pragma: no cover - running from a bare checkout
        return "0+unknown"


def _error(
    status_code: int, code: str, message: str, headers: dict[str, str] | None = None
) -> JSONResponse:
    return error_response(status_code, code, message, headers)


def _runtime_lifespan(
    settings: Settings,
    *,
    database: Database,
    metrics: Metrics,
    rules: tuple[Rule, ...],
    collectors: Iterable[AbstractCollector] | None,
    sinks: Sequence[AlertSink] | None,
    on_fatal: Callable[[], None] | None,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    """Lifespan that runs the detection system for as long as the app serves."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        runtime: Runtime | None = None
        try:
            # Inside the try: a ConfigurationError from building the runtime
            # must still release the database pool.
            runtime = Runtime(
                settings,
                database=database,
                metrics=metrics,
                rules=rules,
                collectors=collectors,
                sinks=sinks,
                on_fatal=on_fatal,
            )
            app.state.runtime = runtime
            runtime.start()
            yield
        finally:
            if runtime is not None:
                await runtime.stop()
            await database.dispose()

    return lifespan


class _DatabaseProbe:
    """The database half of readiness, checked at most once per ``_READY_CACHE_S``.

    Concurrent callers wait for the check in progress instead of starting
    their own, so a flood of probes costs the database one round trip a second.
    """

    def __init__(self, database: Database, clock: Callable[[], float] = time.monotonic) -> None:
        self._database = database
        self._clock = clock
        self._lock = asyncio.Lock()
        self._checked_at: float | None = None
        self._problem: str | None = None

    async def problem(self) -> str | None:
        async with self._lock:
            now = self._clock()
            if self._checked_at is None or now - self._checked_at >= _READY_CACHE_S:
                try:
                    async with asyncio.timeout(_READY_TIMEOUT_S):
                        self._problem = await _database_problem(self._database)
                except TimeoutError:
                    self._problem = "database not responding"
                self._checked_at = self._clock()
            return self._problem


async def _not_ready_reason(runtime: Runtime | None, database: _DatabaseProbe) -> str | None:
    """Why the service cannot do its job right now, or None if it can."""
    if runtime is not None and not runtime.running:
        return "detection pipeline is not running"
    reason = await database.problem()
    if reason is not None:
        return reason
    if runtime is not None and not runtime.persisting:
        # Reads can succeed while every write fails (a full disk, a read-only
        # volume): without this the probe reported ready while data was lost.
        return "database writes failing"
    return None


async def _database_problem(database: Database) -> str | None:
    """Why the database cannot serve the runtime, or None if it can."""
    try:
        async with database.session() as session:
            await session.execute(text("SELECT 1"))
    except Exception:
        return "database not reachable"
    try:
        # Reachable is not enough: without the schema every write fails.
        async with database.session() as session:
            await session.execute(select(EventRow.id).limit(1))
            await session.execute(select(AlertRow.id).limit(1))
    except Exception:
        return "database schema missing; run `alembic upgrade head`"
    return None


def create_app(
    settings: Settings,
    *,
    database: Database,
    metrics: Metrics,
    rules: Iterable[Rule],
    collectors: Iterable[AbstractCollector] | None = None,
    sinks: Sequence[AlertSink] | None = None,
    on_fatal: Callable[[], None] | None = None,
) -> FastAPI:
    """Build the read API around its injected dependencies.

    ``collectors`` and ``sinks`` default to what ``settings`` describes; tests
    inject their own to drive the lifespan deterministically. ``on_fatal`` is
    called if the detection pipeline dies (see :class:`Runtime`).
    """
    rule_list = tuple(rules)
    app = FastAPI(
        title="Sentinel-Linux 2.0",
        version=_package_version(),
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=_runtime_lifespan(
            settings,
            database=database,
            metrics=metrics,
            rules=rule_list,
            collectors=collectors,
            sinks=sinks,
            on_fatal=on_fatal,
        ),
    )
    app.state.settings = settings
    app.state.database = database
    app.state.metrics = metrics
    app.state.rules = rule_list
    app.state.runtime = None
    max_page = settings.api_max_page_size
    page_default = min(_DEFAULT_PAGE_SIZE, max_page)

    # Middleware is added inner-first. From the outside in: security headers
    # (so every response gets them, CORS preflights and 429s included), CORS,
    # request context (request id, access log, unhandled-error containment),
    # then the rate limiter.
    app.add_middleware(
        RateLimitMiddleware,
        limit=settings.api_rate_limit,
        window_seconds=settings.api_rate_window_seconds,
        api_key=settings.api_key,
        exempt_paths=_PROBE_PATHS,
    )
    app.add_middleware(RequestContextMiddleware)
    origins = list(settings.cors_origin_list)
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET"],
            allow_headers=["Authorization"],
            allow_credentials=False,
        )
    app.add_middleware(SecurityHeadersMiddleware)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        headers = dict(exc.headers) if exc.headers else None
        return _error(
            exc.status_code, _CODES.get(exc.status_code, "ERROR"), str(exc.detail), headers
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_request: Request, _exc: RequestValidationError) -> JSONResponse:
        return _error(422, "VALIDATION_ERROR", "request parameters failed validation")

    @app.exception_handler(Exception)
    async def _unhandled(_request: Request, exc: Exception) -> JSONResponse:
        _log.error("api.unhandled_error", error=type(exc).__name__)
        return _error(500, "INTERNAL_ERROR", "an unexpected error occurred")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    database_probe = _DatabaseProbe(database)

    @app.get("/readyz")
    async def readyz(request: Request) -> Response:
        reason = await _not_ready_reason(request.app.state.runtime, database_probe)
        if reason is not None:
            return _error(503, "NOT_READY", reason)
        return JSONResponse({"success": True, "data": {"status": "ready"}})

    @app.get("/metrics", dependencies=[Depends(require_api_key)])
    async def prometheus_metrics() -> Response:
        return Response(content=metrics.render(), media_type=metrics.content_type)

    @app.get("/events", dependencies=[Depends(require_api_key)])
    async def list_events(
        limit: Annotated[int, Query(ge=1, le=max_page)] = page_default,
        cursor: Annotated[int | None, Query(ge=1, le=_MAX_CURSOR)] = None,
    ) -> Page[EventOut]:
        async with database.session() as session:
            repo = Repository(session)
            rows = await repo.list_events(limit=limit + 1, before_id=cursor)
            total = await repo.count_events()
        has_more = len(rows) > limit
        rows = rows[:limit]
        data = [EventOut.from_row(row) for row in rows]
        next_cursor = rows[-1].id if (rows and has_more) else None
        return Page(
            data=data, pagination=Pagination(cursor=next_cursor, has_more=has_more, total=total)
        )

    @app.get("/alerts", dependencies=[Depends(require_api_key)])
    async def list_alerts(
        limit: Annotated[int, Query(ge=1, le=max_page)] = page_default,
        cursor: Annotated[int | None, Query(ge=1, le=_MAX_CURSOR)] = None,
    ) -> Page[AlertOut]:
        async with database.session() as session:
            repo = Repository(session)
            rows = await repo.list_alerts(limit=limit + 1, before_id=cursor)
            total = await repo.count_alerts()
        has_more = len(rows) > limit
        rows = rows[:limit]
        data = [AlertOut.from_row(row) for row in rows]
        next_cursor = rows[-1].id if (rows and has_more) else None
        return Page(
            data=data, pagination=Pagination(cursor=next_cursor, has_more=has_more, total=total)
        )

    @app.get("/rules", dependencies=[Depends(require_api_key)])
    async def list_rules() -> Page[RuleOut]:
        data = [RuleOut.from_rule(rule) for rule in rule_list]
        return Page(data=data, pagination=Pagination(cursor=None, has_more=False, total=len(data)))

    return app


_CODES: dict[int, str] = {
    401: "UNAUTHORIZED",
    403: "FORBIDDEN",
    404: "NOT_FOUND",
    429: "RATE_LIMITED",
    503: "SERVICE_UNAVAILABLE",
}


def get_app() -> FastAPI:
    """Zero-argument factory for Uvicorn (``--factory``): configure from the environment.

    Logging is configured *first*, so the redaction and control-character
    stripping processors are active before any other component can log.
    """
    settings = Settings()
    configure_logging(settings)
    rules = load_rules(settings.rules_dir)
    database = Database(settings.database_url.get_secret_value())
    return create_app(
        settings,
        database=database,
        metrics=Metrics(),
        rules=rules,
        on_fatal=_shut_down_for_restart,
    )


def _shut_down_for_restart() -> None:
    """Gracefully stop the server so the process supervisor starts a fresh one.

    A detector whose pipeline died must not keep serving a healthy-looking
    API: Docker and systemd restart a process that exits, not one that merely
    fails its health check. SIGTERM takes the normal graceful-shutdown path,
    so buffered events are still flushed.
    """
    os.kill(os.getpid(), signal.SIGTERM)
