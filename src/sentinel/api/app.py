"""The hardened read API (FastAPI).

A factory, :func:`create_app`, wires the database, metrics, and rule library into
an app whose every *data* endpoint is authenticated (default-deny) and whose
responses go through the project envelope. Interactive docs and the OpenAPI
schema are disabled — this is a machine read-API, not a public dev portal, and a
smaller surface is a safer surface. Errors are generic (no stack traces or
internal detail leak); all list endpoints are keyset-paginated with a bounded
page size.
"""

# NOTE: no `from __future__ import annotations` here — FastAPI must evaluate the
# `Annotated[int, Query(...)]` route-parameter annotations at runtime, which
# stringified (PEP 563) annotations break.

import asyncio
from collections.abc import AsyncGenerator, Iterable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import JSONResponse, Response

from sentinel.alerting import AlertManager, ConsoleSink
from sentinel.api.schemas import AlertOut, EventOut, Page, Pagination, RuleOut
from sentinel.api.security import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    require_api_key,
)
from sentinel.collectors.authlog import AuthLogCollector
from sentinel.collectors.integrity import FileIntegrityCollector
from sentinel.collectors.network import NetworkCollector
from sentinel.collectors.process import ProcessCollector
from sentinel.detection import DetectionEngine
from sentinel.detection.loader import load_rules
from sentinel.detection.schema import Rule
from sentinel.events import Event
from sentinel.logging import get_logger
from sentinel.metrics import Metrics
from sentinel.pipeline import Pipeline
from sentinel.settings import Settings
from sentinel.storage.database import Database
from sentinel.storage.repository import Repository

_log = get_logger("sentinel.api")
_DEFAULT_PAGE_SIZE = 50


def _error(
    status_code: int, code: str, message: str, headers: dict[str, str] | None = None
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"success": False, "error": {"code": code, "message": message}},
        headers=headers,
    )


@asynccontextmanager
async def _pipeline_lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    pipeline = Pipeline(app.state.settings)
    engine = DetectionEngine(app.state.rules)
    alert_mgr = AlertManager([ConsoleSink()])

    pipeline.register(AuthLogCollector())
    pipeline.register(FileIntegrityCollector(paths=["/etc", "/tmp"]))  # noqa: S108  # nosec B108
    pipeline.register(NetworkCollector())
    pipeline.register(ProcessCollector())

    async def consumer(event: Event) -> None:
        detections = engine.evaluate(event)
        for detection in detections:
            alert = await alert_mgr.process(detection)
            if alert:
                async with app.state.database.session() as session:
                    repo = Repository(session)
                    await repo.save_alert(alert)
                app.state.metrics.inc_alerts(detection.rule_id, detection.severity)

        async with app.state.database.session() as session:
            repo = Repository(session)
            await repo.save_event(event)

        app.state.metrics.inc_events(event.event.category.value)

    pipeline.set_consumer(consumer)
    pipeline_task = asyncio.create_task(pipeline.run())
    yield
    await pipeline.stop()
    await pipeline_task


def create_app(
    settings: Settings,
    *,
    database: Database,
    metrics: Metrics,
    rules: Iterable[Rule],
) -> FastAPI:
    """Build the read API around its injected dependencies."""
    app = FastAPI(
        title="Sentinel-Linux 2.0",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=_pipeline_lifespan,
    )
    app.state.settings = settings
    app.state.database = database
    app.state.metrics = metrics
    app.state.rules = tuple(rules)
    rule_list: tuple[Rule, ...] = app.state.rules
    max_page = settings.api_max_page_size
    page_default = min(_DEFAULT_PAGE_SIZE, max_page)

    # Middleware: added inner-first, so CORS/RequestContext end up outermost.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(
        RateLimitMiddleware,
        limit=settings.api_rate_limit,
        window_seconds=settings.api_rate_window_seconds,
    )
    app.add_middleware(RequestContextMiddleware)
    origins = [origin.strip() for origin in settings.api_cors_origins.split(",") if origin.strip()]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["GET"],
            allow_headers=["Authorization"],
            allow_credentials=False,
        )

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

    @app.get("/readyz")
    async def readyz() -> Response:
        try:
            async with database.session() as session:
                await session.execute(text("SELECT 1"))
        except Exception:
            return _error(503, "NOT_READY", "database not reachable")
        return JSONResponse({"success": True, "data": {"status": "ready"}})

    @app.get("/metrics", dependencies=[Depends(require_api_key)])
    async def prometheus_metrics() -> Response:
        return Response(content=metrics.render(), media_type=metrics.content_type)

    @app.get("/events", dependencies=[Depends(require_api_key)])
    async def list_events(
        limit: Annotated[int, Query(ge=1, le=max_page)] = page_default,
        cursor: Annotated[int | None, Query(ge=1)] = None,
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
        cursor: Annotated[int | None, Query(ge=1)] = None,
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
    """Zero-argument factory for Uvicorn to initialize the app."""
    settings = Settings()
    database = Database(settings.database_url)
    metrics = Metrics()

    rules_dir = Path("/app/rules")
    if not rules_dir.exists():
        rules_dir = Path(__file__).resolve().parent.parent.parent.parent / "rules"
    rules = load_rules(rules_dir)

    return create_app(settings, database=database, metrics=metrics, rules=rules)
