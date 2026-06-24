"""Tests for the sliding-window rate limiter."""

from __future__ import annotations

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from sentinel.api import create_app
from sentinel.api.security import RateLimitMiddleware
from sentinel.detection.schema import Rule
from sentinel.metrics import Metrics
from sentinel.storage import Database
from tests.conftest import make_api_settings

pytestmark = pytest.mark.security


class _FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


async def _ok(_request: Request) -> PlainTextResponse:
    return PlainTextResponse("ok")


def _middleware_client(limit: int, window: float, clock: _FakeClock) -> httpx.AsyncClient:
    app = Starlette(routes=[Route("/", _ok)])
    app.add_middleware(RateLimitMiddleware, limit=limit, window_seconds=window, time_source=clock)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


class TestRateLimitMiddleware:
    async def test_allows_up_to_limit(self) -> None:
        clock = _FakeClock()
        async with _middleware_client(limit=3, window=60.0, clock=clock) as client:
            codes = [(await client.get("/")).status_code for _ in range(3)]
        assert codes == [200, 200, 200]

    async def test_blocks_over_limit_with_retry_after(self) -> None:
        clock = _FakeClock()
        async with _middleware_client(limit=2, window=60.0, clock=clock) as client:
            await client.get("/")
            await client.get("/")
            blocked = await client.get("/")
        assert blocked.status_code == 429
        assert blocked.headers["Retry-After"] == "60"
        assert blocked.json()["error"]["code"] == "RATE_LIMITED"

    async def test_window_slides_open_again(self) -> None:
        clock = _FakeClock()
        async with _middleware_client(limit=1, window=10.0, clock=clock) as client:
            assert (await client.get("/")).status_code == 200
            assert (await client.get("/")).status_code == 429
            clock.advance(11.0)  # the earlier hit ages out of the window
            assert (await client.get("/")).status_code == 200


class TestRateLimitIntegration:
    async def test_api_enforces_configured_limit(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        settings = make_api_settings(api_rate_limit=2)
        app = create_app(settings, database=database, metrics=Metrics(), rules=rules)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            codes = [(await client.get("/healthz")).status_code for _ in range(3)]
        assert codes.count(429) == 1
