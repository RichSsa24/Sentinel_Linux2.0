"""Tests for the sliding-window rate limiter."""

from __future__ import annotations

import httpx
import pytest
from pydantic import SecretStr
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from sentinel.api import create_app, security
from sentinel.api.security import RateLimitMiddleware
from sentinel.detection.schema import Rule
from sentinel.metrics import Metrics
from sentinel.storage import Database
from tests.conftest import TEST_API_KEY, auth_header, make_api_settings

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


def _middleware_client(
    limit: int,
    window: float,
    clock: _FakeClock,
    api_key: SecretStr | None = None,
    exempt_paths: frozenset[str] = frozenset(),
) -> httpx.AsyncClient:
    app = Starlette(routes=[Route("/", _ok), Route("/healthz", _ok)])
    app.add_middleware(
        RateLimitMiddleware,
        limit=limit,
        window_seconds=window,
        api_key=api_key,
        exempt_paths=exempt_paths,
        time_source=clock,
    )
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

    async def test_unauthenticated_traffic_cannot_throttle_key_holders(self) -> None:
        # Regression: one bucket per address meant any local process (or a
        # scanner behind the same NAT) could exhaust it and get Prometheus
        # scrapes and API consumers answered with 429.
        clock = _FakeClock()
        key = SecretStr(TEST_API_KEY)
        async with _middleware_client(limit=2, window=60.0, clock=clock, api_key=key) as client:
            anonymous = [(await client.get("/")).status_code for _ in range(3)]
            wrong_key = await client.get("/", headers={"Authorization": "Bearer not-the-key"})
            keyed = [await client.get("/", headers=auth_header()) for _ in range(3)]
        assert anonymous == [200, 200, 429]
        assert wrong_key.status_code == 429  # a wrong key is anonymous traffic
        # Key holders are limited too, but separately.
        assert [response.status_code for response in keyed] == [200, 200, 429]

    async def test_window_slides_open_again(self) -> None:
        clock = _FakeClock()
        async with _middleware_client(limit=1, window=10.0, clock=clock) as client:
            assert (await client.get("/")).status_code == 200
            assert (await client.get("/")).status_code == 429
            clock.advance(11.0)  # the earlier hit ages out of the window
            assert (await client.get("/")).status_code == 200

    async def test_exempt_paths_are_neither_limited_nor_charged(self) -> None:
        clock = _FakeClock()
        async with _middleware_client(1, 60, clock, exempt_paths=frozenset({"/healthz"})) as c:
            probes = [(await c.get("/healthz")).status_code for _ in range(5)]
            first, second = (await c.get("/")).status_code, (await c.get("/")).status_code
        assert probes == [200] * 5
        assert (first, second) == (200, 429)  # the probes did not use the budget


class TestRateLimitIntegration:
    async def test_api_enforces_configured_limit(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        settings = make_api_settings(api_rate_limit=2)
        app = create_app(settings, database=database, metrics=Metrics(), rules=rules)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            codes = [
                (await client.get("/rules", headers=auth_header())).status_code for _ in range(3)
            ]
        assert codes.count(429) == 1

    async def test_health_probes_are_never_throttled(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        # Regression: probes shared the anonymous budget, so any local client
        # could exhaust it and turn the container's healthcheck unhealthy.
        settings = make_api_settings(api_rate_limit=2)
        app = create_app(settings, database=database, metrics=Metrics(), rules=rules)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            for _ in range(5):
                await client.get("/events")  # anonymous flood: 401, then 429
            codes = {
                (await client.get(path)).status_code
                for path in ("/healthz", "/readyz")
                for _ in range(5)
            }
        assert codes == {200}


class TestMutationGaps:
    async def test_each_client_has_its_own_budget(self) -> None:
        app = Starlette(routes=[Route("/", _ok)])
        app.add_middleware(
            RateLimitMiddleware, limit=1, window_seconds=60, time_source=_FakeClock()
        )

        def client(address: str) -> httpx.AsyncClient:
            transport = httpx.ASGITransport(app=app, client=(address, 40000))
            return httpx.AsyncClient(transport=transport, base_url="http://testserver")

        async with client("10.0.0.1") as first, client("10.0.0.2") as second:
            assert (await first.get("/")).status_code == 200
            assert (await first.get("/")).status_code == 429
            assert (await second.get("/")).status_code == 200  # not charged for the first

    def test_at_the_tracking_cap_the_oldest_client_is_forgotten(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(security, "_MAX_TRACKED_CLIENTS", 2)
        limiter = RateLimitMiddleware(_ok, limit=1, window_seconds=60)  # type: ignore[arg-type]
        for client in ("a", "b", "c"):
            limiter._window_for(client)
        assert list(limiter._hits) == ["b", "c"]
