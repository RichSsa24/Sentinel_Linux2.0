"""Tests for API authentication, security headers, and CORS hardening."""

from __future__ import annotations

import httpx
import pytest

from sentinel.api import create_app
from sentinel.detection.schema import Rule
from sentinel.metrics import Metrics
from sentinel.storage import Database
from tests.conftest import auth_header, make_api_settings


def _client(
    database: Database, rules: tuple[Rule, ...], **settings_overrides: object
) -> httpx.AsyncClient:
    settings = make_api_settings(**settings_overrides)
    app = create_app(settings, database=database, metrics=Metrics(), rules=rules)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver")


class TestAuthentication:
    async def test_missing_token_is_401(self, api_client: httpx.AsyncClient) -> None:
        assert (await api_client.get("/events")).status_code == 401

    async def test_wrong_token_is_401(self, api_client: httpx.AsyncClient) -> None:
        resp = await api_client.get("/events", headers=auth_header("wrong-key"))
        assert resp.status_code == 401

    async def test_non_bearer_scheme_is_401(self, api_client: httpx.AsyncClient) -> None:
        resp = await api_client.get("/events", headers={"Authorization": "Basic abc"})
        assert resp.status_code == 401

    async def test_valid_token_is_200(self, api_client: httpx.AsyncClient) -> None:
        assert (await api_client.get("/events", headers=auth_header())).status_code == 200

    async def test_error_envelope_does_not_leak(self, api_client: httpx.AsyncClient) -> None:
        body = (await api_client.get("/events")).json()
        assert body["success"] is False
        assert body["error"]["code"] == "UNAUTHORIZED"
        assert "Traceback" not in str(body)

    async def test_unauthorized_sets_www_authenticate(self, api_client: httpx.AsyncClient) -> None:
        resp = await api_client.get("/events")
        assert resp.headers.get("WWW-Authenticate") == "Bearer"

    @pytest.mark.security
    @pytest.mark.parametrize("path", ["/events", "/alerts", "/rules", "/metrics"])
    async def test_every_data_endpoint_denies_anonymous(
        self, api_client: httpx.AsyncClient, path: str
    ) -> None:
        assert (await api_client.get(path)).status_code == 401

    @pytest.mark.security
    async def test_unconfigured_key_fails_closed(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        # No key configured -> default-deny: even a "valid-looking" token is refused.
        async with _client(database, rules, api_key=None) as client:
            resp = await client.get("/events", headers=auth_header())
            assert resp.status_code == 503


class TestPublicProbes:
    async def test_healthz_needs_no_auth(self, api_client: httpx.AsyncClient) -> None:
        resp = await api_client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    async def test_readyz_needs_no_auth(self, api_client: httpx.AsyncClient) -> None:
        resp = await api_client.get("/readyz")
        assert resp.status_code == 200
        assert resp.json()["data"]["status"] == "ready"


class TestSecurityHeaders:
    async def test_hardening_headers_present(self, api_client: httpx.AsyncClient) -> None:
        headers = (await api_client.get("/healthz")).headers
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert "max-age=" in headers["Strict-Transport-Security"]
        assert headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
        assert headers["Cache-Control"] == "no-store"

    async def test_request_id_emitted(self, api_client: httpx.AsyncClient) -> None:
        assert (await api_client.get("/healthz")).headers.get("X-Request-ID")


@pytest.mark.security
class TestCors:
    async def test_unconfigured_cors_does_not_reflect_origin(
        self, api_client: httpx.AsyncClient
    ) -> None:
        resp = await api_client.get("/healthz", headers={"Origin": "https://evil.test"})
        assert "access-control-allow-origin" not in {k.lower() for k in resp.headers}

    async def test_allowlisted_origin_is_reflected(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        async with _client(database, rules, api_cors_origins="https://good.test") as client:
            resp = await client.get("/healthz", headers={"Origin": "https://good.test"})
            assert resp.headers.get("access-control-allow-origin") == "https://good.test"

    async def test_unlisted_origin_is_not_reflected(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        async with _client(database, rules, api_cors_origins="https://good.test") as client:
            resp = await client.get("/healthz", headers={"Origin": "https://evil.test"})
            assert resp.headers.get("access-control-allow-origin") != "https://evil.test"
