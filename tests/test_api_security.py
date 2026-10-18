"""Tests for API authentication, security headers, and CORS hardening."""

from __future__ import annotations

import httpx
import pytest
import structlog

from sentinel.api import create_app
from sentinel.detection.schema import Rule
from sentinel.metrics import Metrics
from sentinel.storage import Database
from tests.conftest import TEST_API_KEY, auth_header, make_api_settings


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
    async def test_non_ascii_token_is_401_not_500(self, api_client: httpx.AsyncClient) -> None:
        # hmac.compare_digest raises TypeError on non-ASCII *str* operands; the
        # comparison must run on bytes so a hostile header is a clean 401.
        resp = await api_client.get(
            "/events", headers={b"Authorization": "Bearer caf\xe9".encode("latin-1")}
        )
        assert resp.status_code == 401

    @pytest.mark.security
    @pytest.mark.parametrize("presented", ["wrong-key-value", None])
    async def test_auth_failure_never_logs_credentials(
        self,
        api_client: httpx.AsyncClient,
        capsys: pytest.CaptureFixture[str],
        presented: str | None,
    ) -> None:
        # Regression (CWE-532): a failed auth must log *that* it failed, never
        # the presented token or the configured key.
        headers = auth_header(presented) if presented else {"Authorization": "Bearer"}
        resp = await api_client.get("/events", headers=headers)
        assert resp.status_code == 401
        output = capsys.readouterr().out
        assert "api.auth_failed" in output
        assert TEST_API_KEY not in output
        if presented:
            assert presented not in output

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


@pytest.mark.security
class TestEveryResponseIsHardened:
    """Regressions: some responses were produced outside the hardening middleware."""

    @staticmethod
    def _assert_hardened(response: httpx.Response) -> None:
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Content-Security-Policy"].startswith("default-src 'none'")

    async def test_rate_limited_responses(
        self, database: Database, rules: tuple[Rule, ...]
    ) -> None:
        async with _client(database, rules, api_rate_limit=1) as client:
            await client.get("/events")
            limited = await client.get("/events")
        assert limited.status_code == 429
        self._assert_hardened(limited)
        assert limited.headers["X-Request-ID"]

    async def test_cors_preflight(self, database: Database, rules: tuple[Rule, ...]) -> None:
        async with _client(database, rules, api_cors_origins="https://good.test") as client:
            preflight = await client.options(
                "/events",
                headers={"Origin": "https://good.test", "Access-Control-Request-Method": "GET"},
            )
        assert preflight.status_code == 200
        self._assert_hardened(preflight)

    async def test_unhandled_errors_are_contained(
        self, unreachable_database: Database, rules: tuple[Rule, ...]
    ) -> None:
        # Before, the error escaped every middleware: no request id, no headers,
        # no access log, and the server printed the traceback outside the
        # logging pipeline. The default transport re-raises such escapes.
        capture = structlog.testing.capture_logs(
            processors=[structlog.contextvars.merge_contextvars]
        )
        async with _client(unreachable_database, rules) as client:
            with capture as logs:
                response = await client.get("/events", headers=auth_header())
        assert response.status_code == 500
        assert response.json()["error"]["code"] == "INTERNAL_ERROR"
        self._assert_hardened(response)
        request_id = response.headers["X-Request-ID"]
        events = {entry["event"]: entry for entry in logs}
        assert events["api.unhandled_error"]["request_id"] == request_id
        assert events["api.request"]["status"] == 500


@pytest.mark.security
class TestRequestCorrelation:
    async def test_lines_logged_during_a_request_carry_its_id(
        self, api_client: httpx.AsyncClient
    ) -> None:
        capture = structlog.testing.capture_logs(
            processors=[structlog.contextvars.merge_contextvars]
        )
        with capture as logs:
            response = await api_client.get("/events", headers=auth_header("wrong-key"))
        failure = next(entry for entry in logs if entry["event"] == "api.auth_failed")
        assert failure["request_id"] == response.headers["X-Request-ID"]


@pytest.mark.security
class TestPaginationBounds:
    @pytest.mark.parametrize("path", ["/events", "/alerts"])
    async def test_cursor_beyond_a_64_bit_row_id_is_rejected(
        self, api_client: httpx.AsyncClient, path: str
    ) -> None:
        # Regression: 2**63 overflowed SQLite's INTEGER and became a 500.
        too_big = await api_client.get(f"{path}?cursor={2**63}", headers=auth_header())
        largest = await api_client.get(f"{path}?cursor={2**63 - 1}", headers=auth_header())
        assert too_big.status_code == 422
        assert largest.status_code == 200
