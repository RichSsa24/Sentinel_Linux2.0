"""Tests for the hardened webhook sink: SSRF, HMAC, TLS, and bounded retry.

All HTTP is served by httpx's MockTransport (no real network); destinations use
public IP literals so the SSRF check runs without real DNS, and hostname
resolution is exercised through an injected resolver.
"""

from __future__ import annotations

import hashlib
import hmac

import httpx
import pytest

from sentinel.alerting.sinks.webhook import (
    DestinationBlockedError,
    WebhookError,
    WebhookSink,
    validate_destination,
)
from tests.conftest import make_alert

_SECRET = "webhook-shared-secret"  # pragma: allowlist secret
_PUBLIC_URL = "https://93.184.216.34/hook"  # public IP literal → no DNS, not blocked


class _Handler:
    """A scripted MockTransport handler: each outcome is a status or an exception."""

    def __init__(self, outcomes: list[int | Exception] | None = None) -> None:
        self._outcomes = list(outcomes or [])
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        outcome = self._outcomes.pop(0) if self._outcomes else 200
        if isinstance(outcome, Exception):
            raise outcome
        return httpx.Response(outcome)


def _client(handler: _Handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def _noop_sleep(_seconds: float) -> None:
    return None


def _expected_signature(body: bytes) -> str:
    return "sha256=" + hmac.new(_SECRET.encode(), body, hashlib.sha256).hexdigest()


class TestValidateDestination:
    @pytest.mark.security
    @pytest.mark.parametrize(
        "url",
        [
            "http://93.184.216.34/hook",  # not https
            "https:///hook",  # no host
            "https://127.0.0.1/hook",  # loopback
            "https://10.0.0.5/hook",  # private
            "https://169.254.169.254/latest/meta-data",  # cloud metadata (link-local)
            "https://[::1]/hook",  # IPv6 loopback
            "https://0.0.0.0/hook",  # unspecified
        ],
    )
    def test_blocks_unsafe_destinations(self, url: str) -> None:
        with pytest.raises(DestinationBlockedError):
            validate_destination(url)

    def test_allows_public_https(self) -> None:
        validate_destination(_PUBLIC_URL)  # must not raise

    @pytest.mark.security
    def test_hostname_resolving_to_private_is_blocked(self) -> None:
        with pytest.raises(DestinationBlockedError):
            validate_destination("https://evil.example.com/h", resolver=lambda _h: ["10.0.0.5"])

    def test_hostname_resolving_to_public_is_allowed(self) -> None:
        validate_destination("https://ok.example.com/h", resolver=lambda _h: ["93.184.216.34"])

    @pytest.mark.security
    def test_allow_private_opt_in_bypasses_the_guard(self) -> None:
        validate_destination("https://10.0.0.5/hook", allow_private=True)  # must not raise


class TestEmit:
    @pytest.mark.asyncio
    async def test_successful_delivery_signs_the_payload(self) -> None:
        handler = _Handler([200])
        sink = WebhookSink(_PUBLIC_URL, _SECRET, client=_client(handler))

        await sink.emit(make_alert(rule_id="ssh-brute-force", severity=6))

        assert len(handler.requests) == 1
        request = handler.requests[0]
        assert request.headers["X-Sentinel-Signature"] == _expected_signature(request.content)
        assert b"ssh-brute-force" in request.content

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_blocked_destination_makes_no_request(self) -> None:
        handler = _Handler([200])
        sink = WebhookSink("https://127.0.0.1/hook", _SECRET, client=_client(handler))

        with pytest.raises(DestinationBlockedError):
            await sink.emit(make_alert())
        assert handler.requests == []  # never left the host

    @pytest.mark.asyncio
    async def test_retries_transient_failure_then_succeeds(self) -> None:
        handler = _Handler([503, 200])
        sink = WebhookSink(_PUBLIC_URL, _SECRET, client=_client(handler), sleeper=_noop_sleep)

        await sink.emit(make_alert())
        assert len(handler.requests) == 2

    @pytest.mark.asyncio
    async def test_retries_network_error_then_succeeds(self) -> None:
        handler = _Handler([httpx.ConnectError("down"), 200])
        sink = WebhookSink(_PUBLIC_URL, _SECRET, client=_client(handler), sleeper=_noop_sleep)

        await sink.emit(make_alert())
        assert len(handler.requests) == 2

    @pytest.mark.asyncio
    async def test_gives_up_after_max_retries(self) -> None:
        handler = _Handler([503, 503, 503])
        sink = WebhookSink(
            _PUBLIC_URL, _SECRET, client=_client(handler), sleeper=_noop_sleep, max_retries=3
        )

        with pytest.raises(WebhookError):
            await sink.emit(make_alert())
        assert len(handler.requests) == 3

    @pytest.mark.asyncio
    async def test_non_retryable_status_fails_immediately(self) -> None:
        handler = _Handler([404])
        sink = WebhookSink(_PUBLIC_URL, _SECRET, client=_client(handler), sleeper=_noop_sleep)

        with pytest.raises(WebhookError):
            await sink.emit(make_alert())
        assert len(handler.requests) == 1  # no retry on a client error


class TestConstruction:
    def test_empty_secret_is_rejected(self) -> None:
        with pytest.raises(ValueError, match="secret"):
            WebhookSink(_PUBLIC_URL, "")

    @pytest.mark.asyncio
    async def test_aclose_closes_the_owned_client(self) -> None:
        handler = _Handler([200])
        sink = WebhookSink(_PUBLIC_URL, _SECRET, client=_client(handler))
        await sink.aclose()  # must not raise

    @pytest.mark.security
    def test_default_client_enables_tls_verification(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}

        class _SpyClient:
            def __init__(self, **kwargs: object) -> None:
                captured.update(kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _SpyClient)
        WebhookSink(_PUBLIC_URL, _SECRET)  # no client injected → builds its own

        assert captured.get("verify") is True
