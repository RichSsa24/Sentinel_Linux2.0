"""Tests for the hardened webhook sink: SSRF, HMAC, TLS, and bounded retry.

All HTTP is served by httpx's MockTransport (no real network); destinations use
public IP literals so the SSRF check runs without real DNS, and hostname
resolution is exercised through an injected resolver.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
from collections.abc import Awaitable, Callable

import httpx
import pytest

from sentinel.alerting.sinks.webhook import (
    DestinationBlockedError,
    WebhookError,
    WebhookSink,
    resolve_destination,
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


def _resolves(*addresses: str) -> Callable[[str, int], Awaitable[list[str]]]:
    async def resolver(_host: str, _port: int) -> list[str]:
        return list(addresses)

    return resolver


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
    async def test_hostname_resolving_to_private_is_blocked(self) -> None:
        with pytest.raises(DestinationBlockedError):
            await resolve_destination("https://evil.example.com/h", resolver=_resolves("10.0.0.5"))

    async def test_hostname_resolving_to_public_is_allowed(self) -> None:
        destination = await resolve_destination(
            "https://ok.example.com/h", resolver=_resolves("93.184.216.34")
        )
        assert destination.addresses == ("93.184.216.34",)

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


@pytest.mark.security
class TestHardenedDelivery:
    """Regressions from the alerting review (SSRF gaps, redirects, slow servers)."""

    @pytest.mark.parametrize(
        "address",
        [
            "100.64.0.1",  # shared address space (CGNAT; e.g. Tailscale)
            "100.100.100.200",  # Alibaba Cloud metadata
            "::ffff:127.0.0.1",  # IPv4-mapped loopback
            "192.0.2.10",  # documentation range
            "239.255.255.250",  # multicast
        ],
    )
    async def test_non_global_addresses_are_blocked(self, address: str) -> None:
        with pytest.raises(DestinationBlockedError):
            await resolve_destination("https://hooks.example.com/h", resolver=_resolves(address))

    async def test_the_request_goes_to_the_checked_address(self) -> None:
        # DNS rebinding: httpx used to resolve the name again after the check.
        handler = _Handler([200])
        sink = WebhookSink(
            "https://hooks.example.com:8443/h",
            _SECRET,
            client=_client(handler),
            resolver=_resolves("93.184.216.34"),
        )
        await sink.emit(make_alert())
        request = handler.requests[0]
        assert request.url.host == "93.184.216.34"
        assert request.url.port == 8443
        assert request.headers["Host"] == "hooks.example.com:8443"
        assert request.extensions["sni_hostname"] == "hooks.example.com"  # TLS checks the name

    async def test_a_redirect_is_a_failed_delivery(self) -> None:
        # httpx does not follow redirects, so a 3xx used to count as delivered.
        handler = _Handler([308])
        sink = WebhookSink(_PUBLIC_URL, _SECRET, client=_client(handler), sleeper=_noop_sleep)
        with pytest.raises(WebhookError):
            await sink.emit(make_alert())
        assert len(handler.requests) == 1

    async def test_each_attempt_has_a_total_deadline(self) -> None:
        # A server that drips its response never trips httpx's per-read timeout.
        async def drip(_request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(60)
            return httpx.Response(200)

        client = httpx.AsyncClient(transport=httpx.MockTransport(drip))
        sink = WebhookSink(
            _PUBLIC_URL, _SECRET, client=client, sleeper=_noop_sleep, timeout_seconds=0.05
        )
        with pytest.raises(WebhookError):
            await asyncio.wait_for(sink.emit(make_alert()), timeout=5)

    def test_the_default_client_ignores_proxy_variables_and_redirects(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, object] = {}

        class _SpyClient:
            def __init__(self, **kwargs: object) -> None:
                captured.update(kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _SpyClient)
        WebhookSink(_PUBLIC_URL, _SECRET)
        assert captured["trust_env"] is False  # a proxy would resolve behind the guard
        assert captured["follow_redirects"] is False


class TestMutationGaps:
    """Behaviours mutation testing showed no test pinned."""

    @pytest.mark.security
    def test_the_default_client_is_bounded_and_ignores_the_environment(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, object] = {}

        class _SpyClient:
            def __init__(self, **kwargs: object) -> None:
                captured.update(kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _SpyClient)
        WebhookSink(_PUBLIC_URL, _SECRET, timeout_seconds=2.5)
        assert captured == {
            "timeout": 2.5,
            "verify": True,
            "trust_env": False,  # no HTTPS_PROXY: a proxy would resolve behind the guard
            "follow_redirects": False,
        }

    @pytest.mark.security
    async def test_the_guard_resolves_the_configured_host_and_port(self) -> None:
        asked: list[tuple[str, int]] = []

        async def resolver(host: str, port: int) -> list[str]:
            asked.append((host, port))
            return ["93.184.216.34"]

        handler = _Handler([200])
        sink = WebhookSink(
            "https://hooks.example.com:8443/x", _SECRET, client=_client(handler), resolver=resolver
        )
        await sink.emit(make_alert())
        assert asked == [("hooks.example.com", 8443)]
        assert handler.requests[0].url.host == "93.184.216.34"  # pinned to what was checked

    async def test_a_client_error_is_final_and_too_many_requests_is_retried(self) -> None:
        refused = _Handler([400])
        sink = WebhookSink(_PUBLIC_URL, _SECRET, client=_client(refused), sleeper=_noop_sleep)
        with pytest.raises(WebhookError):
            await sink.emit(make_alert())
        assert len(refused.requests) == 1

        throttled = _Handler([429, 200])
        sink = WebhookSink(_PUBLIC_URL, _SECRET, client=_client(throttled), sleeper=_noop_sleep)
        await sink.emit(make_alert())
        assert len(throttled.requests) == 2

    async def test_backoff_doubles_between_attempts_and_not_after_the_last(self) -> None:
        waits: list[float] = []

        async def sleeper(seconds: float) -> None:
            waits.append(seconds)

        handler = _Handler([503, 503, 503, 503])
        sink = WebhookSink(
            _PUBLIC_URL, _SECRET, client=_client(handler), sleeper=sleeper, max_retries=4
        )
        with pytest.raises(WebhookError):
            await sink.emit(make_alert())
        assert waits == [0.5, 1.0, 2.0]  # four attempts tell doubling from linear

    async def test_the_default_sleeper_really_waits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        waits: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            waits.append(seconds)

        monkeypatch.setattr(asyncio, "sleep", fake_sleep)
        handler = _Handler([503, 200])
        await WebhookSink(_PUBLIC_URL, _SECRET, client=_client(handler)).emit(make_alert())
        assert waits == [0.5]
