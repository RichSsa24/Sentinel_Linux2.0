"""Webhook sink — hardened outbound POST of an alert as signed JSON.

This sink treats the network as hostile in both directions (OWASP A10 SSRF,
NIST SC):

- **HTTPS only, TLS verified.** The URL must be ``https`` and the httpx client
  verifies certificates; a downgrade is refused rather than silently allowed.
- **SSRF guard.** Before every send the destination is resolved and rejected if
  it points at a loopback / private / link-local / reserved address, so a
  attacker-influenced or mistyped URL cannot pivot to cloud metadata
  (169.254.169.254) or internal services. Private targets are allowed only when
  explicitly opted in.
- **HMAC-signed payload.** The body is signed with a shared secret
  (HMAC-SHA256) in the ``X-Sentinel-Signature`` header so the receiver can
  verify authenticity and integrity.
- **Bounded retry.** A timeout plus capped exponential backoff on transient
  failures; the secret and payload never appear in an error.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Final
from urllib.parse import urlparse

import httpx

from sentinel.alerting.sinks.base import AlertSink
from sentinel.logging import get_logger

if TYPE_CHECKING:
    from sentinel.alerting.model import Alert

_DEFAULT_TIMEOUT_S: Final[float] = 5.0
_DEFAULT_MAX_RETRIES: Final[int] = 3
_BACKOFF_BASE_S: Final[float] = 0.5
_SIGNATURE_HEADER: Final[str] = "X-Sentinel-Signature"
_CLIENT_ERROR_FLOOR: Final[int] = 400
_RETRYABLE_STATUS: Final[frozenset[int]] = frozenset({429, 500, 502, 503, 504})

HostResolver = Callable[[str], list[str]]
Sleeper = Callable[[float], Awaitable[None]]


class WebhookError(Exception):
    """A webhook alert could not be delivered."""


class DestinationBlockedError(WebhookError):
    """The destination failed the SSRF / scheme policy and was refused."""


def _default_resolver(host: str) -> list[str]:  # pragma: no cover - real DNS, mocked in tests
    return [str(info[4][0]) for info in socket.getaddrinfo(host, None)]


def _candidate_ips(host: str, resolver: HostResolver) -> list[str]:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return resolver(host)  # a hostname — resolve it
    return [host]  # already an IP literal


def validate_destination(
    url: str,
    *,
    allow_private: bool = False,
    resolver: HostResolver = _default_resolver,
) -> None:
    """Raise :class:`DestinationBlockedError` unless ``url`` is a safe target.

    Enforces HTTPS and blocks any destination that resolves to a non-public
    address (loopback, private, link-local, reserved, multicast, unspecified)
    unless ``allow_private`` is set.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise DestinationBlockedError("webhook URL must use https")
    host = parsed.hostname
    if not host:
        raise DestinationBlockedError("webhook URL has no host")
    if allow_private:
        return
    for ip_text in _candidate_ips(host, resolver):
        ip = ipaddress.ip_address(ip_text)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            msg = f"webhook destination {host} resolves to a blocked address"
            raise DestinationBlockedError(msg)


class WebhookSink(AlertSink):
    """POSTs each alert as HMAC-signed JSON to a validated HTTPS endpoint."""

    name = "webhook"

    def __init__(
        self,
        url: str,
        secret: str,
        *,
        client: httpx.AsyncClient | None = None,
        timeout_seconds: float = _DEFAULT_TIMEOUT_S,
        max_retries: int = _DEFAULT_MAX_RETRIES,
        allow_private: bool = False,
        resolver: HostResolver = _default_resolver,
        sleeper: Sleeper | None = None,
        min_severity: int = 0,
    ) -> None:
        super().__init__(min_severity=min_severity)
        if not secret:
            raise ValueError("webhook secret must not be empty (HMAC signing is required)")
        self._url = url
        self._secret = secret.encode("utf-8")
        self._allow_private = allow_private
        self._resolver = resolver
        self._max_retries = max(1, max_retries)
        self._sleeper = sleeper if sleeper is not None else asyncio.sleep
        self._client = (
            client
            if client is not None
            else httpx.AsyncClient(timeout=timeout_seconds, verify=True)
        )
        self._log = get_logger("sentinel.alerting.webhook")

    async def emit(self, alert: Alert) -> None:
        # Re-validate on every send: DNS (and config) can change between sends.
        validate_destination(self._url, allow_private=self._allow_private, resolver=self._resolver)
        body = alert.model_dump_json().encode("utf-8")
        signature = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/json",
            _SIGNATURE_HEADER: f"sha256={signature}",
        }
        await self._post_with_retry(body, headers)

    async def _post_with_retry(self, body: bytes, headers: dict[str, str]) -> None:
        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                response = await self._client.post(self._url, content=body, headers=headers)
            except httpx.HTTPError as exc:
                last_error = exc  # network/timeout — retryable
            else:
                if response.status_code < _CLIENT_ERROR_FLOOR:
                    return
                if response.status_code not in _RETRYABLE_STATUS:
                    raise WebhookError(f"webhook returned status {response.status_code}")
                last_error = WebhookError(f"webhook returned status {response.status_code}")
            if attempt < self._max_retries - 1:
                await self._sleeper(_BACKOFF_BASE_S * (2**attempt))
        raise WebhookError("webhook delivery failed after retries") from last_error

    async def aclose(self) -> None:
        """Close the underlying client (safe to call on an injected one too)."""
        await self._client.aclose()
