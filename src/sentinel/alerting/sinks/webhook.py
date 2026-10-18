"""Webhook sink — hardened outbound POST of an alert as signed JSON.

This sink treats the network as hostile in both directions (OWASP A10 SSRF,
NIST SC):

- **HTTPS only, TLS verified, no redirects, no proxies from the environment.**
  The URL must be ``https``; certificates and the host name are verified; a
  3xx is a failed delivery (never followed); ``HTTPS_PROXY`` and friends are
  ignored, because a proxy would resolve the host itself, behind the guard.
- **SSRF guard, pinned.** Before every send the host is resolved (without
  blocking the event loop) and every address must be globally routable
  unicast: loopback, private, link-local (cloud metadata 169.254.169.254),
  shared/CGNAT (100.64.0.0/10), reserved, documentation, multicast and
  unspecified addresses are refused, IPv4-mapped IPv6 included. The request
  then goes to the address that was checked — the host name is kept for the
  ``Host`` header and TLS (SNI and certificate check) — so a DNS answer that
  changes between the check and the connection (rebinding) cannot redirect
  it. Private targets are allowed only when explicitly opted in.
- **HMAC-signed payload.** The body is signed with a shared secret
  (HMAC-SHA256) in the ``X-Sentinel-Signature`` header so the receiver can
  verify authenticity and integrity.
- **Bounded.** Each attempt has a total deadline (a server that drips its
  response one byte at a time cannot hold it open), retries are capped with
  exponential backoff, and the secret and payload never appear in an error.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Final, NamedTuple
from urllib.parse import urlsplit

import httpx

from sentinel.alerting.sinks.base import AlertSink
from sentinel.logging import get_logger

if TYPE_CHECKING:
    from sentinel.alerting.model import Alert

_DEFAULT_TIMEOUT_S: Final[float] = 5.0
_DEFAULT_MAX_RETRIES: Final[int] = 3
_BACKOFF_BASE_S: Final[float] = 0.5
_HTTPS_PORT: Final[int] = 443
_SIGNATURE_HEADER: Final[str] = "X-Sentinel-Signature"
_SUCCESS: Final[range] = range(200, 300)
_RETRYABLE_STATUS: Final[frozenset[int]] = frozenset({429, 500, 502, 503, 504})

# (host, port) -> the addresses it resolves to.
HostResolver = Callable[[str, int], Awaitable[list[str]]]
Sleeper = Callable[[float], Awaitable[None]]


class WebhookError(Exception):
    """A webhook alert could not be delivered."""


class DestinationBlockedError(WebhookError):
    """The destination failed the SSRF / scheme policy and was refused."""


class Destination(NamedTuple):
    """A checked webhook target: host and port as configured, addresses as resolved."""

    host: str
    port: int
    addresses: tuple[str, ...]


async def _default_resolver(host: str, port: int) -> list[str]:  # pragma: no cover - real DNS
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


def is_blocked_address(address: str) -> bool:
    """True unless ``address`` is a globally routable unicast address."""
    ip = ipaddress.ip_address(address)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 is 127.0.0.1
    return not ip.is_global or ip.is_multicast


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _split(url: str) -> tuple[str, int]:
    """The host and port of an https URL; raises DestinationBlockedError otherwise."""
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise DestinationBlockedError("webhook URL must use https")
    if not parts.hostname:
        raise DestinationBlockedError("webhook URL has no host")
    try:
        port = parts.port or _HTTPS_PORT
    except ValueError as exc:
        raise DestinationBlockedError("webhook URL has an invalid port") from exc
    return parts.hostname, port


def validate_destination(url: str, *, allow_private: bool = False) -> None:
    """Startup check, without DNS: https, a host, and no blocked IP literal.

    Host names are checked against their resolved addresses on every send
    (:func:`resolve_destination`); DNS may legitimately be unavailable at boot.
    """
    host, _port = _split(url)
    if not allow_private and _is_ip_literal(host) and is_blocked_address(host):
        raise DestinationBlockedError(f"webhook destination {host} is a blocked address")


async def resolve_destination(
    url: str, *, allow_private: bool = False, resolver: HostResolver = _default_resolver
) -> Destination:
    """Resolve ``url``'s host and refuse it unless every address is allowed."""
    host, port = _split(url)
    addresses = [host] if _is_ip_literal(host) else await resolver(host, port)
    if not addresses:
        raise DestinationBlockedError(f"webhook destination {host} did not resolve")
    if not allow_private and any(is_blocked_address(address) for address in addresses):
        raise DestinationBlockedError(f"webhook destination {host} resolves to a blocked address")
    return Destination(host, port, tuple(addresses))


def _pinned_url(url: str, destination: Destination) -> str:
    """``url`` with its host replaced by the checked address (IPv6 bracketed)."""
    address = destination.addresses[0]
    literal = f"[{address}]" if ":" in address else address
    parts = urlsplit(url)
    return parts._replace(netloc=f"{literal}:{destination.port}").geturl()


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
        self._timeout = timeout_seconds
        self._max_retries = max(1, max_retries)
        self._sleeper = sleeper if sleeper is not None else asyncio.sleep
        self._client = (
            client
            if client is not None
            else httpx.AsyncClient(
                timeout=timeout_seconds, verify=True, trust_env=False, follow_redirects=False
            )
        )
        self._log = get_logger("sentinel.alerting.webhook")

    async def emit(self, alert: Alert) -> None:
        # Re-resolve and re-check on every send: DNS (and config) can change.
        destination = await resolve_destination(
            self._url, allow_private=self._allow_private, resolver=self._resolver
        )
        body = alert.model_dump_json().encode("utf-8")
        signature = hmac.new(self._secret, body, hashlib.sha256).hexdigest()
        headers = {
            "Content-Type": "application/json",
            _SIGNATURE_HEADER: f"sha256={signature}",
            "Host": urlsplit(self._url).netloc.rpartition("@")[2],
        }
        # TLS must verify the configured name, not the pinned address.
        extensions = {} if _is_ip_literal(destination.host) else {"sni_hostname": destination.host}
        await self._post_with_retry(_pinned_url(self._url, destination), body, headers, extensions)

    async def _post_with_retry(
        self, url: str, body: bytes, headers: dict[str, str], extensions: dict[str, str]
    ) -> None:
        last_error: Exception | None = None
        for attempt in range(self._max_retries):
            try:
                async with asyncio.timeout(self._timeout):  # the whole attempt, body included
                    response = await self._client.post(
                        url, content=body, headers=headers, extensions=extensions
                    )
            except (httpx.HTTPError, TimeoutError) as exc:
                last_error = exc  # network/timeout — retryable
            else:
                if response.status_code in _SUCCESS:
                    return
                if response.status_code not in _RETRYABLE_STATUS:
                    # A redirect is never followed: it would leave the checked address.
                    raise WebhookError(f"webhook returned status {response.status_code}")
                last_error = WebhookError(f"webhook returned status {response.status_code}")
            if attempt < self._max_retries - 1:
                await self._sleeper(_BACKOFF_BASE_S * (2**attempt))
        raise WebhookError("webhook delivery failed after retries") from last_error

    async def aclose(self) -> None:
        """Close the underlying client (safe to call on an injected one too)."""
        await self._client.aclose()
