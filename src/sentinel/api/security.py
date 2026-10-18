"""API hardening: bearer auth, security headers, rate limiting, request context.

Every data endpoint depends on :func:`require_api_key`, which is **default-deny**:
if no key is configured the API refuses all access, and a supplied token is
compared in constant time. The middlewares add the standard security headers,
a per-client sliding-window rate limit (bounded so spoofed clients can't grow
state without bound), and a request id for correlated structured logging.
"""

from __future__ import annotations

import hmac
import secrets
import time
from collections import deque
from collections.abc import Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Final

import structlog
from fastapi import HTTPException, Request, status
from pydantic import SecretStr
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from sentinel.logging import get_logger

if TYPE_CHECKING:
    from sentinel.settings import Settings

_log = get_logger("sentinel.api")

_Dispatch = Callable[[Request], Awaitable[Response]]

# Applied to every response. HSTS is only meaningful over HTTPS but is harmless
# on http and correct once TLS terminates in front of the app.
_SECURITY_HEADERS: Final[Mapping[str, str]] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cache-Control": "no-store",
    # A JSON API loads nothing and is never framed.
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}

_MAX_TRACKED_CLIENTS: Final[int] = 100_000


def error_response(
    status_code: int, code: str, message: str, headers: Mapping[str, str] | None = None
) -> JSONResponse:
    """The project error envelope, with the hardening headers already applied.

    Carrying the headers itself keeps them on errors produced outside the
    middleware that normally adds them (e.g. Starlette's outermost handler).
    """
    return JSONResponse(
        status_code=status_code,
        content={"success": False, "error": {"code": code, "message": message}},
        headers={**_SECURITY_HEADERS, **(headers or {})},
    )


def _log_auth_failure(request: Request, *, reason: str) -> None:
    """Record a failed authentication without any credential material (CWE-532).

    Only the reason and the client address are logged — never the presented
    token, the Authorization header, or the configured key. The values are
    passed as structured fields (not interpolated into the message) so the
    logging pipeline's control-char stripping still applies to them.
    """
    _log.warning(
        "api.auth_failed",
        reason=reason,
        client=request.client.host if request.client else "unknown",
        path=request.url.path,
    )


def _bearer_token(request: Request) -> str | None:
    """The token of an ``Authorization: Bearer <token>`` header, if present."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    return token if scheme.lower() == "bearer" and token else None


def _token_matches(token: str, configured: SecretStr) -> bool:
    """Constant-time comparison of a presented token with the configured key."""
    return hmac.compare_digest(token.encode(), configured.get_secret_value().encode())


def require_api_key(request: Request) -> None:
    """FastAPI dependency: enforce a valid bearer token; fail closed.

    Raises 503 when no key is configured (the API is unusable without one),
    401 when the bearer token is missing or wrong.
    """
    settings: Settings = request.app.state.settings
    configured = settings.api_key
    if configured is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="authentication is not configured",
        )
    token = _bearer_token(request)
    if token is None:
        _log_auth_failure(request, reason="missing_bearer_token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not _token_matches(token, configured):
        _log_auth_failure(request, reason="invalid_token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add hardening headers to every response."""

    async def dispatch(self, request: Request, call_next: _Dispatch) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach a request id, emit structured access logs, contain unhandled errors.

    The request id is bound to the logging context, so every line logged while
    serving the request carries it. An unhandled exception becomes a generic
    500 here, inside the middleware stack: Starlette's own last-resort handler
    sits outside every middleware, so its 500 had no request id, no hardening
    headers and no access-log line, and it re-raised to the server, which
    printed the traceback outside the logging pipeline.
    """

    async def dispatch(self, request: Request, call_next: _Dispatch) -> Response:
        request_id = secrets.token_hex(8)
        with structlog.contextvars.bound_contextvars(request_id=request_id):
            try:
                response = await call_next(request)
            except Exception as exc:
                _log.exception("api.unhandled_error", error=type(exc).__name__)
                response = error_response(
                    status.HTTP_500_INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "an unexpected error occurred",
                )
            response.headers["X-Request-ID"] = request_id
            _log.info(
                "api.request",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
            )
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-client sliding-window rate limit with bounded client tracking.

    The client is the TCP peer address; ``sentinel serve`` does not trust
    ``X-Forwarded-For``, so a client cannot pick its own bucket. Callers that
    present the API key get a budget separate from unauthenticated traffic
    from the same address, so a scanner — or any local user on a loopback
    deployment — cannot throttle Prometheus or the API's consumers.

    ``exempt_paths`` are never limited and never charged: a health probe that
    could be throttled would let any client mark a healthy service down. An
    exempt endpoint must therefore be cheap to call (see ``/readyz``).
    """

    def __init__(
        self,
        app: Callable[..., Awaitable[None]],
        *,
        limit: int,
        window_seconds: float,
        api_key: SecretStr | None = None,
        exempt_paths: frozenset[str] = frozenset(),
        time_source: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(app)
        self._exempt = exempt_paths
        self._limit = limit
        self._window = window_seconds
        self._api_key = api_key
        self._now = time_source
        self._hits: dict[str, deque[float]] = {}

    async def dispatch(self, request: Request, call_next: _Dispatch) -> Response:
        if request.url.path in self._exempt:
            return await call_next(request)
        client = request.client.host if request.client else "unknown"
        token = _bearer_token(request)
        authenticated = (
            token is not None and self._api_key is not None and _token_matches(token, self._api_key)
        )
        now = self._now()
        window = self._window_for(f"{'key' if authenticated else 'anon'}:{client}")
        cutoff = now - self._window
        while window and window[0] < cutoff:
            window.popleft()
        if len(window) >= self._limit:
            return error_response(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                "rate limit exceeded",
                headers={"Retry-After": str(int(self._window) or 1)},
            )
        window.append(now)
        return await call_next(request)

    def _window_for(self, client: str) -> deque[float]:
        existing = self._hits.get(client)
        if existing is not None:
            return existing
        if len(self._hits) >= _MAX_TRACKED_CLIENTS:
            # Bounded memory: evict the oldest-tracked client (insertion order).
            del self._hits[next(iter(self._hits))]
        window: deque[float] = deque()
        self._hits[client] = window
        return window
