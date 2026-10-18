"""Email sink — sends an alert over authenticated, TLS-protected SMTP.

Security posture (OWASP A02, NIST SC-8/SC-12):

- **Verified TLS.** STARTTLS (port 587) or implicit TLS (port 465) always runs
  with ``ssl.create_default_context()``: certificate chain *and* host name are
  checked. (``smtplib``'s ``starttls()`` without a context does neither, so a
  machine in the middle could present any certificate and read the password.)
  A server that does not offer STARTTLS is an error, not a silent downgrade.
- **No credentials in clear text.** Credentials without TLS are refused at
  construction; a password without a user name (or the reverse) too.
- **Credentials from the caller only.** The username/password are passed in
  (the app sources them from env-backed settings) and are never logged — a
  delivery failure surfaces only the exception type to the manager.
- **Off the event loop.** ``smtplib`` is blocking, so sending runs in a worker
  thread via :func:`asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
import contextlib
import smtplib
import ssl
from collections.abc import Callable, Sequence
from email.message import EmailMessage
from typing import TYPE_CHECKING, Final, Protocol

from sentinel.alerting.model import severity_label
from sentinel.alerting.sinks.base import AlertSink

if TYPE_CHECKING:
    from sentinel.alerting.model import Alert

_DEFAULT_PORT: Final[int] = 587
_DEFAULT_TIMEOUT_S: Final[float] = 10.0


class SmtpClient(Protocol):
    """The subset of ``smtplib.SMTP`` the sink relies on (for injectable tests)."""

    def starttls(self, *, context: ssl.SSLContext) -> object: ...
    def login(self, user: str, password: str) -> object: ...
    def send_message(self, msg: EmailMessage) -> object: ...
    def quit(self) -> object: ...


# (host, port, timeout, context): a context means implicit TLS from the first byte.
SmtpFactory = Callable[[str, int, float, ssl.SSLContext | None], SmtpClient]


def _default_factory(
    host: str, port: int, timeout: float, context: ssl.SSLContext | None
) -> SmtpClient:  # pragma: no cover - real SMTP
    if context is not None:
        return smtplib.SMTP_SSL(host, port, timeout=timeout, context=context)
    return smtplib.SMTP(host, port, timeout=timeout)


class EmailSink(AlertSink):
    """Emails each alert to a fixed recipient list over TLS SMTP."""

    name = "email"

    def __init__(
        self,
        *,
        host: str,
        sender: str,
        recipients: Sequence[str],
        port: int = _DEFAULT_PORT,
        username: str | None = None,
        password: str | None = None,
        use_starttls: bool = True,
        implicit_tls: bool = False,
        timeout_seconds: float = _DEFAULT_TIMEOUT_S,
        smtp_factory: SmtpFactory = _default_factory,
        min_severity: int = 0,
    ) -> None:
        super().__init__(min_severity=min_severity)
        if not host:
            raise ValueError("email sink requires an SMTP host")
        if not recipients:
            raise ValueError("email sink requires at least one recipient")
        if bool(username) != bool(password):
            raise ValueError("SMTP username and password must be set together")
        if username and not (use_starttls or implicit_tls):
            raise ValueError("SMTP credentials require TLS (STARTTLS or implicit TLS)")
        self._host = host
        self._port = port
        self._sender = sender
        self._recipients = tuple(recipients)
        self._username = username
        self._password = password
        self._use_starttls = use_starttls
        self._implicit_tls = implicit_tls
        self._timeout = timeout_seconds
        self._factory = smtp_factory

    async def emit(self, alert: Alert) -> None:
        message = self._build_message(alert)
        await asyncio.to_thread(self._send, message)

    def _build_message(self, alert: Alert) -> EmailMessage:
        label = severity_label(alert.severity)
        message = EmailMessage()
        message["From"] = self._sender
        message["To"] = ", ".join(self._recipients)
        message["Subject"] = f"[Sentinel][{label}] {alert.rule_id} on {alert.host}"
        message.set_content(
            f"Rule:      {alert.rule_id} — {alert.title}\n"
            f"Severity:  {alert.severity} ({label})\n"
            f"ATT&CK:    {', '.join(alert.attack)}\n"
            f"NIST CSF:  {', '.join(alert.nist_csf)}\n"
            f"Host:      {alert.host}\n"
            f"Time:      {alert.timestamp:%Y-%m-%dT%H:%M:%SZ}\n"
            f"Event id:  {alert.event_id}\n\n"
            f"{alert.summary}\n"
        )
        return message

    def _send(self, message: EmailMessage) -> None:
        """Blocking SMTP send — runs in a worker thread."""
        context = ssl.create_default_context()  # verifies the chain and the host name
        implicit = context if self._implicit_tls else None
        client = self._factory(self._host, self._port, self._timeout, implicit)
        try:
            if self._use_starttls and not self._implicit_tls:
                client.starttls(context=context)
            if self._username and self._password:
                client.login(self._username, self._password)
            client.send_message(message)
        finally:
            # A failed quit (e.g. after a refused TLS handshake) must not mask
            # the error that actually explains the failed delivery.
            with contextlib.suppress(smtplib.SMTPException, OSError):
                client.quit()
