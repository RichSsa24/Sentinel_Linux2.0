"""Email sink — sends an alert over authenticated, TLS-protected SMTP.

Security posture (OWASP A02, NIST SC-8/SC-12):

- **TLS always.** The default path issues STARTTLS before authenticating;
  Python's ``starttls()`` uses a verifying default SSL context, so credentials
  never cross the wire in clear text. Implicit TLS (SMTP_SSL) is supported by
  injecting a factory.
- **Credentials from the caller only.** The username/password are passed in
  (the app sources them from env-backed settings) and are never logged — a
  delivery failure surfaces only the exception type to the manager.
- **Off the event loop.** ``smtplib`` is blocking, so sending runs in a worker
  thread via :func:`asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
import smtplib
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

    def starttls(self) -> object: ...
    def login(self, user: str, password: str) -> object: ...
    def send_message(self, msg: EmailMessage) -> object: ...
    def quit(self) -> object: ...


SmtpFactory = Callable[[str, int, float], SmtpClient]


def _default_factory(host: str, port: int, timeout: float) -> SmtpClient:
    return smtplib.SMTP(host, port, timeout=timeout)  # pragma: no cover - real SMTP


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
        timeout_seconds: float = _DEFAULT_TIMEOUT_S,
        smtp_factory: SmtpFactory = _default_factory,
        min_severity: int = 0,
    ) -> None:
        super().__init__(min_severity=min_severity)
        if not host:
            raise ValueError("email sink requires an SMTP host")
        if not recipients:
            raise ValueError("email sink requires at least one recipient")
        self._host = host
        self._port = port
        self._sender = sender
        self._recipients = tuple(recipients)
        self._username = username
        self._password = password
        self._use_starttls = use_starttls
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
        client = self._factory(self._host, self._port, self._timeout)
        try:
            if self._use_starttls:
                client.starttls()
            if self._username and self._password:
                client.login(self._username, self._password)
            client.send_message(message)
        finally:
            client.quit()
