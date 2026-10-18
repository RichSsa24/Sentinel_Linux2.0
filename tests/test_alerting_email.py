"""Tests for the email (SMTP/TLS) sink — no real network or credentials."""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage

import pytest

from sentinel.alerting.sinks.email import EmailSink
from tests.conftest import make_alert

_PASSWORD = "smtp-secret-pw"  # pragma: allowlist secret


class _FakeSMTP:
    """Records the SMTP conversation the sink drives."""

    def __init__(self) -> None:
        self.started_tls = False
        self.tls_context: ssl.SSLContext | None = None
        self.login_args: tuple[str, str] | None = None
        self.sent: EmailMessage | None = None
        self.quit_called = False

    def starttls(self, *, context: ssl.SSLContext) -> object:
        self.started_tls = True
        self.tls_context = context
        return None

    def login(self, user: str, password: str) -> object:
        self.login_args = (user, password)
        return None

    def send_message(self, msg: EmailMessage) -> object:
        self.sent = msg
        return None

    def quit(self) -> object:
        self.quit_called = True
        return None


def _sink(
    fake: _FakeSMTP, implicit: list[ssl.SSLContext | None] | None = None, **kwargs: object
) -> EmailSink:
    def factory(_h: str, _p: int, _t: float, context: ssl.SSLContext | None) -> _FakeSMTP:
        if implicit is not None:
            implicit.append(context)
        return fake

    return EmailSink(
        host="smtp.example.com",
        sender="sentinel@example.com",
        recipients=["soc@example.com"],
        smtp_factory=factory,
        **kwargs,  # type: ignore[arg-type]
    )


def _verifies(context: ssl.SSLContext | None) -> bool:
    return (
        context is not None
        and context.verify_mode is ssl.CERT_REQUIRED
        and context.check_hostname is True
    )


class TestConstruction:
    def test_requires_host(self) -> None:
        with pytest.raises(ValueError, match="SMTP host"):
            EmailSink(host="", sender="a@b.c", recipients=["x@y.z"])

    def test_requires_recipients(self) -> None:
        with pytest.raises(ValueError, match="recipient"):
            EmailSink(host="smtp", sender="a@b.c", recipients=[])


@pytest.mark.security
class TestTransportSecurity:
    """Regression: starttls() ran without a context, i.e. without verification."""

    @pytest.mark.asyncio
    async def test_starttls_verifies_certificate_and_host_name(self) -> None:
        fake = _FakeSMTP()
        await _sink(fake, username="user", password=_PASSWORD).emit(make_alert())
        assert _verifies(fake.tls_context)

    @pytest.mark.asyncio
    async def test_implicit_tls_is_verified_and_skips_starttls(self) -> None:
        fake = _FakeSMTP()
        contexts: list[ssl.SSLContext | None] = []
        sink = _sink(fake, contexts, username="user", password=_PASSWORD, implicit_tls=True)
        await sink.emit(make_alert())
        assert _verifies(contexts[0])
        assert fake.started_tls is False

    @pytest.mark.asyncio
    async def test_the_tls_failure_is_reported_not_masked_by_quit(self) -> None:
        class _RefusedTls(_FakeSMTP):
            def starttls(self, *, context: ssl.SSLContext) -> object:
                raise ssl.SSLCertVerificationError("certificate verify failed")

            def quit(self) -> object:
                raise smtplib.SMTPServerDisconnected("Server not connected")

        with pytest.raises(ssl.SSLCertVerificationError):
            await _sink(_RefusedTls(), username="user", password=_PASSWORD).emit(make_alert())

    def test_credentials_without_tls_are_refused(self) -> None:
        with pytest.raises(ValueError, match="require TLS"):
            _sink(_FakeSMTP(), username="user", password=_PASSWORD, use_starttls=False)

    @pytest.mark.parametrize(
        "credentials", [{"username": "user"}, {"password": _PASSWORD}], ids=["user", "password"]
    )
    def test_half_set_credentials_are_refused(self, credentials: dict[str, str]) -> None:
        with pytest.raises(ValueError, match="together"):
            _sink(_FakeSMTP(), None, **credentials)


class TestEmit:
    @pytest.mark.asyncio
    async def test_starttls_and_login_and_send(self) -> None:
        fake = _FakeSMTP()
        sink = _sink(fake, username="user", password=_PASSWORD)

        await sink.emit(make_alert(rule_id="ssh-brute-force", severity=6))

        assert fake.started_tls is True
        assert fake.login_args == ("user", _PASSWORD)
        assert fake.sent is not None
        assert fake.quit_called is True

    @pytest.mark.asyncio
    async def test_message_has_subject_recipients_and_body(self) -> None:
        fake = _FakeSMTP()
        await _sink(fake).emit(make_alert(rule_id="ssh-brute-force", severity=6, host="db-1"))

        assert fake.sent is not None
        assert "ssh-brute-force" in fake.sent["Subject"]
        assert fake.sent["To"] == "soc@example.com"
        assert "db-1" in fake.sent.get_content()

    @pytest.mark.asyncio
    async def test_no_login_without_credentials(self) -> None:
        fake = _FakeSMTP()
        await _sink(fake).emit(make_alert())
        assert fake.login_args is None  # never authenticates without creds

    @pytest.mark.security
    @pytest.mark.asyncio
    async def test_password_never_appears_in_the_message(self) -> None:
        fake = _FakeSMTP()
        await _sink(fake, username="user", password=_PASSWORD).emit(make_alert())
        assert fake.sent is not None
        rendered = f"{fake.sent['Subject']}\n{fake.sent.get_content()}"
        assert _PASSWORD not in rendered

    @pytest.mark.asyncio
    async def test_starttls_skipped_when_disabled(self) -> None:
        fake = _FakeSMTP()
        await _sink(fake, use_starttls=False).emit(make_alert())
        assert fake.started_tls is False
