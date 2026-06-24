"""Shared pytest fixtures and test helpers."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from sentinel import Settings
from sentinel.alerting.model import Alert
from sentinel.api import create_app
from sentinel.detection.engine import Detection
from sentinel.detection.loader import load_rules
from sentinel.detection.schema import Rule
from sentinel.events import (
    Event,
    EventCategory,
    EventKind,
    EventMeta,
    EventOutcome,
    Host,
    Source,
)
from sentinel.metrics import Metrics
from sentinel.normalizer import Normalizer, RawEvent
from sentinel.storage import Database

_FIXED_TS = datetime(2026, 6, 22, 12, 0, 0, tzinfo=UTC)

# Fixed bearer key for API tests (not a real credential).
TEST_API_KEY = "test-api-key-0123456789"  # pragma: allowlist secret


def make_event(
    *,
    event_id: str = "0" * 64,
    category: EventCategory = EventCategory.NETWORK,
    action: str = "network_listen_started",
    outcome: EventOutcome = EventOutcome.SUCCESS,
    severity: int = 4,
    host: str = "host1",
    source_ip: str | None = "10.0.0.5",
    port: int | None = 4444,
    message: str = "test event",
    timestamp: datetime = _FIXED_TS,
) -> Event:
    """Build a normalized Event for storage/API tests."""
    return Event(
        timestamp=timestamp,
        event=EventMeta(
            id=event_id,
            kind=EventKind.EVENT,
            category=category,
            action=action,
            outcome=outcome,
            severity=severity,
        ),
        host=Host(name=host),
        source=Source(ip=source_ip, port=port),
        message=message,
    )


def make_detection(
    *,
    rule_id: str = "reverse-shell-process",
    severity: int = 5,
    attack: tuple[str, ...] = ("T1059.004",),
    nist_csf: tuple[str, ...] = ("DE.CM",),
    event_id: str = "0" * 64,
    host: str = "host1",
    message: str = "reverse shell detected",
) -> Detection:
    """Build a Detection for alerting tests."""
    return Detection(
        rule_id=rule_id,
        title="Test rule",
        severity=severity,
        attack=attack,
        nist_csf=nist_csf,
        d3fend=(),
        event_id=event_id,
        host=host,
        timestamp=_FIXED_TS,
        message=message,
    )


def make_alert(**overrides: object) -> Alert:
    """Build an Alert from a (possibly customized) Detection."""
    return Alert.from_detection(make_detection(**overrides))  # type: ignore[arg-type]


class DeadLetterNormalizer(Normalizer):
    """A normalizer that dead-letters every record.

    Injected into a collector to exercise its fail-closed skip path: an
    unmappable record must be dropped (not enqueued, not crashing the producer).
    """

    def normalize(self, raw: RawEvent) -> Event | None:
        return None


@pytest.fixture(autouse=True)
def _isolate_sentinel_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Clear all `SENTINEL_*` env vars before each test.

    Settings are env-driven, so test determinism requires that the OS
    environment cannot leak state between tests or from the developer's shell.
    """
    for key in list(os.environ):
        if key.startswith("SENTINEL_"):
            monkeypatch.delenv(key, raising=False)
    yield


def settings_no_env_file() -> Settings:
    """Construct `Settings` while ignoring any local `.env` file.

    `_env_file` is an undocumented underscore kwarg in pydantic-settings v2 —
    real but not in the public stubs, hence the single targeted ignore.
    """
    return Settings(_env_file=None)  # type: ignore[call-arg]


def make_api_settings(**overrides: object) -> Settings:
    """Settings for API tests, with a bearer key configured by default."""
    params: dict[str, object] = {"_env_file": None, "env": "test", "api_key": TEST_API_KEY}
    params.update(overrides)
    return Settings(**params)  # type: ignore[arg-type]


@pytest.fixture
async def database(tmp_path: Path) -> AsyncIterator[Database]:
    """A fresh file-backed SQLite database (shared across sessions)."""
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")
    await db.create_all()
    yield db
    await db.dispose()


@pytest.fixture
def metrics() -> Metrics:
    """A Metrics instance with its own isolated registry."""
    return Metrics()


@pytest.fixture(scope="session")
def rules() -> tuple[Rule, ...]:
    """The real rule library, loaded once."""
    return tuple(load_rules(Path(__file__).resolve().parent.parent / "rules"))


@pytest.fixture
def api_settings() -> Settings:
    """API settings with a bearer key configured."""
    return make_api_settings()


@pytest.fixture
async def api_client(
    database: Database,
    metrics: Metrics,
    api_settings: Settings,
    rules: tuple[Rule, ...],
) -> AsyncIterator[httpx.AsyncClient]:
    """An httpx client bound to the API via ASGI (no network)."""
    app = create_app(api_settings, database=database, metrics=metrics, rules=rules)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


def auth_header(key: str = TEST_API_KEY) -> dict[str, str]:
    """Bearer auth header for API tests."""
    return {"Authorization": f"Bearer {key}"}
