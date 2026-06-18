"""Tests for `sentinel.normalizer`.

Layers:

1. **Golden fixtures** — each ``<source>_raw.json`` must normalize to its
   committed ``<source>_expected.json``. This pins the raw -> ECS mapping for
   every source; an unintended change to a field, the id derivation, or the
   message format breaks the golden file.
2. **Dead-letter** — a raw record that cannot be mapped is quarantined (counted,
   logged) and yields ``None``; no invalid Event escapes the normalizer.
3. **Per-source behavior** — the network listener/connection split, ECS field
   placement, and id determinism.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from sentinel.events import Event, EventCategory
from sentinel.normalizer import Normalizer, RawSource, map_raw
from sentinel.normalizer.enrich import clamp_severity, resolve_host
from sentinel.normalizer.raw import (
    RAW_EVENT_ADAPTER,
    RawAuthEvent,
    RawNetworkEvent,
    RawProcessEvent,
)

FIXTURES = Path(__file__).parent / "fixtures" / "normalizer"
_SOURCES = ["auth", "process", "file", "network"]


def _raw_dict(source: str) -> dict[str, object]:
    data: dict[str, object] = json.loads(
        (FIXTURES / f"{source}_raw.json").read_text(encoding="utf-8")
    )
    return data


class TestGoldenFixtures:
    @pytest.mark.parametrize("source", _SOURCES)
    def test_raw_maps_to_expected_event(self, source: str) -> None:
        expected = json.loads((FIXTURES / f"{source}_expected.json").read_text(encoding="utf-8"))
        raw = RAW_EVENT_ADAPTER.validate_python(_raw_dict(source))

        event = Normalizer().normalize(raw)

        assert event is not None
        assert event.model_dump(mode="json") == expected

    @pytest.mark.parametrize("source", _SOURCES)
    def test_every_normalized_record_is_a_valid_event(self, source: str) -> None:
        raw = RAW_EVENT_ADAPTER.validate_python(_raw_dict(source))
        event = Normalizer().normalize(raw)
        assert isinstance(event, Event)

    def test_adapter_dispatches_on_source_discriminator(self) -> None:
        raw = RAW_EVENT_ADAPTER.validate_python(_raw_dict("network"))
        assert isinstance(raw, RawNetworkEvent)
        assert raw.source is RawSource.NETWORK


class TestDispatch:
    @pytest.mark.parametrize(
        ("source", "category"),
        [
            ("auth", EventCategory.AUTHENTICATION),
            ("process", EventCategory.PROCESS),
            ("file", EventCategory.FILE),
            ("network", EventCategory.NETWORK),
        ],
    )
    def test_map_raw_routes_to_the_right_category(
        self, source: str, category: EventCategory
    ) -> None:
        raw = RAW_EVENT_ADAPTER.validate_python(_raw_dict(source))
        assert map_raw(raw).event.category is category


class TestDeadLetter:
    def test_unknown_outcome_is_dead_lettered_not_raised(self) -> None:
        # `outcome` is free-form on the raw record; an unmappable value (not an
        # ECS outcome) must be quarantined, not crash the caller.
        raw = RawAuthEvent(
            occurred_at=datetime(2026, 6, 17, tzinfo=UTC),
            host="h",
            syslog_ts="Jun 17 12:00:00",
            action="ssh_login_failed",
            outcome="bogus",
            severity=4,
            user="root",
            ip="10.0.0.9",
            port=22,
            message="x",
        )
        normalizer = Normalizer()

        event = normalizer.normalize(raw)

        assert event is None
        assert normalizer.stats == {"normalized": 0, "dead_letters": 1}

    def test_valid_record_increments_normalized_counter(self) -> None:
        normalizer = Normalizer()
        normalizer.normalize(RAW_EVENT_ADAPTER.validate_python(_raw_dict("process")))
        assert normalizer.stats == {"normalized": 1, "dead_letters": 0}


class TestNetworkMapping:
    def _net(self, *, state: str, action: str) -> RawNetworkEvent:
        return RawNetworkEvent(
            occurred_at=datetime(2026, 6, 17, tzinfo=UTC),
            host="h",
            action=action,
            severity=2,
            proto="tcp",
            local_ip="10.0.0.5",
            local_port=51000,
            remote_ip="93.184.216.34",
            remote_port=443,
            state=state,
            uid=1000,
            inode=900,
        )

    def test_established_connection_populates_destination(self) -> None:
        event = map_raw(self._net(state="ESTABLISHED", action="network_connection_opened"))
        assert event.destination.ip == "93.184.216.34"
        assert event.destination.port == 443
        assert "->" in event.message

    def test_listener_leaves_destination_empty(self) -> None:
        event = map_raw(self._net(state="LISTEN", action="network_listen_started"))
        assert event.destination.ip is None
        assert "->" not in event.message


class TestDeterminism:
    def test_same_raw_yields_same_event_id(self) -> None:
        raw = RAW_EVENT_ADAPTER.validate_python(_raw_dict("file"))
        first = map_raw(raw)
        second = map_raw(raw)
        assert first.event.id == second.event.id


class TestRawValidation:
    def test_naive_occurred_at_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="UTC"):
            RawProcessEvent(
                occurred_at=datetime(2026, 6, 17),  # noqa: DTZ001 — testing the reject path
                host="h",
                action="process_started",
                severity=3,
                pid=1,
                ppid=0,
                starttime=1,
            )

    def test_non_utc_occurred_at_is_rejected(self) -> None:
        with pytest.raises(ValidationError, match="UTC"):
            RawProcessEvent(
                occurred_at=datetime(2026, 6, 17, tzinfo=timezone(timedelta(hours=2))),
                host="h",
                action="process_started",
                severity=3,
                pid=1,
                ppid=0,
                starttime=1,
            )


class TestEnrich:
    def test_resolve_host_uses_explicit_name(self) -> None:
        assert resolve_host("web-01").name == "web-01"

    def test_resolve_host_falls_back_to_local_when_empty(self) -> None:
        host = resolve_host(None)
        assert host.name  # some non-empty local host name

    @pytest.mark.parametrize(
        ("value", "expected"),
        [(-3, 0), (0, 0), (4, 4), (7, 7), (99, 7)],
    )
    def test_clamp_severity_bounds_to_ecs_range(self, value: int, expected: int) -> None:
        assert clamp_severity(value) == expected
