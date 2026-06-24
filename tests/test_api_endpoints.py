"""Integration tests for the read API endpoints."""

from __future__ import annotations

import httpx
import pytest

from sentinel.api import create_app
from sentinel.detection.schema import Rule
from sentinel.metrics import Metrics
from sentinel.storage import Database, Repository
from tests.conftest import auth_header, make_alert, make_api_settings, make_event


async def _seed_events(database: Database, count: int) -> None:
    async with database.session() as session:
        repo = Repository(session)
        for i in range(count):
            await repo.save_event(make_event(event_id=f"{i:064d}", message=f"evt-{i}"))


async def _seed_alerts(database: Database, count: int) -> None:
    async with database.session() as session:
        repo = Repository(session)
        for i in range(count):
            await repo.save_alert(make_alert(event_id=f"{i:064d}"))


class TestEventsEndpoint:
    async def test_lists_seeded_events(
        self, database: Database, api_client: httpx.AsyncClient
    ) -> None:
        await _seed_events(database, 3)
        body = (await api_client.get("/events", headers=auth_header())).json()
        assert body["success"] is True
        assert len(body["data"]) == 3
        assert body["pagination"]["total"] == 3
        assert body["pagination"]["hasMore"] is False

    async def test_pagination_cursor_walk(
        self, database: Database, api_client: httpx.AsyncClient
    ) -> None:
        await _seed_events(database, 5)
        first = (await api_client.get("/events?limit=2", headers=auth_header())).json()
        assert len(first["data"]) == 2
        assert first["pagination"]["hasMore"] is True
        cursor = first["pagination"]["cursor"]

        second = (
            await api_client.get(f"/events?limit=2&cursor={cursor}", headers=auth_header())
        ).json()
        first_ids = {row["id"] for row in first["data"]}
        second_ids = {row["id"] for row in second["data"]}
        assert first_ids.isdisjoint(second_ids)

    async def test_last_page_has_no_cursor(
        self, database: Database, api_client: httpx.AsyncClient
    ) -> None:
        await _seed_events(database, 2)
        body = (await api_client.get("/events?limit=50", headers=auth_header())).json()
        assert body["pagination"]["hasMore"] is False
        assert body["pagination"]["cursor"] is None

    @pytest.mark.security
    @pytest.mark.parametrize("limit", [0, -1, 99999, 101])
    async def test_out_of_range_limit_rejected(
        self, api_client: httpx.AsyncClient, limit: int
    ) -> None:
        resp = await api_client.get(f"/events?limit={limit}", headers=auth_header())
        assert resp.status_code == 422

    @pytest.mark.security
    @pytest.mark.parametrize(
        "cursor",
        ["abc", "'; DROP TABLE events;--", "1 OR 1=1", "0", "-5", "1.5"],
    )
    async def test_malicious_cursor_is_neutralized(
        self, api_client: httpx.AsyncClient, cursor: str
    ) -> None:
        # Non-integer / out-of-range cursors never reach the DB — rejected at validation.
        resp = await api_client.get("/events", params={"cursor": cursor}, headers=auth_header())
        assert resp.status_code == 422
        assert resp.json()["error"]["code"] == "VALIDATION_ERROR"

    @pytest.mark.security
    async def test_sql_payload_in_data_is_inert(
        self, database: Database, api_client: httpx.AsyncClient
    ) -> None:
        async with database.session() as session:
            await Repository(session).save_event(make_event(message="'; DROP TABLE events;--"))
        body = (await api_client.get("/events", headers=auth_header())).json()
        # Table intact, payload returned as literal text.
        assert body["data"][0]["message"] == "'; DROP TABLE events;--"


class TestAlertsEndpoint:
    async def test_lists_alerts_with_split_attack(
        self, database: Database, api_client: httpx.AsyncClient
    ) -> None:
        await _seed_alerts(database, 1)
        body = (await api_client.get("/alerts", headers=auth_header())).json()
        assert body["data"][0]["attack"] == ["T1059.004"]
        assert isinstance(body["data"][0]["nist_csf"], list)


class TestRulesEndpoint:
    async def test_lists_all_rules(
        self, api_client: httpx.AsyncClient, rules: tuple[Rule, ...]
    ) -> None:
        body = (await api_client.get("/rules", headers=auth_header())).json()
        assert body["pagination"]["total"] == len(rules)
        assert {"id", "title", "severity", "attack"} <= body["data"][0].keys()


class TestMetricsEndpoint:
    async def test_exposes_prometheus_text(self, api_client: httpx.AsyncClient) -> None:
        resp = await api_client.get("/metrics", headers=auth_header())
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        assert "sentinel_events_ingested_total" in resp.text


class TestErrorHandling:
    async def test_unknown_path_is_generic_404(self, api_client: httpx.AsyncClient) -> None:
        resp = await api_client.get("/does-not-exist", headers=auth_header())
        assert resp.status_code == 404
        body = resp.json()
        assert body["success"] is False
        assert "Traceback" not in resp.text
        assert "sqlite" not in resp.text.lower()

    @pytest.mark.security
    async def test_readyz_reports_503_when_db_unreachable(
        self, tmp_path: object, rules: tuple[Rule, ...]
    ) -> None:
        # A database whose file lives under a non-existent directory cannot open.
        broken = Database(f"sqlite+aiosqlite:///{tmp_path}/missing-dir/x.db")
        app = create_app(make_api_settings(), database=broken, metrics=Metrics(), rules=rules)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/readyz")
        await broken.dispose()
        assert resp.status_code == 503
        assert resp.json()["error"]["code"] == "NOT_READY"

    @pytest.mark.security
    async def test_unhandled_error_is_generic_500(
        self, tmp_path: object, rules: tuple[Rule, ...]
    ) -> None:
        broken = Database(f"sqlite+aiosqlite:///{tmp_path}/missing-dir/x.db")
        app = create_app(make_api_settings(), database=broken, metrics=Metrics(), rules=rules)
        # raise_app_exceptions=False so the transport returns the 500 the handler produced.
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            resp = await client.get("/events", headers=auth_header())
        await broken.dispose()
        assert resp.status_code == 500
        body = resp.json()
        assert body["error"]["code"] == "INTERNAL_ERROR"
        assert "Traceback" not in resp.text
        assert "missing-dir" not in resp.text
