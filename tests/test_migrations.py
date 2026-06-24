"""Tests that the Alembic migrations apply, reverse, and match the ORM."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

from sentinel.storage.models import Base

_ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.security


def _config(db_url: str) -> Config:
    cfg = Config(str(_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


class TestMigrations:
    def test_upgrade_creates_tables(self, tmp_path: Path) -> None:
        url = f"sqlite:///{tmp_path / 'm.db'}"
        command.upgrade(_config(url), "head")
        engine = create_engine(url)
        tables = set(inspect(engine).get_table_names())
        engine.dispose()
        assert {"events", "alerts"} <= tables

    def test_downgrade_is_reversible(self, tmp_path: Path) -> None:
        url = f"sqlite:///{tmp_path / 'm.db'}"
        cfg = _config(url)
        command.upgrade(cfg, "head")
        command.downgrade(cfg, "base")
        engine = create_engine(url)
        tables = set(inspect(engine).get_table_names())
        engine.dispose()
        assert "events" not in tables
        assert "alerts" not in tables

    def test_migration_columns_match_orm(self, tmp_path: Path) -> None:
        url = f"sqlite:///{tmp_path / 'm.db'}"
        command.upgrade(_config(url), "head")
        engine = create_engine(url)
        inspector = inspect(engine)
        for table in ("events", "alerts"):
            migrated = {col["name"] for col in inspector.get_columns(table)}
            modelled = {col.name for col in Base.metadata.tables[table].columns}
            assert migrated == modelled, f"schema drift in {table}"
        engine.dispose()
