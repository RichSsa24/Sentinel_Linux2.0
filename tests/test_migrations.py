"""Tests that the Alembic migrations apply, reverse, and match the ORM."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.migration import MigrationContext
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
    def test_migrating_creates_a_private_database(self, tmp_path: Path) -> None:
        # On bare metal `alembic upgrade head` is what creates the database file.
        path = tmp_path / "m.db"
        previous = os.umask(0o022)
        try:
            command.upgrade(_config(f"sqlite:///{path}"), "head")
        finally:
            os.umask(previous)
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

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

    def test_migrations_match_the_orm_exactly(self, tmp_path: Path) -> None:
        # Column names alone missed type, nullability, default and index drift.
        url = f"sqlite:///{tmp_path / 'm.db'}"
        command.upgrade(_config(url), "head")
        engine = create_engine(url)
        with engine.connect() as connection:
            context = MigrationContext.configure(
                connection, opts={"compare_type": True, "compare_server_default": True}
            )
            drift = compare_metadata(context, Base.metadata)
        engine.dispose()
        assert drift == []
