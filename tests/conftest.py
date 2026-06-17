"""Shared pytest fixtures and test helpers."""

from __future__ import annotations

import os
from collections.abc import Iterator

import pytest

from sentinel import Settings


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
