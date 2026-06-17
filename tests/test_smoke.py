"""Smoke tests proving the harness wires up correctly."""

from __future__ import annotations

import sentinel


def test_package_is_importable_and_versioned() -> None:
    assert sentinel.__version__
    assert hasattr(sentinel, "Settings")
    assert hasattr(sentinel, "Environment")


def test_public_api_surface() -> None:
    expected = {"Environment", "LogFormat", "LogLevel", "Settings", "__version__"}
    assert expected.issubset(set(sentinel.__all__))
