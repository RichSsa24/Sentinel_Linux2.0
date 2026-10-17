"""docs/COVERAGE.md must be exactly what its generator produces from rules/."""

from __future__ import annotations

import runpy
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def test_coverage_matrix_is_up_to_date() -> None:
    generator = runpy.run_path(str(_ROOT / "scripts" / "generate_coverage_matrix.py"))
    expected = generator["render"]()
    actual = (_ROOT / "docs" / "COVERAGE.md").read_text(encoding="utf-8")
    assert actual == expected, "run `uv run python scripts/generate_coverage_matrix.py`"
