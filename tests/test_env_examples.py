"""Keep the shipped `.env.example` templates in lock-step with `Settings`.

`Settings` refuses to start on an unknown `SENTINEL_*` variable, so a template
that documents a misspelled or renamed key is worse than useless: uncommenting
it bricks startup. These tests fail the build on any drift.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from sentinel.settings import ENV_PREFIX, Settings

_ROOT = Path(__file__).resolve().parent.parent
_TEMPLATES = (
    _ROOT / ".env.example",
    _ROOT / "deploy" / ".env.example",
    _ROOT / "deploy" / "systemd" / "sentinel.env.example",
)
# Matches both active (`KEY=`) and documented-but-commented (`# KEY=`) entries.
_KEY_RE = re.compile(rf"^#?\s*({ENV_PREFIX}[A-Z0-9_]+)=", re.MULTILINE)
_VALID_KEYS = frozenset(f"{ENV_PREFIX}{name.upper()}" for name in Settings.model_fields)


def _documented_keys(path: Path) -> set[str]:
    return set(_KEY_RE.findall(path.read_text(encoding="utf-8")))


@pytest.mark.parametrize("template", _TEMPLATES, ids=lambda p: str(p.relative_to(_ROOT)))
def test_template_only_documents_real_settings(template: Path) -> None:
    unknown = _documented_keys(template) - _VALID_KEYS
    assert not unknown, f"{template.name} documents keys Settings would reject: {sorted(unknown)}"


@pytest.mark.parametrize(
    "path",
    [*sorted((_ROOT / "scripts").glob("*.sh")), _ROOT / "deploy" / "docker-compose.yml"],
    ids=lambda p: str(p.relative_to(_ROOT)),
)
def test_scripts_only_use_real_settings(path: Path) -> None:
    # A helper script that reads e.g. SENTINEL_API would invite users to export
    # it, after which every `sentinel` command refuses to start.
    names = set(re.findall(rf"\b({ENV_PREFIX}[A-Z0-9_]+)\b", path.read_text(encoding="utf-8")))
    assert not names - _VALID_KEYS, (
        f"{path.name} uses unknown settings: {sorted(names - _VALID_KEYS)}"
    )


def test_root_template_documents_every_setting() -> None:
    missing = _VALID_KEYS - _documented_keys(_ROOT / ".env.example")
    assert not missing, f".env.example is missing: {sorted(missing)}"
