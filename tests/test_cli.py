"""Tests for the `sentinel` command line and the scripted demo.

The demo is the project's shop window, so it is held to a contract: it must
detect every attack step, stay silent on the benign records, drop the planted
duplicate, and persist what it consumed. If a rule or the pipeline regresses,
this fails in CI before anyone sees a broken demo.
"""

from __future__ import annotations

import asyncio
import io
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import structlog
import uvicorn

from sentinel import cli
from sentinel.demo import ScenarioCollector, run_demo
from sentinel.detection import load_rules
from sentinel.logging import REDACTED_PLACEHOLDER, get_logger

_RULES = Path(__file__).resolve().parent.parent / "rules"

_EXPECTED_DEMO_RULES = {
    "ssh-brute-force",
    "ssh-root-login",
    "reverse-shell-process",
    "interactive-shell-spawn",
    "c2-beacon-port",
    "base64-execution",
    "suspicious-tmp-exec",
    "account-creation",
    "cron-persistence",
    "new-suid-binary",
    "log-tampering",
}


@pytest.fixture(autouse=True)
def _restore_structlog() -> Any:
    yield
    structlog.reset_defaults()


@pytest.mark.integration
async def test_demo_detects_every_attack_step_and_nothing_benign() -> None:
    result = await run_demo(load_rules(_RULES), stream=io.StringIO())
    assert {alert.rule_id for alert in result.alerts} == _EXPECTED_DEMO_RULES
    assert result.alerts_on_benign == 0
    assert result.benign_events == 3
    assert result.duplicates_dropped == 1
    assert result.persisted_events == result.replayed - 1


@pytest.mark.integration
async def test_demo_returns_even_if_the_pipeline_dies(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: the demo waited for every event to be analyzed with no exit,
    # so a pipeline failure hung `sentinel demo` forever.
    async def crash(self: ScenarioCollector, queue: object) -> None:
        raise RuntimeError("collector bug")

    monkeypatch.setattr(ScenarioCollector, "run", crash)
    result = await asyncio.wait_for(run_demo(load_rules(_RULES), stream=io.StringIO()), timeout=10)
    assert result.alerts == ()
    assert result.persisted_events == 0


def test_demo_ignores_a_local_env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # A developer's .env (here: a tiny dropping queue) must not change the replay.
    (tmp_path / ".env").write_text(
        "SENTINEL_QUEUE_MAXSIZE=1\nSENTINEL_QUEUE_BACKPRESSURE=drop_newest\n", encoding="utf-8"
    )
    monkeypatch.chdir(tmp_path)
    out = io.StringIO()
    assert cli.main(["demo", "--rules-dir", str(_RULES)], out=out) == 0
    assert "0 alerts on the 3 benign events" in out.getvalue()
    assert "11 alerts from 11 rules" in out.getvalue()


def test_demo_ignores_exported_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    # Regression: variables exported for the service leaked into the demo. An
    # alert floor cut it to one alert, and an unknown name crashed it.
    monkeypatch.setenv("SENTINEL_ALERT_MIN_SEVERITY", "7")
    monkeypatch.setenv("SENTINEL_QUEUE_MAXSIZE", "1")
    monkeypatch.setenv("SENTINEL_LOG_LEVL", "DEBUG")
    out = io.StringIO()
    assert cli.main(["demo", "--rules-dir", str(_RULES)], out=out) == 0
    assert "11 alerts from 11 rules" in out.getvalue()


def test_demo_fails_cleanly_on_a_bad_rule_library(tmp_path: Path) -> None:
    (tmp_path / "broken.yml").write_text("id: x\n", encoding="utf-8")
    out = io.StringIO()
    assert cli.main(["demo", "--rules-dir", str(tmp_path)], out=out) == 1
    assert out.getvalue().startswith("rule library is invalid")


def test_cli_logs_are_sanitized_and_kept_off_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    cli._quiet_logs()
    log = get_logger("sentinel.test")
    log.info("cli.chatter")
    log.warning("cli.problem", api_key="hunter2", user="x\x1b[2Jy")  # pragma: allowlist secret
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "cli.chatter" not in captured.err  # below WARNING
    assert "cli.problem" in captured.err
    assert REDACTED_PLACEHOLDER in captured.err
    assert "hunter2" not in captured.err
    assert "\x1b" not in captured.err


def test_demo_command_prints_alerts_and_summary() -> None:
    out = io.StringIO()
    assert cli.main(["demo", "--rules-dir", str(_RULES)], out=out) == 0
    text = out.getvalue()
    assert "[CRITICAL] reverse-shell-process (T1059.004)" in text
    assert "0 alerts on the 3 benign events" in text
    assert "1 duplicate dropped" in text


def test_rules_command_lists_the_library() -> None:
    out = io.StringIO()
    assert cli.main(["rules", "--rules-dir", str(_RULES)], out=out) == 0
    text = out.getvalue()
    assert "ssh-brute-force" in text
    assert "T1110" in text
    assert f"{len(list(_RULES.glob('*.yml')))} rules loaded" in text


def test_rules_command_fails_closed_on_a_bad_library(tmp_path: Path) -> None:
    (tmp_path / "broken.yml").write_text("id: [unclosed\n", encoding="utf-8")
    out = io.StringIO()
    assert cli.main(["rules", "--rules-dir", str(tmp_path)], out=out) == 1
    assert "rule library is invalid" in out.getvalue()


def test_serve_runs_the_production_factory(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append((app, kw)))
    assert cli.main(["serve", "--port", "9001"]) == 0
    app, kwargs = calls[0]
    assert app == "sentinel.api.app:get_app"
    assert kwargs["factory"] is True
    assert kwargs["host"] == "127.0.0.1"  # loopback unless told otherwise
    assert kwargs["port"] == 9001


def test_a_command_is_required() -> None:
    with pytest.raises(SystemExit):
        cli.main([])


def test_python_dash_m_entry_point() -> None:
    proc = subprocess.run(  # noqa: S603 — fixed argv, no shell
        [sys.executable, "-m", "sentinel", "rules", "--rules-dir", str(_RULES)],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    assert "all valid" in proc.stdout
