"""Deployment files agree with the code they run.

The supervisors (Docker Compose, systemd) must wait out the worst-case
graceful shutdown before SIGKILL, or the buffered events and undelivered
notifications they would cut off are lost; both must start the server
through `sentinel serve`, whose hardening (no proxy headers, no server
header, the app's own logging) the tests in test_cli.py pin.
"""

from __future__ import annotations

import configparser
import inspect
import re
from pathlib import Path

import yaml

from sentinel.alerting.manager import AlertManager
from tests.conftest import make_api_settings

_DEPLOY = Path(__file__).resolve().parent.parent / "deploy"


def _unit() -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(strict=False)
    parser.optionxform = str  # type: ignore[assignment,method-assign]  # keys are case-sensitive
    parser.read(_DEPLOY / "systemd" / "sentinel.service", encoding="utf-8")
    return parser


def _seconds(value: str) -> float:
    match = re.fullmatch(r"(\d+)(s?)", value.strip())
    assert match, f"unsupported duration {value!r}"
    return float(match.group(1))


def _worst_case_shutdown_s() -> float:
    """The write in flight and the final write, then the alert drain."""
    drain = inspect.signature(AlertManager.aclose).parameters["drain_timeout"].default
    return 2 * make_api_settings().persist_write_timeout_seconds + float(drain)


def test_supervisors_wait_out_a_worst_case_shutdown() -> None:
    budget = _worst_case_shutdown_s()
    compose = yaml.safe_load((_DEPLOY / "docker-compose.yml").read_text("utf-8"))
    assert _seconds(compose["services"]["sentinel"]["stop_grace_period"]) > budget
    assert _seconds(_unit()["Service"]["TimeoutStopSec"]) > budget


def test_the_unit_runs_the_hardened_server_and_restarts_it() -> None:
    service = _unit()["Service"]
    assert service["ExecStart"].endswith("/sentinel serve --host 127.0.0.1 --port 8000")
    assert "alembic upgrade head" in service["ExecStartPre"]
    assert service["Restart"] == "always"  # the pipeline's on_fatal exits for a restart
    assert service["NoNewPrivileges"] == "yes"
    assert service["CapabilityBoundingSet"] == ""
    assert service["UMask"] == "0077"
