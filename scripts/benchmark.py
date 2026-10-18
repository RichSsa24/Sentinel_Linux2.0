#!/usr/bin/env python3
"""Reproducible micro-benchmarks for Sentinel's hot paths.

Each benchmark reports the median of several repetitions, so one noisy run does
not move the number. Run from the repo root:

    uv run python scripts/benchmark.py            # all benchmarks
    uv run python scripts/benchmark.py engine fim # a subset

Benchmarks
----------
engine    DetectionEngine.evaluate over a realistic mixed event stream.
fim       Steady-state FIM poll over a synthetic tree (files settled, no changes).
process   Steady-state process-collector poll over the real /proc.
persist   Events written to SQLite: one commit per event vs one per batch.
pipeline  Collector -> bounded queue -> dedup -> consumer, 80% duplicates.
runtime   End to end: collector -> dedup -> 17 rules -> alerts -> SQLite.

The numbers in the README come from this script; rerun it rather than trusting
them on different hardware.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import platform
import statistics
import sys
import tempfile
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import structlog

from sentinel.collectors.base import AbstractCollector
from sentinel.collectors.integrity import FileIntegrityCollector
from sentinel.collectors.process import ProcessCollector
from sentinel.detection import DetectionEngine, load_rules
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
from sentinel.metrics import Metrics
from sentinel.pipeline import BoundedEventQueue, Pipeline
from sentinel.runtime import Runtime
from sentinel.settings import Settings
from sentinel.storage import Database, Pending, Repository, write_ids

_ROOT = Path(__file__).resolve().parent.parent
_REPEATS = 5


def _median_seconds(func: Callable[[], object], repeats: int = _REPEATS) -> float:
    samples = []
    for _ in range(repeats):
        started = time.perf_counter()
        func()
        samples.append(time.perf_counter() - started)
    return statistics.median(samples)


def _event(i: int, kind: str) -> Event:
    """One synthetic event of the given kind; ids are unique per `i`."""
    meta = {
        "proc": (EventCategory.PROCESS, "process_started" if i % 2 else "process_stopped"),
        "net": (EventCategory.NETWORK, "network_connection_opened"),
        "file": (EventCategory.FILE, "file_modified"),
        "auth": (EventCategory.AUTHENTICATION, "ssh_login_failed"),
    }[kind]
    return Event(
        timestamp=datetime.now(tz=UTC),
        event=EventMeta(
            id=Event.compute_id(kind, i),
            kind=EventKind.EVENT,
            category=meta[0],
            action=meta[1],
            outcome=EventOutcome.SUCCESS,
            severity=3,
        ),
        host=Host(name="bench"),
        source=Source(ip=f"10.0.{i % 250}.{i % 200}", port=40000 + i % 1000, user="alice"),
        destination=Destination(ip="93.184.216.34", port=443) if kind == "net" else Destination(),
        process=(
            Process(
                pid=1000 + i,
                ppid=1,
                name="python3",
                executable="/usr/bin/python3",
                command_line=f"/usr/bin/python3 /opt/app/worker.py --job {i} --verbose",
            )
            if kind == "proc"
            else Process()
        ),
        file=File(path=f"/etc/app/conf.d/{i}.conf", mode="0644") if kind == "file" else None,
        message=f"synthetic {kind} event {i}",
    )


def _mixed_events(count: int) -> list[Event]:
    # Roughly the mix a busy host produces: process churn dominates.
    kinds = ["proc"] * 6 + ["net"] * 2 + ["file", "auth"]
    return [_event(i, kinds[i % len(kinds)]) for i in range(count)]


# ---------------------------------------------------------------- benchmarks


def bench_engine() -> str:
    rules = load_rules(_ROOT / "rules")
    events = _mixed_events(20_000)

    def run() -> None:
        engine = DetectionEngine(rules)
        for event in events:
            engine.evaluate(event)

    seconds = _median_seconds(run)
    return f"{len(events) / seconds:,.0f} events/s ({len(rules)} rules)"


def bench_fim() -> str:
    files, size = 2_000, 16 * 1024
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        payload = os.urandom(size)
        for i in range(files):
            sub = root / f"d{i % 20}"
            sub.mkdir(exist_ok=True)
            (sub / f"f{i}.conf").write_bytes(payload)
        time.sleep(2.5)  # let the files "settle" past the collector's racy-ctime window
        collector = FileIntegrityCollector([root])
        previous = collector._scan()  # warm the page cache; this is the last poll's view
        seconds = _median_seconds(lambda: collector._scan(previous))
    mib = files * size / 2**20
    return f"{seconds * 1e3:,.1f} ms per poll ({files:,} files, {mib:.0f} MiB)"


def bench_process() -> str:
    collector = ProcessCollector()
    snapshot = collector._scan(collector._scan())  # seen twice: settled, steady state
    seconds = _median_seconds(lambda: collector._scan(snapshot), repeats=21)
    per_proc = seconds / max(len(snapshot), 1) * 1e6
    return f"{seconds * 1e3:,.2f} ms per poll ({len(snapshot)} procs, {per_proc:.1f} µs/proc)"


def bench_persist() -> str:
    events = _mixed_events(2_000)

    async def per_event(db: Database) -> None:
        for event in events:
            async with db.session() as session:
                await Repository(session).save_event(event)

    ids = write_ids()
    pending = [Pending(next(ids), event) for event in events]  # as the runtime buffers them

    async def batched(db: Database, batch: int) -> None:
        for start in range(0, len(pending), batch):
            async with db.session() as session:
                await Repository(session).save_batch(events=pending[start : start + batch])

    async def measure(write: Callable[[Database], object]) -> float:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f"sqlite+aiosqlite:///{tmp}/bench.db")
            await db.create_all()
            started = time.perf_counter()
            await write(db)  # type: ignore[misc]
            elapsed = time.perf_counter() - started
            await db.dispose()
            return elapsed

    async def run() -> tuple[float, float]:
        single = statistics.median([await measure(per_event) for _ in range(3)])
        batch = statistics.median([await measure(lambda d: batched(d, 256)) for _ in range(3)])
        return single, batch

    single, batch = asyncio.run(run())
    return (
        f"{len(events) / single:,.0f} events/s one-commit-per-event · "
        f"{len(events) / batch:,.0f} events/s batched (256)"
    )


class _Firehose(AbstractCollector):
    def __init__(self, name: str, events: list[Event]) -> None:
        super().__init__(name=name)
        self._events = events

    async def run(self, queue: BoundedEventQueue) -> None:
        for event in self._events:
            await queue.put(event)


def bench_pipeline() -> str:
    unique = _mixed_events(20_000)
    stream = [event for event in unique for _ in range(5)]  # 80% duplicates

    async def run() -> float:
        pipeline = Pipeline(Settings(env="test"))
        pipeline.register(_Firehose("firehose", stream))
        seen = 0
        all_unique_seen = asyncio.Event()

        async def consumer(_event: Event) -> None:
            nonlocal seen
            seen += 1
            if seen == len(unique):
                all_unique_seen.set()

        pipeline.set_consumer(consumer)
        started = time.perf_counter()
        task = asyncio.create_task(pipeline.run())
        await all_unique_seen.wait()
        await pipeline.stop()  # drains the trailing duplicates, then reaps the consumer
        elapsed = time.perf_counter() - started
        await asyncio.wait({task})
        if seen != len(unique):
            msg = f"expected {len(unique)} unique events, consumer saw {seen}"
            raise RuntimeError(msg)
        return elapsed

    seconds = statistics.median([asyncio.run(run()) for _ in range(3)])
    return f"{len(stream) / seconds:,.0f} events/s ({len(stream):,} in, {len(unique):,} unique)"


def bench_runtime() -> str:
    events = _mixed_events(5_000)
    rules = load_rules(_ROOT / "rules")

    async def run() -> float:
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(f"sqlite+aiosqlite:///{tmp}/bench.db")
            await db.create_all()
            metrics = Metrics()
            runtime = Runtime(
                Settings(env="test"),  # default write-behind settings
                database=db,
                metrics=metrics,
                rules=rules,
                collectors=[_Firehose("firehose", events)],
                sinks=[],
            )
            started = time.perf_counter()
            runtime.start()
            while metrics.events_ingested._value.get() < len(events):  # noqa: ASYNC110 — polls a counter; there is no completion hook to await
                await asyncio.sleep(0.005)
            await runtime.stop()  # includes the final flush
            elapsed = time.perf_counter() - started
            await db.dispose()
            return elapsed

    seconds = statistics.median([asyncio.run(run()) for _ in range(3)])
    return f"{len(events) / seconds:,.0f} events/s ({len(events):,} events, all persisted)"


BENCHMARKS: dict[str, Callable[[], str]] = {
    "engine": bench_engine,
    "fim": bench_fim,
    "process": bench_process,
    "persist": bench_persist,
    "pipeline": bench_pipeline,
    "runtime": bench_runtime,
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("names", nargs="*", choices=[*BENCHMARKS, []], default=[])
    names = parser.parse_args().names or list(BENCHMARKS)
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(40))  # quiet
    print(f"python {platform.python_version()} · {platform.machine()} · {os.cpu_count()} CPUs")
    print("| benchmark | result |\n| --- | --- |")
    for name in names:
        print(f"| {name} | {BENCHMARKS[name]()} |")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
