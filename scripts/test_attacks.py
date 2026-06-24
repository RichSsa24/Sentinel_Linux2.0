# ruff: noqa
"""Simulate the attacks from demo.sh through the DetectionEngine directly."""

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from sentinel.detection.engine import DetectionEngine
from sentinel.detection.loader import load_rules
from sentinel.events import (
    Event,
    EventCategory,
    EventKind,
    EventMeta,
    EventOutcome,
    File,
    Host,
    Process,
)


def build_event(
    action: str,
    category: EventCategory,
    process_cmd: str | None = None,
    executable: str | None = None,
    file_path: str | None = None,
) -> Event:
    now = datetime.now(UTC)
    base_id = hashlib.sha256(f"{now.timestamp()}_{action}".encode()).hexdigest()

    proc = (
        Process(command_line=process_cmd, executable=executable)
        if (process_cmd or executable)
        else Process()
    )
    f = File(path=file_path) if file_path else None

    return Event(
        timestamp=now,
        event=EventMeta(
            id=base_id,
            kind=EventKind.EVENT,
            category=category,
            action=action,
            outcome=EventOutcome.SUCCESS,
            severity=1,
        ),
        host=Host(name="attack_sim_host"),
        process=proc,
        file=f,
        message=f"Simulated {action}",
    )


def main():
    print("Loading rules...")
    rules = load_rules(Path("rules"))
    engine = DetectionEngine(rules)
    print(f"Loaded {len(rules)} rules.\n")

    # 1. Base64 execution
    print("[*] Simulating: echo 'ls -la' | base64 | base64 -d | sh")
    evt1 = build_event(
        "process_started",
        EventCategory.PROCESS,
        process_cmd="echo 'ls -la' | base64 | base64 -d | sh",
    )
    detections1 = engine.evaluate(evt1)
    if detections1:
        for d in detections1:
            print(f"  [ALARM] {d.rule_id} -> {d.title} (Severity: {d.severity})")
    else:
        print("  [-] No detection.")

    print()

    # 2. Suspicious /tmp execution
    print("[*] Simulating: /tmp/totally_legit_binary > /dev/null")
    evt2 = build_event(
        "process_started",
        EventCategory.PROCESS,
        process_cmd="/tmp/totally_legit_binary > /dev/null",
        executable="/tmp/totally_legit_binary",
    )
    detections2 = engine.evaluate(evt2)
    if detections2:
        for d in detections2:
            print(f"  [ALARM] {d.rule_id} -> {d.title} (Severity: {d.severity})")
    else:
        print("  [-] No detection.")

    print()

    # 3. Cron persistence (File drop)
    print("[*] Simulating: touch /etc/cron.d/test_persistence")
    evt3 = build_event("file_created", EventCategory.FILE, file_path="/etc/cron.d/test_persistence")
    detections3 = engine.evaluate(evt3)
    if detections3:
        for d in detections3:
            print(f"  [ALARM] {d.rule_id} -> {d.title} (Severity: {d.severity})")
    else:
        print("  [-] No detection.")

    print("\nSimulation complete.")


if __name__ == "__main__":
    main()
