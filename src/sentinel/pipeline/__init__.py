"""Pipeline spine: bounded queue + dedup window + single-consumer orchestrator."""

from __future__ import annotations

from sentinel.pipeline.dedup import DedupWindow
from sentinel.pipeline.queue import BoundedEventQueue
from sentinel.pipeline.runner import EventConsumer, Pipeline

__all__ = [
    "BoundedEventQueue",
    "DedupWindow",
    "EventConsumer",
    "Pipeline",
]
