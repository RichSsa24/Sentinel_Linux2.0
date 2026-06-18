"""Raw -> ECS event normalization layer.

Collectors produce source-specific raw records; this package owns the single
mapping from those records to the common :class:`~sentinel.events.Event`, with a
fail-closed dead-letter path for anything that cannot be mapped.
"""

from __future__ import annotations

from sentinel.normalizer.mapper import Normalizer, map_raw
from sentinel.normalizer.raw import (
    RawAuthEvent,
    RawEvent,
    RawFileEvent,
    RawNetworkEvent,
    RawProcessEvent,
    RawSource,
)

__all__ = [
    "Normalizer",
    "RawAuthEvent",
    "RawEvent",
    "RawFileEvent",
    "RawNetworkEvent",
    "RawProcessEvent",
    "RawSource",
    "map_raw",
]
