"""Cross-source enrichment for the normalizer.

Pure and **network-free** by design (a normalization step must not block on DNS
or a metadata service): the host name is resolved once from the local system and
cached, and a small severity ceiling keeps every mapper inside the ECS 0-7 band.
Per-source field mapping lives in :mod:`sentinel.normalizer.mapper`; what is
shared across sources lives here so it is decided in exactly one place.
"""

from __future__ import annotations

import socket
from functools import lru_cache
from typing import Final

from sentinel.events import Host

# ECS event.severity is a 0-7 scale; clamp defensively so a miscomputed raw
# severity can never push an Event out of range (the schema would reject it,
# but clamping turns a hard failure into a bounded, observable value).
_MIN_SEVERITY: Final[int] = 0
_MAX_SEVERITY: Final[int] = 7


@lru_cache(maxsize=1)
def _local_hostname() -> str:
    """Resolve and cache the local host name (no network, gethostname only)."""
    return socket.gethostname() or "localhost"


def resolve_host(name: str | None) -> Host:
    """Build the ECS ``host`` block, falling back to the local host name.

    Collectors pass an explicit host where they have one; otherwise the
    normalizer fills it from the local system so every Event is attributable.
    """
    return Host(name=name or _local_hostname())


def clamp_severity(severity: int) -> int:
    """Clamp a raw severity into the ECS 0-7 band."""
    return max(_MIN_SEVERITY, min(_MAX_SEVERITY, severity))
