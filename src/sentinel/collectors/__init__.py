"""Source-specific event collectors.

Each collector owns the producer loop for one source. The framework
enforces one collector per `name` so two producers cannot race on the
same source.
"""

from __future__ import annotations

from sentinel.collectors.authlog import AuthLogCollector, parse_auth_line
from sentinel.collectors.base import AbstractCollector
from sentinel.collectors.integrity import FileIntegrityCollector
from sentinel.collectors.process import ProcessCollector, parse_stat

__all__ = [
    "AbstractCollector",
    "AuthLogCollector",
    "FileIntegrityCollector",
    "ProcessCollector",
    "parse_auth_line",
    "parse_stat",
]
