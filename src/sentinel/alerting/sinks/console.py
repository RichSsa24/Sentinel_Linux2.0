"""Console sink — a readable one-line-per-alert renderer.

Writes to an injectable text stream (stdout by default), so it is trivially
testable against a ``StringIO`` and never reaches for ``print``. The line leads
with a severity label and the ATT&CK technique(s) so an operator scanning a
terminal gets the "what and how bad" at a glance.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

from sentinel.alerting.model import severity_label
from sentinel.alerting.sinks.base import AlertSink

if TYPE_CHECKING:
    from typing import TextIO

    from sentinel.alerting.model import Alert


class ConsoleSink(AlertSink):
    """Renders each alert as a single readable line to a text stream."""

    name = "console"

    def __init__(self, *, stream: TextIO | None = None, min_severity: int = 0) -> None:
        super().__init__(min_severity=min_severity)
        self._stream: TextIO = stream if stream is not None else sys.stdout

    async def emit(self, alert: Alert) -> None:
        self._stream.write(self.render(alert) + "\n")
        self._stream.flush()

    @staticmethod
    def render(alert: Alert) -> str:
        """Format one alert as a readable console line."""
        label = severity_label(alert.severity)
        techniques = ",".join(alert.attack)
        return (
            f"{alert.timestamp:%Y-%m-%dT%H:%M:%SZ} [{label}] "
            f"{alert.rule_id} ({techniques}) host={alert.host} :: {alert.summary}"
        )
