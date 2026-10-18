"""Console sink — one line per alert, readable text or JSON.

Writes to an injectable text stream (stdout by default), so it is trivially
testable against a ``StringIO`` and never reaches for ``print``. The text line
leads with a severity label and the ATT&CK technique(s) so an operator scanning
a terminal gets the "what and how bad" at a glance. With ``json_lines`` (the
service uses it when ``SENTINEL_LOG_FORMAT=json``) each alert is one JSON
object instead, so a log shipper parsing the container's output never meets a
plain-text line.

Part of an alert comes from the host — the host name is whatever a syslog line
said, and rsyslog may accept syslog from the network — so control characters
are escaped in the text line: an ESC sequence must not reach the operator's
terminal (CWE-150). JSON encoding escapes them by itself.
"""

from __future__ import annotations

import json
import sys
from typing import TYPE_CHECKING, Final

from sentinel.alerting.model import severity_label
from sentinel.alerting.sinks.base import AlertSink

if TYPE_CHECKING:
    from typing import TextIO

    from sentinel.alerting.model import Alert

# C0 controls, DEL and C1 controls, written as \xNN.
_CONTROL_ESCAPES: Final[dict[int, str]] = {
    code: f"\\x{code:02x}" for code in (*range(0x20), *range(0x7F, 0xA0))
}


class ConsoleSink(AlertSink):
    """Writes each alert as a single line — readable text, or JSON — to a stream."""

    name = "console"

    def __init__(
        self, *, stream: TextIO | None = None, json_lines: bool = False, min_severity: int = 0
    ) -> None:
        super().__init__(min_severity=min_severity)
        self._stream: TextIO = stream if stream is not None else sys.stdout
        self._json = json_lines

    async def emit(self, alert: Alert) -> None:
        line = self.render_json(alert) if self._json else self.render(alert)
        self._stream.write(line + "\n")
        self._stream.flush()

    @staticmethod
    def render(alert: Alert) -> str:
        """Format one alert as a readable console line, control characters escaped."""
        label = severity_label(alert.severity)
        techniques = ",".join(alert.attack)
        line = (
            f"{alert.timestamp:%Y-%m-%dT%H:%M:%SZ} [{label}] "
            f"{alert.rule_id} ({techniques}) host={alert.host} :: {alert.summary}"
        )
        return line.translate(_CONTROL_ESCAPES)

    @staticmethod
    def render_json(alert: Alert) -> str:
        """Format one alert as a single-line JSON object."""
        record = {"event": "alert", "level": severity_label(alert.severity).lower()}
        record.update(alert.model_dump(mode="json"))
        return json.dumps(record, ensure_ascii=True, separators=(",", ":"))
