"""Alert sink contract.

A sink delivers an :class:`~sentinel.alerting.model.Alert` to one channel
(console, webhook, email). Each sink declares a ``min_severity`` so the manager
can route by severity — a noisy console sink might take everything while an
email sink only takes high-severity alerts. Sinks must be fail-safe: ``emit``
raising is caught by the manager, but a sink should still avoid leaking secrets
or payloads in whatever it logs on its own error paths.
"""

from __future__ import annotations

import abc

from sentinel.alerting.model import Alert


class AlertSink(abc.ABC):
    """Base class for every alert delivery channel."""

    name: str = ""

    def __init__(self, *, name: str | None = None, min_severity: int = 0) -> None:
        if name is not None:
            self.name = name
        if not self.name:
            msg = f"{type(self).__name__} must set a non-empty `name`"
            raise ValueError(msg)
        if not 0 <= min_severity <= 7:  # noqa: PLR2004 — ECS severity is a fixed 0-7 band
            msg = f"min_severity must be within ECS 0-7; got {min_severity}"
            raise ValueError(msg)
        self._min_severity = min_severity

    @property
    def min_severity(self) -> int:
        """Alerts below this ECS severity are not delivered to this sink."""
        return self._min_severity

    def accepts(self, alert: Alert) -> bool:
        """Whether this sink should receive `alert` given its severity floor."""
        return alert.severity >= self._min_severity

    @abc.abstractmethod
    async def emit(self, alert: Alert) -> None:
        """Deliver one alert. May raise; the manager isolates failures."""
