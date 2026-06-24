"""Pydantic response models for the read API.

These are the *output* shapes — deliberately separate from the storage rows and
the internal domain models, so the wire contract is explicit and a column never
leaks by accident. Responses use the project envelope
``{success, data, pagination}``.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from sentinel.detection.schema import Rule
from sentinel.storage.models import AlertRow, EventRow


def _split(value: str) -> list[str]:
    return [part for part in value.split(",") if part]


class EventOut(BaseModel):
    """One persisted event as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    event_id: str
    occurred_at: datetime
    category: str
    action: str
    outcome: str
    severity: int
    host: str
    source_ip: str | None
    message: str

    @classmethod
    def from_row(cls, row: EventRow) -> EventOut:
        return cls.model_validate(row)


class AlertOut(BaseModel):
    """One persisted alert as returned by the API."""

    id: int
    dedup_key: str
    rule_id: str
    severity: int
    attack: list[str]
    nist_csf: list[str]
    event_id: str
    host: str
    occurred_at: datetime
    summary: str

    @classmethod
    def from_row(cls, row: AlertRow) -> AlertOut:
        return cls(
            id=row.id,
            dedup_key=row.dedup_key,
            rule_id=row.rule_id,
            severity=row.severity,
            attack=_split(row.attack),
            nist_csf=_split(row.nist_csf),
            event_id=row.event_id,
            host=row.host,
            occurred_at=row.occurred_at,
            summary=row.summary,
        )


class RuleOut(BaseModel):
    """One detection rule as returned by the API (no condition internals)."""

    id: str
    title: str
    severity: int
    attack: list[str]
    nist_csf: list[str]
    d3fend: list[str]

    @classmethod
    def from_rule(cls, rule: Rule) -> RuleOut:
        return cls(
            id=rule.id,
            title=rule.title,
            severity=rule.severity,
            attack=list(rule.attack),
            nist_csf=list(rule.nist_csf),
            d3fend=list(rule.d3fend),
        )


class Pagination(BaseModel):
    """Keyset pagination metadata."""

    model_config = ConfigDict(populate_by_name=True)

    cursor: int | None = Field(default=None, description="Pass as ?cursor= to fetch the next page.")
    has_more: bool = Field(serialization_alias="hasMore")
    total: int | None = None


class Page[T](BaseModel):
    """The project response envelope for a paginated list."""

    success: bool = True
    data: list[T]
    pagination: Pagination
