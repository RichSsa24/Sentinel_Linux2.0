"""initial schema: events and alerts

Revision ID: 0001
Revises:
Create Date: 2026-06-23

Append-only audit tables for normalized events and processed alerts. Mirrors
``sentinel.storage.models``; kept hand-written so the reviewable schema and the
ORM stay in lock-step.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("action", sa.String(200), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("host", sa.String(253), nullable=False),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_events_event_id", "events", ["event_id"])
    op.create_index("ix_events_occurred_at_id", "events", ["occurred_at", "id"])

    op.create_table(
        "alerts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("dedup_key", sa.String(256), nullable=False),
        sa.Column("rule_id", sa.String(64), nullable=False),
        sa.Column("severity", sa.Integer(), nullable=False),
        sa.Column("attack", sa.String(256), nullable=False),
        sa.Column("nist_csf", sa.String(256), nullable=False),
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("host", sa.String(253), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_alerts_dedup_key", "alerts", ["dedup_key"])
    op.create_index("ix_alerts_rule_id", "alerts", ["rule_id"])
    op.create_index("ix_alerts_occurred_at_id", "alerts", ["occurred_at", "id"])


def downgrade() -> None:
    op.drop_table("alerts")
    op.drop_table("events")
