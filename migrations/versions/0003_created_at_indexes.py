"""index created_at: retention deletes by insertion time

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-18

``SENTINEL_RETENTION_DAYS`` deletes rows stored before a cutoff, in bounded
batches; without these indexes every batch would scan the whole table.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index("ix_events_created_at", "events", ["created_at"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_alerts_created_at", table_name="alerts")
    op.drop_index("ix_events_created_at", table_name="events")
