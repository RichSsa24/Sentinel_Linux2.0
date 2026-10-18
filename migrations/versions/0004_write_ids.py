"""write_id: a retried write cannot store a record twice

Revision ID: 0004
Revises: 0003
Create Date: 2026-10-18

A write can commit while its acknowledgement is lost (a deadline, a dropped
connection), and the writer retries it. Each buffered record now carries a
write id, and inserts skip ids already stored (``ON CONFLICT DO NOTHING`` on
these unique indexes). Rows stored before this revision keep a NULL write id;
NULLs never conflict.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("events", sa.Column("write_id", sa.String(32), nullable=True))
    op.create_index("ix_events_write_id", "events", ["write_id"], unique=True)
    op.add_column("alerts", sa.Column("write_id", sa.String(32), nullable=True))
    op.create_index("ix_alerts_write_id", "alerts", ["write_id"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_alerts_write_id", table_name="alerts")
    with op.batch_alter_table("alerts") as batch:  # SQLite cannot DROP COLUMN in place
        batch.drop_column("write_id")
    op.drop_index("ix_events_write_id", table_name="events")
    with op.batch_alter_table("events") as batch:
        batch.drop_column("write_id")
