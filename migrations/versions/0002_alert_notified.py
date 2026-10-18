"""alerts.notified: record alerts the throttle withheld from notification

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-18

Throttled alerts used to be discarded. They are now stored with
``notified = false``; every alert stored before this revision was notified.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "alerts",
        sa.Column("notified", sa.Boolean(), nullable=False, server_default=sa.true()),
    )


def downgrade() -> None:
    with op.batch_alter_table("alerts") as batch:  # SQLite cannot DROP COLUMN in place
        batch.drop_column("notified")
