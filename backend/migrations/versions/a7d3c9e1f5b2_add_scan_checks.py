"""add not_public and yank results to scans and repo_scan_results

Revision ID: a7d3c9e1f5b2
Revises: f1a2b3c4d5e6
Create Date: 2026-10-29 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'a7d3c9e1f5b2'
down_revision: str | Sequence[str] | None = 'f1a2b3c4d5e6'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = ("scans", "repo_scan_results")


def _new_columns() -> list[sa.Column]:
    return [
        # Existing rows: nothing was counted as not public, and the yank check is not known
        # to have run, the same reading they had before.
        sa.Column("not_public", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("yank_checked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("yanked", sa.JSON(), nullable=True),
        sa.Column("yank_failures", sa.Integer(), nullable=True),
    ]


def upgrade() -> None:
    """Add package-alert #121's scan checks. Each column is guarded so a replay after a
    partial failure converges (7b0e9bd83541's pattern)."""
    bind = op.get_bind()
    for table in _TABLES:
        existing = {c["name"] for c in sa.inspect(bind).get_columns(table)}
        for column in _new_columns():
            if column.name not in existing:
                op.add_column(table, column)


def downgrade() -> None:
    """Drop the columns. The data is re-produced by the next scan."""
    bind = op.get_bind()
    for table in _TABLES:
        existing = {c["name"] for c in sa.inspect(bind).get_columns(table)}
        present = [c.name for c in _new_columns() if c.name in existing]
        if present:
            with op.batch_alter_table(table) as batch:
                for name in present:
                    batch.drop_column(name)
