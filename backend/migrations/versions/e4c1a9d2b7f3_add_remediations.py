"""add remediations to scans and repo_scan_results

Revision ID: e4c1a9d2b7f3
Revises: 7b0e9bd83541
Create Date: 2026-10-06 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'e4c1a9d2b7f3'
down_revision: str | Sequence[str] | None = '7b0e9bd83541'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLES = ("scans", "repo_scan_results")


def upgrade() -> None:
    """Add nullable JSON `remediations` (package-alert >= 0.9.0 upgrade advice).

    Guarded per table so a replay after a partial failure converges, matching
    7b0e9bd83541's pattern.
    """
    bind = op.get_bind()
    for table in _TABLES:
        columns = {c["name"] for c in sa.inspect(bind).get_columns(table)}
        if "remediations" not in columns:
            op.add_column(table, sa.Column("remediations", sa.JSON(), nullable=True))


def downgrade() -> None:
    """Drop `remediations`. The data is advisory and re-produced by the next scan."""
    bind = op.get_bind()
    for table in _TABLES:
        columns = {c["name"] for c in sa.inspect(bind).get_columns(table)}
        if "remediations" in columns:
            with op.batch_alter_table(table) as batch:
                batch.drop_column("remediations")
