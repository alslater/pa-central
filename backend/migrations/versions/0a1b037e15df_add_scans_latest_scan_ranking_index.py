"""add scans latest-scan ranking index

Revision ID: 0a1b037e15df
Revises: feb520b531fe
Create Date: 2026-08-22 15:42:43.803003

"""
from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0a1b037e15df'
down_revision: str | Sequence[str] | None = 'feb520b531fe'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_index(
        'ix_scans_host_project_scanned_received_id',
        'scans',
        ['host_id', 'project_path', 'scanned_at', 'received_at', 'id'],
        if_not_exists=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_scans_host_project_scanned_received_id', table_name='scans', if_exists=True)
