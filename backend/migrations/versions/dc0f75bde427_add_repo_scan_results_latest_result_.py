"""add repo scan results latest-result ranking index

Revision ID: dc0f75bde427
Revises: 0a1b037e15df
Create Date: 2026-08-23 10:33:57.466837

"""
from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'dc0f75bde427'
down_revision: str | Sequence[str] | None = '0a1b037e15df'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_index(
        'ix_repo_scan_results_scan_started_id',
        'repo_scan_results',
        ['repo_scan_id', 'started_at', 'id'],
        if_not_exists=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('ix_repo_scan_results_scan_started_id', table_name='repo_scan_results', if_exists=True)
