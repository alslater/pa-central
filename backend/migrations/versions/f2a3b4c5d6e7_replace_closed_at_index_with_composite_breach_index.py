"""replace closed_at index with composite (closed_at, sla_breach_cutoff_at) breach index

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
Create Date: 2026-07-08

Replaces the single-column ix_finding_records_closed_at with a composite index
on (closed_at, sla_breach_cutoff_at). The composite covers:
  - closed_at IS NULL scans (same as before, via leftmost-prefix rule)
  - breach filter: closed_at IS NULL AND sla_breach_cutoff_at < :now (range scan)
"""
from typing import Sequence, Union

from alembic import op

revision: str = 'f2a3b4c5d6e7'
down_revision: Union[str, Sequence[str], None] = 'e1f2a3b4c5d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index('ix_finding_records_closed_at', table_name='finding_records', if_exists=True)
    op.create_index(
        'ix_finding_records_closed_breach',
        'finding_records',
        ['closed_at', 'sla_breach_cutoff_at'],
    )


def downgrade() -> None:
    op.drop_index('ix_finding_records_closed_breach', table_name='finding_records')
    op.create_index(
        'ix_finding_records_closed_at',
        'finding_records',
        ['closed_at'],
    )
