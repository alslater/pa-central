"""widen_fixed_versions_to_text

Changes finding_records.fixed_versions from String(1000) to Text so that
long version lists from upstream scanners don't cause truncation or
VARCHAR-limit errors on PostgreSQL.

Revision ID: c7d4e8f19a25
Revises: b1e3f7a92c04
Create Date: 2026-06-25 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c7d4e8f19a25'
down_revision: Union[str, Sequence[str], None] = 'b1e3f7a92c04'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('finding_records', schema=None) as batch_op:
        batch_op.alter_column(
            'fixed_versions',
            existing_type=sa.String(length=1000),
            type_=sa.Text(),
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table('finding_records', schema=None) as batch_op:
        batch_op.alter_column(
            'fixed_versions',
            existing_type=sa.Text(),
            type_=sa.String(length=1000),
            existing_nullable=True,
        )
