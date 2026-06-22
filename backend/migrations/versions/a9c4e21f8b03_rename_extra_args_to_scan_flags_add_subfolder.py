"""rename_extra_args_to_scan_flags_add_subfolder

Revision ID: a9c4e21f8b03
Revises: a1b2c3d4e5f6
Create Date: 2026-06-19 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a9c4e21f8b03'
down_revision: Union[str, Sequence[str], None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('repo_scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scan_flags', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('subfolder', sa.String(500), nullable=True))
        batch_op.drop_column('extra_args')


def downgrade() -> None:
    with op.batch_alter_table('repo_scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('extra_args', sa.String(500), nullable=True))
        batch_op.drop_column('subfolder')
        batch_op.drop_column('scan_flags')
