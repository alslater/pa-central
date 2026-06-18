"""add_cron_timezone_to_repo_scans

Revision ID: f3a1c9d82b74
Revises: e52704e9c869
Create Date: 2026-06-13 08:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'f3a1c9d82b74'
down_revision: Union[str, Sequence[str], None] = 'e52704e9c869'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('repo_scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('cron_timezone', sa.String(100), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('repo_scans', schema=None) as batch_op:
        batch_op.drop_column('cron_timezone')
