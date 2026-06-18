"""widen_credential_secret_arn_to_text

Revision ID: a1b2c3d4e5f6
Revises: f3a1c9d82b74
Create Date: 2026-06-16 12:00:00.000000

String(500) was too small for local-mode SSH keys stored inline as
`local://<pem-data>`. Text is unbounded on both SQLite and Postgres.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, Sequence[str], None] = 'f3a1c9d82b74'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('repo_credentials', schema=None) as batch_op:
        batch_op.alter_column(
            'credential_secret_arn',
            existing_type=sa.String(500),
            type_=sa.Text(),
            existing_nullable=True,
        )


def downgrade() -> None:
    with op.batch_alter_table('repo_credentials', schema=None) as batch_op:
        batch_op.alter_column(
            'credential_secret_arn',
            existing_type=sa.Text(),
            type_=sa.String(500),
            existing_nullable=True,
        )
