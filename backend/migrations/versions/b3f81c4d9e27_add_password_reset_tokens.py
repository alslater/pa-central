"""add password reset tokens

Revision ID: b3f81c4d9e27
Revises: 32fdcda2b0de
Create Date: 2026-09-06 10:12:44.318902

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from app.models import UtcDateTime

# revision identifiers, used by Alembic.
revision: str = 'b3f81c4d9e27'
down_revision: str | Sequence[str] | None = '32fdcda2b0de'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'password_reset_tokens',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('token_hash', sa.String(64), nullable=False),
        sa.Column(
            'user_id',
            sa.Integer(),
            sa.ForeignKey('users.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sa.Column('created_at', UtcDateTime(), nullable=False),
        sa.Column('expires_at', UtcDateTime(), nullable=False),
        sa.Column('used_at', UtcDateTime(), nullable=True),
        if_not_exists=True,
    )
    op.create_index(
        'ix_password_reset_tokens_token_hash',
        'password_reset_tokens',
        ['token_hash'],
        unique=True,
        if_not_exists=True,
    )
    op.create_index(
        'ix_password_reset_tokens_user_expires',
        'password_reset_tokens',
        ['user_id', 'expires_at'],
        if_not_exists=True,
    )


def downgrade() -> None:
    op.drop_index(
        'ix_password_reset_tokens_user_expires',
        table_name='password_reset_tokens',
        if_exists=True,
    )
    op.drop_index(
        'ix_password_reset_tokens_token_hash',
        table_name='password_reset_tokens',
        if_exists=True,
    )
    op.drop_table('password_reset_tokens', if_exists=True)
