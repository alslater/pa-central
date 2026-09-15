"""add users.token_epoch

Revision ID: 594fb09ecdfc
Revises: c7a2e5f01d38
Create Date: 2026-09-09 11:36:05

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '594fb09ecdfc'
down_revision: str | Sequence[str] | None = 'c7a2e5f01d38'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add users.token_epoch, defaulted so existing rows and existing
    tokens both keep working.

    A bearer token issued before this migration carries no `epc` claim;
    decode_access_token treats that as epoch 0, matching every existing
    user's backfilled value here, so nobody is force-logged-out by the
    deploy itself.

    Adding the column and dropping its server default are guarded
    independently, not short-circuited on one `if`: a run that dies between
    them would otherwise leave the server default in place on replay, since
    "column already exists" would skip straight past the cleanup step too.
    Reproduced directly — a column added with `server_default='0'` and then
    stamped back to the prior revision (simulating the stranded-database
    recovery in CLAUDE.md) kept `DEFAULT 0` after a second `upgrade head`
    with the naive single-guard version of this migration. The server
    default is only scaffolding to satisfy existing rows during the add; new
    rows get their value from the ORM's `default=0`, and dropping it after
    backfill means a future insert that forgets to set it raises instead of
    silently succeeding with a stale value the database invented.
    """
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("users")}
    if "token_epoch" not in existing:
        op.add_column(
            'users',
            sa.Column(
                'token_epoch', sa.Integer(), nullable=False, server_default='0'
            ),
        )
        existing = {c["name"] for c in sa.inspect(bind).get_columns("users")}

    has_server_default = any(
        c["name"] == "token_epoch" and c.get("default") is not None
        for c in sa.inspect(bind).get_columns("users")
    )
    if has_server_default:
        with op.batch_alter_table('users') as batch_op:
            batch_op.alter_column('token_epoch', server_default=None)


def downgrade() -> None:
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('token_epoch')
