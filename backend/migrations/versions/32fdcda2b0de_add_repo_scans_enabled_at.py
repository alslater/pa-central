"""add repo_scans.enabled_at

Revision ID: 32fdcda2b0de
Revises: dc0f75bde427
Create Date: 2026-08-24 12:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from app.models import UtcDateTime

# revision identifiers, used by Alembic.
revision: str = '32fdcda2b0de'
down_revision: str | Sequence[str] | None = 'dc0f75bde427'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Guard against re-running this migration over a database where the
    # column already physically exists — the documented stranded-database
    # recovery procedure in CLAUDE.md rewinds only the alembic_version
    # stamp, not the schema, so upgrade head can replay this migration a
    # second time against a table that already has enabled_at.
    bind = op.get_bind()
    existing_columns = {c["name"] for c in sa.inspect(bind).get_columns("repo_scans")}
    if "enabled_at" not in existing_columns:
        op.add_column('repo_scans', sa.Column('enabled_at', UtcDateTime(), nullable=True))

    # Backfill: a currently-enabled scan's enabled_at is unknown, but
    # created_at is the same anchor the scheduler used before this column
    # existed — using it here preserves today's due-time behaviour for
    # existing scans instead of silently changing when they next fire.
    # Disabled scans are left NULL; they don't schedule until re-enabled,
    # at which point the application sets enabled_at itself.
    #
    # The WHERE clause must also require enabled_at IS NULL, not just
    # is_enabled — on a replay (the documented stranded-database recovery
    # procedure in CLAUDE.md rewinds only the alembic_version stamp, not
    # the schema or its data), a scan may have been disabled and
    # re-enabled by the application in the time since the first run,
    # giving it a real, newer enabled_at. Without this guard the backfill
    # would unconditionally overwrite that with the stale created_at,
    # destroying a legitimate activation timestamp — not idempotent once
    # real traffic exists between runs, only in the narrow sense that the
    # same starting data produces the same result twice.
    op.execute(sa.text(
        "UPDATE repo_scans SET enabled_at = created_at "
        "WHERE is_enabled AND enabled_at IS NULL"
    ))


def downgrade() -> None:
    op.drop_column('repo_scans', 'enabled_at')
