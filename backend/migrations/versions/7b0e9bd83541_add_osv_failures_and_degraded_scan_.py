"""add osv_failures and degraded scan status

Revision ID: 7b0e9bd83541
Revises: 594fb09ecdfc
Create Date: 2026-09-24 12:51:28.799299

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '7b0e9bd83541'
down_revision: str | Sequence[str] | None = '594fb09ecdfc'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Add osv_failures to scans/repo_scan_results, and 'degraded' to ScanStatus.

    Each step is guarded independently (existing-columns check, IF NOT
    EXISTS) so a replay after a partial failure still converges, matching
    c7a2e5f01d38_add_password_reset_token_kind.py's pattern.
    """
    bind = op.get_bind()

    scans_columns = {c["name"] for c in sa.inspect(bind).get_columns("scans")}
    if "osv_failures" not in scans_columns:
        op.add_column(
            'scans',
            sa.Column('osv_failures', sa.Integer(), nullable=False, server_default='0'),
        )

    results_columns = {c["name"] for c in sa.inspect(bind).get_columns("repo_scan_results")}
    if "osv_failures" not in results_columns:
        op.add_column(
            'repo_scan_results',
            sa.Column('osv_failures', sa.Integer(), nullable=False, server_default='0'),
        )

    # scans.status is sa.Enum(ScanStatus) *without* create_constraint=True
    # (see models.Scan), so on SQLite it renders as a bare VARCHAR with no
    # CHECK constraint at all — a new value needs no schema change there.
    # PostgreSQL uses a real 'scanstatus' enum type and needs the value
    # added explicitly. ALTER TYPE ... ADD VALUE cannot run inside a
    # transaction block, hence autocommit_block(); IF NOT EXISTS (PG12+)
    # makes it safe to replay.
    if bind.dialect.name != "sqlite":
        with op.get_context().autocommit_block():
            op.execute(sa.text("ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'degraded'"))


def downgrade() -> None:
    """Refuse if any 'degraded' rows exist, then drop the osv_failures columns.

    The 'degraded' PostgreSQL enum value is never removed — PostgreSQL has
    no ALTER TYPE ... DROP VALUE, and recreating the whole 'scanstatus' type
    (new type without the value, cast the column through text, swap type
    names, drop the old type) is out of proportion here. That's fine on its
    own: the enum type merely permitting an unused value is harmless.

    What is NOT fine is an actual row left with status='degraded': the
    prior ScanStatus enum (the one the code being rolled back to defines)
    has no 'degraded' member, so SQLAlchemy raises LookupError the moment
    that older code's ORM reads such a row — reproduced directly. A
    downgrade exists specifically to support rolling back to that older
    code, so silently leaving a row in a state it cannot read would defeat
    the point. Refuse instead, naming the row count, and let the operator
    decide how to reclassify or remove those rows first — the same
    fail-loud-with-an-actionable-message pattern as
    app.core.config.validate_database_settings, rather than guessing a
    replacement status (there is no status among 'clean'/'findings'/'error'
    that accurately means "OSV was unreachable for some packages").
    """
    bind = op.get_bind()
    degraded_count = bind.execute(
        sa.text("SELECT count(*) FROM scans WHERE status = 'degraded'")
    ).scalar_one()
    if degraded_count:
        raise RuntimeError(
            f"Cannot downgrade past 7b0e9bd83541: {degraded_count} row(s) in "
            "scans have status='degraded', which the prior ScanStatus enum "
            "cannot represent — the older application code would raise "
            "LookupError reading them. Reclassify or delete these rows "
            "first, e.g.: UPDATE scans SET status = 'error' WHERE status = "
            "'degraded';"
        )

    with op.batch_alter_table('repo_scan_results') as batch:
        batch.drop_column('osv_failures')
    with op.batch_alter_table('scans') as batch:
        batch.drop_column('osv_failures')
