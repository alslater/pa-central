"""add fix plans: package_index credentials, fix_plans_enabled, fix_plan, link table

Revision ID: f1a2b3c4d5e6
Revises: e4c1a9d2b7f3
Create Date: 2026-10-14 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'f1a2b3c4d5e6'
down_revision: str | Sequence[str] | None = 'e4c1a9d2b7f3'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _columns(bind, table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(bind).get_columns(table)}


def upgrade() -> None:
    """Each step is guarded so a replay after a partial failure converges (7b0e9bd83541's pattern).

    credential_type is sa.Enum without create_constraint=True, so on SQLite it is a bare
    VARCHAR and 'package_index' needs no change; PostgreSQL's native 'credentialtype' type
    needs ALTER TYPE ... ADD VALUE, which cannot run inside a transaction block.
    """
    bind = op.get_bind()
    if bind.dialect.name != "sqlite":
        with op.get_context().autocommit_block():
            op.execute(sa.text("ALTER TYPE credentialtype ADD VALUE IF NOT EXISTS 'package_index'"))

    cred_cols = _columns(bind, "repo_credentials")
    if "index_url" not in cred_cols:
        op.add_column("repo_credentials", sa.Column("index_url", sa.String(500), nullable=True))
    if "index_username" not in cred_cols:
        op.add_column("repo_credentials", sa.Column("index_username", sa.String(200), nullable=True))

    if "fix_plans_enabled" not in _columns(bind, "repo_scans"):
        op.add_column("repo_scans", sa.Column(
            "fix_plans_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))
    if "fix_plan" not in _columns(bind, "repo_scan_results"):
        op.add_column("repo_scan_results", sa.Column("fix_plan", sa.JSON(), nullable=True))

    if "repo_scan_package_indexes" not in sa.inspect(bind).get_table_names():
        op.create_table(
            "repo_scan_package_indexes",
            sa.Column("repo_scan_id", sa.Integer(),
                      sa.ForeignKey("repo_scans.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("credential_id", sa.Integer(),
                      sa.ForeignKey("repo_credentials.id"), primary_key=True),
        )


def downgrade() -> None:
    """Refuse while package_index credentials exist, then drop what upgrade added.

    The PostgreSQL enum value stays: there is no ALTER TYPE ... DROP VALUE, and an unused value is
    harmless. A row holding it is not: the older CredentialType has no such member and its ORM
    raises LookupError reading it, so refuse and say what to remove (7b0e9bd83541's pattern).
    """
    bind = op.get_bind()
    count = bind.execute(sa.text(
        "SELECT count(*) FROM repo_credentials WHERE credential_type = 'package_index'")).scalar_one()
    if count:
        raise RuntimeError(
            f"Cannot downgrade past f1a2b3c4d5e6: {count} repo_credentials row(s) have "
            "credential_type='package_index', which the prior CredentialType cannot represent. "
            "Delete them first (unlink them from repo scans): "
            "DELETE FROM repo_scan_package_indexes; "
            "DELETE FROM repo_credentials WHERE credential_type = 'package_index';"
        )
    if "repo_scan_package_indexes" in sa.inspect(bind).get_table_names():
        op.drop_table("repo_scan_package_indexes")
    if "fix_plan" in _columns(bind, "repo_scan_results"):
        with op.batch_alter_table("repo_scan_results") as batch:
            batch.drop_column("fix_plan")
    if "fix_plans_enabled" in _columns(bind, "repo_scans"):
        with op.batch_alter_table("repo_scans") as batch:
            batch.drop_column("fix_plans_enabled")
    cred_cols = _columns(bind, "repo_credentials")
    with op.batch_alter_table("repo_credentials") as batch:
        if "index_username" in cred_cols:
            batch.drop_column("index_username")
        if "index_url" in cred_cols:
            batch.drop_column("index_url")
