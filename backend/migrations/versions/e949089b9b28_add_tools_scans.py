"""add pa scan-tools fields to scans, and rank latest scans per (project_path, scan_type, home, manager)

Revision ID: e949089b9b28
Revises: a7d3c9e1f5b2
Create Date: 2026-10-30 00:00:00.000000

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = 'e949089b9b28'
down_revision: str | Sequence[str] | None = 'a7d3c9e1f5b2'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_INDEX = ("ix_scans_host_project_scanned_received_id",
              ["host_id", "project_path", "scanned_at", "received_at", "id"])
_NEW_INDEX = ("ix_scans_host_project_type_home_manager_scanned_received_id",
              ["host_id", "project_path", "scan_type", "home", "manager", "scanned_at", "received_at", "id"])
# The newest tools run per (home, manager), read newest first (hosts._newest_run_stmt).
_HISTORY_INDEX = ("ix_scans_host_type_home_scanned_received_id",
                  ["host_id", "scan_type", "home", "scanned_at", "received_at", "id"])


def _new_columns() -> list[sa.Column]:
    return [
        sa.Column("manager", sa.String(20), nullable=True),
        # Existing rows are not tools scans: an active layout whose directory exists is the
        # reading that changes nothing for them.
        sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("root_exists", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("run_id", sa.String(100), nullable=True),
        sa.Column("home", sa.String(500), nullable=True),
        sa.Column("managers_scanned", sa.JSON(), nullable=True),
        sa.Column("run_roots", sa.JSON(), nullable=True),
        sa.Column("tools", sa.JSON(), nullable=True),
        sa.Column("unchecked", sa.JSON(), nullable=True),
    ]


def _swap_indexes(drop: list[tuple[str, list[str]]], create: list[tuple[str, list[str]]]) -> None:
    existing = {i["name"] for i in sa.inspect(op.get_bind()).get_indexes("scans")}
    for name, columns in create:
        if name not in existing:
            op.create_index(name, "scans", columns)
    for name, _ in drop:
        if name in existing:
            op.drop_index(name, table_name="scans")


def upgrade() -> None:
    """Add package-alert #117's tools-scan fields (pa-central #26). Each step is guarded so a
    replay after a partial failure converges (7b0e9bd83541's pattern)."""
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("scans")}
    for column in _new_columns():
        if column.name not in existing:
            op.add_column("scans", column)
    _swap_indexes([_OLD_INDEX], [_NEW_INDEX, _HISTORY_INDEX])


def downgrade() -> None:
    """Drop the columns and restore the per-project_path index. The data is re-produced by the
    next tools scan."""
    _swap_indexes([_NEW_INDEX, _HISTORY_INDEX], [_OLD_INDEX])
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("scans")}
    present = [c.name for c in _new_columns() if c.name in existing]
    if present:
        with op.batch_alter_table("scans") as batch:
            for name in present:
                batch.drop_column(name)
