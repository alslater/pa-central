"""add scan_config_hash and closed_reason

Revision ID: d1e2f3a4b5c6
Revises: c7d4e8f19a25
Create Date: 2026-06-26 00:00:00.000000
"""
from typing import Sequence, Union
import hashlib
import json

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text


revision: str = 'd1e2f3a4b5c6'
down_revision: Union[str, Sequence[str], None] = 'c7d4e8f19a25'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _hash(scan_flags, subfolder, config_template_id) -> str:
    raw = json.dumps([scan_flags, subfolder, config_template_id], separators=(',', ':'))
    return hashlib.sha256(raw.encode()).hexdigest()


def upgrade() -> None:
    with op.batch_alter_table('repo_scans', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scan_config_hash', sa.String(64), nullable=True))

    with op.batch_alter_table('repo_scan_results', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scan_config_hash', sa.String(64), nullable=True))

    with op.batch_alter_table('finding_records', schema=None) as batch_op:
        batch_op.add_column(sa.Column('closed_reason', sa.String(50), nullable=True))

    # Backfill scan_config_hash on repo_scans from current config
    conn = op.get_bind()
    scans = conn.execute(
        text("SELECT id, scan_flags, subfolder, config_template_id FROM repo_scans")
    ).fetchall()
    for row in scans:
        h = _hash(row[1], row[2], row[3])
        conn.execute(
            text("UPDATE repo_scans SET scan_config_hash = :h WHERE id = :id"),
            {"h": h, "id": row[0]},
        )

    # Backfill scan_config_hash on repo_scan_results — each result gets its
    # scan's current hash (we cannot reconstruct historical config values).
    results = conn.execute(
        text("SELECT rsr.id, rs.scan_flags, rs.subfolder, rs.config_template_id "
             "FROM repo_scan_results rsr JOIN repo_scans rs ON rs.id = rsr.repo_scan_id")
    ).fetchall()
    for row in results:
        h = _hash(row[1], row[2], row[3])
        conn.execute(
            text("UPDATE repo_scan_results SET scan_config_hash = :h WHERE id = :id"),
            {"h": h, "id": row[0]},
        )


def downgrade() -> None:
    with op.batch_alter_table('finding_records', schema=None) as batch_op:
        batch_op.drop_column('closed_reason')

    with op.batch_alter_table('repo_scan_results', schema=None) as batch_op:
        batch_op.drop_column('scan_config_hash')

    with op.batch_alter_table('repo_scans', schema=None) as batch_op:
        batch_op.drop_column('scan_config_hash')
