"""add risk records

Revision ID: 7ace8b60203b
Revises: 035924a7a885
Create Date: 2026-08-20 09:26:57.139032

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from app.models import UtcDateTime

# revision identifiers, used by Alembic.
revision: str = '7ace8b60203b'
down_revision: str | Sequence[str] | None = '035924a7a885'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('repo_scan_results', sa.Column('risks', sa.JSON(), nullable=True))
    op.add_column(
        'repo_scan_results',
        sa.Column('risk_failures', sa.Integer(), nullable=False, server_default='0'),
    )
    op.add_column('scans', sa.Column('risks', sa.JSON(), nullable=True))
    op.add_column(
        'scans',
        sa.Column('risk_failures', sa.Integer(), nullable=False, server_default='0'),
    )

    op.create_table(
        'risk_records',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('repo_scan_id', sa.Integer(), sa.ForeignKey('repo_scans.id', ondelete='CASCADE'), nullable=False),
        sa.Column('package', sa.String(200), nullable=False),
        sa.Column('ecosystem', sa.String(100), nullable=False),
        sa.Column('package_version', sa.String(200), nullable=True),
        sa.Column('score', sa.Integer(), nullable=False),
        sa.Column('level', sa.String(20), nullable=False),
        sa.Column('signals', sa.JSON(), nullable=False),
        sa.Column('first_found_at', UtcDateTime(), nullable=False),
        sa.Column('closed_at', UtcDateTime(), nullable=True),
        sa.Column('closed_reason', sa.String(50), nullable=True),
        sa.Column('reopen_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('accepted_by_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('accepted_at', UtcDateTime(), nullable=True),
        sa.Column('accepted_reason', sa.String(1000), nullable=True),
        sa.Column('accepted_until', sa.Date(), nullable=True),
        if_not_exists=True,
    )
    op.create_index(
        'ix_risk_records_identity',
        'risk_records',
        ['repo_scan_id', 'package', 'ecosystem'],
        if_not_exists=True,
    )
    op.create_index(
        'ix_risk_records_closed',
        'risk_records',
        ['closed_at'],
        if_not_exists=True,
    )
    # Partial unique index: at most one open episode per identity tuple per scan.
    # op.create_index does not reliably pass the WHERE clause for SQLite, so use raw DDL
    # (same pattern as uq_finding_records_open_identity in cd36263592ce_initial_schema.py).
    op.execute(sa.text(
        'CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_records_open_identity'
        ' ON risk_records (repo_scan_id, package, ecosystem)'
        ' WHERE closed_at IS NULL'
    ))


def downgrade() -> None:
    op.execute(sa.text('DROP INDEX IF EXISTS uq_risk_records_open_identity'))
    op.drop_index('ix_risk_records_closed', table_name='risk_records')
    op.drop_index('ix_risk_records_identity', table_name='risk_records')
    op.drop_table('risk_records')
    op.drop_column('scans', 'risk_failures')
    op.drop_column('scans', 'risks')
    op.drop_column('repo_scan_results', 'risk_failures')
    op.drop_column('repo_scan_results', 'risks')
