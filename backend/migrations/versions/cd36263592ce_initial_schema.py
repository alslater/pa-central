"""initial schema

Revision ID: cd36263592ce
Revises:
Create Date: 2026-07-12 08:21:56.764521

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from app.models import UtcDateTime


# revision identifiers, used by Alembic.
revision: str = 'cd36263592ce'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('email', sa.String(255), nullable=False),
        sa.Column('display_name', sa.String(100), nullable=False),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('role', sa.Enum('admin', 'operator', 'developer', 'viewer', name='userrole'), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('totp_secret', sa.String(64), nullable=True),
        sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', UtcDateTime(), nullable=False),
        if_not_exists=True,
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True, if_not_exists=True)

    op.create_table(
        'api_keys',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('key_hash', sa.String(64), nullable=False),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('last_used_at', UtcDateTime(), nullable=True),
        sa.Column('created_at', UtcDateTime(), nullable=False),
        if_not_exists=True,
    )
    op.create_index('ix_api_keys_key_hash', 'api_keys', ['key_hash'], unique=True, if_not_exists=True)

    op.create_table(
        'hosts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('owner_user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('hostname', sa.String(255), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('pa_version', sa.String(50), nullable=True),
        sa.Column('daemon_status', sa.Enum('running', 'stopped', 'unknown', name='daemonstatus'), nullable=False),
        sa.Column('daemon_uptime_seconds', sa.Integer(), nullable=True),
        sa.Column('last_seen_at', UtcDateTime(), nullable=True),
        sa.Column('created_at', UtcDateTime(), nullable=False),
        if_not_exists=True,
    )

    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=False),
        sa.Column('package_name', sa.String(200), nullable=False),
        sa.Column('package_version', sa.String(100), nullable=True),
        sa.Column('ecosystem', sa.Enum('pypi', 'npm', 'packagist', 'other', name='ecosystem'), nullable=False),
        sa.Column('kind', sa.Enum('osv', 'heuristic', name='alertkind'), nullable=False),
        sa.Column('severity', sa.Enum('critical', 'high', 'medium', 'warning', 'low', 'info', name='alertseverity'), nullable=False),
        sa.Column('advisory_id', sa.String(100), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('signals', sa.JSON(), nullable=True),
        sa.Column('project_path', sa.String(500), nullable=True),
        sa.Column('raw', sa.JSON(), nullable=True),
        sa.Column('acknowledged', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('acknowledged_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('acknowledged_at', UtcDateTime(), nullable=True),
        sa.Column('occurred_at', UtcDateTime(), nullable=False),
        sa.Column('received_at', UtcDateTime(), nullable=False),
        if_not_exists=True,
    )

    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=False),
        sa.Column('project_path', sa.String(500), nullable=False),
        sa.Column('scan_type', sa.String(50), nullable=False, server_default='project'),
        sa.Column('status', sa.Enum('clean', 'findings', 'error', name='scanstatus'), nullable=False),
        sa.Column('finding_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('findings', sa.JSON(), nullable=True),
        sa.Column('sources', sa.JSON(), nullable=True),
        sa.Column('raw', sa.JSON(), nullable=True),
        sa.Column('scanned_at', UtcDateTime(), nullable=False),
        sa.Column('received_at', UtcDateTime(), nullable=False),
        if_not_exists=True,
    )

    op.create_table(
        'config_templates',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('toml_content', sa.Text(), nullable=False),
        sa.Column('created_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', UtcDateTime(), nullable=False),
        sa.Column('updated_at', UtcDateTime(), nullable=False),
        sa.Column('is_default', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.UniqueConstraint('name', name='uq_config_templates_name'),
        if_not_exists=True,
    )

    op.create_table(
        'config_assignments',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=False),
        sa.Column('template_id', sa.Integer(), sa.ForeignKey('config_templates.id'), nullable=False),
        sa.Column('assigned_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('assigned_at', UtcDateTime(), nullable=False),
        if_not_exists=True,
    )

    op.create_table(
        'cooldown_entries',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('package_name', sa.String(200), nullable=False),
        sa.Column('package_version', sa.String(100), nullable=True),
        sa.Column('ecosystem', sa.Enum('pypi', 'npm', 'packagist', 'other', name='ecosystem'), nullable=False),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=True),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('created_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('expires_at', UtcDateTime(), nullable=True),
        sa.Column('created_at', UtcDateTime(), nullable=False),
        if_not_exists=True,
    )

    op.create_table(
        'system_settings',
        sa.Column('key', sa.String(100), primary_key=True),
        sa.Column('value', sa.Text(), nullable=True),
        sa.Column('value_type', sa.Enum('string', 'int', 'bool', 'json', 'secret', name='settingvaluetype'), nullable=False),
        sa.Column('updated_at', UtcDateTime(), nullable=False),
        sa.Column('updated_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        if_not_exists=True,
    )

    op.create_table(
        'repo_credentials',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('credential_type', sa.Enum('none', 'ssh_key', 'https_token', name='credentialtype'), nullable=False),
        sa.Column('credential_secret_arn', sa.Text(), nullable=True),
        sa.Column('created_at', UtcDateTime(), nullable=False),
        sa.Column('updated_at', UtcDateTime(), nullable=False),
        sa.UniqueConstraint('name', name='uq_repo_credentials_name'),
        if_not_exists=True,
    )

    op.create_table(
        'repo_scans',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('url', sa.String(500), nullable=False),
        sa.Column('branch', sa.String(200), nullable=False, server_default='main'),
        sa.Column('credential_id', sa.Integer(), sa.ForeignKey('repo_credentials.id'), nullable=True),
        sa.Column('cron_schedule', sa.String(100), nullable=True),
        sa.Column('cron_timezone', sa.String(100), nullable=True),
        sa.Column('pa_version', sa.String(50), nullable=True),
        sa.Column('scan_flags', sa.Text(), nullable=True),
        sa.Column('subfolder', sa.String(500), nullable=True),
        sa.Column('scan_config_hash', sa.String(64), nullable=True),
        sa.Column('min_notify_severity', sa.Enum('critical', 'high', 'medium', 'warning', 'low', 'info', name='alertseverity'), nullable=False),
        sa.Column('notify_recipients', sa.JSON(), nullable=True),
        sa.Column('config_template_id', sa.Integer(), sa.ForeignKey('config_templates.id'), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('sla_high_days', sa.Integer(), nullable=True),
        sa.Column('sla_medium_days', sa.Integer(), nullable=True),
        sa.Column('last_scan_at', UtcDateTime(), nullable=True),
        sa.Column('created_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', UtcDateTime(), nullable=False),
        sa.Column('updated_at', UtcDateTime(), nullable=False),
        if_not_exists=True,
    )

    op.create_table(
        'repo_scan_results',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('repo_scan_id', sa.Integer(), sa.ForeignKey('repo_scans.id'), nullable=False),
        sa.Column('status', sa.Enum('pending', 'running', 'success', 'failed', name='reposcanstatus'), nullable=False),
        sa.Column('pa_version', sa.String(50), nullable=True),
        sa.Column('finding_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('findings', sa.JSON(), nullable=True),
        sa.Column('sources', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('triggered_by', sa.Enum('scheduled', 'manual', name='scantrigger'), nullable=False),
        sa.Column('ecs_task_arn', sa.String(500), nullable=True),
        sa.Column('started_at', UtcDateTime(), nullable=False),
        sa.Column('completed_at', UtcDateTime(), nullable=True),
        sa.Column('notified', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('scan_config_hash', sa.String(64), nullable=True),
        if_not_exists=True,
    )

    op.create_table(
        'finding_records',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('repo_scan_id', sa.Integer(), sa.ForeignKey('repo_scans.id', ondelete='CASCADE'), nullable=False),
        sa.Column('advisory_id', sa.String(200), nullable=False),
        sa.Column('package', sa.String(200), nullable=False),
        sa.Column('ecosystem', sa.String(100), nullable=False),
        sa.Column('severity', sa.Enum('critical', 'high', 'medium', 'warning', 'low', 'info', name='alertseverity'), nullable=False),
        sa.Column('summary', sa.String(2000), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('package_version', sa.String(200), nullable=True),
        sa.Column('fixed_versions', sa.Text(), nullable=True),
        sa.Column('url', sa.String(500), nullable=True),
        sa.Column('is_malicious', sa.Boolean(), nullable=True),
        sa.Column('first_found_at', UtcDateTime(), nullable=False),
        sa.Column('closed_at', UtcDateTime(), nullable=True),
        sa.Column('closed_reason', sa.String(50), nullable=True),
        sa.Column('reopen_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('accepted_by_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('accepted_at', UtcDateTime(), nullable=True),
        sa.Column('accepted_reason', sa.String(1000), nullable=True),
        sa.Column('accepted_until', sa.Date(), nullable=True),
        sa.Column('sla_breach_cutoff_at', UtcDateTime(), nullable=True),
        if_not_exists=True,
    )
    op.create_index(
        'ix_finding_records_identity',
        'finding_records',
        ['repo_scan_id', 'advisory_id', 'package', 'ecosystem'],
        if_not_exists=True,
    )
    op.create_index(
        'ix_finding_records_closed_breach',
        'finding_records',
        ['closed_at', 'sla_breach_cutoff_at'],
        if_not_exists=True,
    )
    # Partial unique index: at most one open episode per identity tuple per scan.
    # Guards against duplicate rows from concurrent ingests (see finding_lifecycle.py savepoint handling).
    # op.create_index does not reliably pass the WHERE clause for SQLite, so use raw DDL.
    op.execute(sa.text(
        'CREATE UNIQUE INDEX IF NOT EXISTS uq_finding_records_open_identity'
        ' ON finding_records (repo_scan_id, advisory_id, package, ecosystem)'
        ' WHERE closed_at IS NULL'
    ))


def downgrade() -> None:
    op.execute(sa.text('DROP INDEX IF EXISTS uq_finding_records_open_identity'))
    op.drop_table('finding_records')
    op.drop_table('repo_scan_results')
    op.drop_table('repo_scans')
    op.drop_table('repo_credentials')
    op.drop_table('system_settings')
    op.drop_table('cooldown_entries')
    op.drop_table('config_assignments')
    op.drop_table('config_templates')
    op.drop_table('scans')
    op.drop_table('alerts')
    op.drop_table('hosts')
    op.drop_table('api_keys')
    op.drop_table('users')
