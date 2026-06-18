"""initial_schema

Revision ID: 847eafd5e795
Revises:
Create Date: 2026-06-11 09:01:06.670737

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '847eafd5e795'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('email', sa.String(255), nullable=False, unique=True),
        sa.Column('display_name', sa.String(100), nullable=False),
        sa.Column('hashed_password', sa.String(255), nullable=False),
        sa.Column('role', sa.Enum('admin', 'operator', 'developer', 'viewer', name='userrole'), nullable=False, server_default='viewer'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('totp_secret', sa.String(64), nullable=True),
        sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_users_email', 'users', ['email'], unique=True)

    op.create_table(
        'api_keys',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('key_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_api_keys_key_hash', 'api_keys', ['key_hash'], unique=True)

    op.create_table(
        'hosts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('owner_user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('hostname', sa.String(255), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('pa_version', sa.String(50), nullable=True),
        sa.Column('daemon_status', sa.Enum('unknown', 'running', 'stopped', 'error', name='daemonstatus'), nullable=False, server_default='unknown'),
        sa.Column('daemon_uptime_seconds', sa.Integer(), nullable=True),
        sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        'alerts',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=False),
        sa.Column('package_name', sa.String(200), nullable=False),
        sa.Column('package_version', sa.String(100), nullable=True),
        sa.Column('ecosystem', sa.Enum('pypi', 'npm', 'cargo', 'go', 'maven', 'nuget', 'rubygems', 'hex', 'pub', name='ecosystem'), nullable=False, server_default='pypi'),
        sa.Column('kind', sa.Enum('osv', 'heuristic', name='alertkind'), nullable=False, server_default='osv'),
        sa.Column('severity', sa.Enum('critical', 'high', 'medium', 'low', 'info', name='alertseverity'), nullable=False, server_default='medium'),
        sa.Column('advisory_id', sa.String(100), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('signals', sa.JSON(), nullable=True),
        sa.Column('project_path', sa.String(500), nullable=True),
        sa.Column('raw', sa.JSON(), nullable=True),
        sa.Column('acknowledged', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('acknowledged_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('acknowledged_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('occurred_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        'scans',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=False),
        sa.Column('project_path', sa.String(500), nullable=False),
        sa.Column('scan_type', sa.String(50), nullable=False, server_default='project'),
        sa.Column('status', sa.Enum('clean', 'vulnerable', 'error', name='scanstatus'), nullable=False, server_default='clean'),
        sa.Column('finding_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('findings', sa.JSON(), nullable=True),
        sa.Column('raw', sa.JSON(), nullable=True),
        sa.Column('scanned_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        'config_templates',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(100), nullable=False, unique=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('toml_content', sa.Text(), nullable=False),
        sa.Column('created_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('is_default', sa.Boolean(), nullable=False, server_default=sa.false()),
    )

    op.create_table(
        'config_assignments',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=False),
        sa.Column('template_id', sa.Integer(), sa.ForeignKey('config_templates.id'), nullable=False),
        sa.Column('assigned_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('assigned_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        'cooldown_entries',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('package_name', sa.String(200), nullable=False),
        sa.Column('package_version', sa.String(100), nullable=True),
        sa.Column('ecosystem', sa.Enum('pypi', 'npm', 'cargo', 'go', 'maven', 'nuget', 'rubygems', 'hex', 'pub', name='ecosystem'), nullable=False, server_default='pypi'),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=True),
        sa.Column('note', sa.Text(), nullable=True),
        sa.Column('created_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        'system_settings',
        sa.Column('key', sa.String(100), primary_key=True),
        sa.Column('value', sa.Text(), nullable=True),
        sa.Column('value_type', sa.Enum('string', 'integer', 'boolean', 'encrypted', name='settingvaluetype'), nullable=False, server_default='string'),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
    )

    op.create_table(
        'repo_credentials',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False, unique=True),
        sa.Column('credential_type', sa.Enum('ssh_key', 'https_token', name='credentialtype'), nullable=False),
        sa.Column('credential_secret_arn', sa.String(500), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        'repo_scans',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(200), nullable=False),
        sa.Column('url', sa.String(500), nullable=False),
        sa.Column('branch', sa.String(200), nullable=False, server_default='main'),
        sa.Column('credential_id', sa.Integer(), sa.ForeignKey('repo_credentials.id'), nullable=True),
        sa.Column('cron_schedule', sa.String(100), nullable=True),
        sa.Column('pa_version', sa.String(50), nullable=True),
        sa.Column('extra_args', sa.String(500), nullable=True),
        sa.Column('min_notify_severity', sa.Enum('critical', 'high', 'medium', 'low', 'info', name='alertseverity'), nullable=False, server_default='medium'),
        sa.Column('notify_recipients', sa.JSON(), nullable=True),
        sa.Column('config_template_id', sa.Integer(), sa.ForeignKey('config_templates.id'), nullable=True),
        sa.Column('is_enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('last_scan_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_by_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        'repo_scan_results',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('repo_scan_id', sa.Integer(), sa.ForeignKey('repo_scans.id'), nullable=False),
        sa.Column('status', sa.Enum('pending', 'running', 'success', 'failed', name='reposcanstatus'), nullable=False, server_default='pending'),
        sa.Column('pa_version', sa.String(50), nullable=True),
        sa.Column('finding_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('findings', sa.JSON(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('triggered_by', sa.Enum('manual', 'scheduled', name='scantrigger'), nullable=False, server_default='manual'),
        sa.Column('ecs_task_arn', sa.String(500), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('notified', sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
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
