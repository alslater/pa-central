"""add sla_breach_cutoff_at to finding_records

Revision ID: e1f2a3b4c5d6
Revises: d1e2f3a4b5c6
Create Date: 2026-07-06

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision: str = 'e1f2a3b4c5d6'
down_revision: Union[str, Sequence[str], None] = 'd1e2f3a4b5c6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# Hardcoded defaults match finding_lifecycle.DEFAULT_SLA_HIGH / DEFAULT_SLA_MEDIUM.
# At migration time the system_settings table may not have these keys, so we read
# them and fall back to the same defaults the application uses.
_DEFAULT_HIGH = 14
_DEFAULT_MEDIUM = 90


def _get_sla(conn) -> tuple[int, int]:
    """Read global SLA from system_settings, falling back to application defaults."""
    rows = conn.execute(
        text("SELECT key, value FROM system_settings WHERE key IN ('sla_high_days', 'sla_medium_days')")
    ).fetchall()
    settings = {r[0]: r[1] for r in rows}
    def _parse(val, default):
        try:
            parsed = int(val) if val else default
            return parsed if parsed >= 1 else default
        except (ValueError, TypeError):
            return default
    return (
        _parse(settings.get('sla_high_days'), _DEFAULT_HIGH),
        _parse(settings.get('sla_medium_days'), _DEFAULT_MEDIUM),
    )


def upgrade() -> None:
    with op.batch_alter_table('finding_records', schema=None) as batch_op:
        batch_op.add_column(sa.Column('sla_breach_cutoff_at', sa.DateTime(), nullable=True))

    conn = op.get_bind()
    sla_high, sla_medium = _get_sla(conn)

    # Backfill open findings that have an SLA-bearing severity.
    # Per-scan SLA overrides take precedence over global defaults.
    # Severities with no SLA (warning, low, info) are left NULL.
    #
    # +1 day offset: sla_breach_cutoff_at stores first_found_at + (sla_days + 1)
    # so that the SQL comparison `sla_breach_cutoff_at <= now` exactly matches
    # Python's `(now - first_found_at).days > sla_days` (integer-day truncation).
    #
    # SQLite datetime arithmetic: datetime(col, '+N days').
    # This is the only SQLite-specific syntax here; the column add above is portable.
    # For PostgreSQL the equivalent is: col + INTERVAL 'N days' — adjust if migrating.
    conn.execute(text("""
        UPDATE finding_records
        SET sla_breach_cutoff_at = datetime(
            first_found_at,
            '+' || (CASE severity
                WHEN 'critical' THEN COALESCE(
                    (SELECT sla_high_days FROM repo_scans WHERE id = finding_records.repo_scan_id),
                    :sla_high
                )
                WHEN 'high' THEN COALESCE(
                    (SELECT sla_high_days FROM repo_scans WHERE id = finding_records.repo_scan_id),
                    :sla_high
                )
                WHEN 'medium' THEN COALESCE(
                    (SELECT sla_medium_days FROM repo_scans WHERE id = finding_records.repo_scan_id),
                    :sla_medium
                )
                ELSE NULL
            END + 1) || ' days'
        )
        WHERE closed_at IS NULL
          AND severity IN ('critical', 'high', 'medium')
    """), {"sla_high": sla_high, "sla_medium": sla_medium})


def downgrade() -> None:
    with op.batch_alter_table('finding_records', schema=None) as batch_op:
        batch_op.drop_column('sla_breach_cutoff_at')
