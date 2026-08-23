"""add acceptance events

Revision ID: feb520b531fe
Revises: 7ace8b60203b
Create Date: 2026-08-22 10:35:08.712094

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from app.models import UtcDateTime

# revision identifiers, used by Alembic.
revision: str = 'feb520b531fe'
down_revision: str | Sequence[str] | None = '7ace8b60203b'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'finding_acceptance_events',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column(
            'finding_record_id',
            sa.Integer(),
            sa.ForeignKey('finding_records.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sa.Column('action', sa.String(20), nullable=False),
        sa.Column('at', UtcDateTime(), nullable=False),
        sa.Column(
            'by_user_id',
            sa.Integer(),
            sa.ForeignKey('users.id', ondelete='SET NULL'),
            nullable=True,
        ),
        sa.Column('reason', sa.String(1000), nullable=True),
        sa.Column('accepted_until', sa.Date(), nullable=True),
        if_not_exists=True,
    )
    op.create_index(
        'ix_finding_acceptance_events_record_at',
        'finding_acceptance_events',
        ['finding_record_id', 'at'],
        if_not_exists=True,
    )

    op.create_table(
        'risk_acceptance_events',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column(
            'risk_record_id',
            sa.Integer(),
            sa.ForeignKey('risk_records.id', ondelete='CASCADE'),
            nullable=False,
        ),
        sa.Column('action', sa.String(20), nullable=False),
        sa.Column('at', UtcDateTime(), nullable=False),
        sa.Column(
            'by_user_id',
            sa.Integer(),
            sa.ForeignKey('users.id', ondelete='SET NULL'),
            nullable=True,
        ),
        sa.Column('reason', sa.String(1000), nullable=True),
        sa.Column('accepted_until', sa.Date(), nullable=True),
        if_not_exists=True,
    )
    op.create_index(
        'ix_risk_acceptance_events_record_at',
        'risk_acceptance_events',
        ['risk_record_id', 'at'],
        if_not_exists=True,
    )

    # Backfill: one synthetic "accepted" event for every record that is
    # currently accepted, so the exposure chart is correct retroactively from
    # the record's real accepted_at date rather than from migration day.
    #
    # Records that were accepted-then-revoked BEFORE this migration have no
    # surviving trace of that episode — the old revoke code nulled the columns
    # out, and there is nothing left to backfill. That is a known, permanent,
    # unrecoverable gap for pre-migration history.
    #
    # Raw SELECT/INSERT via sa.text() rather than the ORM model classes: a
    # migration must keep working against the schema as of *this* revision,
    # even after app.models has moved on. Deliberately plain, portable SQL —
    # no RETURNING, no ON CONFLICT, no dialect-specific functions — so SQLite
    # and PostgreSQL execute the identical statements.
    #
    # The NOT IN guard makes the backfill idempotent, matching the DDL above
    # (every create_* uses if_not_exists=True). Re-running this upgrade over
    # surviving tables — exactly what the documented recovery procedure of
    # resetting alembic_version and re-running `upgrade head` does — must not
    # insert a second copy of every event and silently double the exposure
    # chart. NOT IN rather than a "table is empty" check so that a partially
    # completed backfill also resumes correctly.
    connection = op.get_bind()

    for table, events_table, fk_column in (
        ('finding_records', 'finding_acceptance_events', 'finding_record_id'),
        ('risk_records', 'risk_acceptance_events', 'risk_record_id'),
    ):
        rows = connection.execute(sa.text(
            "SELECT id, accepted_at, accepted_until, accepted_by_id, accepted_reason "
            f"FROM {table} WHERE accepted_at IS NOT NULL "
            f"AND id NOT IN (SELECT {fk_column} FROM {events_table})"
        )).fetchall()
        for row in rows:
            connection.execute(
                sa.text(
                    f"INSERT INTO {events_table} "
                    f"({fk_column}, action, at, by_user_id, reason, accepted_until) "
                    "VALUES (:record_id, 'accepted', :at, :by_user_id, :reason, "
                    ":accepted_until)"
                ),
                {
                    "record_id": row.id,
                    "at": row.accepted_at,
                    "by_user_id": row.accepted_by_id,
                    "reason": row.accepted_reason,
                    "accepted_until": row.accepted_until,
                },
            )


def downgrade() -> None:
    op.drop_index(
        'ix_risk_acceptance_events_record_at', table_name='risk_acceptance_events'
    )
    op.drop_table('risk_acceptance_events')
    op.drop_index(
        'ix_finding_acceptance_events_record_at',
        table_name='finding_acceptance_events',
    )
    op.drop_table('finding_acceptance_events')
