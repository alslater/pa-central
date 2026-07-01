"""add_open_finding_unique_constraint

Adds a partial unique index on finding_records(repo_scan_id, advisory_id,
package, ecosystem) WHERE closed_at IS NULL. This enforces at the database
level that at most one open episode can exist per identity tuple per scan,
guarding against duplicate rows from concurrent ingests.

Both SQLite and PostgreSQL support partial (filtered) unique indexes.

Revision ID: b1e3f7a92c04
Revises: 4a2db4ae3d0b
Create Date: 2026-06-25 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b1e3f7a92c04'
down_revision: Union[str, Sequence[str], None] = '4a2db4ae3d0b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('finding_records', schema=None) as batch_op:
        batch_op.create_index(
            'uq_finding_records_open_identity',
            ['repo_scan_id', 'advisory_id', 'package', 'ecosystem'],
            unique=True,
            postgresql_where=sa.text('closed_at IS NULL'),
            sqlite_where=sa.text('closed_at IS NULL'),
        )


def downgrade() -> None:
    with op.batch_alter_table('finding_records', schema=None) as batch_op:
        batch_op.drop_index('uq_finding_records_open_identity')
