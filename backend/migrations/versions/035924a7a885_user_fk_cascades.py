"""user_fk_cascades

Revision ID: 035924a7a885
Revises: cd36263592ce
Create Date: 2026-08-06 17:17:30.666445

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '035924a7a885'
down_revision: str | Sequence[str] | None = 'cd36263592ce'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reflected_table(table_name: str, *drop_fk_columns: str) -> sa.Table:
    """Reflect *table_name* and strip all FK constraints on *drop_fk_columns*.

    Passing this as ``copy_from`` to ``batch_alter_table`` tells Alembic to use
    it as the base schema instead of re-reflecting the live table.  Any FK on a
    column in *drop_fk_columns* is excluded so the batch rebuild does not copy
    it into the new table alongside the replacement constraint we add inside the
    batch block.

    Discarding from ``t.constraints`` is what matters here: Alembic's
    ``ApplyBatchImpl._grab_table_elements`` iterates exactly that collection to
    decide what to carry into the rebuilt table.  The per-column ``ForeignKey``
    objects left behind on ``column.foreign_keys`` are inert — Alembic copies
    columns with ``_copy()``, which does not carry them over.

    This only governs the SQLite table-rebuild path.  On PostgreSQL, batch mode
    emits ALTER TABLE directly and never consults ``copy_from``, so the original
    constraint must be dropped by name — see ``_drop_existing_fk``.
    """
    bind = op.get_bind()
    meta = sa.MetaData()
    t = sa.Table(table_name, meta, autoload_with=bind)

    drop_cols = set(drop_fk_columns)
    for fkc in list(t.foreign_key_constraints):
        if {col.key for col in fkc.columns} & drop_cols:
            t.constraints.discard(fkc)

    return t


def _drop_existing_fk(batch_op, table_name: str, column: str) -> None:
    """Drop any pre-existing FK on *table_name.column* inside a batch block.

    Only meaningful on dialects that ALTER in place.  On SQLite the batch block
    rebuilds the table from ``copy_from``, which already omits the old FK — and
    issuing a drop there fails outright with ``No such constraint``, because the
    name is not part of the copied schema.  So this is a deliberate no-op on
    SQLite and the rebuild does the work instead.
    """
    bind = op.get_bind()
    if bind.dialect.name == 'sqlite':
        return

    inspector = sa.inspect(bind)
    for fk in inspector.get_foreign_keys(table_name):
        name = fk.get("name")
        if name and fk["constrained_columns"] == [column]:
            batch_op.drop_constraint(name, type_='foreignkey')


def _repair_orphaned_audit_column(table_name: str, column: str) -> None:
    """Backfill NULLs in *column* before restoring its NOT NULL constraint.

    The upgrade makes these audit columns nullable with ``ondelete='SET NULL'``,
    so deleting a user legitimately leaves NULLs behind.  Restoring
    ``nullable=False`` over that data fails with a NOT NULL violation — and
    because SQLite DDL is non-transactional, the failure would leave earlier
    tables already rebuilt and the schema half-downgraded.

    Rows here carry real operational data (templates, assignments, cooldowns,
    repo scans); only the *attribution* was lost.  Reassign orphans to a
    surviving user — preferring the lowest-id admin — rather than discarding
    them.  If the instance has no users at all there is no value that can
    satisfy the constraint, so the orphans must go.
    """
    bind = op.get_bind()

    # Reflect rather than interpolating identifiers into SQL text: SQLAlchemy
    # then quotes them correctly per dialect, and a name that no longer exists
    # raises here instead of emitting broken SQL mid-migration.
    meta = sa.MetaData()
    users = sa.Table("users", meta, autoload_with=bind)
    target = sa.Table(table_name, meta, autoload_with=bind)
    target_col = target.c[column]

    fallback = bind.execute(
        sa.select(users.c.id)
        .order_by(
            sa.case((users.c.role == "admin", 0), else_=1),
            users.c.id,
        )
        .limit(1)
    ).scalar()

    if fallback is None:
        bind.execute(target.delete().where(target_col.is_(None)))
        return

    bind.execute(
        target.update().where(target_col.is_(None)).values({column: fallback})
    )


# ---------------------------------------------------------------------------
# Upgrade
# ---------------------------------------------------------------------------

def upgrade() -> None:
    """Add ondelete= clauses to FK columns.

    Removing the original FK takes a different mechanism on each dialect, so
    both are applied:

    * **SQLite** rebuilds the table.  ``copy_from=_reflected_table(...)`` hands
      Alembic a pre-reflected table with the old FKs on the affected columns
      already stripped, so the rebuild writes only the replacement.  The old
      constraints are unnamed here, so they cannot be dropped by name.
    * **PostgreSQL** emits ALTER TABLE directly and ignores ``copy_from``
      entirely.  The original is auto-named ``<table>_<column>_fkey`` and must
      be dropped explicitly, or it survives alongside the replacement — and its
      NO ACTION rule then wins, silently defeating the whole migration.

    ``_drop_existing_fk`` is a no-op on SQLite (nothing named to drop), so the
    same code is correct on both.
    """

    # ── alerts ──────────────────────────────────────────────────────────────
    with op.batch_alter_table(
        'alerts',
        copy_from=_reflected_table('alerts', 'host_id', 'acknowledged_by_id'),
    ) as batch_op:
        _drop_existing_fk(batch_op, 'alerts', 'host_id')
        batch_op.create_foreign_key(
            'fk_alerts_host_id_hosts', 'hosts', ['host_id'], ['id'],
            ondelete='CASCADE',
        )
        _drop_existing_fk(batch_op, 'alerts', 'acknowledged_by_id')
        batch_op.create_foreign_key(
            'fk_alerts_acknowledged_by_id_users', 'users', ['acknowledged_by_id'], ['id'],
            ondelete='SET NULL',
        )

    # ── scans ────────────────────────────────────────────────────────────────
    with op.batch_alter_table(
        'scans',
        copy_from=_reflected_table('scans', 'host_id'),
    ) as batch_op:
        _drop_existing_fk(batch_op, 'scans', 'host_id')
        batch_op.create_foreign_key(
            'fk_scans_host_id_hosts', 'hosts', ['host_id'], ['id'],
            ondelete='CASCADE',
        )

    # ── config_assignments ───────────────────────────────────────────────────
    with op.batch_alter_table(
        'config_assignments',
        copy_from=_reflected_table('config_assignments', 'host_id', 'assigned_by_id'),
    ) as batch_op:
        batch_op.alter_column('assigned_by_id', existing_type=sa.INTEGER(), nullable=True)
        _drop_existing_fk(batch_op, 'config_assignments', 'host_id')
        batch_op.create_foreign_key(
            'fk_config_assignments_host_id_hosts', 'hosts', ['host_id'], ['id'],
            ondelete='CASCADE',
        )
        _drop_existing_fk(batch_op, 'config_assignments', 'assigned_by_id')
        batch_op.create_foreign_key(
            'fk_config_assignments_assigned_by_id_users', 'users', ['assigned_by_id'], ['id'],
            ondelete='SET NULL',
        )

    # ── config_templates ─────────────────────────────────────────────────────
    with op.batch_alter_table(
        'config_templates',
        copy_from=_reflected_table('config_templates', 'created_by_id'),
    ) as batch_op:
        batch_op.alter_column('created_by_id', existing_type=sa.INTEGER(), nullable=True)
        _drop_existing_fk(batch_op, 'config_templates', 'created_by_id')
        batch_op.create_foreign_key(
            'fk_config_templates_created_by_id_users', 'users', ['created_by_id'], ['id'],
            ondelete='SET NULL',
        )

    # ── cooldown_entries ─────────────────────────────────────────────────────
    with op.batch_alter_table(
        'cooldown_entries',
        copy_from=_reflected_table('cooldown_entries', 'host_id', 'created_by_id'),
    ) as batch_op:
        batch_op.alter_column('created_by_id', existing_type=sa.INTEGER(), nullable=True)
        _drop_existing_fk(batch_op, 'cooldown_entries', 'host_id')
        batch_op.create_foreign_key(
            'fk_cooldown_entries_host_id_hosts', 'hosts', ['host_id'], ['id'],
            ondelete='CASCADE',
        )
        _drop_existing_fk(batch_op, 'cooldown_entries', 'created_by_id')
        batch_op.create_foreign_key(
            'fk_cooldown_entries_created_by_id_users', 'users', ['created_by_id'], ['id'],
            ondelete='SET NULL',
        )

    # ── hosts ────────────────────────────────────────────────────────────────
    with op.batch_alter_table(
        'hosts',
        copy_from=_reflected_table('hosts', 'owner_user_id'),
    ) as batch_op:
        _drop_existing_fk(batch_op, 'hosts', 'owner_user_id')
        batch_op.create_foreign_key(
            'fk_hosts_owner_user_id_users', 'users', ['owner_user_id'], ['id'],
            ondelete='CASCADE',
        )

    # ── repo_scans ───────────────────────────────────────────────────────────
    with op.batch_alter_table(
        'repo_scans',
        copy_from=_reflected_table('repo_scans', 'created_by_id'),
    ) as batch_op:
        batch_op.alter_column('created_by_id', existing_type=sa.INTEGER(), nullable=True)
        _drop_existing_fk(batch_op, 'repo_scans', 'created_by_id')
        batch_op.create_foreign_key(
            'fk_repo_scans_created_by_id_users', 'users', ['created_by_id'], ['id'],
            ondelete='SET NULL',
        )

    # ── system_settings ──────────────────────────────────────────────────────
    with op.batch_alter_table(
        'system_settings',
        copy_from=_reflected_table('system_settings', 'updated_by_id'),
    ) as batch_op:
        _drop_existing_fk(batch_op, 'system_settings', 'updated_by_id')
        batch_op.create_foreign_key(
            'fk_system_settings_updated_by_id_users', 'users', ['updated_by_id'], ['id'],
            ondelete='SET NULL',
        )


# ---------------------------------------------------------------------------
# Downgrade
# ---------------------------------------------------------------------------

def downgrade() -> None:
    """Remove ondelete= clauses added in upgrade."""

    with op.batch_alter_table(
        'system_settings',
        copy_from=_reflected_table('system_settings', 'updated_by_id'),
    ) as batch_op:
        _drop_existing_fk(batch_op, 'system_settings', 'updated_by_id')
        batch_op.create_foreign_key(
            'fk_system_settings_updated_by_id_users', 'users', ['updated_by_id'], ['id'],
        )

    _repair_orphaned_audit_column('repo_scans', 'created_by_id')
    with op.batch_alter_table(
        'repo_scans',
        copy_from=_reflected_table('repo_scans', 'created_by_id'),
    ) as batch_op:
        _drop_existing_fk(batch_op, 'repo_scans', 'created_by_id')
        batch_op.create_foreign_key(
            'fk_repo_scans_created_by_id_users', 'users', ['created_by_id'], ['id'],
        )
        batch_op.alter_column('created_by_id', existing_type=sa.INTEGER(), nullable=False)

    with op.batch_alter_table(
        'hosts',
        copy_from=_reflected_table('hosts', 'owner_user_id'),
    ) as batch_op:
        _drop_existing_fk(batch_op, 'hosts', 'owner_user_id')
        batch_op.create_foreign_key(
            'fk_hosts_owner_user_id_users', 'users', ['owner_user_id'], ['id'],
        )

    _repair_orphaned_audit_column('cooldown_entries', 'created_by_id')
    with op.batch_alter_table(
        'cooldown_entries',
        copy_from=_reflected_table('cooldown_entries', 'host_id', 'created_by_id'),
    ) as batch_op:
        _drop_existing_fk(batch_op, 'cooldown_entries', 'host_id')
        batch_op.create_foreign_key(
            'fk_cooldown_entries_host_id_hosts', 'hosts', ['host_id'], ['id'],
        )
        _drop_existing_fk(batch_op, 'cooldown_entries', 'created_by_id')
        batch_op.create_foreign_key(
            'fk_cooldown_entries_created_by_id_users', 'users', ['created_by_id'], ['id'],
        )
        batch_op.alter_column('created_by_id', existing_type=sa.INTEGER(), nullable=False)

    _repair_orphaned_audit_column('config_templates', 'created_by_id')
    with op.batch_alter_table(
        'config_templates',
        copy_from=_reflected_table('config_templates', 'created_by_id'),
    ) as batch_op:
        _drop_existing_fk(batch_op, 'config_templates', 'created_by_id')
        batch_op.create_foreign_key(
            'fk_config_templates_created_by_id_users', 'users', ['created_by_id'], ['id'],
        )
        batch_op.alter_column('created_by_id', existing_type=sa.INTEGER(), nullable=False)

    _repair_orphaned_audit_column('config_assignments', 'assigned_by_id')
    with op.batch_alter_table(
        'config_assignments',
        copy_from=_reflected_table('config_assignments', 'host_id', 'assigned_by_id'),
    ) as batch_op:
        _drop_existing_fk(batch_op, 'config_assignments', 'host_id')
        batch_op.create_foreign_key(
            'fk_config_assignments_host_id_hosts', 'hosts', ['host_id'], ['id'],
        )
        _drop_existing_fk(batch_op, 'config_assignments', 'assigned_by_id')
        batch_op.create_foreign_key(
            'fk_config_assignments_assigned_by_id_users', 'users', ['assigned_by_id'], ['id'],
        )
        batch_op.alter_column('assigned_by_id', existing_type=sa.INTEGER(), nullable=False)

    with op.batch_alter_table(
        'scans',
        copy_from=_reflected_table('scans', 'host_id'),
    ) as batch_op:
        _drop_existing_fk(batch_op, 'scans', 'host_id')
        batch_op.create_foreign_key(
            'fk_scans_host_id_hosts', 'hosts', ['host_id'], ['id'],
        )

    with op.batch_alter_table(
        'alerts',
        copy_from=_reflected_table('alerts', 'host_id', 'acknowledged_by_id'),
    ) as batch_op:
        _drop_existing_fk(batch_op, 'alerts', 'host_id')
        batch_op.create_foreign_key(
            'fk_alerts_host_id_hosts', 'hosts', ['host_id'], ['id'],
        )
        _drop_existing_fk(batch_op, 'alerts', 'acknowledged_by_id')
        batch_op.create_foreign_key(
            'fk_alerts_acknowledged_by_id_users', 'users', ['acknowledged_by_id'], ['id'],
        )
