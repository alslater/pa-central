"""add password_reset_tokens.kind

Revision ID: c7a2e5f01d38
Revises: b3f81c4d9e27
Create Date: 2026-09-06 15:10:22.481903

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = 'c7a2e5f01d38'
down_revision: str | Sequence[str] | None = 'b3f81c4d9e27'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Must match models.PasswordResetKind. Named explicitly so PostgreSQL gets a
# real enum type rather than the unnamed one a bare sa.Enum() would produce.
# create_constraint=True: sa.Enum only creates a CHECK constraint on a
# non-native backend (SQLite) when this is set — without it, SQLite (this
# project's default database) got a bare, unconstrained VARCHAR despite the
# column's own docstring assuming a CHECK was already in place. An invalid
# value could then reach storage some other way (a direct DB edit, a
# restore, a future raw-SQL write) and crash every subsequent ORM read of
# that row with an uncaught LookupError. Must match the model's own
# Enum(PasswordResetKind, create_constraint=True) mapping exactly, or the
# two disagree about what's actually enforced at the database level.
_KIND = sa.Enum(
    'self_service', 'admin', 'welcome',
    name='passwordresetkind', create_constraint=True,
)

# Used only for the initial add_column below, deliberately without the
# constraint. SQLite's ALTER TABLE ADD COLUMN cannot add a CHECK constraint
# at all (Alembic warns "Skipping unsupported ALTER for creation of implicit
# constraint" and silently drops it if asked to) — the constraint has to be
# added afterward via batch_alter_table's copy-and-move strategy instead,
# in the alter_column call below. Reproduced directly: passing _KIND (with
# create_constraint=True) straight to op.add_column produced that warning
# and left the CHECK constraint entirely missing from the final schema.
_KIND_NO_CONSTRAINT = sa.Enum(
    'self_service', 'admin', 'welcome',
    name='passwordresetkind', create_constraint=False,
)


def upgrade() -> None:
    """Add password_reset_tokens.kind, backfill it, then make it NOT NULL.

    Each step is guarded independently rather than short-circuiting on the
    column's existence. This migration has three parts, and a run that dies
    between them leaves the database in a state the ORM cannot use: an early
    `return` when the column exists would skip the backfill *and* the NOT
    NULL, so a replay reports success while leaving NULL values behind and
    the column still nullable. Reproduced directly — replay exited 0 with one
    NULL row and `is_nullable = YES`.

    Every step below is therefore idempotent on its own, and the final state
    is enforced regardless of how far a previous attempt got. Replay is a
    real scenario here: the stranded-database recovery in CLAUDE.md rewinds
    the alembic_version stamp without touching the schema.
    """
    bind = op.get_bind()
    existing = {c["name"] for c in sa.inspect(bind).get_columns("password_reset_tokens")}

    # PostgreSQL needs the enum type to exist before a column can use it;
    # checkfirst covers a replay that got this far and no further. SQLite
    # renders the type as VARCHAR + CHECK, where create() is a no-op.
    _KIND.create(bind, checkfirst=True)

    # Added nullable, backfilled, then made NOT NULL: an existing table may
    # hold rows, and PostgreSQL rejects adding a NOT NULL column without a
    # default to a non-empty table. Added without the CHECK constraint (see
    # _KIND_NO_CONSTRAINT above) — SQLite cannot add one via a plain
    # ADD COLUMN, so it is applied afterward instead, below.
    if "kind" not in existing:
        op.add_column(
            'password_reset_tokens',
            sa.Column('kind', _KIND_NO_CONSTRAINT, nullable=True),
        )
    # Existing tokens predate the distinction. 'self_service' is the safe
    # backfill: it is the most restricted kind, so an already-issued link
    # cannot gain a longer TTL or throttle exemption it was never granted.
    op.execute(
        sa.text("UPDATE password_reset_tokens SET kind = 'self_service' WHERE kind IS NULL")
    )
    # batch_alter_table because SQLite has no ALTER COLUMN: it rebuilds the
    # table there, and emits a plain ALTER on PostgreSQL. Re-applying NOT NULL
    # to a column that already has it is a no-op on both, so this needs no
    # guard of its own — and running it unconditionally is what repairs a
    # column left nullable by an interrupted earlier attempt.
    #
    # existing_type=_KIND_NO_CONSTRAINT, type_=_KIND: this is also what
    # actually adds the CHECK constraint on SQLite, since the column
    # currently has none (see above) and this is the one type change
    # Alembic diffs it against. Passing _KIND for both existing_type and
    # type_ (as if only nullability were changing) made batch mode's
    # reflect-and-recreate step emit the constraint *twice* — reproduced
    # directly, a duplicate `CONSTRAINT passwordresetkind CHECK (...)` in
    # the rebuilt table's DDL — because the column type itself, not just
    # this call, already carries the constraint once reflected. Naming the
    # actual before/after types avoids that duplication and gets exactly
    # one CHECK constraint in the final schema. On PostgreSQL, create_constraint
    # is a no-op for both variants (the native enum type is used regardless),
    # so this has no effect there beyond the intended nullability change.
    with op.batch_alter_table('password_reset_tokens') as batch:
        batch.alter_column(
            'kind', existing_type=_KIND_NO_CONSTRAINT, type_=_KIND, nullable=False,
        )


def downgrade() -> None:
    bind = op.get_bind()
    # batch_alter_table, not a plain op.drop_column: SQLite's own
    # ALTER TABLE DROP COLUMN cannot drop a column referenced by a CHECK
    # constraint defined on the table (the constraint the upgrade above now
    # adds) — it raises "no such column: kind" while rebuilding the table,
    # since batch mode's copy-and-move rebuild carries the constraint's SQL
    # text over unchanged unless told to drop it explicitly, and that text
    # still names the column being dropped in the same step. Reproduced
    # directly against the upgraded schema. The constraint has to be
    # dropped explicitly, by its name (matching _KIND's own `name=`), before
    # the column — dropping the column alone is not enough.
    #
    # SQLite-only: on PostgreSQL, create_constraint=True is a no-op (the
    # native enum type is used instead, see _KIND's own docstring note
    # above) — there is no separate CHECK constraint named
    # "passwordresetkind" to drop there (that name belongs to the *type*,
    # dropped by _KIND.drop() below), and calling drop_constraint
    # unconditionally raised "constraint \"passwordresetkind\" of relation
    # \"password_reset_tokens\" does not exist" against a real PostgreSQL
    # database — caught by this migration's own existing PostgreSQL test
    # suite (test_postgres_migrations.py's TestPasswordResetKindBackfill),
    # not by the SQLite-only smoke path this fix was first verified against.
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table('password_reset_tokens') as batch:
            batch.drop_constraint('passwordresetkind', type_='check')
            batch.drop_column('kind')
    else:
        op.drop_column('password_reset_tokens', 'kind')
    _KIND.drop(bind, checkfirst=True)
