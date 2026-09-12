"""SQLite migration tests.

Unlike test_postgres_migrations.py, these run unconditionally — SQLite has
no external service dependency. They exist for the same reason that file
does, in reverse: some migration behaviour only diverges on SQLite (no
native ALTER COLUMN, no native ENUM type, sa.Enum requiring
create_constraint=True to get a CHECK constraint at all), and running
`alembic upgrade head` against a real SQLite file — not the app's own
Base.metadata.create_all() bootstrap the rest of the test suite uses — is
the only thing that actually exercises that path.
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest
import sqlalchemy as sa

BACKEND_DIR = Path(__file__).resolve().parent.parent

PRE_KIND_REVISION = "b3f81c4d9e27"
KIND_REVISION = "c7a2e5f01d38"


def alembic(db_path: str, *args: str) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if not k.upper().startswith("DATABASE_")}
    env.update({
        "DATABASE_TYPE": "sqlite",
        "DATABASE_NAME": db_path,
        "DEBUG": "true",
    })
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _seed_pre_kind_rows(db_path: str) -> None:
    engine = sa.create_engine(f"sqlite:///{db_path}")
    try:
        with engine.begin() as conn:
            conn.execute(sa.text(
                "INSERT INTO users (id,email,display_name,hashed_password,"
                "role,is_active,totp_enabled,created_at) VALUES "
                "(1,'kind@example.invalid','Kind','x','viewer',1,0,'2026-01-01')"
            ))
            conn.execute(sa.text(
                "INSERT INTO password_reset_tokens "
                "(token_hash,user_id,created_at,expires_at,used_at) VALUES "
                "('live','1','2026-01-01','2026-01-02',NULL)"
            ))
    finally:
        engine.dispose()


class TestPasswordResetKindOnSqlite:
    """c7a2e5f01d38's kind column must get a real CHECK constraint on
    SQLite, not just on PostgreSQL's native enum type — sa.Enum only emits
    one on a non-native backend when create_constraint=True is set, and
    without it an invalid value could reach storage (a direct DB edit, a
    restore, a future raw-SQL write) and crash every subsequent ORM read
    with an uncaught LookupError, since nothing in the schema itself would
    have refused the write. See TestPasswordResetKindBackfill in
    test_postgres_migrations.py for the equivalent PostgreSQL-side coverage
    of the same migration (backfill, NOT NULL, replay-after-interruption).
    """

    @pytest.fixture
    def db_path(self, tmp_path):
        path = str(tmp_path / "scratch.db")
        assert alembic(path, "upgrade", PRE_KIND_REVISION).returncode == 0
        _seed_pre_kind_rows(path)
        return path

    def test_the_check_constraint_is_present_after_upgrade(self, db_path):
        assert alembic(db_path, "upgrade", "head").returncode == 0
        engine = sa.create_engine(f"sqlite:///{db_path}")
        try:
            with engine.connect() as conn:
                ddl = conn.execute(sa.text(
                    "SELECT sql FROM sqlite_master WHERE type='table' "
                    "AND name='password_reset_tokens'"
                )).scalar_one()
        finally:
            engine.dispose()
        assert "CHECK" in ddl and "passwordresetkind" in ddl, (
            f"no CHECK constraint found in the created table DDL:\n{ddl}"
        )

    def test_an_invalid_kind_is_rejected_by_the_database_itself(self, db_path):
        """The actual bug: without create_constraint=True, this INSERT
        succeeded, and the ORM then raised an uncaught LookupError on the
        next read of the row rather than the database ever refusing the
        write in the first place."""
        assert alembic(db_path, "upgrade", "head").returncode == 0
        engine = sa.create_engine(f"sqlite:///{db_path}")
        try:
            with engine.connect() as conn, pytest.raises(sa.exc.IntegrityError):
                conn.execute(sa.text(
                    "INSERT INTO password_reset_tokens "
                    "(token_hash,user_id,created_at,expires_at,kind) VALUES "
                    "('bogus','1','2026-01-01','2026-01-02','not_a_kind')"
                ))
                conn.commit()
        finally:
            engine.dispose()

    def test_existing_rows_are_backfilled_and_not_null(self, db_path):
        assert alembic(db_path, "upgrade", "head").returncode == 0
        engine = sa.create_engine(f"sqlite:///{db_path}")
        try:
            with engine.connect() as conn:
                row = conn.execute(sa.text(
                    "SELECT kind FROM password_reset_tokens WHERE token_hash = 'live'"
                )).scalar_one()
        finally:
            engine.dispose()
        assert row == "self_service"

    def test_downgrade_removes_the_column_and_constraint_keeping_rows(self, db_path):
        """The actual regression this fix could have introduced: SQLite
        cannot drop a column referenced by a CHECK constraint via a plain
        ALTER TABLE, so the downgrade needs the constraint dropped
        explicitly, in the same batch, before the column — see the
        migration's own downgrade() docstring comment."""
        assert alembic(db_path, "upgrade", "head").returncode == 0

        r = alembic(db_path, "downgrade", PRE_KIND_REVISION)
        assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"

        engine = sa.create_engine(f"sqlite:///{db_path}")
        try:
            with engine.connect() as conn:
                ddl = conn.execute(sa.text(
                    "SELECT sql FROM sqlite_master WHERE type='table' "
                    "AND name='password_reset_tokens'"
                )).scalar_one()
                rows = conn.execute(sa.text(
                    "SELECT token_hash FROM password_reset_tokens"
                )).all()
        finally:
            engine.dispose()
        assert "kind" not in ddl
        assert "CHECK" not in ddl
        assert [row.token_hash for row in rows] == ["live"]

    def test_upgrade_downgrade_upgrade_round_trips(self, db_path):
        assert alembic(db_path, "upgrade", "head").returncode == 0
        assert alembic(db_path, "downgrade", PRE_KIND_REVISION).returncode == 0
        r = alembic(db_path, "upgrade", "head")
        assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"

        engine = sa.create_engine(f"sqlite:///{db_path}")
        try:
            with engine.connect() as conn:
                row = conn.execute(sa.text(
                    "SELECT kind FROM password_reset_tokens WHERE token_hash = 'live'"
                )).scalar_one()
        finally:
            engine.dispose()
        assert row == "self_service"
