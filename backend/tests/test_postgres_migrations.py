"""PostgreSQL migration and FK-behaviour tests.

The main suite runs on SQLite, which cannot catch dialect-specific defects:

* ``batch_alter_table`` rebuilds the table on SQLite but emits ALTER TABLE on
  PostgreSQL, where ``copy_from`` is ignored entirely — so a migration can look
  correct on SQLite while leaving duplicate constraints on PostgreSQL.
* SQLite ignores FK actions unless ``PRAGMA foreign_keys`` is on; PostgreSQL
  always enforces them.

These tests run the real migration chain against a throwaway database and
assert on ``pg_constraint``, then exercise the delete cascades end to end.
Skipped automatically when neither Docker nor PA_TEST_POSTGRES_URL is available.
"""
import os
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest
import sqlalchemy as sa

BACKEND_DIR = Path(__file__).resolve().parent.parent

BASE_REVISION = "cd36263592ce"
HEAD_REVISION = "035924a7a885"

# (table, column) -> expected ON DELETE action after upgrade.
# 'c' = CASCADE, 'n' = SET NULL, 'a' = NO ACTION (pg_constraint.confdeltype)
EXPECTED_ONDELETE = {
    ("hosts", "owner_user_id"): "c",
    ("alerts", "host_id"): "c",
    ("alerts", "acknowledged_by_id"): "n",
    ("scans", "host_id"): "c",
    ("config_assignments", "host_id"): "c",
    ("config_assignments", "assigned_by_id"): "n",
    ("config_templates", "created_by_id"): "n",
    # host-scoped cooldowns are deleted with the host: nulling host_id would
    # silently promote the entry to fleet-wide and suppress alerts everywhere.
    ("cooldown_entries", "host_id"): "c",
    ("cooldown_entries", "created_by_id"): "n",
    ("repo_scans", "created_by_id"): "n",
    ("system_settings", "updated_by_id"): "n",
}

MIGRATED_TABLES = sorted({t for t, _ in EXPECTED_ONDELETE})


# Query keys this helper knows how to translate into their DATABASE_*
# equivalent — the same libpq TLS vocabulary app.core.db_config uses. Anything
# else on the URL (e.g. ?connect_timeout=5) has no DATABASE_* equivalent, so
# silently keeping only the recognized keys would connect with weaker/
# different settings than the caller asked for.
_SUPPORTED_QUERY_OPTIONS = {
    "sslmode": "DATABASE_SSLMODE",
    "sslrootcert": "DATABASE_SSLROOTCERT",
    "sslcert": "DATABASE_SSLCERT",
    "sslkey": "DATABASE_SSLKEY",
}


def alembic(
    url: str, *args: str, schema: str | None = None
) -> subprocess.CompletedProcess:
    """Run alembic against *url*, returning the completed process.

    env.py builds its URL from structured DATABASE_* environment variables
    (via app.core.db_config.sync_url()), not from a URL string — so those are
    what this decomposes *url* into and sets for the subprocess. *schema* is a
    separate keyword rather than a URL query option: DATABASE_SCHEMA is an
    application-level setting, not a libpq connection parameter, so it has no
    place in a database URL's query string.
    """
    import sqlalchemy as sa

    parsed = sa.engine.make_url(url)
    query = dict(parsed.query)
    unsupported = query.keys() - _SUPPORTED_QUERY_OPTIONS.keys()
    if unsupported:
        raise ValueError(
            f"alembic() cannot translate query option(s) {sorted(unsupported)} "
            f"on {url!r} into DATABASE_* environment variables — add support "
            "or strip them from the URL"
        )

    # Inherit the environment for PYTHONPATH/VIRTUAL_ENV/PG*/proxy/CA-bundle
    # vars, which differ between local and CI setups — but every DATABASE_*
    # var is cleared first. Otherwise an ambient DATABASE_SCHEMA or
    # DATABASE_SSLMODE (e.g. left set by the real app's own .env) would
    # silently take precedence over what *url* actually specifies, and the
    # migration could target the wrong schema or negotiate different TLS
    # settings than the fixture provisioned.
    env = {k: v for k, v in os.environ.items() if not k.startswith("DATABASE_")}
    env.update(
        {
            "DATABASE_TYPE": "postgresql",
            "DATABASE_HOST": str(parsed.host),
            "DATABASE_PORT": str(parsed.port or 5432),
            "DATABASE_NAME": str(parsed.database),
            "DATABASE_USER": str(parsed.username),
            "DEBUG": "true",
            # Explicit, not left to Settings' own field default: this
            # subprocess's environment must be fully determined by *url*,
            # never by whatever DATABASE_SSLMODE happens to be unset to.
            "DATABASE_SSLMODE": str(query.get("sslmode", "prefer")),
        }
    )
    if parsed.password:
        env["DATABASE_PASSWORD"] = parsed.password
    if schema is not None:
        env["DATABASE_SCHEMA"] = schema
    for key, env_name in _SUPPORTED_QUERY_OPTIONS.items():
        if key == "sslmode":
            continue  # already set above, with its "prefer" default
        if key in query:
            env[env_name] = str(query[key])
    env.pop("ALEMBIC_DATABASE_URL", None)
    # check=False: callers assert on returncode themselves so a failed
    # migration surfaces its stdout/stderr rather than a bare CalledProcessError.
    return subprocess.run(
        [sys.executable, "-m", "alembic", *args],
        cwd=str(BACKEND_DIR),
        env=env,
        capture_output=True, text=True, check=False,
    )


class TestAlembicHelperEnvironmentIsSanitized:
    """alembic() must build the subprocess environment entirely from *url*.

    It previously only overrode DATABASE_TYPE/HOST/PORT/NAME/USER/PASSWORD and
    inherited everything else from os.environ unchanged — so an ambient
    DATABASE_SCHEMA or DATABASE_SSLMODE left over from the real app's own
    .env (or a developer's shell) would silently take precedence over what
    the postgres_url fixture actually provisioned, and a query option on an
    externally supplied PA_TEST_POSTGRES_URL (README.md documents
    ?sslmode=require) was dropped entirely since only the URL's authority was
    read.
    """

    @staticmethod
    def _capture_env(monkeypatch):
        captured: dict = {}

        def fake_run(*args, **kwargs):
            captured["env"] = kwargs["env"]
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

        monkeypatch.setattr(subprocess, "run", fake_run)
        return captured

    def test_stale_ambient_vars_are_cleared_not_inherited(self, monkeypatch):
        for name, stale in (
            ("DATABASE_SCHEMA", "stale_schema"),
            ("DATABASE_SSLMODE", "verify-full"),
            ("DATABASE_SSLROOTCERT", "/stale/ca.pem"),
            ("DATABASE_SSLCERT", "/stale/cert.pem"),
            ("DATABASE_SSLKEY", "/stale/key.pem"),
            ("DATABASE_PASSWORD_FILE", "/stale/pw"),
        ):
            monkeypatch.setenv(name, stale)

        captured = self._capture_env(monkeypatch)
        alembic("postgresql+psycopg2://u:p@host/db", "upgrade", "head")

        env = captured["env"]
        for name in (
            "DATABASE_SCHEMA",
            "DATABASE_SSLROOTCERT",
            "DATABASE_SSLCERT",
            "DATABASE_SSLKEY",
            "DATABASE_PASSWORD_FILE",
        ):
            assert name not in env, f"{name} leaked a stale ambient value"
        assert env["DATABASE_SSLMODE"] == "prefer", (
            "sslmode must fall back to the real default, not the stale "
            "ambient value, when the URL specifies none"
        )

    def test_sslmode_query_option_is_honored(self, monkeypatch):
        """README.md documents PA_TEST_POSTGRES_URL=...?sslmode=require —
        that must reach the Alembic subprocess, not be silently dropped."""
        captured = self._capture_env(monkeypatch)
        alembic(
            "postgresql+psycopg2://u:p@host/db?sslmode=require", "upgrade", "head"
        )
        assert captured["env"]["DATABASE_SSLMODE"] == "require"

    def test_unsupported_query_option_is_rejected(self, monkeypatch):
        """A query option this helper cannot translate must fail loudly,
        never be silently ignored — a dropped option can mean the subprocess
        connects with weaker settings than the caller asked for."""
        self._capture_env(monkeypatch)
        with pytest.raises(ValueError, match="connect_timeout"):
            alembic(
                "postgresql+psycopg2://u:p@host/db?connect_timeout=5",
                "upgrade",
                "head",
            )


# Single-column FK constraints, joined via pg_class/pg_namespace.
#
# `conrelid::regclass::text` is search_path-dependent: with `public` off the
# path it renders as `public.hosts`, so matching it against unqualified names
# silently returns *nothing* — and the duplication assertion, which compares
# against an empty dict, would then pass vacuously. Filtering on
# `pg_class.relname` with an explicit schema avoids that entirely.
_FK_FROM_WHERE = (
    "FROM pg_constraint c "
    "JOIN pg_class t ON t.oid = c.conrelid "
    "JOIN pg_namespace n ON n.oid = t.relnamespace "
    "JOIN pg_attribute a "
    "  ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1] "
    "WHERE c.contype = 'f' AND array_length(c.conkey, 1) = 1 "
    "  AND n.nspname = :schema "
    "  AND t.relname = ANY(:tables) "
)

FK_SCHEMA = "public"


def _fk_rows(
    url: str, select_clause: str, group_by: str = ""
) -> Sequence[sa.Row]:
    # `tables` is typed explicitly rather than left to inference. psycopg2
    # adapts a bare Python list to an untyped `ARRAY[...]` literal and lets the
    # server infer the element type from context; declaring ARRAY(Text) sends a
    # real text[] instead, so the query does not depend on that inference.
    # (A `:tables::text[]` cast cannot be used here — sa.text() would read
    # `:tables:` as the parameter name.)
    stmt = sa.text(select_clause + _FK_FROM_WHERE + group_by).bindparams(
        sa.bindparam("tables", type_=sa.ARRAY(sa.Text())),
        sa.bindparam("schema", type_=sa.Text()),
    )
    engine = sa.create_engine(url)
    try:
        with engine.connect() as conn:
            return conn.execute(
                stmt, {"tables": MIGRATED_TABLES, "schema": FK_SCHEMA}
            ).all()
    finally:
        engine.dispose()


def fk_actions(url: str) -> dict[tuple[str, str], str]:
    """Map (table, column) -> ON DELETE action for every single-column FK."""
    rows = _fk_rows(
        url,
        "SELECT t.relname AS tbl, a.attname AS col, "
        "       c.confdeltype::text AS ondelete ",
    )
    return {(r.tbl, r.col): r.ondelete for r in rows}


def fk_counts(url: str) -> dict[tuple[str, str], int]:
    """Count FK constraints per (table, column) — catches duplication."""
    rows = _fk_rows(
        url,
        "SELECT t.relname AS tbl, a.attname AS col, count(*) AS n ",
        group_by="GROUP BY 1, 2",
    )
    return {(r.tbl, r.col): r.n for r in rows}


class TestMigrationChain:
    def test_upgrade_head_succeeds(self, postgres_url):
        r = alembic(postgres_url, "upgrade", "head")
        assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"

        # Pin the head so adding a migration forces a deliberate update here.
        # The assertions below only inspect tables in EXPECTED_ONDELETE and
        # downgrade only as far as BASE_REVISION, so a new revision that slips
        # in unnoticed would be silently under-tested.
        engine = sa.create_engine(postgres_url)
        try:
            with engine.connect() as conn:
                versions = conn.execute(
                    sa.text("SELECT version_num FROM alembic_version")
                ).scalars().all()
        finally:
            engine.dispose()

        assert versions == [HEAD_REVISION], (
            f"expected head {HEAD_REVISION!r}, found {versions!r} — if a migration "
            "was added, update HEAD_REVISION and check EXPECTED_ONDELETE and "
            "BASE_REVISION still cover it (see CLAUDE.md)"
        )

    def test_every_altered_column_has_exactly_one_fk(self, postgres_url):
        """Guards the PostgreSQL duplication bug.

        Batch mode ALTERs in place on PostgreSQL and ignores ``copy_from``, so
        without an explicit drop the original NO ACTION constraint survives
        alongside the new one — and NO ACTION wins, silently defeating the
        migration while SQLite looks perfect.
        """
        assert alembic(postgres_url, "upgrade", "head").returncode == 0
        counts = fk_counts(postgres_url)
        duplicated = {k: n for k, n in counts.items() if n > 1}
        assert duplicated == {}, f"duplicate FK constraints: {duplicated}"

    def test_ondelete_actions_match_the_model(self, postgres_url):
        assert alembic(postgres_url, "upgrade", "head").returncode == 0
        actions = fk_actions(postgres_url)
        for key, expected in EXPECTED_ONDELETE.items():
            assert actions.get(key) == expected, (
                f"{key[0]}.{key[1]}: expected ON DELETE {expected!r}, got {actions.get(key)!r}"
            )

    def test_downgrade_succeeds_and_clears_ondelete(self, postgres_url):
        assert alembic(postgres_url, "upgrade", "head").returncode == 0
        r = alembic(postgres_url, "downgrade", BASE_REVISION)
        assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"

        actions = fk_actions(postgres_url)
        for (table, col) in EXPECTED_ONDELETE:
            assert actions.get((table, col)) == "a", (
                f"{table}.{col} should be NO ACTION after downgrade, got {actions.get((table, col))!r}"
            )
        duplicated = {k: n for k, n in fk_counts(postgres_url).items() if n > 1}
        assert duplicated == {}, f"downgrade left duplicate FKs: {duplicated}"

    def test_round_trip_does_not_accumulate_constraints(self, postgres_url):
        """upgrade -> downgrade -> upgrade must be idempotent."""
        assert alembic(postgres_url, "upgrade", "head").returncode == 0
        first_counts = fk_counts(postgres_url)
        first_actions = fk_actions(postgres_url)

        assert alembic(postgres_url, "downgrade", BASE_REVISION).returncode == 0
        assert alembic(postgres_url, "upgrade", "head").returncode == 0

        # Identical to the first upgrade: no accumulation, no drifted actions.
        assert fk_counts(postgres_url) == first_counts
        assert fk_actions(postgres_url) == first_actions
        for key, expected in EXPECTED_ONDELETE.items():
            assert first_actions.get(key) == expected


class TestCliMigrationCreatesTheSchema:
    """DATABASE_SCHEMA must work identically whether Alembic is invoked by
    the application at startup (app.main._ensure_schema, called before
    migrations run) or directly via the CLI/CI — the latter never goes
    through app startup at all, so env.py must ensure the schema exists
    itself rather than assuming _ensure_schema already ran.

    Reproduced live before any fix existed: version_table_schema=<a schema
    that does not exist yet> made `alembic upgrade head` fail with a raw
    ProgrammingError several frames deep in SQLAlchemy internals
    ("relation \"some_schema.alembic_version\" does not exist" /
    "schema \"some_schema\" does not exist"), naming neither DATABASE_SCHEMA
    nor how to fix it — unlike app startup's clear, schema-specific
    RuntimeError from the same underlying situation.
    """

    def test_cli_invocation_creates_a_missing_schema(self, postgres_url):
        r = alembic(postgres_url, "upgrade", "head", schema="cli_made_schema")
        assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"

        engine = sa.create_engine(postgres_url)
        try:
            with engine.connect() as conn:
                exists = conn.execute(sa.text(
                    "SELECT 1 FROM information_schema.schemata "
                    "WHERE schema_name = 'cli_made_schema'"
                )).scalar()
        finally:
            engine.dispose()
        assert exists == 1

    def test_cli_invocation_with_an_existing_schema_needs_no_ddl(
        self, postgres_url
    ):
        engine = sa.create_engine(postgres_url)
        try:
            with engine.begin() as conn:
                conn.execute(sa.text('CREATE SCHEMA "premade_cli_schema"'))
        finally:
            engine.dispose()

        r = alembic(postgres_url, "upgrade", "head", schema="premade_cli_schema")
        assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"


class TestDowngradeRepairsOrphanedAudit:
    """The downgrade restores NOT NULL on audit columns the upgrade made nullable.

    Deleting a user legitimately leaves NULLs there, so the downgrade must
    repair them first or it fails with a NOT NULL violation partway through.
    """

    def test_downgrade_reassigns_orphaned_rows_to_an_admin(self, postgres_url):
        assert alembic(postgres_url, "upgrade", "head").returncode == 0

        engine = sa.create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        with engine.connect() as conn:
            # id 1 is a viewer, id 2 the admin: proves the repair prefers an
            # admin rather than simply taking the lowest id.
            conn.execute(sa.text(
                "INSERT INTO users (id,email,display_name,hashed_password,role,"
                "is_active,totp_enabled,created_at) VALUES "
                "(1,'v@x','V','h','viewer',true,false,now()),"
                "(2,'a@x','A','h','admin',true,false,now()),"
                "(3,'d@x','D','h','developer',true,false,now())"
            ))
            conn.execute(sa.text(
                "INSERT INTO config_templates (id,name,toml_content,created_by_id,"
                "created_at,updated_at,is_default) "
                "VALUES (1,'t','x',3,now(),now(),false)"
            ))
            conn.execute(sa.text("DELETE FROM users WHERE id = 3"))
            orphaned = conn.execute(
                sa.text("SELECT created_by_id FROM config_templates WHERE id = 1")
            ).scalar()
            assert orphaned is None, "SET NULL should have orphaned the audit column"
        engine.dispose()

        r = alembic(postgres_url, "downgrade", BASE_REVISION)
        assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"

        engine = sa.create_engine(postgres_url)
        with engine.connect() as conn:
            owner = conn.execute(
                sa.text("SELECT created_by_id FROM config_templates WHERE id = 1")
            ).scalar()
            nullable = conn.execute(sa.text(
                "SELECT is_nullable FROM information_schema.columns "
                "WHERE table_name='config_templates' AND column_name='created_by_id'"
            )).scalar()
        engine.dispose()

        assert owner == 2, "orphan should be reassigned to the admin, not the lowest id"
        assert nullable == "NO", "downgrade should restore NOT NULL"


class TestDeleteCascadeBehaviour:
    """End-to-end delete behaviour, enforced by PostgreSQL rather than a PRAGMA."""

    @pytest.fixture
    def migrated(self, postgres_url):
        assert alembic(postgres_url, "upgrade", "head").returncode == 0
        engine = sa.create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        yield engine
        engine.dispose()

    def test_deleting_a_user_cascades_through_hosts_to_alerts(self, migrated):
        with migrated.connect() as conn:
            conn.execute(sa.text(
                "INSERT INTO users (id,email,display_name,hashed_password,role,"
                "is_active,totp_enabled,created_at) VALUES "
                "(1,'a@x','A','h','admin',true,false,now()),"
                "(2,'o@x','O','h','developer',true,false,now())"
            ))
            conn.execute(sa.text(
                "INSERT INTO hosts (id,owner_user_id,name,daemon_status,created_at) "
                "VALUES (1,2,'h1','unknown',now())"
            ))
            conn.execute(sa.text(
                "INSERT INTO alerts (id,host_id,package_name,ecosystem,kind,severity,"
                "acknowledged,acknowledged_by_id,occurred_at,received_at) "
                "VALUES (1,1,'requests','pypi','osv','high',true,2,now(),now())"
            ))
            conn.execute(sa.text(
                "INSERT INTO config_templates (id,name,toml_content,created_by_id,"
                "created_at,updated_at,is_default) VALUES (1,'t','x',2,now(),now(),false)"
            ))

            # Would raise ForeignKeyViolation without the cascade chain.
            conn.execute(sa.text("DELETE FROM users WHERE id = 2"))

            assert conn.execute(sa.text("SELECT count(*) FROM hosts")).scalar() == 0
            assert conn.execute(sa.text("SELECT count(*) FROM alerts")).scalar() == 0
            # The template survives; only its attribution is cleared.
            assert conn.execute(sa.text("SELECT count(*) FROM config_templates")).scalar() == 1
            assert conn.execute(
                sa.text("SELECT created_by_id FROM config_templates WHERE id = 1")
            ).scalar() is None

    def test_host_scoped_cooldown_is_deleted_not_promoted_to_fleet_wide(self, migrated):
        """host_id IS NULL means fleet-wide, so SET NULL here would broaden scope."""
        with migrated.connect() as conn:
            conn.execute(sa.text(
                "INSERT INTO users (id,email,display_name,hashed_password,role,"
                "is_active,totp_enabled,created_at) "
                "VALUES (1,'a@x','A','h','admin',true,false,now())"
            ))
            conn.execute(sa.text(
                "INSERT INTO hosts (id,owner_user_id,name,daemon_status,created_at) "
                "VALUES (1,1,'h1','unknown',now())"
            ))
            conn.execute(sa.text(
                "INSERT INTO cooldown_entries (id,package_name,ecosystem,host_id,created_at) "
                "VALUES (1,'scoped','pypi',1,now()), (2,'fleet','pypi',NULL,now())"
            ))

            conn.execute(sa.text("DELETE FROM hosts WHERE id = 1"))

            remaining = conn.execute(
                sa.text("SELECT id, host_id FROM cooldown_entries ORDER BY id")
            ).all()
            assert [(r.id, r.host_id) for r in remaining] == [(2, None)], (
                "host-scoped entry must be deleted, fleet-wide entry preserved"
            )
