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

from tests.conftest_postgres import _SUPPORTED_QUERY_OPTIONS

BACKEND_DIR = Path(__file__).resolve().parent.parent

BASE_REVISION = "cd36263592ce"
HEAD_REVISION = "7ace8b60203b"

# (table, column) -> expected ON DELETE action once HEAD_REVISION is applied.
# 'c' = CASCADE, 'n' = SET NULL, 'a' = NO ACTION (pg_constraint.confdeltype)
#
# Every altered/added FK belongs here regardless of when its table was
# created — this is what MIGRATED_TABLES, fk_counts, and
# test_every_altered_column_has_exactly_one_fk key off, so a table missing
# from this dict has its FK constraints silently unchecked for duplication
# (the exact bug these tests exist to catch: batch mode ALTERs in place on
# PostgreSQL, so an unresolved copy_from can leave the old constraint
# alongside the new one). DOWNGRADE_EXPECTED_ONDELETE below is the narrower
# subset actually exercised by the downgrade-to-BASE_REVISION test.
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
    ("risk_records", "repo_scan_id"): "c",
    ("risk_records", "accepted_by_id"): "n",
}

MIGRATED_TABLES = sorted({t for t, _ in EXPECTED_ONDELETE})

# Downgrading to BASE_REVISION only unwinds migrations up to that point, so
# only entries for tables/columns that already existed at BASE_REVISION can
# be checked after a downgrade — risk_records postdates it (added by
# HEAD_REVISION) and doesn't exist yet at that point in the chain.
_POST_BASE_REVISION_TABLES = {"risk_records"}
DOWNGRADE_EXPECTED_ONDELETE = {
    k: v for k, v in EXPECTED_ONDELETE.items() if k[0] not in _POST_BASE_REVISION_TABLES
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
        # str(parsed), not the raw url!r: url may be an externally supplied
        # PA_TEST_POSTGRES_URL carrying a real password, and URL.__str__
        # masks it (unlike a plain string's repr, which has no idea a
        # password is embedded in it).
        raise ValueError(
            f"alembic() cannot translate query option(s) {sorted(unsupported)} "
            f"on {parsed} into DATABASE_* environment variables — add support "
            "or strip them from the URL"
        )

    # Inherit the environment for PYTHONPATH/VIRTUAL_ENV/PG*/proxy/CA-bundle
    # vars, which differ between local and CI setups — but every DATABASE_*
    # var is cleared first. Otherwise an ambient DATABASE_SCHEMA or
    # DATABASE_SSLMODE (e.g. left set by the real app's own .env) would
    # silently take precedence over what *url* actually specifies, and the
    # migration could target the wrong schema or negotiate different TLS
    # settings than the fixture provisioned. Matched case-insensitively:
    # pydantic-settings' own config source is case-insensitive (Settings
    # never sets case_sensitive=True), so a lowercase or mixed-case ambient
    # var like database_schema is exactly as live a threat as DATABASE_SCHEMA.
    env = {
        k: v for k, v in os.environ.items() if not k.upper().startswith("DATABASE_")
    }
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
            # Every optional DATABASE_* field this helper doesn't otherwise
            # set is shadowed with an explicit empty value here, not merely
            # omitted -- omitting the key here only clears the *parent's*
            # os.environ copy, but the subprocess's own Settings() (built
            # when Alembic's env.py imports app.core.config) reloads
            # backend/.env independently. pydantic-settings' env-var source
            # only outranks its dotenv source when the key is actually
            # present, even as "" -- confirmed live: a URL without a
            # password picked up a developer's real DATABASE_PASSWORD_FILE
            # from backend/.env and crashed trying to read it, and an
            # unset schema silently resolved to whatever DATABASE_SCHEMA
            # happened to be sitting in that file. Settings' own
            # _blank_to_none validator (app/core/config.py) collapses ""
            # back to None, so this is safe to always set.
            "DATABASE_PASSWORD": "",
            "DATABASE_PASSWORD_FILE": "",
            "DATABASE_SCHEMA": "",
            "DATABASE_SSLROOTCERT": "",
            "DATABASE_SSLCERT": "",
            "DATABASE_SSLKEY": "",
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
        # Present-but-empty, not absent: an absent key would leave the
        # subprocess's own Settings() free to fall back to backend/.env
        # instead (see TestAlembicHelperEnvDoesNotFallBackToDotenv below) --
        # the key must be *there*, just shadowed, to block both sources.
        for name in (
            "DATABASE_SCHEMA",
            "DATABASE_SSLROOTCERT",
            "DATABASE_SSLCERT",
            "DATABASE_SSLKEY",
            "DATABASE_PASSWORD_FILE",
        ):
            assert name in env, f"{name} must be explicitly shadowed, not omitted"
            assert env[name] == "", f"{name} leaked a stale ambient value: {env[name]!r}"
        assert env["DATABASE_SSLMODE"] == "prefer", (
            "sslmode must fall back to the real default, not the stale "
            "ambient value, when the URL specifies none"
        )

    def test_stale_ambient_vars_are_cleared_regardless_of_case(self, monkeypatch):
        """The configuration source (pydantic-settings) reads DATABASE_* env
        vars case-insensitively, so this helper's own sanitizer must strip
        them the same way — a lowercase or mixed-case ambient var is exactly
        as live a threat as an uppercase one."""
        for name, stale in (
            ("database_schema", "stale_lower_schema"),
            ("Database_Sslmode", "verify-full"),
            ("database_url", "postgresql://stale/should-not-be-read"),
        ):
            monkeypatch.setenv(name, stale)

        captured = self._capture_env(monkeypatch)
        alembic("postgresql+psycopg2://u:p@host/db", "upgrade", "head")

        env = captured["env"]
        for name in ("database_schema", "Database_Sslmode", "database_url"):
            assert name not in env, f"{name} leaked a stale ambient value"
        assert env["DATABASE_SSLMODE"] == "prefer", (
            "sslmode must fall back to the real default, not the stale "
            "lower/mixed-case ambient value, when the URL specifies none"
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

    def test_unsupported_query_option_error_does_not_leak_the_password(
        self, monkeypatch
    ):
        """*url* can be an externally supplied PA_TEST_POSTGRES_URL carrying a
        real password — the error naming the unsupported option must not
        print that password into test/CI logs."""
        self._capture_env(monkeypatch)
        with pytest.raises(ValueError) as exc_info:
            alembic(
                "postgresql+psycopg2://u:supersecret@host/db?connect_timeout=5",
                "upgrade",
                "head",
            )
        assert "supersecret" not in str(exc_info.value)


class TestAlembicHelperEnvDoesNotFallBackToDotenv:
    """Clearing DATABASE_* only from the parent's os.environ copy does not
    shadow backend/.env: the subprocess's own Settings() (constructed when
    Alembic's env.py imports app.core.config) reloads that file
    independently, and pydantic-settings' env-var source only outranks its
    dotenv source when the key is actually *present* in the child's
    environment, even as "". Confirmed live before the fix: a URL with no
    password picked up a developer's real DATABASE_PASSWORD_FILE from
    backend/.env and crashed trying to read it, and calling alembic() with
    no schema kwarg silently resolved to whatever DATABASE_SCHEMA happened
    to be sitting in that file -- identical mechanism to
    TestAlembicSubprocessEnvDoesNotFallBackToDotenv in test_db_config.py,
    just at a different call site."""

    @staticmethod
    def _settings_read_back_through(monkeypatch, env: dict, env_file) -> "object":
        """Reconstruct Settings the way the Alembic subprocess would: fresh
        process, same child env, same env_file on disk."""
        from pydantic_settings import BaseSettings, SettingsConfigDict

        class _ChildSettings(BaseSettings):
            model_config = SettingsConfigDict(env_file=str(env_file), extra="ignore")

            database_schema: str | None = None
            database_password_file: str | None = None

        monkeypatch.setattr(os, "environ", env)
        return _ChildSettings()

    def test_schema_does_not_leak_back_from_dotenv(self, monkeypatch, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_SCHEMA=stale-dotenv-schema\n")

        captured = TestAlembicHelperEnvironmentIsSanitized._capture_env(monkeypatch)
        alembic("postgresql+psycopg2://u:p@host/db", "upgrade", "head")  # schema=None

        child = self._settings_read_back_through(monkeypatch, captured["env"], env_file)
        assert not child.database_schema, (
            "the subprocess's own Settings() fell back to backend/.env's "
            f"stale DATABASE_SCHEMA despite alembic() being called with no "
            f"schema: {child.database_schema!r}"
        )

    def test_password_file_does_not_leak_back_from_dotenv(self, monkeypatch, tmp_path):
        env_file = tmp_path / ".env"
        env_file.write_text("DATABASE_PASSWORD_FILE=/from/dotenv\n")

        captured = TestAlembicHelperEnvironmentIsSanitized._capture_env(monkeypatch)
        # No password in the URL -- mirrors a postgres_url fixture/URL that
        # carries no credentials of its own.
        alembic("postgresql+psycopg2://host/db", "upgrade", "head")

        child = self._settings_read_back_through(monkeypatch, captured["env"], env_file)
        assert not child.database_password_file, (
            "the subprocess's own Settings() fell back to backend/.env's "
            "stale DATABASE_PASSWORD_FILE despite the URL carrying no "
            f"password: {child.database_password_file!r}"
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

    def test_risk_records_partial_unique_index_exists(self, postgres_url):
        """`uq_risk_records_open_identity` is raw DDL with a WHERE clause
        (same pattern as `uq_finding_records_open_identity`, see
        TestOpenFindingPartialIndex in test_postgres_behaviour.py) — SQLite's
        DDL execution path can silently diverge from Postgres's, so this
        confirms the partial index actually exists with its WHERE clause
        intact on a real PostgreSQL server.
        """
        assert alembic(postgres_url, "upgrade", "head").returncode == 0
        engine = sa.create_engine(postgres_url)
        try:
            with engine.connect() as conn:
                indexdef = conn.execute(sa.text(
                    "SELECT indexdef FROM pg_indexes "
                    "WHERE indexname = 'uq_risk_records_open_identity'"
                )).scalar()
        finally:
            engine.dispose()
        assert indexdef is not None, "partial unique index was not created"
        assert "closed_at IS NULL" in indexdef, (
            f"index lost its WHERE clause, so it would block closed duplicates too: {indexdef}"
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
        for (table, col) in DOWNGRADE_EXPECTED_ONDELETE:
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
        """A returncode of 0 is not enough on its own: ensure_schema_sync()'s
        schema-already-exists branch used to leave its SELECT's autobegun
        transaction open, which context.configure() then treated as
        externally managed and never committed — so the migration DDL ran,
        Alembic exited 0, and the connection close at the end of
        run_migrations_online() silently rolled the whole thing back anyway.
        Confirmed live: this exact scenario (upgrade against a premade
        schema) left alembic_version missing afterwards before the fix,
        despite returncode == 0.
        """
        engine = sa.create_engine(postgres_url)
        try:
            with engine.begin() as conn:
                conn.execute(sa.text('CREATE SCHEMA "premade_cli_schema"'))
        finally:
            engine.dispose()

        r = alembic(postgres_url, "upgrade", "head", schema="premade_cli_schema")
        assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"

        engine = sa.create_engine(postgres_url)
        try:
            with engine.connect() as conn:
                version = conn.execute(sa.text(
                    'SELECT version_num FROM "premade_cli_schema".alembic_version'
                )).scalar()
        finally:
            engine.dispose()
        assert version == HEAD_REVISION, (
            f"alembic_version in premade_cli_schema was {version!r}, not "
            f"{HEAD_REVISION!r} — the migration reported success but was "
            "silently rolled back"
        )


class TestOfflineSqlSchemaPreamble:
    """`alembic upgrade --sql` with DATABASE_SCHEMA must emit a self-consistent
    script: unlike the online path, offline mode never opens a connection, so
    it can call neither ensure_schema_sync() nor rely on a connection-level
    search_path — without an explicit preamble the generated script created
    every table in whatever schema the executor's session defaulted to
    (public), while only the alembic_version CREATE TABLE was schema-qualified.

    Only generated up to BASE_REVISION: HEAD_REVISION reflects an existing
    table via `autoload_with=bind` (035924a7a885_user_fk_cascades.py), which
    needs a real connection to introspect and always fails against Alembic's
    offline MockConnection — a separate, pre-existing limitation of offline
    mode unrelated to schema/search_path handling.
    """

    def test_generated_sql_contains_schema_and_search_path_preamble(
        self, postgres_url
    ):
        r = alembic(
            postgres_url,
            "upgrade",
            f"base:{BASE_REVISION}",
            "--sql",
            schema="offline_preamble_schema",
        )
        assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
        assert "CREATE SCHEMA" in r.stdout
        assert 'SET search_path TO "offline_preamble_schema"' in r.stdout

        # The preamble must precede the schema-qualified alembic_version
        # table, or that CREATE TABLE fails outright against a fresh database.
        assert r.stdout.index("SET search_path") < r.stdout.index(
            "CREATE TABLE offline_preamble_schema.alembic_version"
        )

    def test_generated_sql_applied_lands_every_table_in_the_schema(
        self, postgres_url
    ):
        r = alembic(
            postgres_url,
            "upgrade",
            f"base:{BASE_REVISION}",
            "--sql",
            schema="offline_preamble_schema",
        )
        assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"

        engine = sa.create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        try:
            with engine.connect() as conn:
                conn.connection.cursor().execute(r.stdout)

                schema_exists = conn.execute(sa.text(
                    "SELECT 1 FROM information_schema.schemata "
                    "WHERE schema_name = 'offline_preamble_schema'"
                )).scalar()
                assert schema_exists == 1

                tables = set(conn.execute(sa.text(
                    "SELECT tablename FROM pg_tables WHERE schemaname = "
                    "'offline_preamble_schema'"
                )).scalars().all())
                assert {"alembic_version", "users", "hosts", "alerts"} <= tables

                public_tables = set(conn.execute(sa.text(
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
                )).scalars().all())
                assert not ({"users", "hosts", "alerts"} & public_tables)
        finally:
            engine.dispose()

    def test_generated_sql_has_no_preamble_without_a_configured_schema(
        self, postgres_url
    ):
        r = alembic(postgres_url, "upgrade", f"base:{BASE_REVISION}", "--sql")
        assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
        assert "CREATE SCHEMA" not in r.stdout
        assert "SET search_path" not in r.stdout
        assert "CREATE TABLE alembic_version" in r.stdout

    def test_schema_name_containing_dollar_dollar_is_handled_safely(
        self, postgres_url
    ):
        """A fixed `$$` dollar-quote tag around the preamble's DO block is
        unsafe: Postgres dollar-quoting has no escape mechanism and closes on
        the first literal occurrence of the tag, ignoring quoting context —
        so a schema name containing "$$" (a valid, if unusual, PostgreSQL
        identifier once double-quoted) truncates the DO block early and
        leaves a dangling SQL fragment. DATABASE_SCHEMA has no character
        restriction, so this must be handled, not merely avoided by
        convention.
        """
        schema = "a$$b"
        r = alembic(
            postgres_url, "upgrade", f"base:{BASE_REVISION}", "--sql", schema=schema
        )
        assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"

        engine = sa.create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        try:
            with engine.connect() as conn:
                conn.connection.cursor().execute(r.stdout)

                exists = conn.execute(sa.text(
                    "SELECT 1 FROM information_schema.schemata "
                    "WHERE schema_name = :schema"
                ), {"schema": schema}).scalar()
                assert exists == 1

                tables = set(conn.execute(sa.text(
                    "SELECT tablename FROM pg_tables WHERE schemaname = :schema"
                ), {"schema": schema}).scalars().all())
                assert "alembic_version" in tables
        finally:
            engine.dispose()


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
