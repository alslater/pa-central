"""PostgreSQL-specific runtime behaviour.

Complements test_postgres_migrations.py. These cover application behaviour that
either cannot run on SQLite at all, or that SQLite implements differently:

* the ``pg_try_advisory_lock`` branch in ``_run_migrations`` — Postgres-only
  code with no SQLite equivalent, guarding concurrent startup migrations
* the partial unique index on ``finding_records``, created via raw DDL and
  enforcing "one open finding per identity"
* ``UtcDateTime``, a TypeDecorator written for SQLite's lack of timezone
  support, which sits on top of a natively tz-aware type here

Skipped automatically when neither Docker nor PA_TEST_POSTGRES_URL is available.
"""
import asyncio
import os
import statistics
import time
from datetime import UTC, datetime, timedelta, timezone

import pytest
import sqlalchemy as sa
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.core.database import get_db
from app.core.security import create_access_token, hash_password, verify_password
from app.main import app
from app.models import (
    FindingRecord,
    Host,
    RepoScan,
    RepoScanResult,
    RepoScanStatus,
    Scan,
    User,
    UserRole,
)
from tests.conftest import auth
from tests.conftest_postgres import make_async_engine
from tests.test_postgres_migrations import HEAD_REVISION, alembic

# Ceiling for the concurrent-migration test. Measured at ~4s locally; generous
# enough for a slow CI runner, short enough to fail before a job-level timeout.
CONCURRENT_MIGRATION_TIMEOUT = 60


@pytest.fixture
def migrated_url(postgres_url: str) -> str:
    """A database at head revision."""
    r = alembic(postgres_url, "upgrade", "head")
    assert r.returncode == 0, f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"
    return postgres_url


# ── apply_postgres_settings TLS translation ──────────────────────────────────
# No postgres_url fixture here: these exercise pure URL-to-settings/env
# translation and must run even without Docker or PA_TEST_POSTGRES_URL.

class TestApplyPostgresSettingsHonorsTlsQueryOptions:
    """apply_postgres_settings() must translate an externally supplied
    PA_TEST_POSTGRES_URL's TLS query options into both the patched Settings
    and the subprocess environment, not hard-code sslmode="prefer" and drop
    the rest — the same query-discarding bug class alembic() had (see
    TestAlembicHelperEnvironmentIsSanitized in test_postgres_migrations.py).
    """

    def test_sslmode_query_option_is_honored(self, monkeypatch):
        from app.core.config import settings as app_settings
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(
            monkeypatch, "postgresql+psycopg2://u:p@host/db?sslmode=verify-full"
        )
        assert app_settings.database_sslmode == "verify-full"
        assert os.environ["DATABASE_SSLMODE"] == "verify-full"

    def test_tls_material_paths_reach_settings_and_environment(self, monkeypatch):
        from app.core.config import settings as app_settings
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(
            monkeypatch,
            "postgresql+psycopg2://u:p@host/db"
            "?sslmode=verify-full&sslrootcert=/ca.pem&sslcert=/cert.pem&sslkey=/key.pem",
        )
        assert app_settings.database_sslrootcert == "/ca.pem"
        assert app_settings.database_sslcert == "/cert.pem"
        assert app_settings.database_sslkey == "/key.pem"
        assert os.environ["DATABASE_SSLROOTCERT"] == "/ca.pem"
        assert os.environ["DATABASE_SSLCERT"] == "/cert.pem"
        assert os.environ["DATABASE_SSLKEY"] == "/key.pem"

    def test_stale_ambient_tls_env_vars_are_cleared_without_query_options(
        self, monkeypatch
    ):
        """A URL with no TLS query options must not leak a previous test's
        (or the developer's own .env) DATABASE_SSLROOTCERT/CERT/KEY."""
        from tests.conftest_postgres import apply_postgres_settings

        monkeypatch.setenv("DATABASE_SSLROOTCERT", "/stale/ca.pem")
        monkeypatch.setenv("DATABASE_SSLCERT", "/stale/cert.pem")
        monkeypatch.setenv("DATABASE_SSLKEY", "/stale/key.pem")

        apply_postgres_settings(monkeypatch, "postgresql+psycopg2://u:p@host/db")

        assert os.environ["DATABASE_SSLMODE"] == "prefer"
        for name in ("DATABASE_SSLROOTCERT", "DATABASE_SSLCERT", "DATABASE_SSLKEY"):
            assert name not in os.environ, f"{name} leaked a stale ambient value"

    def test_unsupported_query_option_is_rejected(self, monkeypatch):
        from tests.conftest_postgres import apply_postgres_settings

        with pytest.raises(ValueError, match="connect_timeout"):
            apply_postgres_settings(
                monkeypatch, "postgresql+psycopg2://u:p@host/db?connect_timeout=5"
            )


# ── Advisory lock ─────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestMigrationAdvisoryLock:
    """`_run_migrations` serialises concurrent startups via pg_advisory_lock.

    This branch only executes when DATABASE_TYPE is postgresql, so SQLite runs
    cannot reach it. Without the lock, two instances starting together both run
    `alembic upgrade head` against the same database.
    """

    async def test_lock_is_exclusive_while_held(self, migrated_url):
        """A second connection cannot take the same lock ID until it is released."""
        # Imported, not duplicated: a changed lock ID must not leave this test
        # silently probing an unrelated one and passing regardless.
        from app.main import MIGRATION_LOCK_ID as lock_id
        engine = make_async_engine(migrated_url)
        try:
            async with engine.connect() as first:
                got_first = (await first.execute(
                    sa.text("SELECT pg_try_advisory_lock(:id)"), {"id": lock_id}
                )).scalar()
                assert got_first is True

                # A separate session must be refused while the first holds it.
                async with engine.connect() as second:
                    got_second = (await second.execute(
                        sa.text("SELECT pg_try_advisory_lock(:id)"), {"id": lock_id}
                    )).scalar()
                    assert got_second is False, (
                        "advisory lock is not exclusive — concurrent startups "
                        "would both run migrations"
                    )

                await first.execute(
                    sa.text("SELECT pg_advisory_unlock(:id)"), {"id": lock_id}
                )

            # Released: a fresh session can now acquire it.
            async with engine.connect() as third:
                got_third = (await third.execute(
                    sa.text("SELECT pg_try_advisory_lock(:id)"), {"id": lock_id}
                )).scalar()
                assert got_third is True, "lock was not released"
                await third.execute(
                    sa.text("SELECT pg_advisory_unlock(:id)"), {"id": lock_id}
                )
        finally:
            await engine.dispose()

    async def test_gives_up_rather_than_waiting_forever(self, postgres_url, monkeypatch):
        """A lock held by someone else must fail startup, not hang it.

        `lifespan` awaits `_run_migrations` with no timeout of its own, so an
        unbounded wait would leave the container in startup indefinitely — no
        crash, no failed health check, nothing for an orchestrator to act on.
        """
        import app.core.database as app_db
        import app.main as app_main
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(monkeypatch, postgres_url)
        # Short ceiling so the test does not wait the production default.
        monkeypatch.setattr(app_main, "MIGRATION_LOCK_TIMEOUT", 2.0)

        holder = make_async_engine(postgres_url)
        test_engine = make_async_engine(postgres_url)
        monkeypatch.setattr(app_db, "engine", test_engine)
        try:
            # Take the lock on a separate session and never release it.
            async with holder.connect() as held:
                got = (await held.execute(
                    sa.text("SELECT pg_advisory_lock(:id)"),
                    {"id": app_main.MIGRATION_LOCK_ID},
                ))
                assert got is not None

                with pytest.raises(RuntimeError, match="could not acquire"):
                    await app_main._run_migrations()
        finally:
            await test_engine.dispose()
            await holder.dispose()

    async def test_concurrent_run_migrations_all_succeed(self, postgres_url, monkeypatch):
        """Three simultaneous _run_migrations() calls converge on head, once.

        The losers spin on pg_try_advisory_lock, then find the schema already
        migrated. Any crash here (duplicate table, duplicate alembic_version
        row) means the lock is not doing its job.
        """
        import app.main as app_main
        from tests.conftest_postgres import apply_postgres_settings

        # Two things need pointing at the test database:
        #  1. settings and the environment, for the is_postgres branch check
        #     and for _alembic_upgrade's subprocess, which shells out to
        #     `alembic` and reads the environment, not settings.
        apply_postgres_settings(monkeypatch, postgres_url)
        #  2. the module-level engine, imported inside _run_migrations
        import app.core.database as app_db
        test_engine = make_async_engine(postgres_url)
        monkeypatch.setattr(app_db, "engine", test_engine)

        # Bounded: _run_migrations spin-waits on pg_try_advisory_lock with no
        # exit condition other than acquiring it, so a regression that never
        # unlocks would hang here until CI kills the whole job. ~4s locally,
        # so 60s is ample headroom while still failing fast and saying why.
        try:
            results = await asyncio.wait_for(
                asyncio.gather(
                    app_main._run_migrations(),
                    app_main._run_migrations(),
                    app_main._run_migrations(),
                    return_exceptions=True,
                ),
                timeout=CONCURRENT_MIGRATION_TIMEOUT,
            )
        except TimeoutError:
            pytest.fail(
                f"concurrent _run_migrations() did not finish within "
                f"{CONCURRENT_MIGRATION_TIMEOUT}s — the advisory lock is "
                "likely never released, or the spin-wait never exits"
            )
        finally:
            await test_engine.dispose()

        failures = [r for r in results if isinstance(r, BaseException)]
        assert not failures, f"concurrent migrations raised: {failures}"

        # Exactly one alembic_version row, and it is at head. Checking the count
        # alone would pass if the migrations had silently no-opped and left the
        # database at its base revision — one row, wrong value.
        check = make_async_engine(postgres_url)
        try:
            async with check.connect() as conn:
                versions = (await conn.execute(
                    sa.text("SELECT version_num FROM alembic_version")
                )).scalars().all()
        finally:
            await check.dispose()
        assert versions == [HEAD_REVISION], (
            f"expected exactly one alembic_version row at {HEAD_REVISION!r}, "
            f"found {versions!r} — more than one row means the lock failed to "
            "serialise; a different value means migrations did not reach head"
        )

    async def test_lock_is_released_if_ensure_schema_raises(
        self, postgres_url, monkeypatch
    ):
        """`_ensure_schema` runs after the lock is acquired but must not be
        able to leak it.

        `_ensure_schema` sits between the lock-acquisition loop and the
        try/finally that unlocks — if it raises (its own documented
        insufficient-privilege path, for one), the exception used to escape
        `_run_migrations` without ever reaching `pg_advisory_unlock`.
        Returning the connection to the pool afterwards does not release a
        Postgres session-level advisory lock — only an explicit unlock or the
        physical session actually closing does — so a retry that reuses a
        pooled connection would block on its own orphaned session until
        MIGRATION_LOCK_TIMEOUT.
        """
        import app.core.database as app_db
        import app.main as app_main
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(monkeypatch, postgres_url)
        test_engine = make_async_engine(postgres_url)
        monkeypatch.setattr(app_db, "engine", test_engine)

        async def failing_ensure_schema(_conn):
            raise RuntimeError("simulated schema creation failure")

        monkeypatch.setattr(app_main, "_ensure_schema", failing_ensure_schema)

        probe = make_async_engine(postgres_url)
        try:
            with pytest.raises(RuntimeError, match="simulated schema creation failure"):
                await app_main._run_migrations()

            async with probe.connect() as conn:
                got = (await conn.execute(
                    sa.text("SELECT pg_try_advisory_lock(:id)"),
                    {"id": app_main.MIGRATION_LOCK_ID},
                )).scalar()
                if got:
                    await conn.execute(
                        sa.text("SELECT pg_advisory_unlock(:id)"),
                        {"id": app_main.MIGRATION_LOCK_ID},
                    )
            assert got, (
                "the advisory lock was not released after _ensure_schema "
                "raised — a retry would block on its own orphaned session "
                "until MIGRATION_LOCK_TIMEOUT"
            )
        finally:
            await test_engine.dispose()
            await probe.dispose()

    async def test_lock_is_released_after_a_real_ensure_schema_failure(
        self, postgres_url, monkeypatch
    ):
        """A genuine PostgreSQL error from `_ensure_schema` — not a mocked
        Python exception — leaves this connection's transaction aborted.
        Postgres then refuses any further command on that connection,
        including `pg_advisory_unlock`, until a rollback happens: without one,
        the unlock itself raises InFailedSqlTransaction, masking the real
        schema-creation error and leaving the session-level lock held on the
        pooled connection. `test_lock_is_released_if_ensure_schema_raises`
        mocks `_ensure_schema` with a plain RuntimeError, which never touches
        the connection's transaction state and so cannot catch this."""
        import app.core.database as app_db
        import app.main as app_main
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(monkeypatch, postgres_url)
        monkeypatch.setattr(app_main.settings, "database_schema", "denied_schema_lock")

        admin = sa.create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        try:
            with admin.connect() as conn:
                conn.execute(sa.text("DROP ROLE IF EXISTS lowpriv_lock_probe"))
                conn.execute(sa.text(
                    "CREATE ROLE lowpriv_lock_probe LOGIN PASSWORD 'x'"
                ))
            parsed = sa.engine.make_url(postgres_url)
            low = parsed.set(username="lowpriv_lock_probe", password="x")
            test_engine = make_async_engine(
                low.render_as_string(hide_password=False)
            )
            monkeypatch.setattr(app_db, "engine", test_engine)

            probe = make_async_engine(postgres_url)
            try:
                with pytest.raises(RuntimeError, match="denied_schema_lock"):
                    await app_main._run_migrations()

                async with probe.connect() as conn:
                    got = (await conn.execute(
                        sa.text("SELECT pg_try_advisory_lock(:id)"),
                        {"id": app_main.MIGRATION_LOCK_ID},
                    )).scalar()
                    if got:
                        await conn.execute(
                            sa.text("SELECT pg_advisory_unlock(:id)"),
                            {"id": app_main.MIGRATION_LOCK_ID},
                        )
                assert got, (
                    "the advisory lock was not released after a real "
                    "_ensure_schema failure aborted the connection's "
                    "transaction — the unlock query itself likely raised "
                    "InFailedSqlTransaction and was swallowed or masked"
                )
            finally:
                await test_engine.dispose()
                await probe.dispose()
        finally:
            with admin.connect() as conn:
                conn.execute(sa.text("DROP ROLE IF EXISTS lowpriv_lock_probe"))
            admin.dispose()

    @pytest.mark.parametrize("cancels", [1, 2, 3])
    async def test_cancelling_startup_holds_the_lock_until_alembic_finishes(
        self, postgres_url, monkeypatch, cancels
    ):
        """Cancellation must not release the lock while the thread still runs.

        `asyncio.to_thread` cannot interrupt a running thread: cancelling the
        await returns immediately while `subprocess.run("alembic upgrade")` keeps
        going. Unshielded, the unlock in the `finally` (and the closing of the
        session, which drops a session-scoped lock by itself) both happen while
        Alembic is still migrating — so a second replica acquires the lock and
        runs concurrently against the same schema.

        Parametrised over *repeated* cancellation because the drain is itself
        cancellable: a second cancel() lands on it, and CancelledError is a
        BaseException, so it escapes `suppress(Exception)` and reaches the
        `finally` with the migration still running. Shutdown paths retry
        cancellation readily — uvicorn re-cancels on a second signal — so one
        cancel is not the realistic worst case.
        """
        import threading

        import app.core.database as app_db
        import app.main as app_main
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(monkeypatch, postgres_url)
        test_engine = make_async_engine(postgres_url)
        monkeypatch.setattr(app_db, "engine", test_engine)

        started = threading.Event()
        release = threading.Event()
        finished = threading.Event()

        def fake_upgrade(_backend_dir):
            # Stands in for subprocess.run(alembic): blocking, uninterruptible,
            # and still running after the awaiting task is cancelled.
            started.set()
            release.wait(timeout=30)
            finished.set()

        monkeypatch.setattr(app_main, "_alembic_upgrade", fake_upgrade)

        probe = make_async_engine(postgres_url)
        try:
            task = asyncio.create_task(app_main._run_migrations())
            # Wait for the migration thread to be genuinely in flight.
            await asyncio.to_thread(started.wait, 10)
            assert started.is_set(), "migration thread never started"

            # Each cancel is separated by a tick so it lands *inside* the drain
            # rather than being coalesced into the first one.
            for _ in range(cancels):
                task.cancel()
                await asyncio.sleep(0.2)
            # Give the cancellation every chance to propagate and release.
            await asyncio.sleep(0.3)

            assert not finished.is_set(), "fake migration ended early"
            # An independent session must NOT be able to take the lock while the
            # migration thread is still running.
            async with probe.connect() as conn:
                got = (await conn.execute(
                    sa.text("SELECT pg_try_advisory_lock(:id)"),
                    {"id": app_main.MIGRATION_LOCK_ID},
                )).scalar()
                if got:
                    await conn.execute(
                        sa.text("SELECT pg_advisory_unlock(:id)"),
                        {"id": app_main.MIGRATION_LOCK_ID},
                    )
            assert not got, (
                "the advisory lock was released while the migration thread was "
                "still running — a second replica could now migrate concurrently"
            )

            # Let the migration finish; startup then settles as cancelled.
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=30)
            assert finished.is_set()

            # And once it has, the lock really is free again.
            async with probe.connect() as conn:
                freed = (await conn.execute(
                    sa.text("SELECT pg_try_advisory_lock(:id)"),
                    {"id": app_main.MIGRATION_LOCK_ID},
                )).scalar()
                if freed:
                    await conn.execute(
                        sa.text("SELECT pg_advisory_unlock(:id)"),
                        {"id": app_main.MIGRATION_LOCK_ID},
                    )
            assert freed, "lock was not released after the migration completed"
        finally:
            release.set()
            await test_engine.dispose()
            await probe.dispose()

    async def test_cancellation_during_cleanup_still_unlocks(
        self, postgres_url, monkeypatch
    ):
        """A cancellation landing on the finally block's own rollback/unlock
        awaits — after the migration has already finished and the drain loop
        has exited — must not skip the unlock and leak the session-level
        advisory lock on a connection that returns to the pool.

        The migration-in-flight case is already covered by
        test_cancelling_startup_holds_the_lock_until_alembic_finishes; this
        covers the narrower, later window the finally block's two awaits
        (rollback, then unlock) are themselves exposed to once that drain is
        done.
        """
        import app.core.database as app_db
        import app.main as app_main
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(monkeypatch, postgres_url)
        test_engine = make_async_engine(postgres_url)
        monkeypatch.setattr(app_db, "engine", test_engine)
        # Migration finishes immediately — nothing for the drain loop to wait on.
        monkeypatch.setattr(app_main, "_alembic_upgrade", lambda _backend_dir: None)

        entered_rollback = asyncio.Event()
        release_rollback = asyncio.Event()
        from sqlalchemy.ext.asyncio import AsyncConnection
        real_rollback = AsyncConnection.rollback

        async def blocking_rollback(self):
            entered_rollback.set()
            await release_rollback.wait()
            await real_rollback(self)

        monkeypatch.setattr(AsyncConnection, "rollback", blocking_rollback)

        probe = make_async_engine(postgres_url)
        try:
            task = asyncio.create_task(app_main._run_migrations())
            await asyncio.wait_for(entered_rollback.wait(), timeout=10)

            # Cancel while execution is inside the finally block's own
            # rollback() await — after the migration future is already done,
            # so the earlier drain loop has already exited. A single cancel
            # is absorbed by the shield-and-drain (identical semantics to the
            # migration drain above it: Task.cancel() only requests
            # cancellation once, and a future that completes before the next
            # cancellation point raises nothing), so _run_migrations returns
            # normally rather than propagating CancelledError — the point
            # under test is that the unlock still ran either way.
            task.cancel()
            await asyncio.sleep(0.2)
            release_rollback.set()

            await asyncio.wait_for(task, timeout=10)

            async with probe.connect() as conn:
                freed = (await conn.execute(
                    sa.text("SELECT pg_try_advisory_lock(:id)"),
                    {"id": app_main.MIGRATION_LOCK_ID},
                )).scalar()
                if freed:
                    await conn.execute(
                        sa.text("SELECT pg_advisory_unlock(:id)"),
                        {"id": app_main.MIGRATION_LOCK_ID},
                    )
            assert freed, (
                "a cancellation landing on the finally block's own cleanup "
                "awaits skipped pg_advisory_unlock, leaking the session-level "
                "lock on a connection returned to the pool"
            )
        finally:
            release_rollback.set()
            await test_engine.dispose()
            await probe.dispose()

    async def test_lock_is_released_if_cleanup_itself_fails(
        self, postgres_url, monkeypatch
    ):
        """If _finish_migration_lock() itself raises (rollback or the unlock
        query fails), the drain loop in the finally block must not silently
        swallow that as an unobserved task exception and let the connection
        return to the pool while still holding the session-level lock.

        The drain (`while not cleanup.done(): with suppress(BaseException):
        await asyncio.shield(cleanup)`) exits as soon as cleanup.done() is
        true, whether it finished by returning or by raising — this test
        forces the latter, standing in for a genuine unlock failure (e.g. the
        connection was already broken) rather than the cancellation this
        drain was originally built to survive."""
        import app.core.database as app_db
        import app.main as app_main
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(monkeypatch, postgres_url)
        test_engine = make_async_engine(postgres_url)
        monkeypatch.setattr(app_db, "engine", test_engine)
        monkeypatch.setattr(app_main, "_alembic_upgrade", lambda _backend_dir: None)

        async def failing_cleanup(_conn):
            raise RuntimeError("simulated unlock failure")

        monkeypatch.setattr(app_main, "_finish_migration_lock", failing_cleanup)

        probe = make_async_engine(postgres_url)
        try:
            with pytest.raises(RuntimeError, match="simulated unlock failure"):
                await app_main._run_migrations()

            async with probe.connect() as conn:
                freed = (await conn.execute(
                    sa.text("SELECT pg_try_advisory_lock(:id)"),
                    {"id": app_main.MIGRATION_LOCK_ID},
                )).scalar()
                if freed:
                    await conn.execute(
                        sa.text("SELECT pg_advisory_unlock(:id)"),
                        {"id": app_main.MIGRATION_LOCK_ID},
                    )
            assert freed, (
                "cleanup failing was silently swallowed by the drain loop — "
                "the connection returned to the pool still holding the "
                "session-level lock, so the next startup would time out "
                "waiting for it"
            )
        finally:
            await test_engine.dispose()
            await probe.dispose()


# ── Partial unique index ──────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestOpenFindingPartialIndex:
    """`uq_finding_records_open_identity` is raw DDL with a WHERE clause.

    It enforces one *open* finding per (repo_scan, advisory, package, ecosystem)
    while allowing any number of closed ones — the guard against duplicate rows
    from concurrent ingests.
    """

    @pytest.fixture
    async def session(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as s:
            # Naive UTC — see _insert_params below.
            now = datetime.now(UTC).replace(tzinfo=None)
            await s.execute(
                sa.text(
                    "INSERT INTO repo_scans "
                    "(id, name, url, branch, min_notify_severity, is_enabled, "
                    " created_at, updated_at) "
                    "VALUES (:id, :name, :url, :branch, :severity, :enabled, "
                    "        :created_at, :updated_at)"
                ),
                {
                    "id": 1, "name": "r", "url": "http://x", "branch": "main",
                    "severity": "high", "enabled": True,
                    "created_at": now, "updated_at": now,
                },
            )
            await s.commit()
            yield s
        await engine.dispose()

    # Every value is bound rather than interpolated. closed_at is passed as a
    # real datetime (or None) instead of switching between the SQL literals
    # `now()` and `NULL`, so the statement text is constant.
    _INSERT = sa.text(
        "INSERT INTO finding_records "
        "(id, repo_scan_id, advisory_id, package, ecosystem, severity, "
        " first_found_at, closed_at, reopen_count) "
        "VALUES (:row_id, :repo_scan_id, :advisory_id, :package, :ecosystem, "
        "        :severity, :first_found_at, :closed_at, :reopen_count)"
    )

    @classmethod
    def _insert_params(cls, *, closed: bool, row_id: int) -> dict:
        # Naive UTC: these columns are TIMESTAMP WITHOUT TIME ZONE (UtcDateTime
        # strips tzinfo on write). Binding through sa.text() bypasses that
        # decorator, so an aware datetime would be rejected by asyncpg.
        now = datetime.now(UTC).replace(tzinfo=None)
        return {
            "row_id": row_id,
            "repo_scan_id": 1,
            "advisory_id": "GHSA-1",
            "package": "pkg",
            "ecosystem": "pypi",
            "severity": "high",
            "first_found_at": now,
            "closed_at": now if closed else None,
            "reopen_count": 0,
        }

    async def test_index_exists_with_its_where_clause(self, session):
        indexdef = (await session.execute(sa.text(
            "SELECT indexdef FROM pg_indexes "
            "WHERE indexname = 'uq_finding_records_open_identity'"
        ))).scalar()
        assert indexdef is not None, "partial unique index was not created"
        assert "closed_at IS NULL" in indexdef, (
            f"index lost its WHERE clause, so it would block closed duplicates too: {indexdef}"
        )

    async def test_duplicate_open_finding_is_rejected(self, session):
        await session.execute(self._INSERT, self._insert_params(closed=False, row_id=1))
        await session.commit()

        with pytest.raises(sa.exc.IntegrityError):
            await session.execute(self._INSERT, self._insert_params(closed=False, row_id=2))
            await session.commit()
        await session.rollback()

    async def test_closed_duplicates_are_allowed(self, session):
        """Reopening history depends on closed rows sharing an identity."""
        await session.execute(self._INSERT, self._insert_params(closed=False, row_id=1))
        await session.execute(self._INSERT, self._insert_params(closed=True, row_id=2))
        await session.execute(self._INSERT, self._insert_params(closed=True, row_id=3))
        await session.commit()

        n = (await session.execute(
            sa.text("SELECT count(*) FROM finding_records")
        )).scalar()
        assert n == 3


class TestRepoScanHeadlineLatestResultRanking:
    """`list_repo_scan_headlines`'s per-scan latest-result lookup uses
    ``row_number().over(partition_by=..., order_by=...)`` to rank results in
    SQL rather than fetching every retained result and picking the first one
    in Python. row_number() is ANSI-standard and not expected to diverge
    between SQLite and PostgreSQL, but this is the first window-function
    query in the codebase, so it's verified directly here rather than
    assumed — enum status values must round-trip correctly through a
    subquery column on PostgreSQL's native enum handling.

    Exercises the real GET /repo-scans/headlines endpoint (not a
    hand-reconstructed copy of its SQL) so a regression to the handler's own
    partition/order/status selection is actually caught here, rather than
    leaving this test green regardless of what the handler does.
    """

    @pytest.fixture
    async def session(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as s:
            yield s
        await engine.dispose()

    @pytest.fixture
    async def client(self, session):
        async def override_db():
            yield session

        app.dependency_overrides[get_db] = override_db
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac
        app.dependency_overrides.pop(get_db, None)

    async def test_ranks_results_per_scan_and_picks_latest(self, session, client):
        admin = User(
            email="admin@x.com", display_name="Admin", role=UserRole.admin,
            hashed_password=hash_password("x"),
        )
        session.add(admin)
        await session.flush()
        token = create_access_token(admin.id, admin.token_epoch)

        scan_a = RepoScan(name="a", url="http://x/a", branch="main")
        scan_b = RepoScan(name="b", url="http://x/b", branch="main")
        session.add_all([scan_a, scan_b])
        await session.flush()
        session.add_all([
            RepoScanResult(repo_scan_id=scan_a.id, status=RepoScanStatus.failed,
                            started_at=datetime(2026, 1, 1, tzinfo=UTC).replace(tzinfo=None)),
            RepoScanResult(repo_scan_id=scan_a.id, status=RepoScanStatus.success,
                            started_at=datetime(2026, 1, 3, tzinfo=UTC).replace(tzinfo=None)),
            RepoScanResult(repo_scan_id=scan_a.id, status=RepoScanStatus.running,
                            started_at=datetime(2026, 1, 2, tzinfo=UTC).replace(tzinfo=None)),
            RepoScanResult(repo_scan_id=scan_b.id, status=RepoScanStatus.pending,
                            started_at=datetime(2026, 1, 1, tzinfo=UTC).replace(tzinfo=None)),
        ])
        await session.commit()

        r = await client.get("/api/repo-scans/headlines", headers=auth(token))
        assert r.status_code == 200
        by_name = {h["name"]: h for h in r.json()}

        assert by_name["a"]["latest_status"] == "success"
        assert by_name["a"]["latest_scanned_at"] == "2026-01-03T00:00:00Z"
        assert by_name["b"]["latest_status"] == "pending"

    async def test_tied_started_at_breaks_tie_by_result_id(self, session, client):
        """Two results for the same scan can share started_at (e.g.
        second-level precision, or a retried scan) — without id as a
        secondary ORDER BY key, row_number()'s tie-break is unspecified, so
        either row could get rank 1 and latest_status would be
        nondeterministic between requests. id desc must be the deciding
        factor, matching the same tie-break strategy used by
        GET /hosts/{id}/latest-scans."""
        admin = User(
            email="admin2@x.com", display_name="Admin2", role=UserRole.admin,
            hashed_password=hash_password("x"),
        )
        session.add(admin)
        await session.flush()
        token = create_access_token(admin.id, admin.token_epoch)

        scan = RepoScan(name="tied-scan", url="http://x/tied", branch="main")
        session.add(scan)
        await session.flush()
        tied = datetime(2026, 1, 5, tzinfo=UTC).replace(tzinfo=None)
        session.add(RepoScanResult(repo_scan_id=scan.id, status=RepoScanStatus.failed, started_at=tied))
        await session.commit()
        # Inserted after the first row, so it has a strictly greater id
        # while sharing the same started_at — this is the row that must win.
        session.add(RepoScanResult(repo_scan_id=scan.id, status=RepoScanStatus.success, started_at=tied))
        await session.commit()

        r = await client.get("/api/repo-scans/headlines", headers=auth(token))
        assert r.status_code == 200
        by_name = {h["name"]: h for h in r.json()}
        assert by_name["tied-scan"]["latest_status"] == "success"


class TestHostLatestScansRanking:
    """GET /hosts/{id}/latest-scans ranks per project_path in SQL, then
    re-fetches full Scan ORM rows by id from the ranked-to-rank-1 subset —
    a different shape from TestRepoScanHeadlineLatestResultRanking's ranked
    subquery above (that one selects plain columns to avoid ORM-entity
    round-tripping through a subquery; this one ranks only the id column,
    then does a second select(Scan).where(Scan.id.in_(...)) to get back real
    ORM objects for FastAPI's response_model=list[ScanOut] to serialize).

    Exercises the real GET /hosts/{id}/latest-scans endpoint (not a
    hand-reconstructed copy of its SQL) so a regression to the handler's own
    partition/order/tie-break columns is actually caught here, rather than
    leaving these tests green regardless of what the handler does.
    """

    @pytest.fixture
    async def session(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as s:
            yield s
        await engine.dispose()

    @pytest.fixture
    async def client(self, session):
        async def override_db():
            yield session

        app.dependency_overrides[get_db] = override_db
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac
        app.dependency_overrides.pop(get_db, None)

    async def test_ranks_by_project_and_refetches_full_rows(self, session, client):
        owner = User(
            email="owner@x.com", display_name="Owner", role=UserRole.admin,
            hashed_password=hash_password("x"),
        )
        session.add(owner)
        await session.flush()
        token = create_access_token(owner.id, owner.token_epoch)

        host = Host(name="h", hostname="h.local", owner_user_id=owner.id)
        session.add(host)
        await session.flush()
        session.add_all([
            Scan(host_id=host.id, project_path="proj-a",
                 scanned_at=datetime(2026, 1, 1, tzinfo=UTC), finding_count=3),
            Scan(host_id=host.id, project_path="proj-a",
                 scanned_at=datetime(2026, 1, 3, tzinfo=UTC), finding_count=0),
            Scan(host_id=host.id, project_path="proj-b",
                 scanned_at=datetime(2026, 1, 2, tzinfo=UTC), finding_count=1),
        ])
        await session.commit()

        r = await client.get(f"/api/hosts/{host.id}/latest-scans", headers=auth(token))
        assert r.status_code == 200
        scans = r.json()

        by_project = {s["project_path"]: s for s in scans}
        assert set(by_project) == {"proj-a", "proj-b"}
        assert by_project["proj-a"]["finding_count"] == 0  # the later proj-a scan, not the earlier one
        # proj-a's latest scan (Jan 3) is more recent than proj-b's (Jan 2).
        assert [s["project_path"] for s in scans] == ["proj-a", "proj-b"]

    async def test_tied_scanned_at_final_order_breaks_tie_by_received_at(self, session, client):
        """Different projects commonly share a scan timestamp (e.g. scans
        triggered together) — without received_at/id as secondary ORDER BY
        keys on the final row fetch, their relative order in the response is
        unspecified and can vary between requests, even though the ranking
        subquery itself already has the correct per-project tie-break.

        Note: dropping the secondary keys does not reliably fail this test —
        PostgreSQL's query planner happens to return this small, unindexed
        result set in insertion order regardless, so the "wrong" order isn't
        forced by any input this test can construct. That's the nature of
        the bug: SQL gives no ordering guarantee without an explicit ORDER
        BY on every tie-breaking column, so relying on incidental planner
        behaviour is exactly what this fix removes, even though a passing
        test can't distinguish "guaranteed correct" from "happened to be
        correct this time" for this specific case.
        """
        owner = User(
            email="owner3@x.com", display_name="Owner3", role=UserRole.admin,
            hashed_password=hash_password("x"),
        )
        session.add(owner)
        await session.flush()
        token = create_access_token(owner.id, owner.token_epoch)

        host = Host(name="h3", hostname="h3.local", owner_user_id=owner.id)
        session.add(host)
        await session.flush()
        tied = datetime(2026, 1, 5, tzinfo=UTC)
        session.add_all([
            Scan(host_id=host.id, project_path="proj-later-received", scanned_at=tied,
                 received_at=tied, finding_count=0),
            Scan(host_id=host.id, project_path="proj-earlier-received", scanned_at=tied,
                 received_at=tied - timedelta(minutes=5), finding_count=0),
        ])
        await session.commit()

        r = await client.get(f"/api/hosts/{host.id}/latest-scans", headers=auth(token))
        assert r.status_code == 200
        scans = r.json()

        # Both projects tie on scanned_at; received_at desc breaks it.
        assert [s["project_path"] for s in scans] == ["proj-later-received", "proj-earlier-received"]

    async def test_tied_scanned_at_breaks_tie_by_received_at(self, session, client):
        """Without a secondary ORDER BY, PostgreSQL's row_number() tie-break
        for equal scanned_at is unspecified — this pins received_at desc as
        the deciding factor, matching the previous client-side behaviour
        (iterate GET /scans' received_at-desc rows, keep the first match)."""
        owner = User(
            email="owner2@x.com", display_name="Owner2", role=UserRole.admin,
            hashed_password=hash_password("x"),
        )
        session.add(owner)
        await session.flush()
        token = create_access_token(owner.id, owner.token_epoch)

        host = Host(name="h2", hostname="h2.local", owner_user_id=owner.id)
        session.add(host)
        await session.flush()
        tied = datetime(2026, 1, 5, tzinfo=UTC)
        session.add_all([
            Scan(host_id=host.id, project_path="proj-retry", scanned_at=tied,
                 received_at=tied - timedelta(minutes=5), finding_count=3),
            Scan(host_id=host.id, project_path="proj-retry", scanned_at=tied,
                 received_at=tied, finding_count=0),
        ])
        await session.commit()

        r = await client.get(f"/api/hosts/{host.id}/latest-scans", headers=auth(token))
        assert r.status_code == 200
        scans = r.json()

        assert len(scans) == 1
        assert scans[0]["finding_count"] == 0  # the row with the greater received_at


# ── Test fixture URL conversion ───────────────────────────────────────────────

class TestFixtureUrlConversionTranslatesSslAliases:
    """conftest_postgres.py's driver-swap helpers must rename sslmode <-> ssl.

    Production code (app.core.db_config) never needs this — it builds each
    driver's connect_args directly from structured settings, with no query
    string to convert. But these two helpers also convert an *externally
    supplied* URL (PA_TEST_POSTGRES_URL, which README.md documents as accepting
    `?sslmode=require`), so a caller's query must survive the driver swap:
    left unrenamed, asyncpg.connect() raises `TypeError: unexpected keyword
    argument 'sslmode'` and psycopg2 raises `invalid connection option "ssl"`.

    Unit-level rather than a live connection: the previous version of this
    guard (deleted alongside db_url.py, since production's conversion no
    longer exists) opened a real socket, but the failure mode here is a
    string/query mismatch, not a driver behaviour worth a live server for.
    """

    def test_sslmode_becomes_ssl_for_asyncpg(self):
        from tests.conftest_postgres import as_async_url

        out = as_async_url(
            "postgresql+psycopg2://u@h:5432/db?sslmode=require"
        )
        query = sa.engine.make_url(out).query
        assert query.get("ssl") == "require"
        assert "sslmode" not in query

    def test_ssl_becomes_sslmode_for_psycopg2(self):
        from tests.conftest_postgres import _as_sync_url

        out = _as_sync_url(
            "postgresql+asyncpg://u@h:5432/db?ssl=verify-full"
        )
        query = sa.engine.make_url(out).query
        assert query.get("sslmode") == "verify-full"
        assert "ssl" not in query

    def test_unrecognized_query_params_are_rejected(self):
        """SQLAlchemy forwards unrecognized query keys straight to
        asyncpg.connect() as keyword arguments, but asyncpg's own connect()
        signature has no top-level `application_name` parameter at all — it
        belongs inside `server_settings`, a dict with no URL-query spelling
        this helper can produce. Passing it through unchanged (the previous
        behaviour this test enshrined) produced a URL that fails only once a
        real connection is attempted, with `TypeError: connect() got an
        unexpected keyword argument 'application_name'` — confirmed live
        against a real asyncpg connect() call. Reject at the point the async
        URL is built instead, the same way sslrootcert/sslcert/sslkey already
        are, rather than deferring to an unrelated TypeError deep in asyncpg."""
        from tests.conftest_postgres import as_async_url

        with pytest.raises(ValueError, match="application_name"):
            as_async_url(
                "postgresql+psycopg2://u@h:5432/db?application_name=x"
            )

    def test_no_query_string_is_unaffected(self):
        from tests.conftest_postgres import as_async_url

        out = as_async_url("postgresql+psycopg2://u@h:5432/db")
        assert sa.engine.make_url(out).query == {}

    def test_round_trip_preserves_the_setting(self):
        """sync -> async -> sync must land back on the original spelling."""
        from tests.conftest_postgres import _as_sync_url, as_async_url

        original = "postgresql+psycopg2://u@h:5432/db?sslmode=verify-ca"
        round_tripped = _as_sync_url(as_async_url(original))
        assert (
            sa.engine.make_url(round_tripped).query
            == sa.engine.make_url(original).query
        )

    def test_conflicting_alias_spellings_are_rejected(self):
        """?sslmode=require&ssl=disable has no correct answer, so refuse it.

        Renaming would silently overwrite one caller-supplied value with the
        other; there is no way to tell which one was meant.
        """
        from tests.conftest_postgres import as_async_url

        with pytest.raises(ValueError, match="conflicting query parameters"):
            as_async_url(
                "postgresql+psycopg2://u@h:5432/db?sslmode=require&ssl=disable"
            )

    def test_agreeing_alias_spellings_are_not_a_conflict(self):
        """Both spellings present with the SAME value is redundant, not wrong."""
        from tests.conftest_postgres import as_async_url

        out = as_async_url(
            "postgresql+psycopg2://u@h:5432/db?sslmode=require&ssl=require"
        )
        assert sa.engine.make_url(out).query.get("ssl") == "require"

    @pytest.mark.parametrize("option", ["sslrootcert", "sslcert", "sslkey"])
    def test_certificate_query_options_are_rejected(self, option):
        """asyncpg.connect() has no sslrootcert/sslcert/sslkey keyword argument
        at all — it takes TLS material only as a pre-built ssl.SSLContext, not
        file paths. Left unrenamed (like sslmode is), these would reach
        asyncpg.connect() as unrecognized kwargs and fail with an unrelated
        TypeError far from any indication of what went wrong; reject them here
        instead, at the point the caller asked for an async URL."""
        from tests.conftest_postgres import as_async_url

        with pytest.raises(ValueError, match=option):
            as_async_url(
                f"postgresql+psycopg2://u@h:5432/db?{option}=/tmp/x.pem"
            )


class TestAsyncEngineArgsCarryCertificateOptions:
    """async_engine_args() must carry a test URL's TLS query options to asyncpg
    as connect_args, where as_async_url() alone can only reject them.

    The postgres_url fixture propagates an external PA_TEST_POSTGRES_URL's
    query options (README.md documents the ``?sslmode=...&sslrootcert=...``
    form), but every integration test in this file builds its async engine
    straight from the URL — so the documented external-server path failed the
    moment certificate authentication was required, before a single connection
    was attempted. asyncpg takes TLS material only as a pre-built
    ssl.SSLContext, which a URL cannot express; this helper builds that context
    through the production path (Settings snapshot -> async_connect_args) and
    hands back a query-free asyncpg URL beside it.
    """

    @staticmethod
    def _self_signed_material(directory) -> tuple[str, str]:
        """One self-signed certificate, usable as both CA file and client chain.

        Generated with the already-present ``cryptography`` dependency rather
        than shelling out to openssl, so these unit tests run on machines
        without the binary (the TLS *integration* fixture still needs it)."""
        import datetime

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "pa-central-unit-test")]
        )
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        cert_pem = directory / "cert.pem"
        key_pem = directory / "key.pem"
        cert_pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_pem.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        return str(cert_pem), str(key_pem)

    def test_certificate_options_become_an_ssl_context(self, tmp_path):
        """The exact URL shape as_async_url() rejects must come back as a
        query-free asyncpg URL plus an SSLContext that actually loaded the CA."""
        import ssl

        from tests.conftest_postgres import async_engine_args

        cert, key = self._self_signed_material(tmp_path)
        a_url, connect_args = async_engine_args(
            "postgresql+psycopg2://u:p@h:5432/db"
            f"?sslmode=verify-full&sslrootcert={cert}&sslcert={cert}&sslkey={key}"
        )

        parsed = sa.engine.make_url(a_url)
        assert parsed.drivername == "postgresql+asyncpg"
        assert parsed.query == {}, (
            "TLS options must move into connect_args, not survive on the URL "
            "where asyncpg.connect() rejects them as unknown kwargs"
        )

        ctx = connect_args["ssl"]
        assert isinstance(ctx, ssl.SSLContext)
        assert ctx.check_hostname is True
        assert ctx.verify_mode == ssl.CERT_REQUIRED
        assert ctx.get_ca_certs(), (
            "the sslrootcert file was not loaded into the SSLContext — "
            "verification would run against an empty trust store"
        )

    def test_plain_url_defaults_to_prefer(self):
        """No query options must mean asyncpg's advisory-string 'prefer', not
        an SSLContext — passing a context at all forces mandatory TLS with no
        plaintext fallback (see TestPreferConnectsToAPlaintextServer)."""
        from tests.conftest_postgres import async_engine_args

        a_url, connect_args = async_engine_args("postgresql+psycopg2://u:p@h:5432/db")
        assert sa.engine.make_url(a_url).drivername == "postgresql+asyncpg"
        assert connect_args == {"ssl": "prefer"}

    def test_unsupported_query_option_is_rejected(self):
        """Same contract as apply_postgres_settings(): an option with no
        translation must raise, not be silently dropped into a connection with
        weaker/different settings than the caller asked for."""
        from tests.conftest_postgres import async_engine_args

        with pytest.raises(ValueError, match="connect_timeout"):
            async_engine_args(
                "postgresql+psycopg2://u:p@h:5432/db?connect_timeout=5"
            )


# ── UtcDateTime ───────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestUtcDateTimeOnPostgres:
    """UtcDateTime strips tzinfo on write and reattaches UTC on read.

    That exists because SQLite has no native timezone support. On Postgres the
    underlying column is timestamp-without-tz, so the same decorator must still
    round-trip correctly rather than double-converting.
    """

    @pytest.fixture
    async def session(self, migrated_url):
        # expire_on_commit=True (the default) is load-bearing here, not a
        # preference. With it disabled, the SELECT after commit is answered from
        # the session's identity map — it returns the very object that was
        # added, so `created_at` is still the datetime handed in and
        # UtcDateTime.process_result_value never runs. These tests exist to
        # exercise exactly that method, so they would assert against their own
        # input. See test_reads_come_from_the_database_not_the_identity_map.
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine)
        async with factory() as s:
            yield s
        await engine.dispose()

    async def test_aware_datetime_round_trips_as_utc(self, session):
        from app.core.security import hash_password
        from app.models import User, UserRole

        created = datetime(2026, 3, 1, 12, 30, tzinfo=UTC)
        session.add(User(
            email="tz@example.com", display_name="TZ",
            hashed_password=hash_password("password123456"),
            role=UserRole.viewer, created_at=created,
        ))
        await session.commit()

        loaded = (await session.execute(
            sa.select(User).where(User.email == "tz@example.com")
        )).scalar_one()

        assert loaded.created_at.tzinfo is not None, "read value lost its tzinfo"
        assert loaded.created_at == created

    async def test_reads_come_from_the_database_not_the_identity_map(self, session):
        """The round-trip tests must actually round-trip.

        A session with expire_on_commit=False answers the post-commit SELECT
        from its identity map: the query returns the same Python object that was
        added, still holding the datetime passed in, so
        UtcDateTime.process_result_value is never called. Both tests below would
        then be comparing their input against itself.

        The offset test is the one that hides this best. Its first assertion
        compares aware datetimes, and `17:30+05:00 == 12:30+00:00` is True —
        same instant — so it passes against the stale object. Only the
        utcoffset() assertion notices, which is why it is there.

        This test keeps `added` referenced for the whole body on purpose. The
        identity map holds objects *weakly*: the tests below add their User
        inline, so it is collectable once commit returns and the SELECT often
        reloads from Postgres by luck. Holding the reference makes the
        identity-map hit deterministic, so this fails reliably rather than
        depending on when the garbage collector runs.
        """
        from app.core.security import hash_password
        from app.models import User, UserRole

        written = datetime(2026, 3, 1, 17, 30, tzinfo=timezone(timedelta(hours=5)))
        added = User(
            email="identity@example.com", display_name="Identity",
            hashed_password=hash_password("password123456"),
            role=UserRole.viewer, created_at=written,
        )
        session.add(added)
        await session.commit()

        loaded = (await session.execute(
            sa.select(User).where(User.email == "identity@example.com")
        )).scalar_one()

        # The instance may well be the same one (the identity map is doing its
        # job); what matters is that its state came back from Postgres, which
        # only happens when commit expired it.
        assert loaded.created_at.utcoffset() == timedelta(0), (
            "created_at still carries its original +05:00 offset — the value "
            "was served from the identity map without a database read, so "
            "UtcDateTime.process_result_value never ran"
        )
        assert loaded.created_at.tzinfo is UTC
        # Referenced here so it cannot be collected earlier, which would let the
        # SELECT reload from Postgres and mask the very thing being tested.
        assert added.email == "identity@example.com"

    async def test_non_utc_offset_is_normalised_not_truncated(self, session):
        """A +05:00 timestamp must come back as the same instant in UTC."""
        from app.core.security import hash_password
        from app.models import User, UserRole

        # 17:30+05:00 is 12:30 UTC — the same instant, different wall clock.
        plus_5 = timezone(timedelta(hours=5))
        written = datetime(2026, 3, 1, 17, 30, tzinfo=plus_5)
        session.add(User(
            email="offset@example.com", display_name="Offset",
            hashed_password=hash_password("password123456"),
            role=UserRole.viewer, created_at=written,
        ))
        await session.commit()

        loaded = (await session.execute(
            sa.select(User).where(User.email == "offset@example.com")
        )).scalar_one()

        # Converted to UTC, not stored as the naive wall-clock 17:30 with the
        # offset silently discarded.
        assert loaded.created_at == datetime(2026, 3, 1, 12, 30, tzinfo=UTC)
        assert loaded.created_at.utcoffset() == timedelta(0)


# ── Schema support ────────────────────────────────────────────────────────────

@pytest.mark.asyncio
class TestSchemaSupport:
    """DATABASE_SCHEMA must create the schema when absent and fail clearly when
    it cannot — verified against a real server, since privilege behaviour is
    the whole point."""

    async def test_missing_schema_is_created(self, postgres_url, monkeypatch):
        import app.core.database as app_db
        import app.main as app_main
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(monkeypatch, postgres_url)
        monkeypatch.setattr(
            __import__("app.core.config", fromlist=["settings"]).settings,
            "database_schema", "made_up_schema",
        )
        engine = make_async_engine(postgres_url)
        monkeypatch.setattr(app_db, "engine", engine)
        try:
            async with engine.connect() as conn:
                await app_main._ensure_schema(conn)
                exists = (await conn.execute(sa.text(
                    "SELECT 1 FROM information_schema.schemata "
                    "WHERE schema_name = 'made_up_schema'"
                ))).scalar()
            assert exists == 1
        finally:
            await engine.dispose()

    async def test_existing_schema_needs_no_ddl(self, postgres_url, monkeypatch):
        """CREATE SCHEMA IF NOT EXISTS raises InsufficientPrivilege even when the
        schema exists, so an existing one must issue no DDL at all."""
        import app.core.database as app_db
        import app.main as app_main
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(monkeypatch, postgres_url)
        monkeypatch.setattr(
            __import__("app.core.config", fromlist=["settings"]).settings,
            "database_schema", "premade",
        )
        engine = make_async_engine(postgres_url)
        monkeypatch.setattr(app_db, "engine", engine)
        try:
            async with engine.begin() as conn:
                await conn.execute(sa.text('CREATE SCHEMA "premade"'))
            async with engine.connect() as conn:
                # Must not raise: the schema is already there.
                await app_main._ensure_schema(conn)
        finally:
            await engine.dispose()

    async def test_no_migrations_fallback_ensures_the_schema(
        self, postgres_url, monkeypatch
    ):
        """The init_db() fallback in _run_migrations (migrations directory
        absent) must ensure the configured schema before creating tables.
        Base.metadata is schema-qualified when DATABASE_SCHEMA is set, so
        create_all emits `CREATE TABLE <schema>.<table>` — against a fresh
        database this supported fallback otherwise dies with
        InvalidSchemaName. The migrated path already runs _ensure_schema
        under the advisory lock; the fallback path returns before ever
        reaching it."""
        import app.core.database as app_db
        import app.main as app_main
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(monkeypatch, postgres_url)
        monkeypatch.setattr(
            __import__("app.core.config", fromlist=["settings"]).settings,
            "database_schema", "fallback_schema",
        )
        # Force the no-migrations-directory fallback branch. Only the
        # migrations path is lied about; everything else sees the real
        # filesystem.
        real_isdir = os.path.isdir
        monkeypatch.setattr(
            app_main.os.path, "isdir",
            lambda p: (
                False if str(p).endswith("migrations") else real_isdir(p)
            ),
        )
        engine = make_async_engine(postgres_url)
        monkeypatch.setattr(app_db, "engine", engine)
        try:
            await app_main._run_migrations()
            async with engine.connect() as conn:
                exists = (await conn.execute(sa.text(
                    "SELECT 1 FROM information_schema.schemata "
                    "WHERE schema_name = 'fallback_schema'"
                ))).scalar()
            assert exists == 1, (
                "the no-migrations init_db() fallback never created the "
                "configured schema — with schema-qualified metadata, "
                "create_all fails with InvalidSchemaName"
            )
        finally:
            await engine.dispose()

    async def test_uncreatable_schema_fails_with_a_clear_error(
        self, postgres_url, monkeypatch
    ):
        import app.core.database as app_db
        import app.main as app_main
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(monkeypatch, postgres_url)
        admin = sa.create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        try:
            with admin.connect() as conn:
                conn.execute(sa.text("DROP ROLE IF EXISTS lowpriv_probe"))
                conn.execute(sa.text(
                    "CREATE ROLE lowpriv_probe LOGIN PASSWORD 'x'"
                ))
            parsed = sa.engine.make_url(postgres_url)
            low = parsed.set(username="lowpriv_probe", password="x")
            engine = make_async_engine(
                low.render_as_string(hide_password=False)
            )
            monkeypatch.setattr(
                __import__("app.core.config", fromlist=["settings"]).settings,
                "database_schema", "denied_schema",
            )
            monkeypatch.setattr(app_db, "engine", engine)
            try:
                async with engine.connect() as conn:
                    with pytest.raises(RuntimeError, match="denied_schema"):
                        await app_main._ensure_schema(conn)
            finally:
                await engine.dispose()
        finally:
            with admin.connect() as conn:
                conn.execute(sa.text("DROP ROLE IF EXISTS lowpriv_probe"))
            admin.dispose()


class TestEnsureSchemaSync:
    """ensure_schema_sync — the sync-driver twin of app.main._ensure_schema,
    used by migrations/env.py so a CLI-invoked `alembic upgrade head` creates
    a missing schema itself rather than assuming app startup already did.
    Mirrors TestSchemaSupport's async coverage of the same logic."""

    def test_missing_schema_is_created(self, postgres_url):
        from app.core.db_config import ensure_schema_sync

        engine = sa.create_engine(postgres_url)
        try:
            with engine.connect() as conn:
                ensure_schema_sync(conn, "sync_made_up_schema")
                exists = conn.execute(sa.text(
                    "SELECT 1 FROM information_schema.schemata "
                    "WHERE schema_name = 'sync_made_up_schema'"
                )).scalar()
            assert exists == 1
        finally:
            engine.dispose()

    def test_existing_schema_needs_no_ddl(self, postgres_url):
        """CREATE SCHEMA IF NOT EXISTS raises InsufficientPrivilege even when
        the schema exists, so an existing one must issue no DDL at all."""
        from app.core.db_config import ensure_schema_sync

        engine = sa.create_engine(postgres_url)
        try:
            with engine.begin() as conn:
                conn.execute(sa.text('CREATE SCHEMA "sync_premade"'))
            with engine.connect() as conn:
                # Must not raise: the schema is already there.
                ensure_schema_sync(conn, "sync_premade")
        finally:
            engine.dispose()

    def test_uncreatable_schema_fails_with_a_clear_error(self, postgres_url):
        from app.core.db_config import ensure_schema_sync

        admin = sa.create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        try:
            with admin.connect() as conn:
                conn.execute(sa.text("DROP ROLE IF EXISTS lowpriv_sync_probe"))
                conn.execute(sa.text(
                    "CREATE ROLE lowpriv_sync_probe LOGIN PASSWORD 'x'"
                ))
            parsed = sa.engine.make_url(postgres_url)
            low = parsed.set(username="lowpriv_sync_probe", password="x")
            engine = sa.create_engine(low.render_as_string(hide_password=False))
            try:
                with (
                    engine.connect() as conn,
                    pytest.raises(RuntimeError, match="denied_sync_schema"),
                ):
                    ensure_schema_sync(conn, "denied_sync_schema")
            finally:
                engine.dispose()
        finally:
            with admin.connect() as conn:
                conn.execute(sa.text("DROP ROLE IF EXISTS lowpriv_sync_probe"))
            admin.dispose()


class TestSchemaNameWithSpecialCharacters:
    """A schema name containing a comma or embedded quote must select that
    one schema literally — search_path's own grammar otherwise treats an
    unquoted comma as a list separator, silently searching two schemas (or
    failing outright) instead of the single one configured. Both drivers are
    exercised since psycopg2's `options` string and asyncpg's server_settings
    take the escaped value through two different paths."""

    async def test_async_driver_uses_the_literal_comma_schema(
        self, postgres_url, monkeypatch
    ):
        from app.core.config import settings as app_settings
        from app.core.db_config import async_connect_args
        from tests.conftest_postgres import apply_postgres_settings

        apply_postgres_settings(monkeypatch, postgres_url)
        schema_name = "a,b"
        monkeypatch.setattr(app_settings, "database_schema", schema_name)

        admin = sa.create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        quoted = admin.dialect.identifier_preparer.quote(schema_name)
        try:
            with admin.connect() as conn:
                conn.execute(sa.text(f"CREATE SCHEMA {quoted}"))

            engine = make_async_engine(
                postgres_url, connect_args=async_connect_args(app_settings)
            )
            try:
                async with engine.connect() as conn:
                    result = (
                        await conn.execute(sa.text("SHOW search_path"))
                    ).scalar()
                    assert result == '"a,b"'
            finally:
                await engine.dispose()
        finally:
            with admin.connect() as conn:
                conn.execute(sa.text(f"DROP SCHEMA IF EXISTS {quoted}"))
            admin.dispose()

    def test_sync_driver_uses_the_literal_comma_schema(
        self, postgres_url, monkeypatch
    ):
        from app.core.config import settings as app_settings
        from app.core.db_config import sync_connect_args
        from tests.conftest_postgres import _as_sync_url, apply_postgres_settings

        apply_postgres_settings(monkeypatch, postgres_url)
        schema_name = "a,b"
        monkeypatch.setattr(app_settings, "database_schema", schema_name)

        admin = sa.create_engine(postgres_url, isolation_level="AUTOCOMMIT")
        quoted = admin.dialect.identifier_preparer.quote(schema_name)
        try:
            with admin.connect() as conn:
                conn.execute(sa.text(f"CREATE SCHEMA {quoted}"))

            engine = sa.create_engine(
                _as_sync_url(postgres_url),
                connect_args=sync_connect_args(app_settings),
            )
            try:
                with engine.connect() as conn:
                    result = conn.execute(sa.text("SHOW search_path")).scalar()
                    assert result == '"a,b"'
            finally:
                engine.dispose()
        finally:
            with admin.connect() as conn:
                conn.execute(sa.text(f"DROP SCHEMA IF EXISTS {quoted}"))
            admin.dispose()


# ── TLS sslmode=prefer against a plain server ─────────────────────────────────

@pytest.mark.asyncio
class TestPreferConnectsToAPlaintextServer:
    """DATABASE_SSLMODE=prefer (the default) must not require TLS.

    asyncpg forces sslmode to verify-full internally whenever `ssl` is passed as
    an SSLContext object at all, regardless of how that context was configured
    — passing one for `prefer` makes TLS mandatory with no plaintext fallback,
    the opposite of what `prefer` means. Only asyncpg's *string* sslmode values
    get its ssl_is_advisory retry path. This is the actual regression case: the
    project's own `docker compose --profile pg` server has no TLS listener at
    all, so `prefer` is the mode that must work against it by default.

    Exercised against `postgres_url` (the plain, non-TLS fixture used
    throughout this file) rather than the TLS-only `postgres_tls` fixture in
    test_postgres_tls.py — that fixture cannot reproduce this, since a
    TLS-enabled server never triggers the "rejected SSL upgrade" failure mode.
    """

    async def test_prefer_connects_when_the_server_has_no_tls(self, postgres_url):
        from app.core.config import Settings
        from app.core.db_config import async_connect_args

        parsed = sa.engine.make_url(postgres_url)
        cfg = Settings(
            _env_file=None, debug=True,
            database_type="postgresql",
            database_host=parsed.host,
            database_port=parsed.port,
            database_name=parsed.database,
            database_user=parsed.username,
            database_password=parsed.password,
            database_sslmode="prefer",
        )
        engine = make_async_engine(
            postgres_url, connect_args=async_connect_args(cfg)
        )
        try:
            async with engine.connect() as conn:
                assert (await conn.execute(sa.text("SELECT 1"))).scalar() == 1
        finally:
            await engine.dispose()


class TestAcceptRevokeRowLocking:
    """accept_finding/revoke_accept (and the risks equivalents) use
    ``db.get(..., with_for_update=True)`` to serialise concurrent accept/
    revoke requests on the same record.

    Without it, two overlapping requests can both read the row before
    either commits, then commit their live-column writes in whichever order
    the database happens to schedule them — independent of the order their
    FindingAcceptanceEvent rows' `at` timestamps say the actions happened
    in. is_accepted_as_of replays by `at`, so the live columns and the
    event-derived history could permanently disagree about current state.
    A second, distinct failure mode: two concurrent revokes can each read
    accepted_at as non-NULL and both append their own "revoked" event.

    SQLite ignores FOR UPDATE entirely (confirmed by reading its rows with
    no error, but no actual blocking), so this can only be verified against
    real PostgreSQL.
    """

    @pytest.fixture
    async def session_factory(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        yield factory
        await engine.dispose()

    @pytest.fixture
    async def finding_id(self, session_factory):
        async with session_factory() as s:
            scan = RepoScan(name="lock-test", url="http://x/lock", branch="main")
            s.add(scan)
            await s.flush()
            record = FindingRecord(
                repo_scan_id=scan.id, advisory_id="GHSA-lock", package="pkg",
                ecosystem="pypi", severity="high", first_found_at=datetime(2026, 1, 1, tzinfo=UTC),
            )
            s.add(record)
            await s.commit()
            return record.id

    async def test_select_for_update_blocks_a_second_session(self, session_factory, finding_id):
        """The mechanism the fix relies on: a row locked FOR UPDATE by one
        transaction is not readable-for-update by a second, concurrent one
        until the first commits or rolls back."""
        async with session_factory() as first:
            await first.execute(
                sa.text("SELECT id FROM finding_records WHERE id = :id FOR UPDATE"),
                {"id": finding_id},
            )
            # first now holds the row lock, uncommitted.

            async with session_factory() as second:
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(
                        second.execute(
                            sa.text("SELECT id FROM finding_records WHERE id = :id FOR UPDATE"),
                            {"id": finding_id},
                        ),
                        timeout=2.0,
                    )
                await second.rollback()

            await first.commit()

            # Released: a fresh session can now acquire it without blocking.
            async with session_factory() as third:
                row = await asyncio.wait_for(
                    third.execute(
                        sa.text("SELECT id FROM finding_records WHERE id = :id FOR UPDATE"),
                        {"id": finding_id},
                    ),
                    timeout=2.0,
                )
                assert row.scalar() == finding_id
                await third.commit()

    async def test_db_get_with_for_update_blocks_a_second_session(self, session_factory, finding_id):
        """Same guarantee, exercised through the exact ORM call the fix
        actually uses (db.get(..., with_for_update=True)) rather than raw
        SQL, so a change to how that option is passed would be caught here
        too."""
        async with session_factory() as first:
            await first.get(FindingRecord, finding_id, with_for_update=True)

            async with session_factory() as second:
                with pytest.raises(asyncio.TimeoutError):
                    await asyncio.wait_for(
                        second.get(FindingRecord, finding_id, with_for_update=True),
                        timeout=2.0,
                    )
                await second.rollback()

            await first.commit()


@pytest.mark.asyncio
class TestPasswordResetTokenSingleUseUnderConcurrency:
    """A reset token must be consumable exactly once, even by two requests
    that overlap.

    If the claim were a SELECT followed by a separate `used_at` write, two
    concurrent requests would both read `used_at IS NULL`, both pass the
    check, and both commit a password change. The second wins the final
    write, so an attacker holding a leaked-but-unused link can silently
    overwrite the password the legitimate user just set — the single-use
    guarantee the token exists to provide.

    The claim is a single conditional UPDATE, so PostgreSQL serialises the
    two writers itself: the second blocks on the first's uncommitted row and
    then matches nothing. These tests exercise that interleaving against a
    real server; the SQLite-side guarantee has its own coverage in
    test_password_reset.py, because the two backends reach it differently
    and an earlier FOR UPDATE version was correct here while leaving SQLite
    — this project's default database — racing.
    """

    @pytest.fixture
    async def session_factory(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        yield factory
        await engine.dispose()

    @pytest.fixture
    async def token_hash(self, session_factory):
        from app.models import PasswordResetToken

        async with session_factory() as s:
            user = User(
                email="race@example.com", display_name="Race",
                hashed_password=hash_password("originalpassword"),
                role=UserRole.viewer, is_active=True,
            )
            s.add(user)
            await s.flush()
            s.add(PasswordResetToken(
                token_hash="9" * 64, user_id=user.id,
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(minutes=60),
            ))
            await s.commit()
            return "9" * 64

    async def test_only_one_of_two_concurrent_consumers_succeeds(
        self, session_factory, token_hash
    ):
        """Two overlapping resets, each in its own transaction, must not both
        succeed. The loser must see the token as already consumed."""
        from app.models import PasswordResetToken
        from app.services.password_reset import consume_reset_token

        async def attempt(new_password: str) -> bool:
            async with session_factory() as s:
                consumed = await consume_reset_token(s, token_hash)
                if not consumed:
                    await s.rollback()
                    return False
                row, user = consumed
                user.hashed_password = hash_password(new_password)
                row.used_at = datetime.now(UTC)
                await s.commit()
                return True

        # Serialised deliberately: even with no overlap in wall-clock time,
        # an unlocked implementation lets the second attempt succeed only if
        # it fails to observe the first's committed used_at. Running them
        # back-to-back isolates the read-check itself from lock timing.
        first = await attempt("first-new-password")
        second = await attempt("second-new-password")
        assert first is True
        assert second is False, "a consumed token was accepted a second time"

        async with session_factory() as s:
            rows = (await s.execute(
                sa.select(PasswordResetToken).where(
                    PasswordResetToken.token_hash == token_hash
                )
            )).scalars().all()
            assert len(rows) == 1
            assert rows[0].used_at is not None

    async def test_two_open_transactions_cannot_both_consume_it(
        self, session_factory, token_hash
    ):
        """The real race: two independent sessions both read the token before
        either commits, then both write.

        With no lock, both reads see used_at IS NULL, both commit, and the
        second password change silently overwrites the first — so a leaked
        link stays usable after the legitimate user has already reset. The
        locking read must make the second session block until the first
        commits, and then observe the token as consumed.
        """
        from app.models import PasswordResetToken
        from app.services.password_reset import consume_reset_token

        a = session_factory()
        b = session_factory()
        try:
            consumed_a = await consume_reset_token(a, token_hash)
            assert consumed_a is not None

            # b must not be able to take the row while a holds it. Its own
            # read is expected to block on a's lock rather than return.
            task_b = asyncio.create_task(consume_reset_token(b, token_hash))
            await asyncio.sleep(0.2)
            assert not task_b.done(), (
                "the second session read the token while the first still held "
                "it uncommitted — the read is not locking"
            )

            row_a, user_a = consumed_a
            user_a.hashed_password = hash_password("aaaa-new-password")
            row_a.used_at = datetime.now(UTC)
            await a.commit()

            consumed_b = await asyncio.wait_for(task_b, timeout=5.0)
            assert consumed_b is None, (
                "the token was consumed twice — a leaked link would still work "
                "after a completed reset"
            )
            await b.rollback()
        finally:
            await a.close()
            await b.close()

        async with session_factory() as s:
            row = (await s.execute(
                sa.select(PasswordResetToken).where(
                    PasswordResetToken.token_hash == token_hash
                )
            )).scalar_one()
            assert row.used_at is not None


class TestConsumeResetTokenExpiryCutoffOnPostgres:
    """consume_reset_token used to capture its expiry cutoff (`now`) before
    locking the account, then compare a token's expires_at against that
    stale value inside the claim. Acquiring the account's row lock can
    genuinely block here — behind another session holding the same lock —
    so a token due to expire during that wait would be compared against a
    timestamp from before the wait and wrongly accepted, despite having
    actually expired by the time the claim executes. Fixed by reading
    `now` after the lock, immediately before the claim.

    PostgreSQL specifically: the account lock is a genuine row lock here
    (unlike SQLite's whole-file BEGIN IMMEDIATE), so this proves the fix
    against the real blocking mechanism production uses, not a stand-in.
    The SQLite-side proof lives in test_password_reset.py's
    TestTokenClaimIsAtomicOnSqlite.test_the_expiry_cutoff_is_read_after_the_lock_is_acquired.
    """

    @pytest.fixture
    async def session_factory(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        yield factory
        await engine.dispose()

    async def test_a_token_expiring_during_the_lock_wait_is_not_claimed(
        self, session_factory
    ):
        from app.models import PasswordResetToken
        from app.services.password_reset import consume_reset_token

        async with session_factory() as s:
            user = User(
                email="pg-expiry-lock@example.com", display_name="PG Expiry Lock",
                hashed_password=hash_password("originalpassword"),
                role=UserRole.viewer, is_active=True,
            )
            s.add(user)
            await s.flush()
            expires_at = datetime.now(UTC) + timedelta(seconds=1)
            s.add(PasswordResetToken(
                token_hash="7" * 64, user_id=user.id,
                created_at=datetime.now(UTC), expires_at=expires_at,
            ))
            await s.commit()

        holder = session_factory()
        checker = session_factory()
        try:
            await holder.execute(
                sa.update(User).where(User.email == "pg-expiry-lock@example.com")
                .values(is_active=User.is_active)
            )
            # holder now holds the row lock, uncommitted.

            check_task = asyncio.create_task(
                consume_reset_token(checker, "7" * 64)
            )
            await asyncio.sleep(0.3)
            assert not check_task.done(), (
                "the claim completed before the lock was even released — "
                "it is not actually waiting on the held lock, so this "
                "test cannot prove anything about the fix"
            )
            assert datetime.now(UTC) < expires_at, (
                "the token already expired before the lock was even "
                "held — widen the margin above"
            )

            # Release only once the token has genuinely expired.
            await asyncio.sleep(0.9)
            assert datetime.now(UTC) > expires_at, (
                "the token has not actually expired yet — widen the "
                "margin above"
            )
            await holder.commit()

            result = await asyncio.wait_for(check_task, timeout=5.0)
            assert result is None, (
                "an expired token was claimed successfully on PostgreSQL "
                "— the expiry cutoff was read before the lock wait "
                "rather than after it"
            )
            await checker.rollback()
        finally:
            await holder.close()
            await checker.close()


class TestPatchSettingsTransitionDetectionOnPostgres:
    """patch_settings' was_reset_on/had_smtp_host used to be read before
    the settings-row lock was ever acquired, with the lock only taken
    later, gated on turning_off/losing_smtp — themselves computed from
    that unlocked read. A concurrent request that commits an enable and
    issues a token in the gap between this request's unlocked read and
    its own later write is invisible to it: a genuine on-to-off
    transition (the stored value really did flip true, briefly, then
    this request's own write brings it back to false) computed
    turning_off=False from the stale pre-lock snapshot and skipped the
    sweep, leaving the concurrently-issued token live. Fixed by
    acquiring the settings-row lock unconditionally at the very top of
    patch_settings, before was_reset_on/had_smtp_host are read at all.

    PostgreSQL specifically: the settings-row lock is a genuine row lock
    here (unlike SQLite's whole-file BEGIN IMMEDIATE), so this proves the
    fix against the real blocking mechanism production uses. The SQLite-
    side proof lives in test_password_reset.py's
    TestDisablingRevokesOutstandingLinks.test_was_reset_on_is_read_under_the_lock_not_before_it.
    """

    @pytest.fixture
    async def session_factory(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        yield factory
        await engine.dispose()

    async def test_a_transition_committed_during_the_lock_wait_is_still_revoked(
        self, session_factory
    ):
        from app.api.system_settings import patch_settings
        from app.models import PasswordResetToken, SettingValueType, SystemSetting
        from app.schemas import SystemSettingPatch

        async with session_factory() as s:
            admin = User(
                email="pg-stale-snapshot-admin@example.com", display_name="Admin",
                hashed_password=hash_password("password123456"),
                role=UserRole.admin, is_active=True,
            )
            target = User(
                email="pg-stale-snapshot@example.com", display_name="Target",
                hashed_password=hash_password("password123456"),
                role=UserRole.viewer, is_active=True,
            )
            s.add(admin)
            s.add(target)
            s.add(SystemSetting(
                key="self_service_password_reset", value="false",
                value_type=SettingValueType.bool,
            ))
            await s.commit()
            admin_id, target_id = admin.id, target.id

        holder = session_factory()
        patcher = session_factory()
        try:
            await holder.execute(
                sa.update(SystemSetting)
                .where(SystemSetting.key == "self_service_password_reset")
                .values(value_type=SystemSetting.value_type)
            )
            # holder now holds the settings-row lock, uncommitted.

            async def run_patch_settings():
                admin = await patcher.get(User, admin_id)
                body = SystemSettingPatch(updates={"self_service_password_reset": "false"})
                return await patch_settings(body, patcher, admin)

            patch_task = asyncio.create_task(run_patch_settings())
            await asyncio.sleep(0.3)
            assert not patch_task.done(), (
                "patch_settings completed before the lock was even "
                "released — it is not actually waiting on the held lock, "
                "so this test cannot prove anything about the fix"
            )

            # While still holding the lock: enable the feature and issue
            # a token, exactly what a concurrent request represents.
            await holder.execute(
                sa.update(SystemSetting)
                .where(SystemSetting.key == "self_service_password_reset")
                .values(value="true")
            )
            holder.add(PasswordResetToken(
                token_hash="c" * 64, user_id=target_id,
                created_at=datetime.now(UTC),
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            ))
            await holder.commit()

            await asyncio.wait_for(patch_task, timeout=5.0)

            async with session_factory() as s:
                row = (await s.execute(
                    sa.select(PasswordResetToken).where(
                        PasswordResetToken.token_hash == "c" * 64
                    )
                )).scalar_one()
            assert row.used_at is not None, (
                "the token committed by a concurrent request while "
                "patch_settings was blocked on the lock was not revoked "
                "on PostgreSQL — patch_settings read stale pre-lock "
                "state (the flag still 'false') instead of waiting for "
                "the lock to actually clear the concurrent 'true'"
            )
        finally:
            await holder.close()
            await patcher.close()

    async def test_many_concurrent_first_patches_against_an_absent_row_do_not_conflict(
        self, session_factory
    ):
        """The settings-row lock's own self-assigning UPDATE only
        locks/serializes anything when a matching row already exists —
        on a fresh or freshly-migrated database, self_service_password_reset
        has no row at all until an admin's first PATCH creates one
        (nothing seeds it: _list_settings_with_defaults's synthesis is
        read-time only and never writes a row). Two concurrent *first*
        PATCHes then both see no row to lock, both fall through to the
        per-key update loop, and both attempt to INSERT the same primary
        key. Reproduced directly against a real PostgreSQL server with a
        deterministically forced interleaving (a standalone script, not
        this test): one request succeeded and the other raised
        `UniqueViolationError: duplicate key value violates unique
        constraint "system_settings_pkey"`. Fixed by an
        INSERT ... ON CONFLICT (key) DO NOTHING immediately before the
        lock's own UPDATE, guaranteeing a row exists — created by
        whichever request gets there first, silently absorbed by
        whichever loses that race — before the lock ever runs.

        This test is deliberately probabilistic, not deterministic, unlike
        the other lock tests in this file — and, honestly, has not been
        made to reproduce the historical bug at all in this harness: the
        buggy lock statement itself is a no-op when the row is absent (an
        UPDATE matching zero rows takes no lock on PostgreSQL), so unlike
        every other lock test here there is nothing to hold or block on
        to pin the race open from outside patch_settings. Neither a bare
        two-call asyncio.gather nor 20, nor 60, concurrent calls against
        the reverted code reproduced the IntegrityError in this
        environment, even with measured, confirmed wall-clock overlap
        across all of them — apparently each request's full round trip
        (read, validate, insert, commit) resolves fast enough end-to-end
        that the specific multi-millisecond window the bug needs rarely
        or never lines up under plain asyncio.gather, unlike the
        standalone reproduction script that forced it directly by
        monkeypatching `AsyncSession.get` to make one coroutine pause
        mid-transaction. That direct reproduction (not this test) is the
        actual verification the fix is correct — see the dated entry in
        project_self_service_password_reset memory for the full trace,
        including the confirmed `UniqueViolationError` before the fix and
        its absence after. This test is kept anyway as a real-code-path
        smoke test under load (it does prove concurrent first-time
        PATCHes succeed together against the *fixed* code, which is worth
        having), not as a regression guard for the specific race — a
        genuinely reliable automated reproduction was not found despite
        significant effort, and shipping one that only sometimes catches
        the bug would be worse than being explicit about that limit here.
        """
        from app.api.system_settings import patch_settings
        from app.models import SystemSetting
        from app.schemas import SystemSettingPatch

        concurrency = 20
        admin_ids = []
        async with session_factory() as s:
            for i in range(concurrency):
                admin = User(
                    email=f"pg-absent-row-{i}@example.com", display_name=f"Admin {i}",
                    hashed_password=hash_password("password123456"),
                    role=UserRole.admin, is_active=True,
                )
                s.add(admin)
                admin_ids.append(admin)
            await s.commit()
            admin_ids = [a.id for a in admin_ids]
        # No system_settings row exists at all yet — the normal state for
        # a fresh/migrated database this test deliberately starts from.

        async def run_patch(admin_id: int):
            async with session_factory() as s:
                admin = await s.get(User, admin_id)
                body = SystemSettingPatch(updates={"self_service_password_reset": "false"})
                return await patch_settings(body, s, admin)

        results = await asyncio.gather(*(run_patch(aid) for aid in admin_ids))

        assert len(results) == concurrency, (
            f"all {concurrency} concurrent first-time PATCHes against an "
            "absent row must succeed cleanly — at least one raised instead "
            "of the insert-then-lock sequence absorbing the race"
        )

        async with session_factory() as s:
            row = await s.get(SystemSetting, "self_service_password_reset")
        assert row is not None and row.value == "false"


@pytest.mark.asyncio
class TestConcurrentIssuanceIsSerializedOnPostgres:
    """Issuing a reset link counts recent tokens, retires the outstanding one
    and inserts a replacement — three statements that must not interleave.

    Unserialized, overlapping requests all read the same pre-write count, all
    pass the cap and all insert. Measured here before the fix: six concurrent
    requests produced six links against a cap of five, and left five valid at
    once where the invariant is one.

    The SQLite side has its own coverage in test_password_reset.py. Both are
    needed: the lock is an inert UPDATE precisely because a locking read is a
    no-op on SQLite, and this test would pass against a FOR UPDATE version
    that leaves the default database racing.
    """

    @pytest.fixture
    async def session_factory(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        yield factory
        await engine.dispose()

    async def test_a_burst_cannot_exceed_the_cap(self, session_factory):
        from app.models import PasswordResetToken, SettingValueType, SystemSetting
        from app.services.password_reset import (
            RESET_REQUESTS_PER_HOUR,
            prepare_reset_email,
        )

        async with session_factory() as s:
            user = User(
                email="burst-pg@example.com", display_name="Burst",
                hashed_password=hash_password("password123456"),
                role=UserRole.viewer, is_active=True,
            )
            s.add(user)
            # prepare_reset_email's settings-row re-check now refuses unless
            # stored rows agree with settings_map below — a genuinely
            # absent/differing row is no longer treated as "don't refuse"
            # (see TestDisableRacesIssuanceOnPostgres's null-clear and
            # base-url-change tests).
            s.add(SystemSetting(
                key="self_service_password_reset", value="true",
                value_type=SettingValueType.bool, updated_at=datetime.now(UTC),
            ))
            s.add(SystemSetting(
                key="app_base_url", value="https://pa.example.com",
                value_type=SettingValueType.string, updated_at=datetime.now(UTC),
            ))
            await s.commit()
            user_id = user.id

        settings_map = {
            "smtp_host": "smtp.example.com",
            "smtp_from": "pa-central@example.com",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        }

        async def attempt():
            async with session_factory() as s:
                u = await s.get(User, user_id)
                return await prepare_reset_email(s, u, settings_map)

        results = await asyncio.gather(
            *[attempt() for _ in range(RESET_REQUESTS_PER_HOUR + 1)],
            return_exceptions=True,
        )
        issued = sum(
            1 for r in results
            if not isinstance(r, BaseException) and r is not None
        )
        assert issued <= RESET_REQUESTS_PER_HOUR, (
            f"{issued} links issued against a cap of {RESET_REQUESTS_PER_HOUR}"
        )
        # A concurrent burst is bounded by the *cooldown* — only the first
        # request finds no outstanding link — so this alone says nothing about
        # the hourly cap. Stated explicitly so the assertion above is not
        # mistaken for cap coverage; the cap has its own test below.
        assert issued == 1, (
            f"{issued} links issued from one burst — the cooldown should have "
            "suppressed all but the first"
        )

        async with session_factory() as s:
            live = (await s.execute(
                sa.select(PasswordResetToken)
                .where(PasswordResetToken.used_at.is_(None))
            )).scalars().all()
        assert len(live) == 1, f"{len(live)} links valid at once"

    async def test_the_hourly_cap_bounds_issuance_across_bursts(
        self, session_factory
    ):
        """The cap, as distinct from the cooldown.

        Each burst is preceded by ageing the ledger past the cooldown, so
        every one of them reaches the cap check rather than being suppressed.
        Without this the cap is never consulted — removing it entirely left
        the burst test above green.
        """
        from app.models import PasswordResetToken, SettingValueType, SystemSetting
        from app.services.password_reset import (
            RESET_REQUEST_COOLDOWN_SECONDS,
            RESET_REQUESTS_PER_HOUR,
            prepare_reset_email,
        )

        async with session_factory() as s:
            user = User(
                email="cap-across-bursts@example.com", display_name="Cap",
                hashed_password=hash_password("password123456"),
                role=UserRole.viewer, is_active=True,
            )
            s.add(user)
            # See test_a_burst_cannot_exceed_the_cap above:
            # prepare_reset_email's settings-row re-check now refuses unless
            # stored rows agree with settings_map below.
            s.add(SystemSetting(
                key="self_service_password_reset", value="true",
                value_type=SettingValueType.bool, updated_at=datetime.now(UTC),
            ))
            s.add(SystemSetting(
                key="app_base_url", value="https://pa.example.com",
                value_type=SettingValueType.string, updated_at=datetime.now(UTC),
            ))
            await s.commit()
            user_id = user.id

        settings_map = {
            "smtp_host": "smtp.example.com",
            "smtp_from": "pa-central@example.com",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        }

        issued = 0
        for _ in range(RESET_REQUESTS_PER_HOUR + 3):
            async with session_factory() as s:
                rows = (await s.execute(sa.select(PasswordResetToken))).scalars().all()
                for row in rows:
                    row.created_at = row.created_at - timedelta(
                        seconds=RESET_REQUEST_COOLDOWN_SECONDS + 30
                    )
                await s.commit()
            async with session_factory() as s:
                result = await prepare_reset_email(
                    s, await s.get(User, user_id), settings_map
                )
            issued += result is not None

        assert issued == RESET_REQUESTS_PER_HOUR, (
            f"{issued} links issued against a cap of {RESET_REQUESTS_PER_HOUR}"
        )


@pytest.mark.asyncio
class TestTokenEpochIncrementIsAtomicOnPostgres:
    """set_password's token_epoch bump must not be a lost update.

    `user.token_epoch += 1` reads the ORM attribute, computes in Python, and
    writes it back — two concurrent password changes can both read the same
    starting value and both write the same result, silently losing one
    increment. Reproduced directly before the fix: two concurrent
    set_password calls both read epoch 0 and both committed epoch 1, so a
    token minted between the two writes (carrying epoch 1) remained valid
    after the *second* password change — exactly the revocation
    token_epoch exists to guarantee.

    Fixed with a single atomic `UPDATE ... SET token_epoch = token_epoch + 1
    RETURNING token_epoch`, computed in the database rather than in Python.
    SQLite's own coverage is in test_password_reset.py
    (TestTokenEpochRevocation and the sibling race test); this is needed
    too because SQLite's default-database concurrency story (a single
    writer lock serializing the whole file) does not prove the *statement
    itself* is atomic under PostgreSQL's genuinely concurrent transactions —
    a version relying on SQLite's incidental serialization could still race
    here.
    """

    @pytest.fixture
    async def session_factory(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        yield factory
        await engine.dispose()

    async def test_concurrent_password_changes_do_not_lose_an_increment(
        self, session_factory
    ):
        from app.services.password_reset import set_password

        async with session_factory() as s:
            user = User(
                email="epoch-race-pg@example.com", display_name="EpochRace",
                hashed_password=hash_password("originalpassword1"),
                role=UserRole.viewer, is_active=True,
            )
            s.add(user)
            await s.commit()
            user_id = user.id

        N = 10

        async def change(i: int) -> int:
            async with session_factory() as s:
                u = await s.get(User, user_id)
                await set_password(s, u, f"concurrent-password-{i:02d}")
                await s.commit()
                return u.token_epoch

        results = await asyncio.gather(*[change(i) for i in range(N)])

        async with session_factory() as s:
            final = await s.get(User, user_id)

        assert final.token_epoch == N, (
            f"{N} concurrent password changes left token_epoch="
            f"{final.token_epoch} — a lost update means a token minted "
            "between two of them would survive a later password change"
        )
        # Each caller's committed result must be a distinct epoch value —
        # two callers reporting the same epoch is precisely the lost-update
        # signature the finding described (both read 0, both wrote 1).
        assert sorted(results) == list(range(1, N + 1)), (
            f"expected epochs 1..{N} with no duplicates, got {sorted(results)} "
            "— a repeated value means two writers computed the same "
            "increment from the same starting point"
        )


@pytest.mark.asyncio
class TestResetLockOrderingOnPostgres:
    """Issuance and consumption must take `users` and `password_reset_tokens`
    in the same order.

    Issuance locks the account, then writes tokens. Consumption claims a
    token, then writes the account's password. Taken in opposite orders those
    two form a cycle, and PostgreSQL resolves it by aborting one transaction —
    reproduced as a DeadlockDetected that killed the password reset while
    issuance succeeded, leaving the user's link consumed but their password
    unchanged: locked out of the very reset they were completing.

    Only PostgreSQL detects and reports a deadlock, which is why this lives
    here; SQLite's coarser locking cannot express the cycle. The ordering
    itself is a property of the code, so a regression breaks both backends
    even though only this test names it.
    """

    @pytest.fixture
    async def session_factory(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        yield factory
        await engine.dispose()

    async def _seed(self, factory) -> tuple[int, str]:
        from app.core.security import generate_reset_token
        from app.models import PasswordResetToken, SettingValueType, SystemSetting

        _raw, token_hash = generate_reset_token()
        async with factory() as s:
            user = User(
                email="lockorder@example.com", display_name="Lock Order",
                hashed_password=hash_password("password123456"),
                role=UserRole.viewer, is_active=True,
            )
            s.add(user)
            # prepare_reset_email's settings-row re-check now refuses issue()
            # below unless stored rows agree with its settings_map — a
            # genuinely absent/differing row is no longer treated as "don't
            # refuse" (see TestDisableRacesIssuanceOnPostgres's null-clear
            # and base-url-change tests). Neither test in this class
            # currently asserts on issue()'s own outcome, but seeding this
            # keeps that outcome meaningful rather than a trivial "always
            # refused" no-op.
            s.add(SystemSetting(
                key="self_service_password_reset", value="true",
                value_type=SettingValueType.bool, updated_at=datetime.now(UTC),
            ))
            s.add(SystemSetting(
                key="app_base_url", value="https://pa.example.com",
                value_type=SettingValueType.string, updated_at=datetime.now(UTC),
            ))
            await s.flush()
            user_id = user.id
            s.add(PasswordResetToken(
                token_hash=token_hash, user_id=user_id,
                # Backdated past RESET_REQUEST_COOLDOWN_SECONDS so the
                # issuance under test is not suppressed before it reaches the
                # token table — otherwise the two paths never contend and
                # this class stops exercising lock ordering at all.
                created_at=datetime.now(UTC) - timedelta(minutes=10),
                expires_at=datetime.now(UTC) + timedelta(minutes=60),
            ))
            await s.commit()
        return user_id, token_hash

    async def test_a_reset_overlapping_an_issuance_does_not_deadlock(
        self, session_factory
    ):
        """Consumption holds its locks while issuance arrives — the
        interleaving that deadlocked before the orders were aligned."""
        from app.services.password_reset import (
            consume_reset_token,
            prepare_reset_email,
        )

        user_id, token_hash = await self._seed(session_factory)
        settings_map = {
            "smtp_host": "smtp.example.com",
            "smtp_from": "pa-central@example.com",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        }
        claimed = asyncio.Event()

        async def reset():
            async with session_factory() as s:
                got = await consume_reset_token(s, token_hash)
                claimed.set()
                await asyncio.sleep(0.3)
                if not got:
                    return "rejected"
                _row, user = got
                user.hashed_password = hash_password("chosen-by-the-user")
                await s.commit()
                return "committed"

        async def issue():
            await claimed.wait()
            async with session_factory() as s:
                user = await s.get(User, user_id)
                result = await prepare_reset_email(s, user, settings_map)
                return "issued" if result else "not-issued"

        outcomes = await asyncio.gather(reset(), issue(), return_exceptions=True)
        aborted = [o for o in outcomes if isinstance(o, BaseException)]
        assert not aborted, (
            f"a transaction was aborted rather than serialised: "
            f"{type(aborted[0]).__name__}: {aborted[0]}"
        )
        assert outcomes[0] == "committed"

        async with session_factory() as s:
            user = await s.get(User, user_id)
        assert verify_password("chosen-by-the-user", user.hashed_password), (
            "the reset was lost even though it reported success"
        )

    async def test_an_issuance_overlapping_a_reset_does_not_deadlock(
        self, session_factory
    ):
        """The mirror interleaving: issuance holds the account lock first.

        The reset is legitimately rejected here — by the time it gets the
        account lock, issuance has superseded its token — which is correct
        behaviour, not an abort. The user simply uses their newer link.
        """
        from sqlalchemy import update as sa_update

        from app.services.password_reset import (
            consume_reset_token,
            prepare_reset_email,
        )

        user_id, token_hash = await self._seed(session_factory)
        settings_map = {
            "smtp_host": "smtp.example.com",
            "smtp_from": "pa-central@example.com",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        }
        holding = asyncio.Event()

        async def issue():
            async with session_factory() as s:
                user = await s.get(User, user_id)
                # Take the account lock the way prepare_reset_email does, then
                # hold it across the window the reset arrives in.
                await s.execute(
                    sa_update(User).where(User.id == user_id)
                    .values(is_active=User.is_active)
                )
                holding.set()
                await asyncio.sleep(0.3)
                result = await prepare_reset_email(s, user, settings_map)
                await s.commit()
                return "issued" if result else "not-issued"

        async def reset():
            await holding.wait()
            async with session_factory() as s:
                got = await consume_reset_token(s, token_hash)
                if not got:
                    return "rejected"
                _row, user = got
                user.hashed_password = hash_password("chosen-by-the-user")
                await s.commit()
                return "committed"

        outcomes = await asyncio.gather(issue(), reset(), return_exceptions=True)
        aborted = [o for o in outcomes if isinstance(o, BaseException)]
        assert not aborted, (
            f"a transaction was aborted rather than serialised: "
            f"{type(aborted[0]).__name__}: {aborted[0]}"
        )
        # What matters here is that both transactions completed rather than
        # one being aborted. Issuance may legitimately report "not-issued":
        # the fixture seeds a token, so this request falls inside the
        # cooldown and is suppressed — see TestForgotPasswordThrottling.
        assert outcomes[0] in ("issued", "not-issued")
        assert outcomes[1] in ("committed", "rejected")


@pytest.mark.asyncio
class TestThrottledIssuanceReleasesItsLock:
    """A rate-limited request must not keep the per-account write lock.

    prepare_reset_email takes an inert UPDATE on the user row to serialize
    issuance, then reads the count. The rate-limit branch returns before
    anything is committed, so without an explicit rollback that lock is held
    for the remainder of the request — and forgot_password holds it across its
    250ms constant-time sleep.

    That reintroduces the very oracle the sleep exists to remove: concurrent
    requests for a throttled *real* account serialize behind one another,
    while requests for unknown addresses never touch the row and do not. It is
    also a public write-lock DoS — an unauthenticated caller can pin a row
    lock at will, and on SQLite block unrelated writers outright.
    """

    @pytest.fixture
    async def session_factory(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        yield factory
        await engine.dispose()

    async def test_a_throttled_request_leaves_no_lock_behind(self, session_factory):
        from app.services.password_reset import (
            RESET_REQUESTS_PER_HOUR,
            prepare_reset_email,
        )

        settings_map = {
            "smtp_host": "smtp.example.com",
            "smtp_from": "pa-central@example.com",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        }

        from app.models import SettingValueType, SystemSetting

        async with session_factory() as s:
            user = User(
                email="throttled-lock@example.com", display_name="Throttled",
                hashed_password=hash_password("password123456"),
                role=UserRole.viewer, is_active=True,
            )
            s.add(user)
            # prepare_reset_email's settings-row re-check now refuses unless
            # stored rows agree with settings_map above — a genuinely
            # absent/differing row is no longer treated as "don't refuse"
            # (see TestDisableRacesIssuanceOnPostgres's null-clear and
            # base-url-change tests).
            s.add(SystemSetting(
                key="self_service_password_reset", value="true",
                value_type=SettingValueType.bool, updated_at=datetime.now(UTC),
            ))
            s.add(SystemSetting(
                key="app_base_url", value="https://pa.example.com",
                value_type=SettingValueType.string, updated_at=datetime.now(UTC),
            ))
            await s.commit()
            user_id = user.id

        # Age each attempt past the cooldown before making the next, so the
        # quota is genuinely exhausted. Back-to-back these collapse into a
        # single ledger row — every request after the first is answered by
        # cooldown suppression — and the rate-limit branch this test names is
        # never reached: an earlier version passed with that branch's lock
        # release removed entirely.
        from app.models import PasswordResetToken
        from app.services.password_reset import RESET_REQUEST_COOLDOWN_SECONDS

        async def _age_past_cooldown() -> None:
            async with session_factory() as s:
                rows = (await s.execute(sa.select(PasswordResetToken))).scalars().all()
                for row in rows:
                    row.created_at = row.created_at - timedelta(
                        seconds=RESET_REQUEST_COOLDOWN_SECONDS + 30
                    )
                await s.commit()

        for _ in range(RESET_REQUESTS_PER_HOUR):
            await _age_past_cooldown()
            async with session_factory() as s:
                issued = await prepare_reset_email(
                    s, await s.get(User, user_id), settings_map
                )
                assert issued is not None, "setup request was unexpectedly refused"

        async with session_factory() as s:
            ledger = (await s.execute(
                sa.select(sa.func.count()).select_from(PasswordResetToken)
            )).scalar_one()
        assert ledger == RESET_REQUESTS_PER_HOUR, (
            f"{ledger} ledger rows for {RESET_REQUESTS_PER_HOUR} requests — the "
            "quota was not filled, so the rate-limit branch will not be reached"
        )

        # Past the cooldown too, so this is refused by the cap rather than
        # suppressed — the two branches release the lock separately.
        await _age_past_cooldown()

        throttled = session_factory()
        try:
            refused = await prepare_reset_email(
                throttled, await throttled.get(User, user_id), settings_map
            )
            assert refused is None, "expected this request to be rate limited"

            async with session_factory() as s:
                after = (await s.execute(
                    sa.select(sa.func.count()).select_from(PasswordResetToken)
                )).scalar_one()
            assert after == RESET_REQUESTS_PER_HOUR, (
                "the throttled request issued a token — it was not refused by "
                "the rate limit"
            )

            # The throttled session is still open, exactly as it would be
            # while forgot_password sleeps out its constant-time floor. An
            # unrelated writer must not be blocked by it.
            async with session_factory() as other:
                await asyncio.wait_for(
                    other.execute(
                        sa.update(User)
                        .where(User.id == user_id)
                        .values(display_name="Renamed")
                    ),
                    timeout=3.0,
                )
                await other.rollback()
        except TimeoutError:
            pytest.fail(
                "the rate-limited request is still holding the per-account "
                "write lock — it must roll back before returning"
            )
        finally:
            await throttled.rollback()
            await throttled.close()


@pytest.mark.asyncio
class TestForgotPasswordBurstTimingOnPostgres:
    """A concurrent burst must not take longer for a real address.

    The constant-time floor removes the *sequential* signal, but only a real,
    active account reaches prepare_reset_email, which takes a per-user write
    lock. Under a burst those requests queue on it while requests for an
    unknown address never touch it — so if the queue outlasts the floor,
    latency discloses account existence again.

    PostgreSQL-only because that queueing is what the test needs: SQLite
    serialises writers globally, so both bursts queue equally and the
    asymmetry cannot appear there at all.

    Measured before FORGOT_PASSWORD_MIN_SECONDS was raised to 1s: 430ms vs
    252ms at N=10 with a 0.25s floor, worsening as the burst grew. The floor
    alone was not sufficient either — it held to ~N=150 and then failed, which
    is why issuance is also bounded by a deadline (see prepare_reset_email).

    Scope of this test, stated plainly: it compares *medians*, so it resists
    a single scheduling outlier but is correspondingly less sensitive than
    the max-latency ratio the fix was tuned against. It fails reliably at a
    0.25s floor; a 0.5s floor — which does leak on max latency at this burst
    size — can still pass here. It is a regression guard against the floor
    being removed or slashed, not a proof that any particular smaller value
    is safe. The measurements behind the chosen 1s are recorded on
    FORGOT_PASSWORD_MIN_SECONDS itself.
    """

    # 50, not a smaller burst: a 0.5s floor looks fine at 25 and only leaks
    # once the queue is long enough to outlast it. The test has to sit on the
    # far side of that.
    # 300, not 50: with only the 1s floor and no ceiling on the work, N=50
    # and N=150 both measured flat (1.00x) while N=300 leaked at 1.25x and
    # N=500 at 2.06x. A burst test sized where the fix already passes proves
    # nothing about the fix.
    BURST = 300

    @pytest.fixture
    async def configured(self, migrated_url, monkeypatch):
        from app.core.database import get_db
        from app.main import app
        from app.models import SettingValueType, SystemSetting

        async def no_send(self, msg, recipients, *, interactive=False):
            return None

        monkeypatch.setattr("app.core.email.EmailService.send", no_send)

        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        async with factory() as s:
            for key, value, vtype in (
                ("smtp_host", "smtp.example.com", SettingValueType.string),
                ("app_base_url", "https://pa.example.com", SettingValueType.string),
                ("self_service_password_reset", "true", SettingValueType.bool),
            ):
                s.add(SystemSetting(
                    key=key, value=value, value_type=vtype,
                    updated_at=datetime.now(UTC),
                ))
            s.add(User(
                email="burst-timing@example.com", display_name="Burst",
                hashed_password=hash_password("password123456"),
                role=UserRole.viewer, is_active=True,
            ))
            await s.commit()

        async def override():
            async with factory() as session:
                yield session

        app.dependency_overrides[get_db] = override
        yield app
        app.dependency_overrides.pop(get_db, None)
        await engine.dispose()

    async def _burst(self, app, email: str) -> list[float]:
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test"
        ) as client:
            async def one() -> float:
                start = time.perf_counter()
                await client.post(
                    "/api/auth/forgot-password", json={"email": email}
                )
                return time.perf_counter() - start

            return await asyncio.gather(*[one() for _ in range(self.BURST)])

    async def test_a_burst_does_not_reveal_account_existence(self, configured):
        real = await self._burst(configured, "burst-timing@example.com")
        unknown = await self._burst(configured, "nobody@example.com")

        # Compare medians: a single scheduling outlier in either burst should
        # not fail this, but a systematic queue would move the whole
        # distribution.
        real_median = statistics.median(real)
        unknown_median = statistics.median(unknown)
        assert real_median < unknown_median * 1.25, (
            f"a burst against a registered address took {real_median * 1000:.0f}ms "
            f"versus {unknown_median * 1000:.0f}ms for an unknown one — lock "
            "queueing is outlasting the constant-time floor"
        )

        # And the floor is doing its job at all.
        from app.services.password_reset import FORGOT_PASSWORD_MIN_SECONDS

        assert unknown_median >= FORGOT_PASSWORD_MIN_SECONDS * 0.9


@pytest.mark.asyncio
class TestDisableRacesIssuanceOnPostgres:
    """Disabling the feature must be atomic with respect to token issuance.

    A request reads the settings map once, up front. An admin can disable the
    feature and sweep outstanding tokens in the gap before that request
    inserts — and the request would then add a fresh live token from its stale
    view. Consumption is deliberately ungated (see api/auth.py), so the sweep
    is the *only* revocation: a token inserted after it stays usable
    indefinitely, defeating the disable entirely.

    Both paths therefore take the same settings-row lock, and issuance
    re-reads the flag while holding it. Whichever order they arrive in, the
    outcome is the same: no usable token survives the disable.
    """

    @pytest.fixture
    async def session_factory(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        yield factory
        await engine.dispose()

    @pytest.fixture
    async def configured(self, session_factory, monkeypatch):
        from app.models import SettingValueType, SystemSetting

        async def no_send(self, msg, recipients, *, interactive=False):
            return None

        monkeypatch.setattr("app.core.email.EmailService.send", no_send)

        async with session_factory() as s:
            for key, value, vtype in (
                ("smtp_host", "smtp.example.com", SettingValueType.string),
                ("app_base_url", "https://pa.example.com", SettingValueType.string),
                ("self_service_password_reset", "true", SettingValueType.bool),
            ):
                s.add(SystemSetting(
                    key=key, value=value, value_type=vtype,
                    updated_at=datetime.now(UTC),
                ))
            user = User(
                email="disable-race@example.com", display_name="Race",
                hashed_password=hash_password("password123456"),
                role=UserRole.viewer, is_active=True,
            )
            s.add(user)
            await s.commit()
            return user.id

    @staticmethod
    async def _disable_and_sweep(session_factory) -> None:
        """What PATCH /system-settings does when the feature is turned off."""
        from app.models import PasswordResetToken, SystemSetting

        async with session_factory() as s:
            row = await s.get(SystemSetting, "self_service_password_reset")
            row.value = "false"
            await s.execute(
                sa.update(SystemSetting)
                .where(SystemSetting.key == "self_service_password_reset")
                .values(value_type=SystemSetting.value_type)
            )
            await s.execute(
                sa.update(PasswordResetToken)
                .where(PasswordResetToken.used_at.is_(None))
                .values(used_at=datetime.now(UTC))
            )
            await s.commit()

    @staticmethod
    async def _live_tokens(session_factory) -> int:
        from app.models import PasswordResetToken

        async with session_factory() as s:
            return (await s.execute(
                sa.select(sa.func.count())
                .select_from(PasswordResetToken)
                .where(PasswordResetToken.used_at.is_(None))
            )).scalar_one()

    async def test_a_disable_between_read_and_insert_wins(
        self, session_factory, configured
    ):
        """The reported ordering: settings read, feature disabled and swept,
        then the in-flight request tries to issue. It must refuse."""
        from app.core.smtp_settings import load_settings_map
        from app.services.password_reset import prepare_reset_email

        issuing = session_factory()
        try:
            stale = await load_settings_map(issuing)
            await self._disable_and_sweep(session_factory)

            prepared = await prepare_reset_email(
                issuing, await issuing.get(User, configured), stale
            )
            assert prepared is None, (
                "a link was issued from a stale settings map after the "
                "feature was disabled"
            )
        finally:
            await issuing.close()

        assert await self._live_tokens(session_factory) == 0

    async def test_an_issuance_in_progress_is_swept_by_the_disable(
        self, session_factory, configured
    ):
        """The mirror ordering: issuance holds the lock first. It may
        legitimately create a token — but the sweep, which waits on the same
        lock, must then retire it. Either way nothing usable survives."""
        from app.core.smtp_settings import load_settings_map
        from app.services.password_reset import prepare_reset_email

        issuing = session_factory()
        try:
            stale = await load_settings_map(issuing)
            user = await issuing.get(User, configured)

            async def issue():
                return await prepare_reset_email(issuing, user, stale)

            async def disable():
                await asyncio.sleep(0.05)
                await self._disable_and_sweep(session_factory)

            outcomes = await asyncio.gather(
                issue(), disable(), return_exceptions=True
            )
            aborted = [o for o in outcomes if isinstance(o, BaseException)]
            assert not aborted, (
                f"a transaction was aborted rather than serialised: "
                f"{type(aborted[0]).__name__}: {aborted[0]}"
            )
            await issuing.commit()
        finally:
            await issuing.close()

        assert await self._live_tokens(session_factory) == 0, (
            "a token issued alongside the disable was left usable"
        )

    async def test_the_admin_flow_is_also_stopped_by_a_disable(
        self, session_factory, configured
    ):
        """admin_initiated and welcome bypass the *throttle*, not the feature
        being switched off — they must respect the same re-check."""
        from app.core.smtp_settings import load_settings_map
        from app.services.password_reset import prepare_reset_email

        issuing = session_factory()
        try:
            stale = await load_settings_map(issuing)
            await self._disable_and_sweep(session_factory)

            prepared = await prepare_reset_email(
                issuing, await issuing.get(User, configured), stale,
                admin_initiated=True,
            )
            assert prepared is None
        finally:
            await issuing.close()

        assert await self._live_tokens(session_factory) == 0

    @staticmethod
    async def _disable_via_null_and_sweep(session_factory) -> None:
        """What PATCH /system-settings does when self_service_password_reset
        is cleared with `null` rather than explicitly set to "false" — the
        key is not in RUNTIME_DEFAULTS, so clearing it leaves the row in
        place with value=NULL rather than deleting it (see
        patch_settings). Distinct from _disable_and_sweep above, which sets
        the stored value to the string "false" — this exercises the
        specific stored state ("row present, value=NULL") that used to be
        indistinguishable from "no row at all" in _prepare_reset_email's
        own re-check."""
        from app.models import PasswordResetToken, SystemSetting

        async with session_factory() as s:
            row = await s.get(SystemSetting, "self_service_password_reset")
            row.value = None
            await s.execute(
                sa.update(SystemSetting)
                .where(SystemSetting.key == "self_service_password_reset")
                .values(value_type=SystemSetting.value_type)
            )
            await s.execute(
                sa.update(PasswordResetToken)
                .where(PasswordResetToken.used_at.is_(None))
                .values(used_at=datetime.now(UTC))
            )
            await s.commit()

    async def test_a_null_stored_value_is_not_mistaken_for_an_absent_row(
        self, session_factory, configured
    ):
        """_prepare_reset_email's re-check used to select only
        SystemSetting.value and call scalar_one_or_none() on it — collapsing
        "no row matched" and "a row matched with value=NULL" into the same
        None result. Its own guard explicitly only refuses when
        `fresh_row is not None`, so a stored NULL (this test's scenario, via
        the documented null-clear path) fell through unrefused exactly like
        a genuinely absent row would — a request in flight when this
        disable-via-null committed would still issue a fresh, consumable
        token. Reproduced directly against the unfixed code before this
        test existed: this exact scenario returned a token instead of None.

        Selecting `key` alongside `value` and reading `.one_or_none()` on
        the row fixes this — `key` is the primary key and can never itself
        be NULL, so presence and value are no longer conflated."""
        from app.core.smtp_settings import load_settings_map
        from app.services.password_reset import prepare_reset_email

        issuing = session_factory()
        try:
            stale = await load_settings_map(issuing)
            await self._disable_via_null_and_sweep(session_factory)

            prepared = await prepare_reset_email(
                issuing, await issuing.get(User, configured), stale,
            )
            assert prepared is None, (
                "a link was issued from a stale settings map after the "
                "feature was disabled via a null-clear — the stored NULL "
                "was mistaken for an absent row"
            )
        finally:
            await issuing.close()

        assert await self._live_tokens(session_factory) == 0

    @staticmethod
    async def _change_base_url_and_sweep(session_factory, new_url: str) -> None:
        """What PATCH /system-settings does when app_base_url changes to a
        genuinely different value (its own changing_base_url condition) —
        the sibling of _disable_and_sweep above, but for the base-URL
        route to the same sweep rather than the enable-flag route."""
        from app.models import PasswordResetToken, SystemSetting

        async with session_factory() as s:
            row = await s.get(SystemSetting, "app_base_url")
            row.value = new_url
            await s.execute(
                sa.update(PasswordResetToken)
                .where(PasswordResetToken.used_at.is_(None))
                .values(used_at=datetime.now(UTC))
            )
            await s.commit()

    async def test_a_base_url_change_between_read_and_insert_wins(
        self, session_factory, configured
    ):
        """_prepare_reset_email re-reads self_service_password_reset under
        its settings-row lock, but used to trust `base_url` — computed
        from the caller's own settings_map, read before that lock was even
        acquired — unchanged for the rest of the function. An admin
        changing app_base_url (and sweeping outstanding tokens, per
        api/system_settings.py's changing_base_url condition) in the gap
        between that read and this function's own insert left the enable
        flag re-check satisfied (it never touched self_service_password_reset)
        while the message built further down still used the old, abandoned
        URL — a fresh, live token whose emailed link pointed at an address
        that may later be retired or repurposed by someone else, exactly
        the exposure changing_base_url's own sweep exists to close.
        Reproduced directly against the unfixed code: this exact ordering
        issued a token with the stale URL baked into its message body.
        """
        from app.core.smtp_settings import load_settings_map
        from app.services.password_reset import prepare_reset_email

        issuing = session_factory()
        try:
            stale = await load_settings_map(issuing)
            await self._change_base_url_and_sweep(
                session_factory, "https://new.pa.example.com"
            )

            prepared = await prepare_reset_email(
                issuing, await issuing.get(User, configured), stale
            )
            assert prepared is None, (
                "a link was issued from a stale settings map after "
                "app_base_url changed — the fresh value was never re-checked"
            )
        finally:
            await issuing.close()

        assert await self._live_tokens(session_factory) == 0

    async def test_an_issuance_in_progress_is_swept_by_a_base_url_change(
        self, session_factory, configured
    ):
        """The mirror ordering: issuance holds the lock first, so it may
        legitimately commit a token built from the still-current URL — but
        the sweep, waiting on the same lock, then retires it regardless.
        Either way nothing usable survives."""
        from app.core.smtp_settings import load_settings_map
        from app.services.password_reset import prepare_reset_email

        issuing = session_factory()
        try:
            stale = await load_settings_map(issuing)
            user = await issuing.get(User, configured)

            async def issue():
                return await prepare_reset_email(issuing, user, stale)

            async def change_url():
                await asyncio.sleep(0.05)
                await self._change_base_url_and_sweep(
                    session_factory, "https://new.pa.example.com"
                )

            outcomes = await asyncio.gather(
                issue(), change_url(), return_exceptions=True
            )
            aborted = [o for o in outcomes if isinstance(o, BaseException)]
            assert not aborted, (
                f"a transaction was aborted rather than serialised: "
                f"{type(aborted[0]).__name__}: {aborted[0]}"
            )
            await issuing.commit()
        finally:
            await issuing.close()

        assert await self._live_tokens(session_factory) == 0, (
            "a token issued alongside the base_url change was left usable"
        )


@pytest.mark.asyncio
class TestLockTimeoutsDoNotLeakExistenceOnPostgres:
    """A lock timeout anywhere in issuance must still answer 202.

    `SET LOCAL lock_timeout` applies to the whole transaction, so every
    statement after it can raise 55P03 — the account row, the settings row,
    the retirement UPDATE, the INSERT. Only a *registered* address reaches any
    of them, so an uncaught one becomes a 500 where an unknown address returns
    202: account enumeration by status code. Reproduced by holding the
    settings row, which surfaced LockNotAvailableError uncaught.

    Parametrised over the rows issuance locks, so a handler that covers only
    the first fails here.
    """

    @pytest.fixture
    async def session_factory(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        yield factory
        await engine.dispose()

    @pytest.fixture
    async def configured(self, session_factory, monkeypatch):
        from app.core.database import get_db
        from app.main import app
        from app.models import SettingValueType, SystemSetting

        async def no_send(self, msg, recipients, *, interactive=False):
            return None

        monkeypatch.setattr("app.core.email.EmailService.send", no_send)
        # Small enough that the held row below trips it immediately.
        monkeypatch.setattr(
            "app.services.password_reset.FORGOT_PASSWORD_LOCK_TIMEOUT_SECONDS", 0.05
        )

        async with session_factory() as s:
            for key, value, vtype in (
                ("smtp_host", "smtp.example.com", SettingValueType.string),
                ("app_base_url", "https://pa.example.com", SettingValueType.string),
                ("self_service_password_reset", "true", SettingValueType.bool),
            ):
                s.add(SystemSetting(
                    key=key, value=value, value_type=vtype,
                    updated_at=datetime.now(UTC),
                ))
            s.add(User(
                email="locked@example.com", display_name="Locked",
                hashed_password=hash_password("password123456"),
                role=UserRole.viewer, is_active=True,
            ))
            await s.commit()

        async def override():
            async with session_factory() as session:
                yield session

        app.dependency_overrides[get_db] = override
        yield app
        app.dependency_overrides.pop(get_db, None)

    @pytest.mark.parametrize("held_row", ["user", "settings"])
    async def test_a_held_row_still_answers_202(
        self, session_factory, configured, held_row
    ):
        from app.models import SystemSetting

        holder = session_factory()
        try:
            if held_row == "user":
                await holder.execute(
                    sa.update(User)
                    .where(User.email == "locked@example.com")
                    .values(is_active=User.is_active)
                )
            else:
                await holder.execute(
                    sa.update(SystemSetting)
                    .where(SystemSetting.key == "self_service_password_reset")
                    .values(value_type=SystemSetting.value_type)
                )

            async with AsyncClient(
                transport=ASGITransport(app=configured), base_url="http://test"
            ) as client:
                registered = await client.post(
                    "/api/auth/forgot-password",
                    json={"email": "locked@example.com"},
                )
                unknown = await client.post(
                    "/api/auth/forgot-password",
                    json={"email": "nobody@example.com"},
                )
        finally:
            await holder.rollback()
            await holder.close()

        assert registered.status_code == unknown.status_code == 202, (
            f"a lock timeout on the {held_row} row leaked account existence: "
            f"registered={registered.status_code} unknown={unknown.status_code}"
        )
        assert registered.json() == unknown.json()

    async def test_a_real_database_error_is_not_swallowed(
        self, session_factory, configured, monkeypatch
    ):
        """The handler matches SQLSTATE 55P03 only — a genuine failure must
        still surface rather than being reported as a quiet 202."""
        from sqlalchemy.exc import DBAPIError

        import app.services.password_reset as pr

        async def boom(*args, **kwargs):
            raise DBAPIError("SELECT 1", {}, Exception("disk on fire"))

        monkeypatch.setattr(pr, "_prepare_reset_email", boom)

        async with AsyncClient(
            transport=ASGITransport(app=configured), base_url="http://test"
        ) as client:
            with pytest.raises(DBAPIError):
                await client.post(
                    "/api/auth/forgot-password",
                    json={"email": "locked@example.com"},
                )


@pytest.mark.asyncio
class TestPasswordResetTokenExpiryOnPostgres:
    """Reset-token expiry compares a UtcDateTime column against an aware
    datetime, so it depends on the decorator's strip-on-write behaviour being
    consistent across dialects.

    The suite's SQLite run cannot catch a divergence here: SQLite stores the
    naive string UtcDateTime hands it and compares lexically, whereas Postgres
    compares a real timestamp-without-tz. A decorator bug that offset stored
    values would still order correctly under SQLite (every value shifted the
    same way) while making a live token read as expired here, or — worse — an
    expired one read as live.
    """

    @pytest.fixture
    async def session(self, migrated_url):
        engine = make_async_engine(migrated_url)
        factory = async_sessionmaker(engine)
        async with factory() as s:
            yield s
        await engine.dispose()

    async def _user(self, session, email: str) -> User:
        user = User(
            email=email, display_name="Reset",
            hashed_password=hash_password("password123456"),
            role=UserRole.viewer, is_active=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user

    async def test_live_token_is_consumable(self, session):
        from app.models import PasswordResetToken
        from app.services.password_reset import consume_reset_token

        user = await self._user(session, "live-token@example.com")
        session.add(PasswordResetToken(
            token_hash="a" * 64, user_id=user.id,
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(minutes=60),
        ))
        await session.commit()

        assert await consume_reset_token(session, "a" * 64) is not None

    async def test_expired_token_is_rejected(self, session):
        from app.models import PasswordResetToken
        from app.services.password_reset import consume_reset_token

        user = await self._user(session, "expired-token@example.com")
        session.add(PasswordResetToken(
            token_hash="b" * 64, user_id=user.id,
            created_at=datetime.now(UTC) - timedelta(hours=2),
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        ))
        await session.commit()

        assert await consume_reset_token(session, "b" * 64) is None

    async def test_token_expiring_in_a_non_utc_offset_is_still_live(self, session):
        """An aware datetime in a non-UTC offset must be normalised, not
        stored with its wall-clock reading. +05:00 is the offset that hides
        this best: a value stored unconverted would read five hours later
        than intended, keeping an expired token alive."""
        from app.models import PasswordResetToken
        from app.services.password_reset import consume_reset_token

        user = await self._user(session, "offset-token@example.com")
        expires = (datetime.now(UTC) + timedelta(minutes=30)).astimezone(
            timezone(timedelta(hours=5))
        )
        session.add(PasswordResetToken(
            token_hash="c" * 64, user_id=user.id,
            created_at=datetime.now(UTC), expires_at=expires,
        ))
        await session.commit()
        session.expire_all()

        assert await consume_reset_token(session, "c" * 64) is not None

    async def test_expired_token_in_a_non_utc_offset_is_rejected(self, session):
        from app.models import PasswordResetToken
        from app.services.password_reset import consume_reset_token

        user = await self._user(session, "offset-expired@example.com")
        expires = (datetime.now(UTC) - timedelta(minutes=30)).astimezone(
            timezone(timedelta(hours=5))
        )
        session.add(PasswordResetToken(
            token_hash="d" * 64, user_id=user.id,
            created_at=datetime.now(UTC) - timedelta(hours=2), expires_at=expires,
        ))
        await session.commit()
        session.expire_all()

        assert await consume_reset_token(session, "d" * 64) is None

    async def test_token_is_deleted_when_its_user_is(self, session):
        """ondelete=CASCADE, asserted against a server that actually enforces
        it — SQLite ignores FK actions unless the pragma is on per connection."""
        from app.models import PasswordResetToken

        user = await self._user(session, "cascade-token@example.com")
        # Read the id before the commit below expires the instance — this
        # session uses expire_on_commit=True, so a post-commit attribute
        # access would trigger lazy IO outside the async greenlet context.
        user_id = user.id
        session.add(PasswordResetToken(
            token_hash="e" * 64, user_id=user_id,
            created_at=datetime.now(UTC),
            expires_at=datetime.now(UTC) + timedelta(minutes=60),
        ))
        await session.commit()

        await session.execute(sa.delete(User).where(User.id == user_id))
        await session.commit()

        remaining = (await session.execute(
            sa.select(PasswordResetToken).where(PasswordResetToken.token_hash == "e" * 64)
        )).scalar_one_or_none()
        assert remaining is None

