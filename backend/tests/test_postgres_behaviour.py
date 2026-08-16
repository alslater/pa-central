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
from datetime import UTC, datetime, timedelta, timezone

import pytest
import sqlalchemy as sa
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from tests.conftest_postgres import as_async_url as async_url
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
        engine = create_async_engine(async_url(migrated_url))
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
        url = async_url(postgres_url)
        # Short ceiling so the test does not wait the production default.
        monkeypatch.setattr(app_main, "MIGRATION_LOCK_TIMEOUT", 2.0)

        holder = create_async_engine(url)
        test_engine = create_async_engine(url)
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
        url = async_url(postgres_url)
        #  2. the module-level engine, imported inside _run_migrations
        import app.core.database as app_db
        test_engine = create_async_engine(url)
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
        check = create_async_engine(url)
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
        url = async_url(postgres_url)
        test_engine = create_async_engine(url)
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

        probe = create_async_engine(url)
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
        engine = create_async_engine(async_url(migrated_url))
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

    def test_unrelated_query_params_pass_through_unchanged(self):
        from tests.conftest_postgres import as_async_url

        out = as_async_url(
            "postgresql+psycopg2://u@h:5432/db?application_name=x"
        )
        assert sa.engine.make_url(out).query.get("application_name") == "x"

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
        engine = create_async_engine(async_url(migrated_url))
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
        engine = create_async_engine(async_url(postgres_url))
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
        engine = create_async_engine(async_url(postgres_url))
        monkeypatch.setattr(app_db, "engine", engine)
        try:
            async with engine.begin() as conn:
                await conn.execute(sa.text('CREATE SCHEMA "premade"'))
            async with engine.connect() as conn:
                # Must not raise: the schema is already there.
                await app_main._ensure_schema(conn)
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
            engine = create_async_engine(async_url(
                low.render_as_string(hide_password=False)
            ))
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

            engine = create_async_engine(
                async_url(postgres_url), connect_args=async_connect_args(app_settings)
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
        engine = create_async_engine(
            async_url(postgres_url), connect_args=async_connect_args(cfg)
        )
        try:
            async with engine.connect() as conn:
                assert (await conn.execute(sa.text("SELECT 1"))).scalar() == 1
        finally:
            await engine.dispose()
