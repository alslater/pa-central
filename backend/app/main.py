"""PA Central — central management server for package-alert installations."""
import asyncio
import os
import random
import subprocess
import sys
import time
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text

from app.api import (
    alerts,
    api_keys,
    auth,
    config_templates,
    cooldown,
    dashboard,
    findings,
    hosts,
    ingest,
    repo_credentials,
    repo_scans,
    scan_options,
    scans,
    system_settings,
    users,
)
from app.core.config import settings
from app.core.database import init_db
from app.core.db_config import resolved_password

# Advisory lock ID for serialising startup migrations — "pacmig" as an int.
# Module-level so tests can assert against the real value rather than
# duplicating the literal and silently drifting from it.
MIGRATION_LOCK_ID = 0x7061636D6967

# Base interval between lock attempts; the actual wait is jittered around it.
MIGRATION_LOCK_POLL_SECONDS = 0.5

# Ceiling on the total wait, read through Settings (not os.getenv directly)
# so MIGRATION_LOCK_TIMEOUT set in backend/.env — the documented direct-run
# configuration file — is actually honored; pydantic-settings' dotenv source
# never touches os.environ, so a bare os.getenv() here would silently see
# only the real process environment and default to 300 regardless of .env.
# Validation (finite, non-negative) lives on the Settings field itself.
MIGRATION_LOCK_TIMEOUT = settings.migration_lock_timeout


async def _ensure_schema(conn) -> None:
    """Create the configured schema if it is absent.

    Check first, then create. `CREATE SCHEMA IF NOT EXISTS` raises
    InsufficientPrivilege even when the schema already exists — it is a
    permission check on the statement, not a guard — so always attempting it
    would break the normal production case, where a DBA provisions the schema
    and the application user holds only USAGE.
    """
    schema = settings.database_schema
    if not schema:
        return

    exists = (await conn.execute(
        text(
            "SELECT 1 FROM information_schema.schemata "
            "WHERE schema_name = :name"
        ),
        {"name": schema},
    )).scalar()
    if exists:
        return

    try:
        # Not an f-string interpolation: a schema name cannot be bound as a SQL
        # parameter in DDL, and naively quoting it (f'"{schema}"') would let an
        # embedded `"` break out of the identifier — IdentifierPreparer quotes
        # it the way the dialect actually requires, doubling any embedded quote.
        quoted = conn.dialect.identifier_preparer.quote(schema)
        await conn.execute(text(f"CREATE SCHEMA {quoted}"))
        await conn.commit()
    except Exception as exc:  # noqa: BLE001 — any DB error here becomes a clear startup failure
        raise RuntimeError(
            f"database schema {schema!r} does not exist and could not be "
            f"created as user {settings.database_user!r}: {exc}. Create it "
            "manually, or grant CREATE on the database."
        ) from None


async def _finish_migration_lock(conn) -> None:
    """Roll back and release the migration advisory lock. Always run behind
    a shield-and-drain loop in _run_migrations — never awaited directly —
    since a cancellation landing mid-way through would skip the unlock."""
    await conn.rollback()
    await conn.execute(
        text("SELECT pg_advisory_unlock(:id)"),
        {"id": MIGRATION_LOCK_ID},
    )


async def _run_migrations() -> None:
    """Run Alembic migrations on startup, serialised with a DB advisory lock on Postgres.

    On SQLite the lock is skipped — SQLite is always single-process so there is no
    concurrent-startup race. On Postgres, multiple workers or replicas starting at
    the same time will queue here; the first acquires the lock and runs migrations,
    the rest wait, then find the schema already at head and finish in milliseconds.
    """
    from app.core.database import engine

    backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    migrations_dir = os.path.join(backend_dir, "migrations")
    if not os.path.isdir(migrations_dir):
        if settings.database_schema:
            # Base.metadata is schema-qualified when DATABASE_SCHEMA is set,
            # so init_db()'s create_all emits `CREATE TABLE <schema>.<table>`
            # — against a fresh database it fails with InvalidSchemaName
            # unless the schema exists first. The migrated path below runs
            # _ensure_schema under the advisory lock; this fallback needs the
            # same guarantee. No lock here: create_all is idempotent-enough
            # for this dev/packaging fallback, and _ensure_schema itself
            # checks before creating. database_schema is Postgres-only
            # (validated at startup), so no dialect check is needed.
            async with engine.connect() as conn:
                await _ensure_schema(conn)
        await init_db()
        return

    is_postgres = settings.database_type == "postgresql"

    if is_postgres:
        # Hold a single raw connection open for the entire lock window.
        # pg_advisory_lock is session-scoped: the lock is released when the
        # connection closes, so we must not close it until after migrations finish.
        async with engine.connect() as conn:
            # Poll with pg_try_advisory_lock rather than blocking in the DB, so
            # the event loop stays responsive. Bounded: without a ceiling a lock
            # that is never released (a peer killed mid-migration, say) would
            # hang startup forever with no crash for an orchestrator to act on.
            deadline = time.monotonic() + MIGRATION_LOCK_TIMEOUT
            while True:
                result = await conn.execute(
                    text("SELECT pg_try_advisory_lock(:id)"),
                    {"id": MIGRATION_LOCK_ID},
                )
                if result.scalar():
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError(
                        f"could not acquire the migration advisory lock within "
                        f"{MIGRATION_LOCK_TIMEOUT}s — another instance may be "
                        f"stuck mid-migration, or a stale session still holds "
                        f"lock id {MIGRATION_LOCK_ID}"
                    )
                # Jitter so simultaneously-started replicas do not poll in
                # lockstep and repeatedly collide on the same retry tick.
                await asyncio.sleep(MIGRATION_LOCK_POLL_SECONDS * (0.5 + random.random()))

            # Everything from here on runs with the lock held, so it all lives
            # inside this try/finally — including _ensure_schema. That call
            # can raise (its own documented insufficient-privilege path, for
            # one), and returning this connection to the pool afterwards does
            # not release a Postgres session-level advisory lock — only an
            # explicit unlock or the physical session actually closing does —
            # so a retry that reused a pooled connection would otherwise block
            # on its own orphaned session until MIGRATION_LOCK_TIMEOUT.
            # None until the migration thread actually starts — a
            # cancellation landing during _ensure_schema (before there is any
            # thread to drain) must not reference an undefined migration.
            migration = None
            try:
                await _ensure_schema(conn)

                # Shielded, because asyncio.to_thread cannot interrupt a
                # running thread: cancelling the await abandons it while
                # subprocess.run is still executing `alembic upgrade`.
                # Unshielded, the finally below would unlock — and closing
                # this connection would drop the session-scoped lock anyway —
                # while Alembic is mid-migration, letting a second replica
                # acquire the lock and run concurrently against the same
                # schema.
                migration = asyncio.ensure_future(
                    asyncio.to_thread(_alembic_upgrade, backend_dir)
                )
                await asyncio.shield(migration)
            except asyncio.CancelledError:
                # Startup is going away, but the thread is not. Hold the lock
                # until the migration it is protecting has actually finished,
                # then re-raise so shutdown proceeds.
                #
                # A loop, not a single await: a second cancel() lands *on this
                # drain*, and CancelledError is a BaseException, so it would
                # escape a `suppress(Exception)` and reach the finally below
                # with the thread still running — releasing the lock mid-
                # migration, which is the exact failure the shield exists to
                # prevent. Shutdown paths retry cancellation readily (uvicorn
                # re-cancels on a second signal), so tolerate it and keep
                # waiting until the future is genuinely done.
                #
                # BaseException also covers the migration's own failure, which
                # is deliberately not raised in place of the cancellation:
                # cancellation is the outcome the caller asked for, and
                # _alembic_upgrade has already captured stderr into its
                # RuntimeError.
                if migration is not None:
                    while not migration.done():
                        with suppress(BaseException):
                            await asyncio.shield(migration)
                raise
            finally:
                # Reached only once no thread is still migrating. The unlock is
                # explicit rather than left to the closing session so the lock is
                # gone before the connection is returned to the pool.
                #
                # Rolled back first: a real PostgreSQL error from _ensure_schema
                # (e.g. CREATE SCHEMA permission denial) leaves this connection's
                # transaction aborted, and Postgres refuses any further command —
                # including pg_advisory_unlock — until it is rolled back. Without
                # this, the unlock itself raises InFailedSqlTransaction, masking
                # the original error and leaving the session-level lock held on
                # the pooled connection. Safe to call unconditionally: rollback
                # on a connection with no active transaction (the ordinary
                # success path) is a no-op.
                #
                # Shielded and drained exactly like the migration future above:
                # a cancellation can still land here (the migration drain only
                # protects the thread's own await, not this cleanup), and
                # rollback/unlock are two separate unshielded awaits that a
                # bare CancelledError would abandon mid-way, skipping the
                # unlock and leaking the session-level lock on a connection
                # that then returns to the pool.
                cleanup = asyncio.ensure_future(_finish_migration_lock(conn))
                while not cleanup.done():
                    with suppress(BaseException):
                        await asyncio.shield(cleanup)
                if cleanup.exception() is not None:
                    # Rollback or the unlock query itself failed — the drain
                    # above only proves cleanup finished, not that it
                    # succeeded, and letting this connection return to the
                    # pool unexamined risks the session-level lock still
                    # being held (a later startup would then time out
                    # acquiring it). Invalidating discards the physical
                    # connection instead of pooling it: closing that session
                    # releases a session-scoped advisory lock just as
                    # effectively as an explicit unlock would have.
                    await conn.invalidate()
                    raise cleanup.exception()
    else:
        await asyncio.to_thread(_alembic_upgrade, backend_dir)


def _alembic_upgrade(backend_dir: str) -> None:
    # Passed explicitly from the settings this process locked against, rather
    # than inherited: the lock and the migration must target the same database.
    # There is no override variable, so there is nothing that can disagree.
    #
    # Every DATABASE_* var is cleared first, matched case-insensitively:
    # pydantic-settings' own config source is case-insensitive (Settings never
    # sets case_sensitive=True), so an ambient lowercase or mixed-case var
    # (e.g. database_password_file) is exactly as live a threat as its
    # uppercase form — left unfiltered, it would reach this subprocess
    # alongside the freshly resolved DATABASE_PASSWORD below and trip
    # Settings' own "Set DATABASE_PASSWORD or DATABASE_PASSWORD_FILE, not
    # both" validation.
    env = {
        k: v for k, v in os.environ.items() if not k.upper().startswith("DATABASE_")
    }
    env.update(
        {
            "DATABASE_TYPE": settings.database_type,
            "DATABASE_PORT": str(settings.database_port),
            "DATABASE_SSLMODE": settings.database_sslmode,
        }
    )
    for name, value in (
        ("DATABASE_NAME", settings.database_name),
        ("DATABASE_HOST", settings.database_host),
        ("DATABASE_USER", settings.database_user),
        ("DATABASE_SCHEMA", settings.database_schema),
        ("DATABASE_SSLROOTCERT", settings.database_sslrootcert),
        ("DATABASE_SSLCERT", settings.database_sslcert),
        ("DATABASE_SSLKEY", settings.database_sslkey),
    ):
        # Always set explicitly, never popped: pydantic-settings' own env
        # source only outranks its dotenv source when the key is actually
        # present in os.environ — even as an empty string — but a *missing*
        # key falls through to whatever backend/.env defines (confirmed
        # live). The subprocess's own Settings() construction (triggered
        # when Alembic's env.py imports app.core.config) would otherwise
        # silently pick up a stray or stale dotenv value this process never
        # intended to pass on, even though this process's own settings
        # leave the field unset.
        env[name] = str(value) if value else ""

    # The password is resolved here and passed as a literal so the subprocess
    # need not re-read a secret file it may not have permission to open. Both
    # set explicitly for the same reason as the loop above:
    # DATABASE_PASSWORD_FILE in particular must shadow a dotenv value, or the
    # subprocess re-derives it from backend/.env and trips Settings' own "Set
    # DATABASE_PASSWORD or DATABASE_PASSWORD_FILE, not both" check even
    # though this process already resolved the password.
    env["DATABASE_PASSWORD"] = resolved_password() or ""
    env["DATABASE_PASSWORD_FILE"] = ""

    result = subprocess.run(  # noqa: PLW1510
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=backend_dir,
        capture_output=True,
        text=True,
        env=env,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Alembic migration failed:\n{result.stderr}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _run_migrations()
    await bootstrap_admin()
    yield


async def bootstrap_admin() -> None:
    """Create a default admin user on first run if BOOTSTRAP_ADMIN_PASSWORD is set."""
    if not settings.bootstrap_admin_password:
        return
    from sqlalchemy import select

    from app.core.database import AsyncSessionLocal
    from app.core.security import hash_password
    from app.models import User, UserRole
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(User).where(User.role == UserRole.admin))
        if result.scalar_one_or_none():
            return  # admin already exists
        admin = User(
            email="admin@localhost",
            display_name="Admin",
            hashed_password=hash_password(settings.bootstrap_admin_password),
            role=UserRole.admin,
        )
        db.add(admin)
        await db.commit()
        print("✓ Bootstrap admin created: admin@localhost")


app = FastAPI(
    title=settings.app_title,
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routes
for router in [
    auth.router,
    hosts.router,
    api_keys.router,
    ingest.router,
    alerts.router,
    scans.router,
    config_templates.router,
    cooldown.router,
    dashboard.router,
    users.router,
    system_settings.router,
    scan_options.router,
    repo_scans.router,
    repo_credentials.router,
    findings.router,
]:
    app.include_router(router, prefix="/api")

# Serve React SPA in production (when frontend/dist exists)
FRONTEND_DIST = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
if os.path.isdir(os.path.join(FRONTEND_DIST, "assets")):
    app.mount("/assets", StaticFiles(directory=os.path.join(FRONTEND_DIST, "assets")), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        from fastapi import HTTPException
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(404, "Not found")
        return FileResponse(os.path.join(FRONTEND_DIST, "index.html"))


if __name__ == "__main__":
    # Load .env here (after Settings is already instantiated above) purely to
    # pick up UVICORN_* keys that pydantic-settings intentionally ignores.
    try:
        from dotenv import load_dotenv
        load_dotenv(override=False)
    except ImportError:
        pass

    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=os.getenv("UVICORN_HOST", "127.0.0.1"),
        port=int(os.getenv("UVICORN_PORT", "8000")),
        reload=os.getenv("UVICORN_RELOAD", "").lower() in ("1", "true"),
        timeout_graceful_shutdown=int(os.getenv("UVICORN_TIMEOUT_GRACEFUL_SHUTDOWN", "5")),
    )
