from sqlalchemy import MetaData, event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings
from app.core.db_config import async_connect_args, async_url

_is_sqlite = settings.database_type == "sqlite"


def sqlite_on_connect(dbapi_conn, connection_record) -> None:
    """`connect` listener: set the pragmas a fresh SQLite connection needs.

    A named, module-level function rather than a closure registered inline,
    so a test can attach the exact same logic (not a re-implementation of it)
    to a throwaway engine and prove the pool-checkin behaviour below without
    touching the application's real engine or its database file.
    """
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys = ON")
    # Remember this connection's default lock timeout so anything that
    # narrows it per-transaction can be undone on checkin. Read rather than
    # hardcoded: it comes from the driver's `timeout` argument (sqlite3
    # defaults to 5s), so a future connect_args change stays correct here
    # for free.
    cursor.execute("PRAGMA busy_timeout")
    connection_record.info["default_busy_timeout"] = cursor.fetchone()[0]
    cursor.close()


def sqlite_on_checkin(dbapi_conn, connection_record) -> None:
    """`checkin` listener: restore busy_timeout when a connection returns to
    the pool.

    `PRAGMA busy_timeout` is *connection*-scoped and SQLite has no
    `SET LOCAL`, so a short bound applied per-transaction (e.g. reset-email
    issuance narrowing it to avoid leaking account existence through lock
    contention) outlives the session that set it: pool checkin issues a
    rollback, which does not touch connection-level pragmas. Measured before
    this existed — an unrelated session that later borrowed the same
    connection inherited 500ms instead of the driver's 5000ms default, which
    hands arbitrary application writes that one endpoint's deadline. That is
    the same engine-wide bug a per-transaction pragma exists to avoid,
    arriving by a slower route (leaking through the pool instead of the
    engine's connect_args).

    Restoring here rather than in the session/ORM layer is deliberate: doing
    it there — a `finally` in the issuing code, an endpoint helper, the
    session's own connection — broke ~25 unrelated tests, because the extra
    statement expires the identity map and the next attribute access on a
    held ORM instance becomes a lazy load outside the greenlet
    (MissingGreenlet). This hook runs on the raw DBAPI connection after the
    session is done with it, so there is no identity map to disturb.

    `dbapi_conn` can be `None` here: SQLAlchemy fires `checkin` with it unset
    when the connection was invalidated (e.g. `Connection.invalidate()`, or a
    driver-level disconnect) rather than cleanly returned. There is no
    connection to restore anything on — the pool will open a fresh one next,
    which gets the driver's real default via `sqlite_on_connect` — so this
    is a no-op, not an error.
    """
    if dbapi_conn is None:
        return
    default = connection_record.info.get("default_busy_timeout")
    if default is None:
        return
    cursor = dbapi_conn.cursor()
    cursor.execute(f"PRAGMA busy_timeout = {int(default)}")
    cursor.close()


engine = create_async_engine(
    async_url(),
    echo=settings.debug,
    pool_pre_ping=True,
    connect_args=async_connect_args() | (
        {"check_same_thread": False} if _is_sqlite else {}
    ),
)

if _is_sqlite:
    event.listens_for(engine.sync_engine, "connect")(sqlite_on_connect)
    event.listens_for(engine.sync_engine, "checkin")(sqlite_on_checkin)


AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


class Base(DeclarativeBase):
    # Set only when configured, so the default behaviour (search_path → public)
    # is byte-for-byte what it was before schema support existed.
    metadata = MetaData(schema=settings.database_schema) if settings.database_schema else MetaData()


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    """Create all tables. For production, use Alembic migrations instead."""
    async with engine.begin() as conn:
        import app.models  # noqa — registers all models with Base.metadata
        await conn.run_sync(Base.metadata.create_all)
