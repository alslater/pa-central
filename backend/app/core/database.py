from sqlalchemy import MetaData, event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings
from app.core.db_config import async_connect_args, async_url

_is_sqlite = settings.database_type == "sqlite"

engine = create_async_engine(
    async_url(),
    echo=settings.debug,
    pool_pre_ping=True,
    connect_args=async_connect_args() | (
        {"check_same_thread": False} if _is_sqlite else {}
    ),
)

if _is_sqlite:
    @event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

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
