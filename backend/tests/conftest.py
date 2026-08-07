"""
Shared pytest fixtures for the PA Central backend test suite.

Strategy: session-scoped engine with in-memory SQLite. Each test gets a
connection that starts a SAVEPOINT so commits inside fixtures and handlers
write to the DB, but the outer transaction is rolled back after the test.
"""
import os

# Must be set before any app module is imported so the insecure-default guard
# in config.py doesn't fire during test runs.
os.environ.setdefault("DEBUG", "true")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.database import Base, get_db
from app.core.security import create_access_token, generate_api_key, hash_password
from app.main import app
from app.models import ApiKey, Host, User, UserRole

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"


@pytest_asyncio.fixture(scope="session")
async def engine():
    eng = create_async_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(eng.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_conn, _connection_record):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys = ON")
        cursor.close()

    async with eng.begin() as conn:
        import app.models  # noqa
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def db(engine):
    """
    Function-scoped DB session. Wraps each test in a SAVEPOINT so all
    changes (including those committed by the app under test) are rolled
    back after the test without dropping/recreating tables.
    """
    async with engine.connect() as conn:
        await conn.begin()
        # Use a nested transaction (SAVEPOINT) so the app's commits are visible
        # within the test but the outer transaction is rolled back at teardown.
        await conn.begin_nested()

        factory = async_sessionmaker(bind=conn, expire_on_commit=False, class_=AsyncSession)
        async with factory() as session:
            # When the session tries to commit, restart the savepoint so the
            # data is visible for subsequent queries within the same test.
            @event.listens_for(session.sync_session, "after_transaction_end")
            def restart_savepoint(session_, transaction):
                if transaction.nested and not transaction._parent.nested:
                    session_.begin_nested()

            yield session

        await conn.rollback()


@pytest_asyncio.fixture
async def client(db):
    """AsyncClient with the DB dependency overridden to the test session."""
    async def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.pop(get_db, None)


# ── User fixtures ─────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def admin_user(db) -> User:
    user = User(
        email="admin@example.com",
        display_name="Admin",
        hashed_password=hash_password("adminpass"),
        role=UserRole.admin,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest_asyncio.fixture
async def operator_user(db) -> User:
    user = User(
        email="operator@example.com",
        display_name="Operator",
        hashed_password=hash_password("operatorpass"),
        role=UserRole.operator,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest_asyncio.fixture
async def viewer_user(db) -> User:
    user = User(
        email="viewer@example.com",
        display_name="Viewer",
        hashed_password=hash_password("viewerpass"),
        role=UserRole.viewer,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest_asyncio.fixture
async def developer_user(db) -> User:
    user = User(
        email="developer@example.com",
        display_name="Developer",
        hashed_password=hash_password("developerpass"),
        role=UserRole.developer,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


# ── Auth token helpers ────────────────────────────────────────────────────────
# Bypass the login endpoint (which now requires TOTP) by minting tokens directly.

@pytest_asyncio.fixture
async def admin_token(admin_user) -> str:
    return create_access_token(admin_user.id)


@pytest_asyncio.fixture
async def operator_token(operator_user) -> str:
    return create_access_token(operator_user.id)


@pytest_asyncio.fixture
async def viewer_token(viewer_user) -> str:
    return create_access_token(viewer_user.id)


@pytest_asyncio.fixture
async def developer_token(developer_user) -> str:
    return create_access_token(developer_user.id)


def auth(token: str) -> dict:
    """Return Authorization header dict."""
    return {"Authorization": f"Bearer {token}"}


# ── Host / API key fixtures ───────────────────────────────────────────────────

@pytest_asyncio.fixture
async def host(db, admin_user) -> Host:
    h = Host(
        owner_user_id=admin_user.id,
        name="test-host",
        hostname="test-host.local",
    )
    db.add(h)
    await db.commit()
    await db.refresh(h)
    return h


@pytest_asyncio.fixture
async def api_key(db, admin_user) -> tuple[str, ApiKey]:
    """Returns (raw_key, ApiKey ORM object)."""
    raw, hashed = generate_api_key()
    key = ApiKey(
        name="test-key",
        key_hash=hashed,
        user_id=admin_user.id,
        is_active=True,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)
    return raw, key


# Import AWS fixtures so they are available session-wide
from tests.conftest_aws import (  # noqa: F401
    ecs_client,
    localstack,
    secretsmanager,
)
