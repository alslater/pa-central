"""PA Central — central management server for package-alert installations."""
import asyncio
import os
import subprocess
import sys
from contextlib import asynccontextmanager

from sqlalchemy import text

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.core.config import settings
from app.core.database import init_db
from app.api import auth, hosts, api_keys, ingest, alerts, scans, config_templates, cooldown, dashboard, users, system_settings, repo_scans, repo_credentials


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
        await init_db()
        return

    db_url = str(settings.database_url)
    is_postgres = db_url.startswith("postgresql")

    # Advisory lock ID — "pacmig" as int
    _MIGRATION_LOCK_ID = 0x7061636D6967

    if is_postgres:
        # Hold a single raw connection open for the entire lock window.
        # pg_advisory_lock is session-scoped: the lock is released when the
        # connection closes, so we must not close it until after migrations finish.
        async with engine.connect() as conn:
            # Spin-wait with pg_try_advisory_lock so we don't block the event loop.
            while True:
                result = await conn.execute(
                    text("SELECT pg_try_advisory_lock(:id)"),
                    {"id": _MIGRATION_LOCK_ID},
                )
                if result.scalar():
                    break
                await asyncio.sleep(0.5)

            try:
                await asyncio.to_thread(_alembic_upgrade, backend_dir)
            finally:
                await conn.execute(
                    text("SELECT pg_advisory_unlock(:id)"),
                    {"id": _MIGRATION_LOCK_ID},
                )
    else:
        await asyncio.to_thread(_alembic_upgrade, backend_dir)


def _alembic_upgrade(backend_dir: str) -> None:
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=backend_dir,
        capture_output=True,
        text=True,
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
    repo_scans.router,
    repo_credentials.router,
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
