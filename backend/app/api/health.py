"""Unauthenticated liveness/health endpoints for ALB/ECS.

See AWS_FARGATE_DEPLOYMENT.md §8: /ping is the sole signal ECS/ALB gate
deployments and routing on; /health is informational only, never wired into
a pass/fail gate — see each schema's own docstring in app/schemas for why.
"""
import logging

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.schemas import HealthOut, PingOut

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/ping", response_model=PingOut)
async def ping() -> PingOut:
    return PingOut()


@router.get("/health", response_model=HealthOut)
async def health(db: AsyncSession = Depends(get_db)) -> HealthOut:
    try:
        await db.execute(text("SELECT 1"))
        database = "ok"
    except (SQLAlchemyError, OSError):
        # SQLAlchemyError covers a failure once a connection is already
        # established (bad query, auth rejected, DB error) — the driver
        # wraps those. A failure to establish the connection at all
        # (refused, DNS failure, connect timeout) is NOT wrapped: asyncpg
        # raises the raw OSError subclass (ConnectionRefusedError,
        # socket.gaierror, TimeoutError) straight through, confirmed by
        # reproducing a refused connection directly against this engine.
        # Catching only SQLAlchemyError let exactly that case escape as an
        # unhandled 500 instead of the promised 200/"unreachable".
        logger.exception("Health check: database unreachable")
        database = "unreachable"
    return HealthOut(database=database)
