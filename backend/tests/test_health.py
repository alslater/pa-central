"""Tests for GET /ping and GET /health.

Both are unauthenticated by design (an ALB/ECS health check carries no
bearer token) and live outside the /api prefix — see
AWS_FARGATE_DEPLOYMENT.md §8 and app/api/health.py's own module docstring
for why /ping (pure liveness) and /health (DB reachability, informational
only) are deliberately different checks with different consumers.
"""
import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.core.database import get_db
from app.main import app


@pytest.mark.asyncio
class TestPing:
    async def test_returns_ok_with_no_auth(self, client):
        r = await client.get("/ping")
        assert r.status_code == 200
        assert r.json() == {"status": "ok"}

    async def test_not_mounted_under_api_prefix(self, client):
        r = await client.get("/api/ping")
        assert r.status_code == 404


@pytest.mark.asyncio
class TestHealth:
    async def test_returns_ok_with_no_auth_when_db_reachable(self, client):
        r = await client.get("/health")
        assert r.status_code == 200
        assert r.json() == {"status": "ok", "database": "ok"}

    async def test_still_returns_200_when_a_statement_fails_on_an_established_connection(self, client):
        # A DB outage must not fail this check — see HealthOut's own
        # docstring for why: this endpoint is informational, never a
        # deploy/routing gate, so a human/monitoring system reading the
        # body sees the real state without also tripping an ALB/ECS
        # pass/fail check that would take a live process out of rotation.
        # SQLAlchemyError is what the driver wraps a failure in once a
        # connection is already established (bad query, auth rejected).
        class BrokenSession:
            async def execute(self, *args, **kwargs):
                raise SQLAlchemyError("simulated statement failure")

        async def override_db():
            yield BrokenSession()

        app.dependency_overrides[get_db] = override_db
        try:
            r = await client.get("/health")
        finally:
            app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 200
        assert r.json() == {"status": "ok", "database": "unreachable"}

    async def test_still_returns_200_when_the_connection_itself_cannot_be_established(self, client):
        # Regression: a failure to establish the connection AT ALL (refused,
        # DNS failure, connect timeout) is not wrapped in SQLAlchemyError —
        # asyncpg raises the raw OSError subclass straight through.
        # Reproduced directly against a real engine pointed at a refused
        # port: connecting to postgresql+asyncpg://.../db on a port nothing
        # listens on raises builtins.ConnectionRefusedError, not any
        # sqlalchemy.exc type. Catching only SQLAlchemyError let exactly
        # this escape as an unhandled 500 instead of the promised 200.
        class UnreachableSession:
            async def execute(self, *args, **kwargs):
                raise ConnectionRefusedError("simulated connection refused")

        async def override_db():
            yield UnreachableSession()

        app.dependency_overrides[get_db] = override_db
        try:
            r = await client.get("/health")
        finally:
            app.dependency_overrides.pop(get_db, None)

        assert r.status_code == 200
        assert r.json() == {"status": "ok", "database": "unreachable"}

    async def test_not_mounted_under_api_prefix(self, client):
        r = await client.get("/api/health")
        assert r.status_code == 404
