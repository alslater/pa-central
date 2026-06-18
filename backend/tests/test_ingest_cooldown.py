"""Tests for GET /api/ingest/cooldown."""
from datetime import datetime, timezone, timedelta

import pytest
from app.models import CooldownEntry, Ecosystem


def api_key_header(raw: str) -> dict:
    return {"X-API-Key": raw}


@pytest.mark.asyncio
class TestIngestCooldown:
    async def test_returns_fleet_wide_entries(self, client, api_key, db):
        raw, _ = api_key
        entry = CooldownEntry(
            package_name="dodgy-pkg",
            ecosystem=Ecosystem.pypi,
            host_id=None,
            created_by_id=(await _owner_id(api_key)),
        )
        db.add(entry)
        await db.commit()

        r = await client.get(
            "/api/ingest/cooldown?hostname=my-host",
            headers=api_key_header(raw),
        )
        assert r.status_code == 200
        names = [e["package_name"] for e in r.json()]
        assert "dodgy-pkg" in names

    async def test_returns_host_specific_entries(self, client, api_key, db):
        raw, key_obj = api_key
        # Trigger host creation via heartbeat
        await client.post(
            "/api/ingest/heartbeat",
            json={"hostname": "scoped-host"},
            headers=api_key_header(raw),
        )
        from sqlalchemy import select
        from app.models import Host
        result = await db.execute(select(Host).where(Host.hostname == "scoped-host"))
        host = result.scalar_one()

        entry = CooldownEntry(
            package_name="host-only-pkg",
            ecosystem=Ecosystem.pypi,
            host_id=host.id,
            created_by_id=key_obj.user_id,
        )
        db.add(entry)
        await db.commit()

        r = await client.get(
            "/api/ingest/cooldown?hostname=scoped-host",
            headers=api_key_header(raw),
        )
        assert r.status_code == 200
        names = [e["package_name"] for e in r.json()]
        assert "host-only-pkg" in names

    async def test_excludes_other_host_entries(self, client, api_key, db):
        raw, key_obj = api_key
        # Create a host and attach an entry to it
        await client.post(
            "/api/ingest/heartbeat",
            json={"hostname": "other-host"},
            headers=api_key_header(raw),
        )
        from sqlalchemy import select
        from app.models import Host
        result = await db.execute(select(Host).where(Host.hostname == "other-host"))
        other_host = result.scalar_one()

        entry = CooldownEntry(
            package_name="other-host-pkg",
            ecosystem=Ecosystem.pypi,
            host_id=other_host.id,
            created_by_id=key_obj.user_id,
        )
        db.add(entry)
        await db.commit()

        r = await client.get(
            "/api/ingest/cooldown?hostname=different-host",
            headers=api_key_header(raw),
        )
        assert r.status_code == 200
        names = [e["package_name"] for e in r.json()]
        assert "other-host-pkg" not in names

    async def test_excludes_expired_entries(self, client, api_key, db):
        raw, key_obj = api_key
        expired = CooldownEntry(
            package_name="expired-pkg",
            ecosystem=Ecosystem.pypi,
            host_id=None,
            created_by_id=key_obj.user_id,
            expires_at=datetime.now(timezone.utc) - timedelta(days=1),
        )
        db.add(expired)
        await db.commit()

        r = await client.get(
            "/api/ingest/cooldown?hostname=any-host",
            headers=api_key_header(raw),
        )
        assert r.status_code == 200
        names = [e["package_name"] for e in r.json()]
        assert "expired-pkg" not in names

    async def test_includes_non_expired_entries(self, client, api_key, db):
        raw, key_obj = api_key
        active = CooldownEntry(
            package_name="active-pkg",
            ecosystem=Ecosystem.pypi,
            host_id=None,
            created_by_id=key_obj.user_id,
            expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        )
        db.add(active)
        await db.commit()

        r = await client.get(
            "/api/ingest/cooldown?hostname=any-host",
            headers=api_key_header(raw),
        )
        assert r.status_code == 200
        names = [e["package_name"] for e in r.json()]
        assert "active-pkg" in names

    async def test_requires_api_key(self, client):
        r = await client.get("/api/ingest/cooldown?hostname=x")
        assert r.status_code == 401

    async def test_rejects_revoked_key(self, client, api_key, db):
        raw, key_obj = api_key
        key_obj.is_active = False
        await db.commit()
        r = await client.get(
            "/api/ingest/cooldown?hostname=x",
            headers=api_key_header(raw),
        )
        assert r.status_code == 401


async def _owner_id(api_key_fixture) -> int:
    _, key_obj = api_key_fixture
    return key_obj.user_id
