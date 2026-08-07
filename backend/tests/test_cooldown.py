"""Tests for /api/cooldown endpoints."""
import pytest

from tests.conftest import auth


@pytest.mark.asyncio
class TestListCooldowns:
    async def test_returns_empty(self, client, admin_token):
        r = await client.get("/api/cooldown", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json() == []

    async def test_requires_auth(self, client):
        r = await client.get("/api/cooldown")
        assert r.status_code == 401

    async def test_filter_fleet_wide(self, client, operator_token, host):
        # Create fleet-wide (no host_id)
        await client.post("/api/cooldown", json={
            "package_name": "flask", "ecosystem": "pypi",
        }, headers=auth(operator_token))
        # Create per-host
        await client.post("/api/cooldown", json={
            "package_name": "django", "ecosystem": "pypi", "host_id": host.id,
        }, headers=auth(operator_token))

        r = await client.get("/api/cooldown?fleet_wide=true", headers=auth(operator_token))
        assert all(e["host_id"] is None for e in r.json())
        assert len(r.json()) == 1

    async def test_filter_by_host_id(self, client, operator_token, host):
        await client.post("/api/cooldown", json={
            "package_name": "pytest", "ecosystem": "pypi", "host_id": host.id,
        }, headers=auth(operator_token))

        r = await client.get(f"/api/cooldown?host_id={host.id}", headers=auth(operator_token))
        assert len(r.json()) >= 1
        assert all(e["host_id"] == host.id for e in r.json())


@pytest.mark.asyncio
class TestCreateCooldown:
    async def test_operator_can_create_fleet_wide(self, client, operator_token):
        r = await client.post("/api/cooldown", json={
            "package_name": "requests",
            "ecosystem": "pypi",
            "note": "known false positive",
        }, headers=auth(operator_token))
        assert r.status_code == 201
        assert r.json()["package_name"] == "requests"
        assert r.json()["host_id"] is None

    async def test_operator_can_create_per_host(self, client, operator_token, host):
        r = await client.post("/api/cooldown", json={
            "package_name": "urllib3",
            "ecosystem": "pypi",
            "host_id": host.id,
        }, headers=auth(operator_token))
        assert r.status_code == 201
        assert r.json()["host_id"] == host.id

    async def test_viewer_cannot_create(self, client, viewer_token):
        r = await client.post("/api/cooldown", json={
            "package_name": "foo", "ecosystem": "pypi",
        }, headers=auth(viewer_token))
        assert r.status_code == 403


@pytest.mark.asyncio
class TestDeleteCooldown:
    async def test_operator_can_delete(self, client, operator_token):
        r = await client.post("/api/cooldown", json={
            "package_name": "to-delete", "ecosystem": "pypi",
        }, headers=auth(operator_token))
        entry_id = r.json()["id"]

        r2 = await client.delete(f"/api/cooldown/{entry_id}", headers=auth(operator_token))
        assert r2.status_code == 204

    async def test_delete_missing_returns_404(self, client, operator_token):
        r = await client.delete("/api/cooldown/999999", headers=auth(operator_token))
        assert r.status_code == 404


@pytest.mark.asyncio
class TestHostDeletionScope:
    """Deleting a host must not broaden the scope of its cooldown entries.

    `host_id IS NULL` means fleet-wide (see the ingest cooldown query), so
    SET NULL on host deletion would silently promote a host-scoped suppression
    into a global one, hiding alerts on hosts that were never allowlisted.

    This exercises the *database* cascade, not the ORM one: deleting the owning
    user cascades user -> host -> cooldown_entries entirely in the DB, where the
    `cascade="all, delete-orphan"` on Host.cooldown_entries never runs. Deleting
    a host through DELETE /api/hosts/{id} is safe either way, because the ORM
    cascade removes the children in Python first.
    """

    async def test_host_scoped_entry_is_deleted_when_host_cascades(self, client, db, admin_token):
        from app.core.security import hash_password
        from app.models import CooldownEntry, Ecosystem, Host, User, UserRole

        owner = User(
            email="cooldown-owner@example.com",
            display_name="CooldownOwner",
            hashed_password=hash_password("password123456"),
            role=UserRole.developer,
        )
        db.add(owner)
        await db.commit()
        await db.refresh(owner)

        owned_host = Host(owner_user_id=owner.id, name="cooldown-host")
        db.add(owned_host)
        await db.commit()
        await db.refresh(owned_host)

        scoped = CooldownEntry(
            package_name="scoped-pkg", ecosystem=Ecosystem.pypi, host_id=owned_host.id,
        )
        fleet = CooldownEntry(
            package_name="fleet-pkg", ecosystem=Ecosystem.pypi, host_id=None,
        )
        db.add_all([scoped, fleet])
        await db.commit()
        scoped_id, fleet_id = scoped.id, fleet.id

        # Deleting the user DB-cascades to the host, and the host to its entries.
        r = await client.delete(f"/api/users/{owner.id}", headers=auth(admin_token))
        assert r.status_code == 204

        await db.run_sync(lambda s: s.expire_all())

        # The scoped entry is gone — not silently converted to fleet-wide.
        assert await db.get(CooldownEntry, scoped_id) is None
        # The genuinely fleet-wide entry is untouched.
        surviving = await db.get(CooldownEntry, fleet_id)
        assert surviving is not None
        assert surviving.host_id is None
