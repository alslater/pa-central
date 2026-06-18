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
