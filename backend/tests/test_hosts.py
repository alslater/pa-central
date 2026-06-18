"""Tests for /api/hosts endpoints."""
import pytest
from tests.conftest import auth


@pytest.mark.asyncio
class TestListHosts:
    async def test_returns_empty_list_when_no_hosts(self, client, admin_token):
        r = await client.get("/api/hosts", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json() == []

    async def test_returns_hosts(self, client, admin_token, host):
        r = await client.get("/api/hosts", headers=auth(admin_token))
        assert r.status_code == 200
        names = [h["name"] for h in r.json()]
        assert "test-host" in names

    async def test_requires_auth(self, client):
        r = await client.get("/api/hosts")
        assert r.status_code == 401

    async def test_non_admin_sees_only_own_hosts(self, client, operator_token, operator_user, host, db):
        """Hosts owned by the admin should not appear for the operator."""
        r = await client.get("/api/hosts", headers=auth(operator_token))
        assert r.status_code == 200
        assert r.json() == []

    async def test_admin_sees_all_hosts(self, client, admin_token, host):
        r = await client.get("/api/hosts", headers=auth(admin_token))
        assert r.status_code == 200
        assert len(r.json()) >= 1


@pytest.mark.asyncio
class TestGetHost:
    async def test_returns_host_by_id(self, client, admin_token, host):
        r = await client.get(f"/api/hosts/{host.id}", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["name"] == "test-host"

    async def test_returns_404_for_unknown_host(self, client, admin_token):
        r = await client.get("/api/hosts/999999", headers=auth(admin_token))
        assert r.status_code == 404

    async def test_requires_auth(self, client, host):
        r = await client.get(f"/api/hosts/{host.id}")
        assert r.status_code == 401


@pytest.mark.asyncio
class TestUpdateHost:
    async def test_operator_cannot_update_admin_owned_host(self, client, operator_token, host):
        # host is owned by admin — operator must get 404, not 200
        r = await client.patch(
            f"/api/hosts/{host.id}",
            json={"description": "updated"},
            headers=auth(operator_token),
        )
        assert r.status_code == 404

    async def test_operator_can_update_own_host(self, client, operator_token, operator_user, db):
        from app.models import Host
        own_host = Host(
            owner_user_id=operator_user.id,
            name="operator-host",
            hostname="operator-host.local",
        )
        db.add(own_host)
        await db.commit()
        await db.refresh(own_host)
        r = await client.patch(
            f"/api/hosts/{own_host.id}",
            json={"description": "updated by owner"},
            headers=auth(operator_token),
        )
        assert r.status_code == 200
        assert r.json()["description"] == "updated by owner"

    async def test_update_tags(self, client, admin_token, host):
        r = await client.patch(
            f"/api/hosts/{host.id}",
            json={"tags": ["prod", "eu"]},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        assert r.json()["tags"] == ["prod", "eu"]

    async def test_viewer_cannot_update(self, client, viewer_token, host):
        r = await client.patch(
            f"/api/hosts/{host.id}",
            json={"description": "nope"},
            headers=auth(viewer_token),
        )
        assert r.status_code == 403

    async def test_update_missing_host_returns_404(self, client, admin_token):
        r = await client.patch(
            "/api/hosts/999999",
            json={"description": "x"},
            headers=auth(admin_token),
        )
        assert r.status_code == 404


@pytest.mark.asyncio
class TestDeleteHost:
    async def test_admin_can_delete_host(self, client, admin_token, host):
        r = await client.delete(f"/api/hosts/{host.id}", headers=auth(admin_token))
        assert r.status_code == 204
        r2 = await client.get(f"/api/hosts/{host.id}", headers=auth(admin_token))
        assert r2.status_code == 404

    async def test_operator_cannot_delete_host(self, client, operator_token, host):
        r = await client.delete(f"/api/hosts/{host.id}", headers=auth(operator_token))
        assert r.status_code == 403

    async def test_delete_missing_host_returns_404(self, client, admin_token):
        r = await client.delete("/api/hosts/999999", headers=auth(admin_token))
        assert r.status_code == 404
