"""Tests for /api/users endpoints."""
import pytest
from tests.conftest import auth


@pytest.mark.asyncio
class TestListUsers:
    async def test_admin_can_list_users(self, client, admin_token, admin_user):
        r = await client.get("/api/users", headers=auth(admin_token))
        assert r.status_code == 200
        assert len(r.json()) >= 1

    async def test_non_admin_cannot_list(self, client, viewer_token):
        r = await client.get("/api/users", headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_requires_auth(self, client):
        r = await client.get("/api/users")
        assert r.status_code == 401


@pytest.mark.asyncio
class TestGetUser:
    async def test_admin_can_get_any_user(self, client, admin_token, viewer_user):
        r = await client.get(f"/api/users/{viewer_user.id}", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["email"] == viewer_user.email

    async def test_user_can_get_themselves(self, client, viewer_token, viewer_user):
        r = await client.get(f"/api/users/{viewer_user.id}", headers=auth(viewer_token))
        assert r.status_code == 200

    async def test_user_cannot_get_other_user(self, client, viewer_token, admin_user):
        r = await client.get(f"/api/users/{admin_user.id}", headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_returns_404_for_unknown(self, client, admin_token):
        r = await client.get("/api/users/999999", headers=auth(admin_token))
        assert r.status_code == 404


@pytest.mark.asyncio
class TestUpdateUser:
    async def test_admin_can_change_role(self, client, admin_token, viewer_user):
        r = await client.patch(f"/api/users/{viewer_user.id}", json={
            "role": "operator"
        }, headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["role"] == "operator"

    async def test_admin_can_deactivate_user(self, client, admin_token, viewer_user):
        r = await client.patch(f"/api/users/{viewer_user.id}", json={
            "is_active": False
        }, headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["is_active"] is False

    async def test_user_can_update_own_display_name(self, client, viewer_token, viewer_user):
        r = await client.patch(f"/api/users/{viewer_user.id}", json={
            "display_name": "New Name"
        }, headers=auth(viewer_token))
        assert r.status_code == 200
        assert r.json()["display_name"] == "New Name"

    async def test_non_admin_cannot_change_own_role(self, client, viewer_token, viewer_user):
        """Role field in patch is silently ignored for non-admins."""
        r = await client.patch(f"/api/users/{viewer_user.id}", json={
            "role": "admin"
        }, headers=auth(viewer_token))
        assert r.status_code == 200
        assert r.json()["role"] == "viewer"  # unchanged

    async def test_user_cannot_update_other_user(self, client, viewer_token, admin_user):
        r = await client.patch(f"/api/users/{admin_user.id}", json={
            "display_name": "hacked"
        }, headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_update_missing_user_returns_404(self, client, admin_token):
        r = await client.patch("/api/users/999999", json={"display_name": "x"}, headers=auth(admin_token))
        assert r.status_code == 404

    async def test_non_admin_patching_nonexistent_user_returns_403_not_404(self, client, viewer_token):
        # Non-admin must not learn whether user 999999 exists — always 403
        r = await client.patch("/api/users/999999", json={"display_name": "x"}, headers=auth(viewer_token))
        assert r.status_code == 403
