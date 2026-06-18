"""Tests for /api/api-keys endpoints."""
import pytest
from tests.conftest import auth


@pytest.mark.asyncio
class TestListApiKeys:
    async def test_returns_own_keys(self, client, admin_token, api_key):
        r = await client.get("/api/api-keys", headers=auth(admin_token))
        assert r.status_code == 200
        assert len(r.json()) == 1
        assert r.json()[0]["name"] == "test-key"

    async def test_operator_sees_only_own_keys(self, client, operator_token, api_key):
        """api_key belongs to admin; operator should see none."""
        r = await client.get("/api/api-keys", headers=auth(operator_token))
        assert r.status_code == 200
        assert r.json() == []

    async def test_requires_auth(self, client):
        r = await client.get("/api/api-keys")
        assert r.status_code == 401


@pytest.mark.asyncio
class TestCreateApiKey:
    async def test_creates_key_and_returns_raw(self, client, admin_token):
        r = await client.post("/api/api-keys", json={"name": "new-key"}, headers=auth(admin_token))
        assert r.status_code == 201
        data = r.json()
        assert data["name"] == "new-key"
        assert "raw_key" in data
        assert data["raw_key"].startswith("pa_")

    async def test_raw_key_not_returned_on_subsequent_list(self, client, admin_token):
        await client.post("/api/api-keys", json={"name": "k"}, headers=auth(admin_token))
        r = await client.get("/api/api-keys", headers=auth(admin_token))
        for key in r.json():
            assert "raw_key" not in key

    async def test_viewer_can_create_key(self, client, viewer_token):
        """Any authenticated user can create API keys for their own use."""
        r = await client.post("/api/api-keys", json={"name": "viewer-key"}, headers=auth(viewer_token))
        assert r.status_code == 201

    async def test_requires_auth(self, client):
        r = await client.post("/api/api-keys", json={"name": "x"})
        assert r.status_code == 401


@pytest.mark.asyncio
class TestRevokeApiKey:
    async def test_owner_can_revoke_key(self, client, admin_token, api_key):
        _, key_obj = api_key
        r = await client.delete(f"/api/api-keys/{key_obj.id}", headers=auth(admin_token))
        assert r.status_code == 204

        r2 = await client.get("/api/api-keys", headers=auth(admin_token))
        assert r2.json()[0]["is_active"] is False

    async def test_other_user_cannot_revoke_key(self, client, operator_token, api_key):
        _, key_obj = api_key
        r = await client.delete(f"/api/api-keys/{key_obj.id}", headers=auth(operator_token))
        assert r.status_code == 403

    async def test_admin_can_revoke_any_key(self, client, admin_token, db, operator_user):
        from app.core.security import generate_api_key
        from app.models import ApiKey
        raw, hashed = generate_api_key()
        key = ApiKey(name="ops-key", key_hash=hashed, user_id=operator_user.id, is_active=True)
        db.add(key)
        await db.commit()
        await db.refresh(key)

        r = await client.delete(f"/api/api-keys/{key.id}", headers=auth(admin_token))
        assert r.status_code == 204

    async def test_revoke_missing_key_returns_404(self, client, admin_token):
        r = await client.delete("/api/api-keys/999999", headers=auth(admin_token))
        assert r.status_code == 404

    async def test_revoked_key_cannot_authenticate_ingest(self, client, admin_token, api_key):
        """After revocation the raw key must be rejected on ingest endpoints."""
        raw, key_obj = api_key

        # confirm the key works before revocation
        r = await client.post("/api/ingest/heartbeat", json={
            "hostname": "pre-revoke", "daemon_status": "running",
        }, headers={"X-API-Key": raw})
        assert r.status_code == 204

        # revoke it
        r = await client.delete(f"/api/api-keys/{key_obj.id}", headers=auth(admin_token))
        assert r.status_code == 204

        # same key must now be rejected
        r = await client.post("/api/ingest/heartbeat", json={
            "hostname": "post-revoke", "daemon_status": "running",
        }, headers={"X-API-Key": raw})
        assert r.status_code == 401
