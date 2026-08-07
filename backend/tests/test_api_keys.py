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
class TestApiKeyOwnerDisplayName:
    """`owner_display_name` is joined in from ApiKey.user via selectinload.

    The relationship is accessed while building the response, so dropping the
    eager load turns it into an implicit lazy load — which raises MissingGreenlet
    under async SQLAlchemy. These tests expire the identity map before the
    request so the relationship genuinely has to be fetched; without that the
    fixture-created User is already cached and a missing selectinload goes
    unnoticed.
    """

    async def test_admin_sees_all_keys_with_correct_owner_each(
        self, client, db, admin_token, admin_user, operator_user, api_key
    ):
        from app.core.security import generate_api_key
        from app.models import ApiKey

        _raw, key_hash = generate_api_key()
        db.add(ApiKey(name="operator-key", key_hash=key_hash, user_id=operator_user.id))
        await db.commit()

        await db.run_sync(lambda s: s.expire_all())

        r = await client.get("/api/api-keys", headers=auth(admin_token))
        assert r.status_code == 200
        by_name = {k["name"]: k["owner_display_name"] for k in r.json()}
        # Admin sees both users' keys, each attributed to its own owner.
        assert by_name == {
            "test-key": admin_user.display_name,
            "operator-key": operator_user.display_name,
        }

    async def test_non_admin_sees_only_own_key_with_owner_populated(
        self, client, db, operator_token, operator_user, api_key
    ):
        from app.core.security import generate_api_key
        from app.models import ApiKey

        _raw, key_hash = generate_api_key()
        db.add(ApiKey(name="operator-key", key_hash=key_hash, user_id=operator_user.id))
        await db.commit()

        await db.run_sync(lambda s: s.expire_all())

        r = await client.get("/api/api-keys", headers=auth(operator_token))
        assert r.status_code == 200
        body = r.json()
        # api_key belongs to admin and must be filtered out.
        assert [k["name"] for k in body] == ["operator-key"]
        # Scope + populated owner only. This case cannot detect a missing eager
        # load: a non-admin sees only their own keys, and authenticating already
        # cached that User — see the third-party test below for that guard.
        assert body[0]["owner_display_name"] == operator_user.display_name
        assert body[0]["owner_display_name"] != ""

    async def test_owner_loaded_eagerly_for_another_users_key(
        self, client, db, admin_token, viewer_user
    ):
        """Guards the selectinload: fails with MissingGreenlet if it is removed.

        The key must belong to someone *other* than the caller. Authenticating
        loads the caller's own User into the identity map, so a key owned by the
        admin resolves from cache even with no eager load — only a third party's
        key forces real IO. expire_all() then drops the fixture-created User so
        the relationship cannot be served from cache either.
        """
        from app.core.security import generate_api_key
        from app.models import ApiKey

        _raw, key_hash = generate_api_key()
        db.add(ApiKey(name="viewer-key", key_hash=key_hash, user_id=viewer_user.id))
        await db.commit()
        expected = viewer_user.display_name

        await db.run_sync(lambda s: s.expire_all())

        r = await client.get("/api/api-keys", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()[0]["owner_display_name"] == expected


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
        _raw, hashed = generate_api_key()
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
