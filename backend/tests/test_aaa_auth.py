"""Tests for /api/auth endpoints."""
import pytest

from tests.conftest import auth


@pytest.mark.asyncio
class TestLogin:
    async def test_login_json_debug_skips_totp(self, client, admin_user):
        # conftest sets DEBUG=true, so login issues a token directly
        r = await client.post("/api/auth/login", json={"email": "admin@example.com", "password": "adminpass"})
        assert r.status_code == 200
        assert "access_token" in r.json()

    async def test_login_json_returns_totp_challenge_when_not_debug(self, client, admin_user):
        from app.core.config import settings as app_settings
        original = app_settings.debug
        app_settings.debug = False
        try:
            r = await client.post("/api/auth/login", json={"email": "admin@example.com", "password": "adminpass"})
            assert r.status_code == 200
            data = r.json()
            assert data["totp_required"] is True
            assert "totp_session_token" in data
        finally:
            app_settings.debug = original

    async def test_login_wrong_password_returns_401(self, client, admin_user):
        r = await client.post("/api/auth/login", json={"email": "admin@example.com", "password": "wrong"})
        assert r.status_code == 401

    async def test_login_unknown_email_returns_401(self, client):
        r = await client.post("/api/auth/login", json={"email": "nobody@example.com", "password": "x"})
        assert r.status_code == 401

    async def test_login_disabled_user_returns_401(self, client, db):
        from app.core.security import hash_password
        from app.models import User, UserRole
        u = User(email="inactive@example.com", display_name="X",
                 hashed_password=hash_password("pw"), role=UserRole.viewer, is_active=False)
        db.add(u)
        await db.commit()
        r = await client.post("/api/auth/login", json={"email": "inactive@example.com", "password": "pw"})
        assert r.status_code == 401

    async def test_oauth_token_endpoint(self, client, admin_user):
        r = await client.post(
            "/api/auth/token",
            data={"username": "admin@example.com", "password": "adminpass"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert r.status_code == 200
        assert "access_token" in r.json()


@pytest.mark.asyncio
class TestMe:
    async def test_me_returns_current_user(self, client, admin_token, admin_user):
        r = await client.get("/api/auth/me", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["email"] == "admin@example.com"
        assert r.json()["role"] == "admin"

    async def test_me_requires_auth(self, client):
        r = await client.get("/api/auth/me")
        assert r.status_code == 401

    async def test_me_rejects_invalid_token(self, client):
        r = await client.get("/api/auth/me", headers=auth("garbage.token.here"))
        assert r.status_code == 401


@pytest.mark.asyncio
class TestRegister:
    async def test_admin_can_create_user(self, client, admin_token):
        r = await client.post("/api/auth/register", json={
            "email": "new@example.com", "display_name": "New", "password": "Password1!abcd", "role": "viewer"
        }, headers=auth(admin_token))
        assert r.status_code == 201, r.text
        assert r.json()["email"] == "new@example.com"

    async def test_register_duplicate_email_returns_409(self, client, admin_token, admin_user):
        r = await client.post("/api/auth/register", json={
            "email": "admin@example.com", "display_name": "Dup", "password": "Password1!abcd", "role": "viewer"
        }, headers=auth(admin_token))
        assert r.status_code == 409

    async def test_non_admin_cannot_register(self, client, viewer_token):
        r = await client.post("/api/auth/register", json={
            "email": "sneaky@example.com", "display_name": "S", "password": "Password1!abcd", "role": "viewer"
        }, headers=auth(viewer_token))
        assert r.status_code == 403


@pytest.mark.asyncio
class TestDeleteUser:
    async def test_admin_can_delete_user(self, client, db, admin_token):
        from app.core.security import hash_password
        from app.models import User, UserRole
        target = User(email="todelete@example.com", display_name="Del", hashed_password=hash_password("password123456"), role=UserRole.viewer)
        db.add(target)
        await db.commit()
        await db.refresh(target)
        r = await client.delete(f"/api/users/{target.id}", headers=auth(admin_token))
        assert r.status_code == 204
        gone = await db.get(User, target.id)
        assert gone is None

    async def test_admin_cannot_delete_self(self, client, admin_user, admin_token):
        r = await client.delete(f"/api/users/{admin_user.id}", headers=auth(admin_token))
        assert r.status_code == 403

    async def test_delete_nonexistent_returns_404(self, client, admin_token):
        r = await client.delete("/api/users/999999", headers=auth(admin_token))
        assert r.status_code == 404

    async def test_unauthenticated_delete_returns_401(self, client, admin_user):
        r = await client.delete(f"/api/users/{admin_user.id}")
        assert r.status_code == 401

    async def test_non_admin_delete_returns_403(self, client, admin_user, viewer_token):
        r = await client.delete(f"/api/users/{admin_user.id}", headers=auth(viewer_token))
        assert r.status_code == 403


@pytest.mark.asyncio
class TestResetTotp:
    async def test_admin_can_reset_totp(self, client, db, admin_token):
        from app.core.security import hash_password
        from app.models import User, UserRole
        target = User(email="totp@example.com", display_name="TOTP", hashed_password=hash_password("password123456"), role=UserRole.viewer, totp_secret="SOMESECRET", totp_enabled=True)
        db.add(target)
        await db.commit()
        await db.refresh(target)
        r = await client.post(f"/api/users/{target.id}/reset-totp", headers=auth(admin_token))
        assert r.status_code == 200
        data = r.json()
        assert data["totp_enabled"] is False
        await db.refresh(target)
        assert target.totp_secret is None
        assert target.totp_enabled is False

    async def test_reset_totp_nonexistent_returns_404(self, client, admin_token):
        r = await client.post("/api/users/999999/reset-totp", headers=auth(admin_token))
        assert r.status_code == 404

    async def test_unauthenticated_reset_totp_returns_401(self, client, admin_user):
        r = await client.post(f"/api/users/{admin_user.id}/reset-totp")
        assert r.status_code == 401

    async def test_non_admin_reset_totp_returns_403(self, client, admin_user, viewer_token):
        r = await client.post(f"/api/users/{admin_user.id}/reset-totp", headers=auth(viewer_token))
        assert r.status_code == 403


@pytest.mark.asyncio
class TestDeleteUserCascade:
    """Verify deleting a user with owned hosts and deep dependent data succeeds.

    The delete chain is:
      user → host (CASCADE) → alerts, scans, config_assignments (CASCADE)
      user → api_keys (ORM cascade)
    If any FK in this chain lacks ondelete the endpoint returns 500 on
    PostgreSQL and leaves orphans on SQLite (FK pragma on).
    """

    async def test_delete_user_with_associated_data_succeeds(self, client, db, admin_token):
        from app.core.security import generate_api_key, hash_password
        from app.models import (
            Alert,
            AlertKind,
            AlertSeverity,
            ApiKey,
            ConfigTemplate,
            CooldownEntry,
            Ecosystem,
            Host,
            RepoScan,
            User,
            UserRole,
        )

        owner = User(
            email="cascade-owner@example.com",
            display_name="CascadeOwner",
            hashed_password=hash_password("password123456"),
            role=UserRole.developer,
        )
        db.add(owner)
        await db.commit()
        await db.refresh(owner)

        _raw, key_hash = generate_api_key()
        api_key = ApiKey(name="owner-key", key_hash=key_hash, user_id=owner.id)
        host = Host(owner_user_id=owner.id, name="cascade-host")
        config = ConfigTemplate(
            name="cascade-tmpl",
            toml_content="[sources]\npypi = true\n",
            created_by_id=owner.id,
        )
        cooldown = CooldownEntry(
            package_name="requests",
            ecosystem=Ecosystem.pypi,
            created_by_id=owner.id,
        )
        repo_scan = RepoScan(
            name="cascade-scan",
            url="https://github.com/example/repo",
            created_by_id=owner.id,
        )
        db.add_all([api_key, host, config, cooldown, repo_scan])
        await db.commit()
        await db.refresh(host)

        # Attach an alert to the host — this is the deep FK that previously caused
        # a violation (alerts.host_id had no ondelete clause).
        alert = Alert(
            host_id=host.id,
            package_name="requests",
            ecosystem=Ecosystem.pypi,
            kind=AlertKind.osv,
            severity=AlertSeverity.high,
        )
        db.add(alert)
        await db.commit()
        alert_id = alert.id
        api_key_id = api_key.id
        owner_id = owner.id

        # Delete should succeed through the full cascade chain.
        r = await client.delete(f"/api/users/{owner_id}", headers=auth(admin_token))
        assert r.status_code == 204

        # Expire the identity map so subsequent gets hit the DB, not the cache.
        await db.run_sync(lambda s: s.expire_all())

        # User row is gone.
        assert await db.get(User, owner_id) is None

        # ApiKey deleted via ORM cascade="all, delete-orphan" on User.api_keys.
        assert await db.get(ApiKey, api_key_id) is None

        # Alert deleted transitively: user→host CASCADE, host→alert CASCADE.
        assert await db.get(Alert, alert_id) is None
