"""Tests for /api/auth endpoints."""
import pytest
from tests.conftest import auth


@pytest.mark.asyncio
class TestLogin:
    async def test_login_json_debug_skips_totp(self, client, admin_user):
        # conftest sets DEBUG=true, so login issues a token directly
        r = await client.post("/api/auth/login", json={"email": "admin@example.com", "password": "adminpass"})  # noqa: S106
        assert r.status_code == 200
        assert "access_token" in r.json()

    async def test_login_json_returns_totp_challenge_when_not_debug(self, client, admin_user):
        from app.core.config import settings as app_settings
        original = app_settings.debug
        app_settings.debug = False
        try:
            r = await client.post("/api/auth/login", json={"email": "admin@example.com", "password": "adminpass"})  # noqa: S106
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
        from app.models import User, UserRole
        from app.core.security import hash_password
        u = User(email="inactive@example.com", display_name="X",
                 hashed_password=hash_password("pw"), role=UserRole.viewer, is_active=False)
        db.add(u)
        await db.commit()
        r = await client.post("/api/auth/login", json={"email": "inactive@example.com", "password": "pw"})
        assert r.status_code == 401

    async def test_oauth_token_endpoint(self, client, admin_user):
        r = await client.post(
            "/api/auth/token",
            data={"username": "admin@example.com", "password": "adminpass"},  # noqa: S106
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
