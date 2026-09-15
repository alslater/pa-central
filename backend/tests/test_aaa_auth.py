"""Tests for /api/auth endpoints."""
import pytest

from app.main import app
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

    async def test_login_json_rejects_a_password_over_bcrypt_limit(self, client, admin_user):
        """bcrypt hashes only the first 72 bytes of its input and raises
        ValueError past that. Reproduced before the schema-level guard
        existed: this request reached bcrypt.checkpw() unvalidated and
        crashed with an unhandled 500 instead of a clean validation error."""
        r = await client.post(
            "/api/auth/login",
            json={"email": "admin@example.com", "password": "a" * 100},
        )
        assert r.status_code == 422

    async def test_oauth_token_endpoint_rejects_a_password_over_bcrypt_limit(
        self, client, admin_user
    ):
        """OAuth2PasswordRequestForm is not a Pydantic model this codebase
        controls, so the schema-level guard above cannot reach this
        endpoint — core.security's own length check is what stops it
        reaching bcrypt.checkpw() and crashing here. A too-long password is
        indistinguishable from any other wrong password: 401, not 500 or a
        different error that would disclose the length limit."""
        r = await client.post(
            "/api/auth/token",
            data={"username": "admin@example.com", "password": "a" * 100},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert r.status_code == 401


@pytest.mark.asyncio
class TestMe:
    async def test_me_returns_current_user(self, client, admin_token, admin_user):
        r = await client.get("/api/auth/me", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["email"] == "admin@example.com"
        assert r.json()["role"] == "admin"

    async def test_me_reports_false_for_has_outstanding_welcome_token_even_with_one_stored(
        self, client, db, admin_token, admin_user
    ):
        """Not a bug, unlike GET /users returning this field's bare False
        default for an ORM row (see users.py's user_out): being
        authenticated at all and holding an unused welcome token for that
        SAME account are mutually exclusive by construction — see me()'s
        own comment for the full chain (login_json/login_form only ever
        issue a token to someone who already proved they know the
        account's CURRENT password hash, and a welcome token's only
        purpose is setting that first real password; using it, or an
        admin resetting the password some other way, always retires it
        first). So the real value here is always False regardless of what
        computing it from the DB would say — this test stores a welcome
        token row for the SAME account the bearer token authenticates as
        (a state that cannot arise through any real code path) specifically
        to confirm me() doesn't even attempt to compute it, rather than
        happening to agree by coincidence."""
        from datetime import timedelta

        from app.models import PasswordResetKind, PasswordResetToken, utcnow

        db.add(PasswordResetToken(
            token_hash="me-endpoint-welcome-hash", user_id=admin_user.id,
            kind=PasswordResetKind.welcome,
            expires_at=utcnow() + timedelta(days=1),
        ))
        await db.commit()

        r = await client.get("/api/auth/me", headers=auth(admin_token))
        assert r.status_code == 200
        assert r.json()["has_outstanding_welcome_token"] is False

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

    async def test_register_rejects_a_password_over_the_bcrypt_limit(
        self, client, admin_token
    ):
        """bcrypt hashes only the first 72 bytes of its input and raises
        ValueError past that. Reproduced before this schema-level guard
        existed: this request reached hash_password -> bcrypt.hashpw()
        unvalidated and would have crashed with an unhandled 500 instead of
        a clean 422."""
        r = await client.post("/api/auth/register", json={
            "email": "toolong@example.com", "display_name": "Too Long",
            "password": "a" * 100, "role": "viewer",
        }, headers=auth(admin_token))
        assert r.status_code == 422

    async def test_openapi_documents_the_202_pending_response(self):
        # response.status_code = 202 is set dynamically inside the handler
        # when a welcome-link send is genuinely backgrounded — FastAPI only
        # reflects a status code in the generated schema when it's declared
        # via the route's own `responses=` metadata, so a generated client
        # would otherwise never know to expect anything but the decorator's
        # declared 201 here.
        responses = app.openapi()["paths"]["/api/auth/register"]["post"]["responses"]
        assert "202" in responses
        schema_ref = responses["202"]["content"]["application/json"]["schema"]["$ref"]
        assert schema_ref == responses["201"]["content"]["application/json"]["schema"]["$ref"]


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
