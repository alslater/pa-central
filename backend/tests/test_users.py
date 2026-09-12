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

    async def test_password_over_the_bcrypt_limit_is_rejected(
        self, client, db, admin_token, viewer_user
    ):
        """bcrypt hashes only the first 72 bytes of its input and raises
        ValueError past that. Reproduced before this schema-level guard
        existed: this request reached set_password -> hash_password ->
        bcrypt.hashpw() unvalidated and would have crashed with an
        unhandled 500 instead of a clean 422."""
        original_hash = viewer_user.hashed_password
        r = await client.patch(f"/api/users/{viewer_user.id}", json={
            "password": "a" * 100,
        }, headers=auth(admin_token))
        assert r.status_code == 422

        await db.refresh(viewer_user)
        assert viewer_user.hashed_password == original_hash

    async def test_changing_own_password_returns_a_replacement_access_token(
        self, client, db, viewer_token, viewer_user
    ):
        """set_password bumps token_epoch on every password change (see its
        own docstring: this is what makes a change actually revoke sessions
        already issued) — which invalidates the very bearer token that just
        authenticated this request when caller and target are the same
        account. Without a replacement, the caller's next API call 401s
        with nothing telling the frontend that was coming. Reproduced
        before this fix: this exact request returned 200 with a plain
        UserOut body, and the next request using the same token 401ed."""
        r = await client.patch(f"/api/users/{viewer_user.id}", json={
            "password": "a-brand-new-password",
        }, headers=auth(viewer_token))
        assert r.status_code == 200
        body = r.json()
        assert "access_token" in body
        assert isinstance(body["access_token"], str) and body["access_token"]

        # The new token authenticates future requests...
        r2 = await client.get(f"/api/users/{viewer_user.id}", headers=auth(body["access_token"]))
        assert r2.status_code == 200

        # ...while the token that authenticated the PATCH itself is now
        # rejected, exactly the failure mode this fix exists to warn about.
        r3 = await client.get(f"/api/users/{viewer_user.id}", headers=auth(viewer_token))
        assert r3.status_code == 401

    async def test_admin_changing_anothers_password_does_not_return_a_token(
        self, client, admin_token, viewer_user
    ):
        """The admin's own session is untouched by resetting someone
        *else's* password — token_epoch only changes on the target
        account, not the caller's — so there is nothing to replace and the
        response must stay a plain UserOut."""
        r = await client.patch(f"/api/users/{viewer_user.id}", json={
            "password": "a-brand-new-password",
        }, headers=auth(admin_token))
        assert r.status_code == 200
        assert "access_token" not in r.json()

        # The admin's own token still works — nothing about their session
        # was affected by resetting a different account's password.
        r2 = await client.get("/api/users", headers=auth(admin_token))
        assert r2.status_code == 200

    async def test_admin_changing_own_password_returns_a_replacement_token(
        self, client, admin_token, admin_user
    ):
        """The same self-change case, but for an admin acting on their own
        account through this endpoint rather than the non-admin path above
        — current.id == user_id is what matters, not the caller's role."""
        r = await client.patch(f"/api/users/{admin_user.id}", json={
            "password": "a-brand-new-password",
        }, headers=auth(admin_token))
        assert r.status_code == 200
        assert "access_token" in r.json()

        r2 = await client.get("/api/users", headers=auth(admin_token))
        assert r2.status_code == 401

    async def test_changing_display_name_only_does_not_return_a_token(
        self, client, viewer_token, viewer_user
    ):
        """No password change means no epoch bump — the caller's existing
        token is still valid, so there is nothing to replace."""
        r = await client.patch(f"/api/users/{viewer_user.id}", json={
            "display_name": "New Name",
        }, headers=auth(viewer_token))
        assert r.status_code == 200
        assert "access_token" not in r.json()

        r2 = await client.get(f"/api/users/{viewer_user.id}", headers=auth(viewer_token))
        assert r2.status_code == 200


@pytest.mark.asyncio
class TestResetPassword:
    async def test_requires_auth(self, client, viewer_user):
        r = await client.post(f"/api/users/{viewer_user.id}/reset-password")
        assert r.status_code == 401

    async def test_non_admin_forbidden(self, client, viewer_token, admin_user):
        r = await client.post(f"/api/users/{admin_user.id}/reset-password", headers=auth(viewer_token))
        assert r.status_code == 403

    async def test_admin_can_reset(self, client, admin_token, viewer_user):
        r = await client.post(f"/api/users/{viewer_user.id}/reset-password", headers=auth(admin_token))
        assert r.status_code == 200
        new_password = r.json()["password"]
        assert len(new_password) >= 12

        login = await client.post("/api/auth/login", json={
            "email": viewer_user.email, "password": new_password,
        })
        assert login.status_code == 200

    async def test_returns_404_for_unknown(self, client, admin_token):
        r = await client.post("/api/users/999999/reset-password", headers=auth(admin_token))
        assert r.status_code == 404
