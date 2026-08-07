"""Tests for GET/PATCH /api/system-settings."""
import pytest

from tests.conftest import auth


@pytest.mark.asyncio
class TestSystemSettings:
    async def test_get_returns_all_settings(self, client, admin_token):
        r = await client.get("/api/system-settings", headers=auth(admin_token))
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    async def test_patch_creates_setting(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"pa_version": "1.2.3"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}
        assert settings["pa_version"]["value"] == "1.2.3"

    async def test_patch_updates_existing_setting(self, client, admin_token):
        await client.patch(
            "/api/system-settings",
            json={"updates": {"pa_version": "1.0.0"}},
            headers=auth(admin_token),
        )
        await client.patch(
            "/api/system-settings",
            json={"updates": {"pa_version": "2.0.0"}},
            headers=auth(admin_token),
        )
        r = await client.get("/api/system-settings", headers=auth(admin_token))
        settings = {s["key"]: s for s in r.json()}
        assert settings["pa_version"]["value"] == "2.0.0"

    async def test_secret_value_redacted_in_get(self, client, admin_token, db):
        from app.models import SettingValueType, SystemSetting
        s = SystemSetting(key="smtp_password", value="encrypted_blob", value_type=SettingValueType.secret)
        db.add(s)
        await db.commit()
        r = await client.get("/api/system-settings", headers=auth(admin_token))
        settings_map = {s["key"]: s for s in r.json()}
        assert settings_map["smtp_password"]["value"] is None

    async def test_requires_admin(self, client, operator_token):
        r = await client.get("/api/system-settings", headers=auth(operator_token))
        assert r.status_code == 403

    async def test_patch_requires_admin(self, client, operator_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"pa_version": "1.0.0"}},
            headers=auth(operator_token),
        )
        assert r.status_code == 403
