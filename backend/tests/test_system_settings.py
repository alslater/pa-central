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

    async def test_patch_rejects_non_integer_int_setting(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_port": "not-a-number"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400


@pytest.mark.asyncio
class TestSystemSettingsPositiveIntValidation:
    """sla_high_days/sla_medium_days/finding_retention_days feed
    get_global_sla's parse_int, which silently substitutes a default for any
    stored value < 1 — so a PATCH that accepted 0 or a negative value would
    report success while the effective value at read time diverges from what
    was saved. Regression coverage for the deleted FindingSettingsPut(gt=0)
    validation, now enforced by patch_settings instead."""

    @pytest.mark.parametrize("key", ["sla_high_days", "sla_medium_days", "finding_retention_days"])
    async def test_rejects_zero(self, client, admin_token, key):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {key: "0"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400

    @pytest.mark.parametrize("key", ["sla_high_days", "sla_medium_days", "finding_retention_days"])
    async def test_rejects_negative(self, client, admin_token, key):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {key: "-5"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400

    async def test_accepts_positive_value(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"sla_high_days": "14"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}
        assert settings["sla_high_days"]["value"] == "14"


@pytest.mark.asyncio
class TestSystemSettingsNonNegativeIntValidation:
    """scan_result_retention_days feeds prune_old_results' cutoff
    calculation directly (utcnow() - timedelta(days=...)) with no
    parse_int-style default substitution. A negative value therefore
    computes a cutoff in the *future*, matching and deleting every
    historical scan result — a real, previously-shipped P1. Unlike
    POSITIVE_INT_KEYS above, 0 is a valid, meaningful value here (it
    disables day-based retention), so only negative values are rejected."""

    async def test_rejects_negative_retention_days(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"scan_result_retention_days": "-5"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400

    async def test_rejects_negative_retention_count(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"scan_result_retention_count": "-1"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400

    async def test_accepts_zero_retention_days(self, client, admin_token):
        """0 intentionally disables day-based retention — must remain a valid write."""
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"scan_result_retention_days": "0"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}
        assert settings["scan_result_retention_days"]["value"] == "0"

    async def test_accepts_positive_retention_days(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"scan_result_retention_days": "30"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}
        assert settings["scan_result_retention_days"]["value"] == "30"
