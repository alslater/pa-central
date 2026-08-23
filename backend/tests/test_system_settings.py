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


@pytest.mark.asyncio
class TestSystemSettingsRuntimeDefaults:
    """sla_high_days/sla_medium_days/finding_retention_days have no row in
    system_settings on a fresh database, but get_global_sla() still applies
    a numeric default (14/90/365) for each — the application is actively
    using that value even though nothing was ever saved. Without
    synthesizing these into the GET response, the settings page renders
    blank fields for values that are genuinely in effect, giving an admin no
    way to see the real configuration short of reading source code.

    scan_result_retention_days/_count are deliberately excluded from this:
    absence there means "no day/count-based pruning" — a real, meaningful
    state, not a hidden number — so they are not synthesized."""

    async def test_absent_sla_and_retention_keys_are_synthesized_as_defaults(self, client, admin_token):
        from app.services.finding_lifecycle import (
            DEFAULT_FINDING_RETENTION,
            DEFAULT_SLA_HIGH,
            DEFAULT_SLA_MEDIUM,
        )
        r = await client.get("/api/system-settings", headers=auth(admin_token))
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}

        for key, expected in (
            ("sla_high_days", DEFAULT_SLA_HIGH),
            ("sla_medium_days", DEFAULT_SLA_MEDIUM),
            ("finding_retention_days", DEFAULT_FINDING_RETENTION),
        ):
            assert key in settings, f"{key} missing from response entirely"
            assert settings[key]["value"] == str(expected)
            assert settings[key]["is_default"] is True
            assert settings[key]["updated_at"] is None

    async def test_scan_result_retention_keys_are_not_synthesized(self, client, admin_token):
        """Absence here means retention is disabled, not "using a default
        number" — synthesizing a fake value would misrepresent that."""
        r = await client.get("/api/system-settings", headers=auth(admin_token))
        settings = {s["key"]: s for s in r.json()}
        assert "scan_result_retention_days" not in settings
        assert "scan_result_retention_count" not in settings

    async def test_saved_value_suppresses_the_synthesized_default(self, client, admin_token):
        await client.patch(
            "/api/system-settings",
            json={"updates": {"sla_high_days": "21"}},
            headers=auth(admin_token),
        )
        r = await client.get("/api/system-settings", headers=auth(admin_token))
        settings = {s["key"]: s for s in r.json()}
        assert settings["sla_high_days"]["value"] == "21"
        assert settings["sla_high_days"]["is_default"] is False
        assert settings["sla_high_days"]["updated_at"] is not None

    async def test_saving_one_default_key_does_not_suppress_the_others(self, client, admin_token):
        await client.patch(
            "/api/system-settings",
            json={"updates": {"sla_high_days": "21"}},
            headers=auth(admin_token),
        )
        r = await client.get("/api/system-settings", headers=auth(admin_token))
        settings = {s["key"]: s for s in r.json()}
        assert settings["sla_medium_days"]["is_default"] is True
        assert settings["finding_retention_days"]["is_default"] is True

    async def test_clearing_a_saved_value_restores_the_synthesized_default(self, client, admin_token, db):
        """P2 regression: PATCH with value=null previously left a row behind
        with value=NULL. present_keys only checked key membership, not
        whether value was non-NULL, so get_settings() treated that row as
        "already saved" and never re-synthesized the default — the field
        rendered blank forever after, even though parse_int() (which treats
        NULL exactly like an absent key) is still actively applying 14 at
        runtime. Clearing the key must now delete the row so the next GET
        re-synthesizes it, not leave a NULL row masking the default."""
        await client.patch(
            "/api/system-settings",
            json={"updates": {"sla_high_days": "21"}},
            headers=auth(admin_token),
        )
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"sla_high_days": None}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}
        assert settings["sla_high_days"]["value"] == "14"
        assert settings["sla_high_days"]["is_default"] is True
        assert settings["sla_high_days"]["updated_at"] is None

        # Confirm at the row level, not just via the redacted response: no
        # row should exist at all, not one with value=NULL.
        from app.models import SystemSetting
        row = await db.get(SystemSetting, "sla_high_days")
        assert row is None

        # A second, independent GET must show the same thing — this is the
        # part the bug actually broke (a stale in-memory response looking
        # right by coincidence would not have caught it).
        r2 = await client.get("/api/system-settings", headers=auth(admin_token))
        settings2 = {s["key"]: s for s in r2.json()}
        assert settings2["sla_high_days"]["value"] == "14"
        assert settings2["sla_high_days"]["is_default"] is True

    async def test_clearing_a_key_that_was_never_saved_stays_absent_from_the_row_table(
        self, client, admin_token, db
    ):
        """Clearing a default-bearing key that has no existing row (e.g. the
        admin loaded the page, saw the default, and "saved" it as empty
        without ever having set a value) must not create a NULL row either."""
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"sla_medium_days": None}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}
        assert settings["sla_medium_days"]["value"] == "90"
        assert settings["sla_medium_days"]["is_default"] is True

        from app.models import SystemSetting
        row = await db.get(SystemSetting, "sla_medium_days")
        assert row is None

    async def test_clearing_a_non_default_key_still_saves_a_null_row(self, client, admin_token, db):
        """Scoped fix: only the three RUNTIME_DEFAULTS keys get the
        delete-on-clear behaviour. Every other setting keeps saving a
        value=NULL row (preserving updated_at/updated_by_id as a record of
        who cleared it and when), matching the pre-existing behaviour."""
        await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_host": "smtp.example.com"}},
            headers=auth(admin_token),
        )
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_host": None}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200

        from app.models import SystemSetting
        row = await db.get(SystemSetting, "smtp_host")
        assert row is not None
        assert row.value is None
        assert row.updated_by_id is not None

    async def test_preexisting_null_row_still_reads_back_as_the_default(self, client, admin_token, db):
        """P2 regression: patch_settings' delete-on-clear only prevents new
        NULL rows from being created — it does nothing for a row that was
        already left in that shape by an older version of this code (or any
        other write path), since _list_settings_with_defaults previously
        only checked key *presence*, not whether the persisted value was
        actually non-NULL. Simulates that pre-existing data directly (not
        through the API, since the current PATCH path no longer produces
        this shape) and confirms it still reads back as the default rather
        than a stale blank field."""
        from app.models import SettingValueType, SystemSetting
        db.add(SystemSetting(
            key="finding_retention_days", value=None, value_type=SettingValueType.int,
        ))
        await db.commit()

        r = await client.get("/api/system-settings", headers=auth(admin_token))
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}
        assert settings["finding_retention_days"]["value"] == "365"
        assert settings["finding_retention_days"]["is_default"] is True

    async def test_preexisting_legacy_invalid_value_reads_back_as_the_default(self, client, admin_token, db):
        """P2 regression: a row saved before POSITIVE_INT_KEYS validation
        existed (or written by a path that bypasses it) can hold "0", a
        negative value, or a non-numeric string for a RUNTIME_DEFAULTS key.
        parse_int() treats every one of those as invalid and silently
        substitutes the default at runtime, but _list_settings_with_defaults
        previously only excluded value=NULL rows — a legacy "0"/"-5"/"abc"
        row read back as if it were the real, effective value."""
        from app.models import SettingValueType, SystemSetting
        db.add_all([
            SystemSetting(key="sla_high_days", value="0", value_type=SettingValueType.int),
            SystemSetting(key="sla_medium_days", value="-5", value_type=SettingValueType.int),
            SystemSetting(key="finding_retention_days", value="not-a-number", value_type=SettingValueType.int),
        ])
        await db.commit()

        r = await client.get("/api/system-settings", headers=auth(admin_token))
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}

        assert settings["sla_high_days"]["value"] == "14"
        assert settings["sla_high_days"]["is_default"] is True
        assert settings["sla_medium_days"]["value"] == "90"
        assert settings["sla_medium_days"]["is_default"] is True
        assert settings["finding_retention_days"]["value"] == "365"
        assert settings["finding_retention_days"]["is_default"] is True

    async def test_preexisting_null_row_for_one_key_does_not_affect_others(self, client, admin_token, db):
        """The NULL-row exclusion must key off the specific row's value, not
        wipe out a sibling key that is genuinely saved."""
        from app.models import SettingValueType, SystemSetting
        db.add_all([
            SystemSetting(key="sla_high_days", value=None, value_type=SettingValueType.int),
            SystemSetting(key="sla_medium_days", value="45", value_type=SettingValueType.int),
        ])
        await db.commit()

        r = await client.get("/api/system-settings", headers=auth(admin_token))
        settings = {s["key"]: s for s in r.json()}
        assert settings["sla_high_days"]["value"] == "14"
        assert settings["sla_high_days"]["is_default"] is True
        assert settings["sla_medium_days"]["value"] == "45"
        assert settings["sla_medium_days"]["is_default"] is False
