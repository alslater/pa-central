"""Tests for GET/PATCH /api/system-settings."""
import pytest

from app.core.email import MAX_SMTP_TIMEOUT_SECONDS
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

    async def test_an_unrelated_patch_seeds_the_reset_flag_with_its_real_type(
        self, client, admin_token
    ):
        """patch_settings takes a lock on self_service_password_reset before
        touching anything else, on *every* PATCH regardless of which keys it
        actually names — and that lock's own upsert seeds the row if it
        doesn't exist yet (see its own comment for why: an absent row is a
        no-op to lock). The upsert's raw INSERT hardcoded value_type='string'
        even though KEY_TYPES declares this key as bool, so a completely
        unrelated PATCH on a fresh database — this one only ever mentions
        pa_version — used to leave GET /system-settings reporting the wrong
        type for self_service_password_reset until an admin happened to PATCH
        that key directly (the per-key update loop's own
        `existing.value_type = vtype` only fires then). Reproduced directly
        against the unfixed code: this exact PATCH left the row with
        value_type="string".
        """
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"pa_version": "1.2.3"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200

        g = await client.get("/api/system-settings", headers=auth(admin_token))
        settings = {s["key"]: s for s in g.json()}
        assert settings["self_service_password_reset"]["value_type"] == "bool", (
            "an unrelated PATCH seeded self_service_password_reset with the "
            "wrong value_type — the lock's own upsert must use this key's "
            "canonical type, not a generic placeholder"
        )

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
class TestSystemSettingsTimeoutValidation:
    """smtp_timeout_seconds feeds core.smtp_settings.parse_smtp_timeout,
    which silently substitutes the 30s default for anything non-numeric,
    non-finite, non-positive, or over MAX_SMTP_TIMEOUT_SECONDS — the same
    class of gap POSITIVE_INT_KEYS/NON_NEGATIVE_INT_KEYS close for the
    integer settings above. Unlike those, this key is stored as a plain
    string (SettingValueType.string, not .int) because it must accept
    decimals, so it never reached the generic int-validation branch and had
    no shape validation of its own at all — reproduced directly before this
    fix: "abc", "0", "-5", "nan", and "1e309" all saved with a 200 while
    parse_smtp_timeout silently used 30s at read time regardless of what
    was displayed as saved.
    """

    @pytest.mark.parametrize("bad_value", ["abc", "not-a-number", "nan", "NaN"])
    async def test_rejects_non_numeric(self, client, admin_token, bad_value):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_timeout_seconds": bad_value}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400
        assert "smtp_timeout_seconds" in r.json()["detail"]

    @pytest.mark.parametrize("bad_value", ["0", "-5", "-0.1"])
    async def test_rejects_non_positive(self, client, admin_token, bad_value):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_timeout_seconds": bad_value}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400

    @pytest.mark.parametrize("bad_value", ["inf", "Infinity", "1e309"])
    async def test_rejects_non_finite_or_overflowing(self, client, admin_token, bad_value):
        """"1e309" parses to float('inf') in Python — same failure mode as
        the literal infinities, all three must be rejected identically."""
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_timeout_seconds": bad_value}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400

    async def test_rejects_a_value_over_the_maximum(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_timeout_seconds": str(MAX_SMTP_TIMEOUT_SECONDS + 1)}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400

    async def test_accepts_the_maximum(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_timeout_seconds": str(MAX_SMTP_TIMEOUT_SECONDS)}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200

    async def test_accepts_a_decimal_value(self, client, admin_token):
        """The whole reason this key is a string, not an int, is decimal
        support (a sub-second timeout is meaningful) — the fix must not
        regress that."""
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_timeout_seconds": "0.5"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}
        assert settings["smtp_timeout_seconds"]["value"] == "0.5"

    async def test_accepts_an_ordinary_integer_value(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_timeout_seconds": "45"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}
        assert settings["smtp_timeout_seconds"]["value"] == "45"

    async def test_accepts_clearing_the_value(self, client, admin_token):
        """An absent/empty value means "use the default" — that is not an
        error, and must remain a valid write (e.g. an admin reverting to
        the default explicitly)."""
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_timeout_seconds": ""}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200

    async def test_unrelated_updates_are_unaffected(self, client, admin_token):
        """The validation must trigger only when smtp_timeout_seconds is
        actually present in the request body — not on every PATCH."""
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"pa_version": "1.2.3"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200


@pytest.mark.asyncio
class TestSystemSettingsPortValidation:
    """smtp_port is neither in POSITIVE_INT_KEYS nor NON_NEGATIVE_INT_KEYS
    (see parse_smtp_port's own docstring for why), so the generic int
    check alone only confirmed it parses as *an* integer — an
    out-of-range value like "99999" or "-1" passed untouched, with a 200,
    regardless of whether self_service_password_reset was even enabled.

    That mattered beyond self-service reset: smtp_port is also read by
    the independent scan-result-notification path
    (api/ingest.py:224, build_smtp_config(settings_map)). With reset off,
    an out-of-range port previously saved successfully, and
    build_smtp_config then silently returned None for every subsequent
    scan-result email — indistinguishable from SMTP never having been
    configured at all, with no error surfaced anywhere. Reproduced
    directly: self_service_password_reset off, PATCH
    {"smtp_port": "99999"} returned 200, and
    build_smtp_config({"smtp_port": "99999", ...}) returned None.
    """

    @pytest.mark.parametrize("bad_value", ["99999", "-1", "0", "65536"])
    async def test_rejects_an_out_of_range_port_regardless_of_reset_state(
        self, client, admin_token, bad_value
    ):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_port": bad_value}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400
        assert "smtp_port" in r.json()["detail"]

    async def test_accepts_a_valid_port(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_port": "2525"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}
        assert settings["smtp_port"]["value"] == "2525"

    async def test_accepts_clearing_the_value(self, client, admin_token):
        """An absent/cleared value means "use the 587 default" — that is
        not an error, and must remain a valid write. Cleared via null:
        smtp_port is an int-typed key, and an empty string fails the
        generic int-type check further up in the same loop before this
        check ever runs — that behaviour predates this fix and is
        unrelated to it (every int-typed key rejects "", not just this
        one); null is how the frontend itself clears an int field."""
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_port": None}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200

    async def test_unrelated_updates_are_unaffected(self, client, admin_token):
        """The validation must trigger only when smtp_port is actually
        present in the request body — not on every PATCH."""
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"pa_version": "1.2.3"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200

    async def test_a_bad_port_with_reset_off_and_an_unrelated_change_is_rejected(
        self, client, admin_token
    ):
        """The exact scenario the finding describes: self-service reset
        is off, and this PATCH doesn't even mention it — only the new
        per-key check (not the reset_enabled-gated effective-value check,
        which never runs when reset is off) can catch this."""
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {
                "smtp_host": "smtp.example.com",
                "smtp_port": "99999",
                "finding_retention_days": "400",
            }},
            headers=auth(admin_token),
        )
        assert r.status_code == 400
        assert "smtp_port" in r.json()["detail"]


@pytest.mark.asyncio
class TestSystemSettingsTlsModeValidation:
    """smtp_tls_mode feeds EmailService._send_sync, which only recognises
    the exact strings "ssl" and "starttls" — anything else, including a
    typo, falls through identically to plain, unencrypted smtplib.SMTP
    with no starttls() upgrade at all. This key had no shape validation of
    its own at all, so a typo such as "start-tls" previously saved
    successfully with a 200 and silently sent password reset links over an
    unencrypted connection. The frontend restricts this field to a fixed
    dropdown, but that is not a backend guarantee — this endpoint accepts
    arbitrary strings from any direct API caller.
    """

    @pytest.mark.parametrize("bad_value", ["start-tls", "STARTTLS", "tls", "SSL"])
    async def test_rejects_an_unrecognised_value(self, client, admin_token, bad_value):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_tls_mode": bad_value}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400
        assert "smtp_tls_mode" in r.json()["detail"]

    @pytest.mark.parametrize("bad_value", [" ssl", "ssl ", " none", "starttls "])
    async def test_rejects_a_whitespace_padded_variant_of_a_valid_value(
        self, client, admin_token, bad_value
    ):
        """A padded variant is not auto-corrected — it must fail exactly
        like an unrelated typo, not be silently trimmed into working."""
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_tls_mode": bad_value}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400

    @pytest.mark.parametrize("valid_value", ["none", "ssl", "starttls"])
    async def test_accepts_every_valid_value(self, client, admin_token, valid_value):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_tls_mode": valid_value}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}
        assert settings["smtp_tls_mode"]["value"] == valid_value

    async def test_accepts_clearing_the_value(self, client, admin_token):
        """An absent/empty value means "use the starttls default" — that
        is not an error, and must remain a valid write."""
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_tls_mode": ""}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200

    async def test_unrelated_updates_are_unaffected(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"pa_version": "1.2.3"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200


@pytest.mark.asyncio
class TestSystemSettingsFromAddrValidation:
    """smtp_from is assigned straight to EmailMessage()["From"]
    (core/email.py's build_password_reset_email) — Python's own email
    module raises ValueError for a value containing a carriage return or
    line feed (a header-injection vector), and that assignment happens
    after the reset token has already been committed, or after
    set_password has already invalidated the admin-reset target's
    password. This key had no shape validation at all, so a value with an
    embedded CR/LF previously saved successfully with a 200 and only
    surfaced as an unhandled 500 the next time a real account actually
    triggered issuance.
    """

    async def test_rejects_a_value_with_a_carriage_return(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_from": "pa\r\nBcc: evil@example.com"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400
        assert "smtp_from" in r.json()["detail"]

    async def test_rejects_a_value_with_a_bare_line_feed(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_from": "pa\nBcc: evil@example.com"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 400

    async def test_accepts_an_ordinary_value(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_from": "pa-central@example.com"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200
        settings = {s["key"]: s for s in r.json()}
        assert settings["smtp_from"]["value"] == "pa-central@example.com"

    async def test_accepts_clearing_the_value(self, client, admin_token):
        """An absent/empty value means "use the default" — that is not an
        error, and must remain a valid write."""
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"smtp_from": ""}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200

    async def test_unrelated_updates_are_unaffected(self, client, admin_token):
        r = await client.patch(
            "/api/system-settings",
            json={"updates": {"pa_version": "1.2.3"}},
            headers=auth(admin_token),
        )
        assert r.status_code == 200


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
