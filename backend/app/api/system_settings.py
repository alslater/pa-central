"""System-wide settings — admin only."""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_admin
from app.core.config import settings as app_settings
from app.core.database import get_db
from app.core.email import MAX_SMTP_TIMEOUT_SECONDS
from app.core.encryption import encrypt_value
from app.core.smtp_settings import (
    VALID_SMTP_TLS_MODES,
    load_settings_map,
    looks_like_public_url,
    looks_like_smtp_host,
    parse_smtp_from_addr,
    parse_smtp_port,
    parse_smtp_tls_mode,
    smtp_timeout_is_usable,
)
from app.models import (
    BOOL_TRUE_VALUES,
    PasswordResetToken,
    SettingValueType,
    SystemSetting,
    User,
    setting_is_true,
    utcnow,
)
from app.schemas import PasswordResetReadinessOut, SystemSettingOut, SystemSettingPatch
from app.services.finding_lifecycle import (
    DEFAULT_FINDING_RETENTION,
    DEFAULT_SLA_HIGH,
    DEFAULT_SLA_MEDIUM,
)

router = APIRouter(prefix="/system-settings", tags=["system-settings"])

DbDep = Annotated[AsyncSession, Depends(get_db)]
AdminDep = Annotated[User, Depends(require_admin)]

# Known key → value_type mapping for auto-typing on upsert
KEY_TYPES: dict[str, SettingValueType] = {
    "pa_version": SettingValueType.string,
    "smtp_host": SettingValueType.string,
    "smtp_port": SettingValueType.int,
    "smtp_username": SettingValueType.string,
    "smtp_password": SettingValueType.secret,
    "smtp_from": SettingValueType.string,
    "smtp_tls_mode": SettingValueType.string,
    "smtp_timeout_seconds": SettingValueType.string,
    "scan_result_retention_days": SettingValueType.int,
    "scan_result_retention_count": SettingValueType.int,
    "app_base_url": SettingValueType.string,
    "default_cron_timezone": SettingValueType.string,
    "sla_high_days": SettingValueType.int,
    "sla_medium_days": SettingValueType.int,
    "finding_retention_days": SettingValueType.int,
    "self_service_password_reset": SettingValueType.bool,
}

# Keys whose runtime consumer (get_global_sla's parse_int) silently discards
# non-positive values and substitutes a default — so a PATCH accepting 0 or a
# negative value would report success while the stored value is ignored at
# read time. Enforced here since this is the only place these keys are
# validated on write.
POSITIVE_INT_KEYS = frozenset({"sla_high_days", "sla_medium_days", "finding_retention_days"})

# scan_result_retention_days treats 0 as "day-based retention disabled" (see
# scheduler.prune_old_results), so unlike POSITIVE_INT_KEYS, 0 is a valid,
# meaningful value here — only negative values are rejected. A negative value
# would make the pruning worker compute a cutoff in the future and delete
# every historical scan result.
NON_NEGATIVE_INT_KEYS = frozenset({"scan_result_retention_days", "scan_result_retention_count"})

# Keys whose runtime consumer (get_global_sla's parse_int) silently applies a
# numeric default when no row exists, rather than treating absence itself as
# meaningful (contrast scan_result_retention_days/_count, where "no row"
# means "no day/count-based pruning" — not a hidden number). Without this,
# GET /system-settings shows these fields blank on a fresh database even
# though the application is actively enforcing the value on the right.
RUNTIME_DEFAULTS: dict[str, int] = {
    "sla_high_days": DEFAULT_SLA_HIGH,
    "sla_medium_days": DEFAULT_SLA_MEDIUM,
    "finding_retention_days": DEFAULT_FINDING_RETENTION,
}

# Re-exported under the old name for callers/tests that reference it. The set
# itself lives in models so the write path here and every runtime reader share
# one definition rather than each restating it.
TRUE_VALUES = BOOL_TRUE_VALUES
_is_true = setting_is_true

# The write-time counterpart to BOOL_TRUE_VALUES — deliberately *not* shared
# with models.py the same way, and deliberately *not* consulted by
# setting_is_true(). That function's own docstring context (see
# BOOL_TRUE_VALUES's comment) is explicit that runtime readers must keep
# tolerating any stored value: a row predating this validation, or one
# written directly to the database, can hold anything, and setting_is_true's
# job is only "is this truthy," which "not true" already answers correctly
# for such a row. This set exists only to reject what the write path accepts
# in the first place — self_service_password_reset is the only
# SettingValueType.bool key that exists, and the only reader that cares about
# its exact value is the token-revoking sweep (turning_off, further down):
# an unrecognised value used to be silently canonicalised to "false" and
# accepted with 200, so a typo such as "tru" was stored as false and — if the
# feature was genuinely on — satisfied turning_off and revoked every
# outstanding reset and welcome link, with nothing telling the admin their
# request was misread. Reproduced directly: PATCHing
# self_service_password_reset="tru" against a genuinely-enabled feature
# returned 200, stored "false", and stamped every live token's used_at.
BOOL_FALSE_VALUES = frozenset({"false", "0", "no", "off"})


def _redact(s: SystemSetting) -> SystemSettingOut:
    return SystemSettingOut(
        key=s.key,
        value=None if s.value_type == SettingValueType.secret else s.value,
        value_type=s.value_type,
        updated_at=s.updated_at,
        updated_by_id=s.updated_by_id,
    )


def _disagrees_with_parse_int(value: str | None) -> bool:
    """True when parse_int() would silently discard this stored value and
    substitute its default at runtime — i.e. anything that isn't a positive
    integer: NULL, "0", a negative value, or a non-numeric string. Mirrors
    parse_int()'s own validity rule exactly, so a row that would be ignored
    at runtime is never displayed here as if it were the effective value."""
    if value is None:
        return True
    try:
        return int(value) < 1
    except (ValueError, TypeError):
        return True


async def _list_settings_with_defaults(db: AsyncSession) -> list[SystemSettingOut]:
    """All persisted settings, plus a synthesized row for any RUNTIME_DEFAULTS
    key with no persisted row, or a persisted row whose value parse_int()
    would ignore at runtime (NULL, "0", negative, or non-numeric) — shared by
    GET and PATCH so the two can't drift (PATCH's own final query previously
    bypassed this synthesis entirely, so clearing a key back to its default
    showed the stale blank value until the next unrelated GET).

    Such a row is treated the same as a missing row, not just excluded
    outright: patch_settings validates on write for these specific keys (see
    POSITIVE_INT_KEYS) and deletes the row on clear rather than saving one
    with value=NULL, but any row already left in an invalid shape by a prior
    version of that logic, a direct DB write, or any future write path this
    file doesn't control, must still read back as the default rather than a
    value that silently disagrees with what parse_int() applies at runtime.
    """
    result = await db.execute(select(SystemSetting).order_by(SystemSetting.key))
    persisted = list(result.scalars().all())
    out = [
        _redact(s) for s in persisted
        if not (s.key in RUNTIME_DEFAULTS and _disagrees_with_parse_int(s.value))
    ]
    present_keys = {s.key for s in out}
    for key, default in RUNTIME_DEFAULTS.items():
        if key not in present_keys:
            out.append(SystemSettingOut(
                key=key, value=str(default), value_type=SettingValueType.int,
                updated_at=None, updated_by_id=None, is_default=True,
            ))
    out.sort(key=lambda s: s.key)
    return out


@router.get("", response_model=list[SystemSettingOut])
async def get_settings(db: DbDep, _: AdminDep) -> list[SystemSettingOut]:
    return await _list_settings_with_defaults(db)


@router.patch("", response_model=list[SystemSettingOut])
async def patch_settings(body: SystemSettingPatch, db: DbDep, user: AdminDep) -> list[SystemSettingOut]:
    now = utcnow()

    # Serialize against the same settings-row lock issuance takes (see
    # _prepare_reset_email in services/password_reset.py) *before* reading
    # anything this request will use to decide whether it represents a
    # genuine transition, not just before the eventual sweep. An earlier
    # version read was_reset_on/had_smtp_host (below) with no lock at all,
    # then only acquired this lock — gated on turning_off/losing_smtp,
    # which are themselves computed from that unlocked read — inside the
    # sweep block far below. That is circular: a concurrent request that
    # commits an enable + issues a token in the gap between this request's
    # unlocked read and its own write is invisible to it, so a genuine
    # on-to-off transition (the stored value really did flip true, briefly,
    # then this request's own write brings it back to false) computes
    # turning_off=False from the stale pre-lock snapshot and skips the
    # sweep entirely — the concurrently-issued token is never revoked.
    # Reproduced directly: request A reads self_service_password_reset as
    # already false, is then delayed; request B enables the feature and
    # commits a fresh token; A resumes and writes false again — a real
    # true-to-false transition just happened, but A's stale snapshot never
    # saw the "true" and skipped revocation.
    #
    # Taking the lock unconditionally, every time this handler runs, is
    # what closes it: an admin-only settings PATCH is not a hot path, so
    # one inert extra write is the acceptable cost of guaranteeing the read
    # immediately below is never stale relative to a concurrent commit.
    # Self-assigning value_type, for the same reason is_active is used
    # elsewhere for row locks: an inert write to an ordinary column, not
    # the primary key. Raw SQL, not the ORM's update() construct — see the
    # sweep's own comment further below for why (SQLAlchemy applies a
    # column's onupdate= default to a Core update() regardless of which
    # columns are named in .values(), corrupting updated_at otherwise).
    #
    # An UPDATE ... WHERE key = ... only locks/serializes anything when a
    # matching row already exists — on a fresh or freshly-migrated
    # database, self_service_password_reset has no row at all until an
    # admin's first PATCH creates one (nothing seeds it; see
    # _list_settings_with_defaults's own synthesis, which is read-time
    # only and never writes a row). Two concurrent *first* PATCHes then
    # both see no row to lock, both fall through to the per-key update
    # loop below, and both attempt to INSERT the same primary key — on
    # PostgreSQL that is a genuine race ending in an unhandled
    # IntegrityError for whichever commits second, instead of the
    # serialized "one applies, the other observes it" outcome this lock
    # exists to guarantee. Reproduced directly against a real PostgreSQL
    # server: two concurrent PATCHes against an absent row, one succeeded
    # and the other raised `UniqueViolationError: duplicate key value
    # violates unique constraint "system_settings_pkey"`. The INSERT ...
    # ON CONFLICT DO NOTHING below guarantees a row exists — created by
    # whichever request gets there first, silently absorbed by whichever
    # loses that race — before the UPDATE immediately after it locks that
    # now-guaranteed-to-exist row. Supported identically on SQLite (3.24+,
    # already required by this project) and PostgreSQL.
    await db.execute(
        text(
            "INSERT INTO system_settings (key, value, value_type, updated_at) "
            "VALUES (:key, NULL, 'bool', CURRENT_TIMESTAMP) "
            "ON CONFLICT (key) DO NOTHING"
        ),
        # 'bool', not 'string': this lock exists only for
        # self_service_password_reset, KEY_TYPES' one bool-typed key — a
        # literal here must match its canonical type, not merely be *some*
        # valid value_type. Reproduced directly: the previous 'string'
        # literal meant a fresh database's first unrelated settings PATCH
        # (any key, since this lock always seeds this row) left GET
        # /system-settings reporting value_type="string" for this key until
        # an admin's own PATCH to it happened to overwrite value_type via
        # the per-key update loop's `existing.value_type = vtype` — API
        # consumers reading the documented type, not just this project's own
        # frontend (which never reads value_type from the response at all;
        # see SystemSettings.tsx's hardcoded KNOWN_SETTINGS), would see the
        # wrong type in the meantime.
        #
        # CURRENT_TIMESTAMP, not a bound `now` value: this raw INSERT
        # bypasses UtcDateTime's own bind-processor (process_bind_param,
        # which strips tzinfo — PostgreSQL's updated_at column is
        # TIMESTAMP WITHOUT TIME ZONE, so a tz-aware datetime is rejected
        # outright by asyncpg: "can't subtract offset-naive and
        # offset-aware datetimes"), and a naive datetime object there
        # triggers Python 3.12's sqlite3 default-datetime-adapter
        # deprecation warning — while an ISO string in its place is
        # rejected by asyncpg just as bluntly ("expected a datetime.date
        # or datetime.datetime instance, got 'str'"), all reproduced
        # directly. CURRENT_TIMESTAMP is ANSI SQL both dialects already
        # support natively, needs no bind parameter or adapter at all,
        # and this row's created-on-first-touch updated_at has no
        # precision requirement matching `now` elsewhere in this
        # function — any subsequent real update overwrites it via the
        # ORM's typed onupdate machinery regardless.
        {"key": "self_service_password_reset"},
    )
    await db.execute(
        text(
            "UPDATE system_settings SET value_type = value_type "
            "WHERE key = :key"
        ),
        {"key": "self_service_password_reset"},
    )

    # Validate the state this PATCH *leaves behind*, not just the keys it
    # mentions.
    #
    # Self-service reset needs an SMTP host to send from and a base URL to
    # point at. Checking only when the request enables the flag left a gap:
    # the endpoint accepts partial updates, so an admin could enable it
    # correctly and later PATCH just app_base_url to an empty, malformed, or
    # query/fragment-bearing value. That write succeeded while the config
    # endpoint still advertised the feature as on, so forgot-password either
    # sent nothing or built a structurally broken link
    # (…?next=/x/reset-password#token=… — the path is appended after the
    # query). Resolving the effective value for both keys closes that, and
    # covers clearing smtp_host by the same route.
    async def _effective(key: str) -> str:
        if key in body.updates:
            return (body.updates[key] or "").strip()
        existing = await db.get(SystemSetting, key)
        return ((existing.value if existing else None) or "").strip()

    # Read under the lock just acquired above, and before the update loop
    # below touches anything: both are read again there (see
    # turning_off/losing_smtp further down) to decide whether this request
    # represents a genuine transition, and by then db.get() would return
    # the loop's own in-session, already-mutated value for a key present
    # in body.updates rather than what was actually stored when the
    # request arrived — the identity map serves the mutated object without
    # re-querying. Reading them once, here — under the lock, before
    # anything is mutated — is what lets that comparison mean anything.
    stored_reset_flag = await db.get(SystemSetting, "self_service_password_reset")
    was_reset_on = _is_true(stored_reset_flag.value if stored_reset_flag else None)
    stored_smtp_host = await db.get(SystemSetting, "smtp_host")
    had_smtp_host = bool((
        (stored_smtp_host.value if stored_smtp_host else None) or ""
    ).strip())
    stored_app_base_url = await db.get(SystemSetting, "app_base_url")
    prior_app_base_url = (
        (stored_app_base_url.value if stored_app_base_url else None) or ""
    ).strip()

    if "self_service_password_reset" in body.updates:
        reset_enabled = _is_true(body.updates["self_service_password_reset"])
    else:
        reset_enabled = was_reset_on

    if reset_enabled:
        effective_smtp_host = await _effective("smtp_host")
        if not effective_smtp_host:
            raise HTTPException(
                400,
                "Self-service password reset requires an SMTP host — there is "
                "no way to deliver a reset link without one. Turn the feature "
                "off first if you mean to remove it.",
            )
        if not looks_like_smtp_host(effective_smtp_host):
            raise HTTPException(
                400,
                f"SMTP host {effective_smtp_host!r} is not a usable hostname "
                "or address — it must not contain whitespace or control "
                "characters. Turn the feature off first if you mean to leave "
                "it as is.",
            )

        # self_service_reset_enabled() (core/smtp_settings.py, consulted by
        # GET /password-reset-config and forgot_password) refuses the
        # feature when smtp_port is not a usable TCP port (1-65535) —
        # parse_smtp_port's own docstring covers why an unhandled bad value
        # is worse than merely "unconfigured": it used to raise, reaching
        # forgot_password only for a real account (an enumeration oracle by
        # status code) and reaching the admin-reset path only after the
        # target's password was already invalidated. This gate did not
        # check it at all, so a PATCH could enable the flag against an
        # already-stored bad port, or set an out-of-range port in the same
        # request that enables the flag — succeeding here while
        # self_service_reset_enabled() immediately reported the feature
        # unavailable, exactly the write-time/read-time disagreement this
        # whole effective-state gate exists to prevent for smtp_host and
        # app_base_url. parse_smtp_port itself supplies the default when
        # the effective value is empty, so passing the raw effective string
        # through unchanged is correct — an empty value is not an error.
        if parse_smtp_port(await _effective("smtp_port")) is None:
            raise HTTPException(
                400,
                "Self-service password reset requires a usable SMTP port "
                "(1-65535) — the stored or submitted value cannot be used "
                "to connect. Turn the feature off first if you mean to "
                "leave it as is.",
            )

        # Same reasoning as smtp_port immediately above, and the same gap
        # the whole effective-state pattern this block uses exists to
        # close: the per-key validation further down in this function (see
        # the smtp_tls_mode/smtp_from checks in the loop below) only
        # inspects keys present in *this* request's body.updates. A PATCH
        # that enables self_service_password_reset without also touching
        # smtp_tls_mode or smtp_from never runs those checks at all, so an
        # already-stored bad value — a legacy row, a direct edit, or one
        # set before this validation existed — let this gate report 200
        # while self_service_reset_enabled() (core/smtp_settings.py)
        # immediately reported the feature unavailable. Reproduced
        # directly: PATCHing only self_service_password_reset=true against
        # a stored smtp_tls_mode="start-tls" (or a stored smtp_from
        # containing CR/LF) returned 200, and the very next
        # GET /password-reset-config reported self_service_enabled: false.
        if parse_smtp_tls_mode(await _effective("smtp_tls_mode")) is None:
            raise HTTPException(
                400,
                f"Self-service password reset requires a usable SMTP TLS "
                f"mode (one of {sorted(VALID_SMTP_TLS_MODES)}) — the stored "
                "or submitted value cannot be used to connect. Turn the "
                "feature off first if you mean to leave it as is.",
            )
        if parse_smtp_from_addr(await _effective("smtp_from")) is None:
            raise HTTPException(
                400,
                "Self-service password reset requires a usable From "
                "address — the stored or submitted value cannot be used "
                "to send. Turn the feature off first if you mean to leave "
                "it as is.",
            )

        effective_base_url = await _effective("app_base_url")
        if not effective_base_url:
            raise HTTPException(
                400,
                "Self-service password reset requires the App Base URL — reset "
                "links have to point at this deployment. Turn the feature off "
                "first if you mean to remove it.",
            )
        if not looks_like_public_url(effective_base_url):
            raise HTTPException(
                400,
                f"App Base URL {effective_base_url!r} is not a usable public "
                "address for reset links — it must be an http(s) URL with a "
                "hostname reachable by the people receiving the email, and no "
                "query string or fragment. "
                "(A localhost address is accepted only when DEBUG is set.)",
            )

    for key, raw_value in body.updates.items():
        vtype = KEY_TYPES.get(key, SettingValueType.string)
        if vtype == SettingValueType.int and raw_value is not None:
            try:
                int_value = int(raw_value)
            except (ValueError, TypeError):
                raise HTTPException(400, f"Setting '{key}' requires an integer value, got: {raw_value!r}")
            if key in POSITIVE_INT_KEYS and int_value < 1:
                raise HTTPException(400, f"Setting '{key}' requires a positive integer, got: {raw_value!r}")
            if key in NON_NEGATIVE_INT_KEYS and int_value < 0:
                raise HTTPException(400, f"Setting '{key}' requires a non-negative integer, got: {raw_value!r}")
        # smtp_port is neither in POSITIVE_INT_KEYS nor NON_NEGATIVE_INT_KEYS
        # (see parse_smtp_port's own docstring), so the generic int check
        # above only confirms it parses as *an* integer — an out-of-range
        # value like "99999" or "-1" passed untouched. That mattered only
        # for self-service reset until now (the reset_enabled block below
        # already catches a bad port there), but smtp_port is also read by
        # the independent scan-result-notification path
        # (api/ingest.py:224, build_smtp_config(settings_map)), which has
        # nothing to do with self_service_password_reset. With reset off,
        # a PATCH setting smtp_port to an out-of-range value previously
        # returned 200; build_smtp_config then silently returned None for
        # every subsequent scan-result email, indistinguishable from SMTP
        # never having been configured at all — no error, no log, nothing
        # visible to the admin. Reproduced directly: self_service_password_reset
        # off, PATCH {"smtp_port": "99999"} returned 200, and
        # build_smtp_config({"smtp_port": "99999", ...}) returned None.
        # Checked unconditionally here (not inside the reset_enabled block,
        # and not through _effective(), which only matters for that
        # block's own "does this PATCH leave a promised feature working"
        # question) — parse_smtp_port itself supplies the 587 default for
        # an absent/empty value, so passing the raw submitted string
        # through unchanged is correct: only a value present and unusable
        # is an error, not one left blank.
        if key == "smtp_port" and raw_value and parse_smtp_port(raw_value) is None:
            raise HTTPException(
                400,
                "Setting 'smtp_port' must be a usable TCP port (1-65535), "
                f"got: {raw_value!r}",
            )
        # smtp_timeout_seconds is stored as a plain string, not
        # SettingValueType.int, because parse_smtp_timeout accepts
        # decimals (a sub-second timeout is meaningful) — so it never
        # reaches the int branch above and had no shape validation at all.
        # "abc", "0", "-5", "nan", and an overflowing literal like "1e309"
        # all saved successfully while parse_smtp_timeout silently
        # substituted the 30s default at read time, leaving System
        # Settings displaying a value the runtime was never using — the
        # exact class of gap POSITIVE_INT_KEYS/NON_NEGATIVE_INT_KEYS exist
        # to close for their own keys. An absent/empty value is left alone
        # here (not an error): that is what "use the default" looks like,
        # and is exactly what parse_smtp_timeout does with it too.
        # smtp_timeout_is_usable is the same function parse_smtp_timeout
        # itself calls, so the two cannot drift on what "usable" means.
        if key == "smtp_timeout_seconds" and raw_value:
            try:
                timeout_value = float(raw_value)
            except (TypeError, ValueError):
                raise HTTPException(
                    400,
                    f"Setting 'smtp_timeout_seconds' requires a numeric "
                    f"value, got: {raw_value!r}",
                )
            if not smtp_timeout_is_usable(timeout_value):
                raise HTTPException(
                    400,
                    "Setting 'smtp_timeout_seconds' requires a finite value "
                    f"greater than 0 and at most {MAX_SMTP_TIMEOUT_SECONDS:g}, "
                    f"got: {raw_value!r}",
                )
        # Same reasoning as smtp_timeout_seconds above: smtp_tls_mode is a
        # plain string with no shape validation at all, and its runtime
        # consumer (EmailService._send_sync) treats *any* unrecognised
        # value identically to the deliberate "none" opt-out — plain,
        # unencrypted smtplib.SMTP with no starttls() upgrade. Unlike a bad
        # timeout, which merely degrades to a default, an unrecognised
        # tls_mode silently sends password reset links (containing the raw
        # credential) over an unencrypted connection — a typo such as
        # "start-tls" would previously save with a 200 and nothing would
        # ever indicate the admin's intended setting was not honoured. The
        # frontend restricts this field to a fixed dropdown
        # (SystemSettings.tsx), but that is not a backend guarantee: this
        # endpoint accepts arbitrary strings from any direct API caller.
        if key == "smtp_tls_mode" and raw_value and raw_value not in VALID_SMTP_TLS_MODES:
            raise HTTPException(
                400,
                f"Setting 'smtp_tls_mode' must be one of "
                f"{sorted(VALID_SMTP_TLS_MODES)}, got: {raw_value!r}",
            )
        # smtp_from is assigned straight to EmailMessage()["From"]
        # (core/email.py's build_password_reset_email) — Python's own
        # email module raises ValueError for a value containing a
        # carriage return or line feed (a header-injection vector), and
        # that assignment happens *after* the reset token has already
        # been committed, or after set_password has already invalidated
        # the admin-reset target's password. This key had no shape
        # validation at all, so a stored value with an embedded CR/LF
        # previously saved with a 200 and only surfaced as an unhandled
        # 500 the next time a real account actually triggered issuance —
        # for forgot_password specifically, only for a real, active
        # account, since an unknown address never reaches that code at
        # all. parse_smtp_from_addr is the same check build_smtp_config
        # and self_service_reset_enabled already share.
        if key == "smtp_from" and raw_value and parse_smtp_from_addr(raw_value) is None:
            raise HTTPException(
                400,
                "Setting 'smtp_from' must not contain a carriage return or "
                f"line feed, got: {raw_value!r}",
            )
        if vtype == SettingValueType.secret and raw_value is not None:
            stored_value = encrypt_value(raw_value, app_settings.settings_encryption_key)
        elif vtype == SettingValueType.bool and raw_value is not None:
            # Canonicalise on write. TRUE_VALUES accepts "1"/"yes"/"on" and any
            # casing, so a bool could be stored in several shapes meaning the
            # same thing — and every reader then has to reimplement this exact
            # set to agree. Storing only "true"/"false" means a plain equality
            # check is correct everywhere, instead of a second parser that can
            # silently drift (the frontend's did: it matched "true" alone, so a
            # setting saved as "yes" displayed as off and was overwritten with
            # "false" by any unrelated save).
            #
            # An unrecognised value is rejected, not silently treated as
            # false — see BOOL_FALSE_VALUES's own comment for why: this
            # canonicalisation used to accept anything not in TRUE_VALUES as
            # "false" with a 200, so a typo such as "tru" for
            # self_service_password_reset (the only bool-typed key) was
            # stored as false and, while the feature was genuinely on, also
            # satisfied turning_off further down — silently revoking every
            # outstanding reset and welcome link on a request the admin
            # believed had failed to change anything, or had turned the
            # feature *on*.
            normalized = (raw_value or "").strip().lower()
            if normalized in BOOL_TRUE_VALUES:
                stored_value = "true"
            elif normalized in BOOL_FALSE_VALUES:
                stored_value = "false"
            else:
                raise HTTPException(
                    400,
                    f"Setting '{key}' must be one of "
                    f"{sorted(BOOL_TRUE_VALUES | BOOL_FALSE_VALUES)}, "
                    f"got: {raw_value!r}",
                )
        else:
            stored_value = raw_value
        existing = await db.get(SystemSetting, key)
        # For keys with a runtime default (see RUNTIME_DEFAULTS/get_settings),
        # clearing the field back to NULL must remove the row entirely, not
        # leave one behind with value=NULL — get_settings() only synthesizes
        # the default for a *missing* key, so a present-but-NULL row would
        # otherwise render as a blank field even though parse_int() is
        # actively applying 14/90/365 at runtime. Other keys keep the
        # existing NULL-row behavior (preserves updated_at/updated_by_id
        # for who cleared it and when).
        if raw_value is None and key in RUNTIME_DEFAULTS and existing:
            await db.delete(existing)
        elif existing:
            existing.value = stored_value
            existing.value_type = vtype
            existing.updated_at = now
            existing.updated_by_id = user.id
        elif not (raw_value is None and key in RUNTIME_DEFAULTS):
            db.add(SystemSetting(
                key=key, value=stored_value, value_type=vtype,
                updated_at=now, updated_by_id=user.id,
            ))

    # Switching self-service reset off revokes outstanding links, rather than
    # leaving them live and refusing them at the endpoint.
    #
    # POST /auth/reset-password deliberately does not check this setting: a
    # token that already exists was delivered under the policy that applied
    # then, and refusing it strands anyone whose password is *already* gone —
    # an admin-reset victim, or a new account whose only credential is its
    # welcome link. Retiring here is the honest revocation, and unlike a gate
    # it sticks: leaving the rows live meant re-enabling the setting revived
    # every link refused in the meantime.
    #
    # Clearing smtp_host counts too — self_service_reset_enabled() treats a
    # missing host as off, so it is the same revocation by another route.
    # (A syntactically unusable, non-empty host — looks_like_smtp_host()
    # failing — reaches self_service_reset_enabled() the same way, but
    # cannot appear here: the enabling gate above already refuses any PATCH
    # that would leave the flag on with such a value stored, so the only
    # way this key can hold one while the flag was previously on is a
    # request that also turns the flag off — already covered by
    # turning_off below.)
    #
    # turning_off/losing_smtp both require the *stored* value (was_reset_on/
    # had_smtp_host, captured before the update loop above touched
    # anything) to actually have been the opposite before this request —
    # not just "the submitted value happens to be false/empty" — because
    # this key (like every bool the frontend tracks) is resubmitted on
    # every save regardless of whether the admin touched it:
    # SystemSettings.tsx always echoes the current checkbox state so an
    # unchecked box round-trips as an explicit "false" rather than
    # silently vanishing from the request. Without the "was different
    # before" check, saving an entirely unrelated field (retention days,
    # timezone) while the feature was already off re-ran this sweep on
    # every single save, retiring outstanding admin-reset and welcome
    # tokens that had nothing to do with the fields the admin thought they
    # were changing. Reproduced directly: self_service_password_reset
    # already false, PATCHing only finding_retention_days (which still
    # implicitly resubmits the current false value, matching how the
    # frontend always builds its request body) retired a live token that
    # existed before the request and was never mentioned by it.
    turning_off = (
        "self_service_password_reset" in body.updates
        and not _is_true(body.updates["self_service_password_reset"])
        and was_reset_on
    )
    losing_smtp = (
        "smtp_host" in body.updates
        and not (body.updates["smtp_host"] or "").strip()
        and had_smtp_host
    )
    # A changed app_base_url counts too, for a different reason than the
    # two above: those retire tokens because self-service becomes
    # *unusable* (no way to build or deliver a link at all). This one
    # retires tokens because every outstanding link was already built
    # against the *old* base_url and still points there —
    # consume_reset_token takes only the raw token hash, with no binding
    # to which origin it was minted for, so a link is redeemable at
    # whatever host actually serves this API regardless of which base_url
    # built it. If the old origin is later retired or ends up under
    # someone else's control, its JavaScript can read the token straight
    # out of the URL fragment (see build_reset_url — deliberately never
    # sent to any server, but still readable by whatever page loads at
    # that address) and redeem it against this deployment, since
    # redemption isn't origin-bound at all. Changing to a new value
    # (rotating domains, fixing a typo, moving to a new environment) is
    # exactly the same exposure as turning the feature off or losing SMTP
    # from a link's point of view: the link was built for a base_url that
    # is no longer the one this deployment uses, so it must not remain
    # live and redeemable.
    #
    # Compared against the raw stored string, not a parsed origin — the
    # same granularity as had_smtp_host/was_reset_on above. A no-op
    # resubmission of the identical stored value does not count (the
    # `!=` comparison below already excludes it, matching the "was
    # actually different before" guard both other conditions use), but
    # any other edit does, including one that only changes the path or
    # trailing slash: this is a rare, deliberate admin action, not a
    # noisy resubmission risk like the boolean fields above, so there is
    # no need for finer-grained origin parsing to avoid false positives.
    changing_base_url = (
        "app_base_url" in body.updates
        and (body.updates["app_base_url"] or "").strip() != prior_app_base_url
        and prior_app_base_url != ""
    )
    if turning_off or losing_smtp or changing_base_url:
        # The row lock issuance takes (see prepare_reset_email) is already
        # held at this point — acquired unconditionally at the top of this
        # function, before was_reset_on/had_smtp_host were even read — so
        # a concurrent issuance is already serialized against this sweep:
        # either it committed before this transaction started and its
        # token is caught below, or it is blocked on this same lock and
        # will only proceed (and find the feature genuinely off) once this
        # transaction commits. No second lock-acquisition needed here.
        await db.execute(
            update(PasswordResetToken)
            .where(PasswordResetToken.used_at.is_(None))
            .values(used_at=now)
        )

    await db.commit()
    return await _list_settings_with_defaults(db)


@router.get("/password-reset-readiness", response_model=PasswordResetReadinessOut)
async def password_reset_readiness(db: DbDep, _: AdminDep) -> PasswordResetReadinessOut:
    """Whether self-service password reset can be enabled right now, with
    reasons — for SystemSettings.tsx to render instead of its own
    smtp_host/app_base_url-only guess (canEnableReset), which disagreed
    with this exact backend contract for every other precondition
    (SMTP port, TLS mode, From address, and App Base URL's shape/scheme):
    the toggle looked enableable while enabling it would 400, and a
    stored bad value could leave it looking active while
    self_service_reset_enabled() already reported it unavailable.

    Runs the identical checks patch_settings() enforces on enabling and
    self_service_reset_enabled() enforces at read time, via the same
    shared validators, against the currently *stored* values — there is
    no submitted PATCH body here, so there is no effective-value
    resolution to do, unlike patch_settings()'s own _effective().
    """
    settings_map = await load_settings_map(db)
    reasons: list[str] = []

    smtp_host = (settings_map.get("smtp_host") or "").strip()
    if not smtp_host:
        reasons.append(
            "Requires an SMTP host — there is no way to deliver a reset "
            "link without one."
        )
    elif not looks_like_smtp_host(smtp_host):
        reasons.append(
            "SMTP host is not a usable hostname or address — it must not "
            "contain whitespace or control characters."
        )

    if parse_smtp_port(settings_map.get("smtp_port")) is None:
        reasons.append("SMTP port must be a usable value (1-65535).")

    if parse_smtp_tls_mode(settings_map.get("smtp_tls_mode")) is None:
        reasons.append(
            f"SMTP TLS mode must be one of {sorted(VALID_SMTP_TLS_MODES)}."
        )

    if parse_smtp_from_addr(settings_map.get("smtp_from")) is None:
        reasons.append("From address is not usable — it cannot contain a line break.")

    base_url = (settings_map.get("app_base_url") or "").strip()
    if not base_url:
        reasons.append(
            "Requires the App Base URL — reset links have to point at "
            "this deployment."
        )
    elif not looks_like_public_url(base_url):
        reasons.append(
            f"App Base URL {base_url!r} is not a usable public address — it "
            "must be an https:// URL (http:// only under DEBUG) with a "
            "hostname reachable by the people receiving the email, and no "
            "query string or fragment."
        )

    return PasswordResetReadinessOut(ready=not reasons, reasons=reasons)
