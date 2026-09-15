"""Issuing and consuming self-service password reset tokens."""
import asyncio
import logging
import time
from collections.abc import Callable
from datetime import timedelta
from email.message import EmailMessage
from typing import Literal, NamedTuple

from sqlalchemy import select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.email import (
    MAX_CONCURRENT_SENDS as email_MAX_CONCURRENT_SENDS,
)
from app.core.email import (
    EmailService,
    SmtpConfig,
    build_password_reset_email,
    filter_deliverable_recipients,
)
from app.core.security import generate_reset_token, hash_password
from app.core.smtp_settings import build_smtp_config, looks_like_public_url
from app.models import (
    PasswordResetKind,
    PasswordResetToken,
    SystemSetting,
    User,
    setting_is_true,
    utcnow,
)
from app.schemas import build_admin_action_result_event

# Throttling for POST /auth/forgot-password. The endpoint is public and takes
# only an email address, so without limits anyone who knows a user's address
# can request links indefinitely — and because each request reissues the
# token, every link the user actually receives is invalidated by the next
# attacker request. That is a recovery-denial attack, not just mail spam.
#
# Two limits, because they stop different things:
#   * the cooldown bounds how often a *new* link can supersede an old one
#   * the hourly cap bounds total mail sent to one address
RESET_REQUEST_COOLDOWN_SECONDS = 120
RESET_REQUESTS_PER_HOUR = 5
RESET_REQUEST_WINDOW_SECONDS = 3600

# How long a *welcome* link stays valid, for an account created by an admin
# with self-service enabled. Longest of the three by a wide margin: there is
# no compromise to contain and no existing access to cut off, and a new user
# is routinely onboarded before they start, or is on leave when the account
# is made. A window measured in hours would mostly generate re-issues.
WELCOME_TOKEN_TTL_MINUTES = 7 * 24 * 60

# How long an *admin-initiated* reset link stays valid. Much longer than the
# self-service TTL because the user is not expecting this email — they did not
# ask for it, and may not read their mail for hours. Their password has
# already been invalidated by the time it arrives, so a short window would
# just mean a locked-out user needing a second admin action.
ADMIN_RESET_TOKEN_TTL_MINUTES = 24 * 60

# How long an emailed reset link stays valid. Long enough to survive an email
# being read on a phone and acted on at a desk; short enough that a link left
# in an inbox is not a standing credential.
RESET_TOKEN_TTL_MINUTES = 60

# Grace period past expiry before the scheduler deletes a row. Keeping a
# just-expired token means a user who clicks a stale link is told the link
# expired rather than that it is invalid.
RESET_TOKEN_PRUNE_GRACE_HOURS = 24

class MissingAppBaseUrl(RuntimeError):
    """No usable app_base_url, so no deliverable link can be built.

    Raised rather than defaulted. A fallback to the Vite dev origin made the
    feature report success while emailing links to http://localhost:5173 —
    unusable on any real deployment — and the admin-reset path invalidates the
    password *before* sending, so the user was left locked out holding a link
    that goes nowhere. api/system_settings.py refuses to enable the feature
    without the setting, so this is the defence-in-depth case: a row cleared,
    corrupted, or written directly, bypassing that check entirely.

    Also raised for a *present but unusable* value — not only an empty one.
    require_app_base_url originally checked non-empty and nothing else, so a
    row that reached storage some other way (restored from a backup, edited
    directly, or simply predating this validation) could hold a non-empty but
    structurally broken URL — `ftp://host`, `https://host?next=x` — and the
    feature would advertise itself as enabled while every link it built was
    dead. api/system_settings.py's PATCH validator catches this on write, but
    that is not the only way a value reaches this column, so it must be
    caught here too.
    """


def require_app_base_url(settings_map: dict[str, str]) -> str:
    base_url = (settings_map.get("app_base_url") or "").strip()
    if not base_url:
        raise MissingAppBaseUrl(
            "app_base_url is not set, so password reset links cannot be built"
        )
    # Same check as the PATCH validator in api/system_settings.py, shared via
    # core/smtp_settings.py rather than duplicated — a divergence between
    # "what write-time validation rejects" and "what read-time issuance
    # trusts" is exactly the gap that let a malformed value through both.
    if not looks_like_public_url(base_url):
        raise MissingAppBaseUrl(
            f"app_base_url {base_url!r} is not a usable public URL, so "
            "password reset links cannot be built"
        )
    return base_url

logger = logging.getLogger(__name__)


def build_reset_url(base_url: str, raw_token: str) -> str:
    """Reset link for the frontend's /reset-password route.

    The token goes in the **fragment**, not the query string. A fragment is
    never sent to the server, so it stays out of reverse-proxy and access
    logs, out of `Referer` headers on same-origin navigation, and out of
    anything else that records request URLs. A query parameter would put the
    raw credential in all of them — contradicting the guarantee that it
    exists only inside the emailed link, and doing so for as long as the
    token lives: a day for an admin reset, a week for a welcome link.

    The frontend reads it from `window.location.hash` and posts it in a
    request body; the token never travels as part of a URL the server sees.
    """
    return f"{base_url.rstrip('/')}/reset-password#token={raw_token}"


async def set_password(session: AsyncSession, user: User, new_password: str) -> None:
    """Set a user's password and retire every outstanding reset link.

    **Every path that changes a password must go through this.** Token
    usability is decided by `used_at` and expiry alone, so a link issued
    before the change stays valid afterwards — anyone holding one can later
    overwrite the credential the user just chose, which is a full account
    takeover from a link that was never used. Reproduced end to end: a
    forgot-password link issued, the user changed their password via
    PATCH /users/{id}, and the stale link then returned 204 and replaced it.

    Retiring by stamping `used_at` rather than deleting, for the same reason
    as in prepare_reset_email: the rows are the rate-limit ledger, and
    deleting them would erase the counter the public throttle reads.

    Also bumps `token_epoch`, which revokes every bearer token already
    issued to this user. Without it, changing the password does not actually
    end an attacker's session: create_access_token embeds only sub/exp, and
    get_current_user checked only that the user exists and is active — so a
    JWT obtained before an admin-initiated reset (the flow whose whole
    purpose is responding to a suspected compromise) kept working for its
    full 8-hour lifetime regardless. Incrementing here, in the same
    transaction as the password change, means both land together or not at
    all — there is no window where the password is new but old sessions
    still work, or vice versa.

    The increment is a single atomic `UPDATE ... SET token_epoch =
    token_epoch + 1`, not a Python `user.token_epoch += 1`. The latter reads
    the ORM attribute, computes in Python, and writes it back — two
    concurrent password changes can both read the same starting value and
    both write the same result, silently losing one increment. Reproduced
    directly: two concurrent set_password calls both read epoch 0 and both
    committed epoch 1, so a token minted between the two writes (carrying
    epoch 1) remained valid after the *second* password change, which is
    exactly the revocation this column exists to guarantee. `RETURNING`
    (SQLite 3.35+, well within this project's bundled version, and
    PostgreSQL) both computes the new value in the database and refreshes
    the in-memory attribute in one round trip, so `user.token_epoch` reflects
    reality immediately rather than a value this session's own read raced
    against.

    Does not commit — the caller decides the transaction boundary, so the
    password change and the retirement land together or not at all.
    """
    user.hashed_password = hash_password(new_password)
    new_epoch = (await session.execute(
        update(User)
        .where(User.id == user.id)
        .values(token_epoch=User.token_epoch + 1)
        .returning(User.token_epoch)
    )).scalar_one()
    user.token_epoch = new_epoch
    await session.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        )
        .values(used_at=utcnow())
    )


# sqlite3 reports contention through these result codes. Matched numerically
# rather than on the message, which is localisable and driver-dependent.
_SQLITE_BUSY = 5      # SQLITE_BUSY
_SQLITE_LOCKED = 6    # SQLITE_LOCKED


def _is_lock_contention(exc: DBAPIError) -> bool:
    """True for a bounded lock/busy failure, not a genuine database error.

    Covers both backends, because both can refuse a contended write and both
    are in use here — PostgreSQL in production, SQLite by default:

    * PostgreSQL raises SQLSTATE 55P03 when `SET LOCAL lock_timeout` fires;
    * SQLite raises SQLITE_BUSY / SQLITE_LOCKED once its busy timeout expires.

    Only a *registered* address reaches the write that can hit either, so an
    unhandled one becomes an error response where an unknown address returns a
    padded 202 — account enumeration by status code. Reproduced on SQLite by
    holding a write lock: registered raised OperationalError, unknown returned
    202.

    Matched on codes rather than message text so it does not depend on locale
    or wording, and so a real failure is never swallowed as contention.
    """
    orig = getattr(exc, "orig", None)
    sqlstate = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    if sqlstate == "55P03":
        return True
    # aiosqlite/sqlite3 expose the result code as sqlite_errorcode (3.11+).
    return getattr(orig, "sqlite_errorcode", None) in (_SQLITE_BUSY, _SQLITE_LOCKED)


async def prepare_reset_email(
    session: AsyncSession,
    user: User,
    settings_map: dict[str, str],
    *,
    admin_initiated: bool = False,
    welcome: bool = False,
    deadline: float | None = None,
) -> tuple[EmailMessage, SmtpConfig, str] | None:
    """Issue a reset token and build the email. See _prepare_reset_email.

    This wrapper exists to catch a lock timeout from *any* statement in
    issuance, not just the first one.
    `SET LOCAL lock_timeout` applies to the whole transaction, so every
    statement after it can raise 55P03 — the account-row lock, the
    settings-row lock, the retirement UPDATE and the INSERT alike. Guarding
    only the first left the others escaping as a 500 while an unknown address
    still returned 202, which is account enumeration by status code.
    Reproduced by holding the settings row: LockNotAvailableError surfaced
    uncaught from the settings UPDATE.

    Catching once around the whole body also means a statement added later is
    covered by default rather than needing its own handler — the failure mode
    that produced this bug.
    """
    try:
        return await _prepare_reset_email(
            session, user, settings_map,
            admin_initiated=admin_initiated, welcome=welcome, deadline=deadline,
        )
    except DBAPIError as exc:
        # Contention somewhere in issuance. Give up rather than delay the
        # response past the constant-time floor — declining to issue *this*
        # link is what the throttle does anyway, and is indistinguishable to
        # the caller. Anything that is not a lock timeout is a real failure
        # and must not be swallowed.
        if not _is_lock_contention(exc):
            raise
        logger.info(
            "Password reset for user %s abandoned: lock contention exceeded "
            "the budget",
            user.id,
        )
        await session.rollback()
        return None


async def _prepare_reset_email(
    session: AsyncSession,
    user: User,
    settings_map: dict[str, str],
    *,
    admin_initiated: bool = False,
    welcome: bool = False,
    deadline: float | None = None,
) -> tuple[EmailMessage, SmtpConfig, str] | None:
    """Issue a reset token for `user` and build the email, without sending it.

    Returns the message, the SMTP config to send it with, and the issued
    token's hash, or None when no link could be issued at all (SMTP
    unconfigured, or an address no real server would accept). The token row
    is committed before returning, so the link is valid the moment the
    message goes out — and the hash lets dispatch_reset_email's own
    completion query confirm afterwards that it is *still* valid, since
    committing here releases the per-account lock and a concurrent admin
    reset for the same user can retire this token before the send completes
    (see dispatch_reset_email's _run_completion_query).

    Sending is deliberately *not* done here. An SMTP round-trip takes
    hundreds of milliseconds against a few for a database miss, so performing
    it inside a request that must not reveal whether the address is
    registered would leak exactly that through response timing — measured at
    ~180x on a 500ms send. Callers that can afford to wait (and have no
    enumeration concern) use send_reset_email directly; the public
    forgot-password endpoint hands the result to a background task instead.

    Requests are rate limited per account (see
    RESET_REQUEST_COOLDOWN_SECONDS / RESET_REQUESTS_PER_HOUR) and None is
    returned when a limit is hit. The endpoint is public and keyed only on an
    email address, so without this anyone who knows a user's address could
    request links continuously — and since each request supersedes the last
    token, every link the user actually received would be dead by the time
    they clicked it.

    Only one link is ever live at a time: the previous unused token is
    retired, so an inbox never accumulates working credentials.

    Within RESET_REQUEST_COOLDOWN_SECONDS of a still-valid link, a further
    self-service request is suppressed entirely — no new token, no second
    email — and None is returned. Reissuing instead would mean the user holds
    two emails whose delivery order is not guaranteed (sends are detached),
    so the one they open last can carry an already-retired token.
    """
    smtp_cfg = build_smtp_config(settings_map)
    if not smtp_cfg:
        return None
    if not filter_deliverable_recipients([user.email]):
        # e.g. admin@localhost — a real SMTP server would reject it, and
        # smtplib swallows a partial refusal (see filter_deliverable_recipients).
        return None

    # Validated here, with the other preconditions, rather than where the URL
    # is actually used: by that point the token is committed, and on the
    # admin path the password has already been invalidated. Failing before any
    # of that means a misconfigured deployment refuses the reset outright
    # instead of locking someone out and mailing them a link to nowhere.
    try:
        base_url = require_app_base_url(settings_map)
    except MissingAppBaseUrl:
        logger.warning(
            "Password reset for user %s not issued: app_base_url is not set, "
            "so no usable link can be built",
            user.id,
        )
        return None

    now = utcnow()

    # Serialize issuance per account *before* reading the count. Counting,
    # retiring the old token and inserting the replacement are three
    # statements; without a lock across them, overlapping requests all read
    # the same pre-write count, all pass the cap, and all insert. Measured on
    # PostgreSQL: six concurrent requests produced six emails against a cap of
    # five, and left five simultaneously-valid links where the invariant is
    # one.
    #
    # The owning user row is the lock, not the token rows: the tokens being
    # counted are exactly what each caller is about to add to, so there is no
    # stable set of them to lock.
    #
    # It is taken as a *write*, not SELECT ... FOR UPDATE. SQLite ignores FOR
    # UPDATE, and SQLite is this project's default database — a locking read
    # there is a no-op, so every caller would still read the same pre-write
    # count and the cap would hold only on PostgreSQL. Confirmed by measuring
    # both: with FOR UPDATE, PostgreSQL issued 5 of 6 and SQLite issued all 6.
    # A no-op UPDATE takes a genuine row lock on PostgreSQL and forces
    # SQLite's write lock, so both serialize here.
    # Self-assigning is_active rather than the primary key: an inert write to
    # an ordinary column, with no chance of touching identity or FK semantics.
    # Bound the wait for this lock *in the database*, so a long queue gives up
    # instead of pushing the response past the constant-time floor.
    #
    # lock_timeout rather than asyncio.wait_for: cancelling this coroutine
    # mid-await leaves the AsyncSession unusable — SQLAlchemy raises
    # MissingGreenlet on the next operation, including the rollback meant to
    # clean up, because the cancellation lands inside the driver. Verified at
    # N=300. Letting PostgreSQL refuse the lock keeps the failure inside a
    # normal transaction the caller can roll back.
    #
    # SQLite gets the equivalent bound via PRAGMA busy_timeout. It is *not*
    # immune to the asymmetry — an earlier comment here claimed it was, on the
    # reasoning that SQLite serialises writers globally, which misses that only
    # a registered address reaches the write at all: a contended one errors
    # while an unknown address returns a padded 202.
    #
    # Both are applied per-connection/per-transaction rather than on the shared
    # engine. Setting busy_timeout in the engine's connect_args gave *every*
    # write in the application this endpoint's deadline — verified: an
    # unrelated write behind a 0.8s transaction failed at 0.5s where it had
    # previously succeeded after 1.08s. The short bound is only correct here,
    # where the constant-time floor has to absorb it.
    #
    # Neither statement takes bind parameters, so the value is interpolated;
    # safe, as it is an int derived from a module constant, never user input.
    dialect = session.bind.dialect.name
    if dialect == "postgresql":
        await session.execute(
            text(
                "SET LOCAL lock_timeout = "
                f"{int(FORGOT_PASSWORD_LOCK_TIMEOUT_SECONDS * 1000)}"
            )
        )
    elif dialect == "sqlite":
        # Connection-scoped, not transaction-scoped: SQLite has no SET LOCAL,
        # so this persists on the connection until it is closed.
        #
        # Not restored *here*: doing it through the session — a `finally`,
        # an endpoint helper, the session's own connection — broke ~25
        # unrelated tests, because the extra statement expires the identity
        # map and the next attribute access on a held ORM instance becomes a
        # lazy load outside the greenlet (MissingGreenlet).
        #
        # It is restored on pool checkin instead, by the `checkin` listener in
        # core/database.py, which runs on the raw DBAPI connection once the
        # session is finished with it. That hook is load-bearing, not
        # belt-and-braces: pool return issues a rollback, which does *not*
        # clear connection-scoped pragmas, so without it this bound leaks into
        # whichever unrelated request borrows the connection next (measured:
        # 500ms inherited where 5000ms was expected). That would hand every
        # write in the application this endpoint's deadline — the engine-wide
        # bug this per-transaction approach exists to avoid.
        await session.execute(
            text(
                "PRAGMA busy_timeout = "
                f"{int(FORGOT_PASSWORD_LOCK_TIMEOUT_SECONDS * 1000)}"
            )
        )

    lock_result = await session.execute(
        update(User)
        .where(User.id == user.id)
        .values(is_active=User.is_active)
    )
    if lock_result.rowcount == 0:
        # The account no longer exists — a concurrent admin deleted it (a
        # second admin action, or the same admin double-clicking) after
        # `user` was looked up by this request's own caller but before this
        # lock statement ran. An UPDATE ... WHERE id = ... matches nothing
        # against a deleted row rather than raising, so without this check
        # execution would carry on into the token INSERT further down,
        # which then violates PasswordResetToken.user_id's FK against a
        # row that is already gone — an unhandled IntegrityError, not the
        # clean "not issued" this function reports for every other
        # precondition it already checks (SMTP unconfigured, a malformed
        # base URL, the feature disabled mid-request). Reproduced directly:
        # deleting the user between this request's own lookup and this
        # lock statement raised "FOREIGN KEY constraint failed" out of the
        # INSERT, uncaught by prepare_reset_email's wrapper (which only
        # recognises lock-contention SQLSTATEs, not a constraint
        # violation) and therefore uncaught by register() (api/auth.py)
        # too — a 500 where every other concurrent-deletion path this
        # feature handles (a delete racing the *send*, after the token
        # already exists) already returns a clean, existing 409. Nothing
        # is committed yet, so rollback discards only the inert lock write
        # attempted above.
        logger.info(
            "Password reset for user %s abandoned: the account no longer "
            "exists",
            user.id,
        )
        await session.rollback()
        return None

    # Second gate, on elapsed time rather than the lock.
    #
    # Measured at N=300: the lock timeout never fires and this function stays
    # well inside its budget (48ms median), yet responses for a registered
    # address still ran ~290ms long. The cost is not contention on the lock
    # but the event loop and connection pool saturating — the registered path
    # simply performs more database round-trips than the unknown one, and
    # under enough concurrency that difference shows up in latency however
    # fast each individual step is.
    #
    # So the work is abandoned on wall-clock overrun too, before the writes
    # below. Nothing has been committed at this point; the caller's rollback
    # discards the lock write along with everything else.
    if deadline is not None and time.perf_counter() >= deadline:
        logger.info(
            "Password reset for user %s abandoned: issuance exceeded its "
            "share of the response budget",
            user.id,
        )
        await session.rollback()
        return None

    # Serialize against the settings row too, then re-read the flag under
    # that lock.
    #
    # `settings_map` was read before any of this, so it can be stale: an
    # admin can disable the feature and sweep outstanding tokens in the gap
    # between that read and the insert below, and this request would then add
    # a fresh live token from its stale view. Consumption is deliberately
    # ungated (see api/auth.py), so the sweep is the only thing revoking
    # tokens — a token inserted after it stays usable indefinitely, which is
    # exactly what disabling the feature is meant to prevent.
    #
    # Taking the same row lock both paths need gives them a deterministic
    # order: either this issuance completes and the sweep then retires its
    # token, or the disable commits first and the re-check below refuses.
    # The admin and welcome flows are locked as well — they are exempt from
    # the *throttle*, not from the feature being switched off.
    # Self-assigning value_type, for the same reason is_active is used above:
    # an inert write to an ordinary column, not the primary key (`key`).
    #
    # Raw SQL, not the ORM's update() construct: SQLAlchemy applies a
    # column's Python-side onupdate= default to a Core update() statement
    # whenever the table has one, regardless of which columns are named in
    # .values() — self-assigning value_type does not exempt updated_at from
    # it. Reproduced directly: this lock rewrote self_service_password_reset's
    # updated_at to the current time on every issuance, including from
    # anonymous forgot-password requests that never touched the setting,
    # silently corrupting the "when was this last changed by an admin"
    # audit trail the column exists to record.
    #
    # Preceded by an upsert guaranteeing the row exists, for the same
    # reason api/system_settings.py's patch_settings needs one before its
    # own copy of this exact lock: an UPDATE ... WHERE key = ... only
    # locks/serializes anything when a matching row already exists, and
    # nothing seeds self_service_password_reset — it has no row at all
    # until an admin's first PATCH creates one. This path's own
    # precondition (issuance only runs once the feature is believed
    # enabled) makes an absent row here far less likely than at that
    # PATCH endpoint, but not impossible — a row deleted directly, or any
    # future caller reaching this function without going through that
    # same precondition — so the identical defence is applied here too
    # rather than leaving this copy of the lock exploitable by the exact
    # mechanism the sibling one was just fixed for. CURRENT_TIMESTAMP
    # (not a bound value) sidesteps both a tzinfo mismatch with
    # PostgreSQL's TIMESTAMP WITHOUT TIME ZONE column and Python 3.12's
    # sqlite3 datetime-adapter deprecation warning, and is standard SQL
    # both dialects already support without a cast.
    await session.execute(
        text(
            "INSERT INTO system_settings (key, value, value_type, updated_at) "
            "VALUES (:key, NULL, 'bool', CURRENT_TIMESTAMP) "
            "ON CONFLICT (key) DO NOTHING"
        ),
        # 'bool', matching this lock's one target key's canonical type in
        # KEY_TYPES (api/system_settings.py) — see that sibling upsert's own
        # comment for what a mismatched literal here costs: GET
        # /system-settings would report value_type="string" for this key
        # until an admin's own PATCH happened to correct it via the per-key
        # update loop's `existing.value_type = vtype`.
        {"key": "self_service_password_reset"},
    )
    await session.execute(
        text(
            "UPDATE system_settings SET value_type = value_type "
            "WHERE key = :key"
        ),
        {"key": "self_service_password_reset"},
    )
    # Compared against what the caller read, not against "true" absolutely.
    # The point is to detect the flag *changing* mid-request: only refuse if
    # the stored value now actively disagrees with what this request's own
    # settings_map believed when it started.
    #
    # The row is guaranteed to exist by now — the upsert immediately above
    # seeds it with value=NULL the first time this ever runs for this key —
    # so "no row" is no longer a real case to special-case here. What *can*
    # still legitimately happen is value=NULL on a row that does exist:
    # either that fresh seed itself, or an admin explicitly clearing the
    # bool key via PATCH (self_service_password_reset is not in
    # RUNTIME_DEFAULTS, so clearing it sets value=NULL rather than deleting
    # the row). setting_is_true(None) is correctly False either way, so it
    # is treated the same as any other stored "off" value below.
    #
    # Selecting only SystemSetting.value here previously made that stored
    # NULL indistinguishable from "no row": scalar_one_or_none() returns
    # None in both cases, and the guard's own "must not be refused just
    # because the row is absent" condition then let a stored NULL slip
    # through unrefused too. Selecting `key` alongside `value` and calling
    # `.one_or_none()` on the row (not `.scalar_one_or_none()` on the
    # column) separates "did a row match" from "what is this row's value" —
    # key is the primary key and can never itself be NULL. Reproduced
    # directly: a row with value=NULL alongside caller_thought_enabled=True
    # returned a fresh, consumable token instead of None, i.e. a request in
    # flight when a concurrent disable committed NULL would still issue a
    # link after the feature was switched off.
    caller_thought_enabled = setting_is_true(
        settings_map.get("self_service_password_reset")
    )
    fresh_row = (await session.execute(
        select(SystemSetting.key, SystemSetting.value)
        .where(SystemSetting.key == "self_service_password_reset")
    )).one_or_none()
    fresh_value = fresh_row.value if fresh_row is not None else None
    if caller_thought_enabled and not setting_is_true(fresh_value):
        logger.info(
            "Password reset for user %s abandoned: the feature was disabled "
            "while this request was in flight",
            user.id,
        )
        await session.commit()
        return None

    # Re-read app_base_url under the same lock, for the identical reason
    # the flag above is re-read here rather than trusted from `settings_map`
    # (read before this lock was even acquired, hence "stale" — see that
    # variable's own comment): `base_url` above was computed from that same
    # stale map. api/system_settings.py's changing_base_url sweep retires
    # every outstanding token when app_base_url changes, on the reasoning
    # that a link built for the old address stays redeemable forever
    # against whatever this deployment's current origin is — but that
    # sweep and this function only serialize against each other because
    # both take this same row lock; re-checking only the enable flag left
    # `base_url` itself unguarded, so a request already past its own read of
    # the old URL could still commit a brand-new token built with it,
    # immediately after the sweep that was supposed to retire exactly this
    # kind of link. Reproduced directly: a concurrent admin PATCH changing
    # app_base_url and sweeping tokens committed between this request's own
    # settings_map read and this point, and the request still issued a
    # fresh, live token whose emailed link pointed at the abandoned address.
    # Abandoning here (like the flag check above) rather than rebuilding
    # the message with the fresh URL: the message was already built above
    # from the stale value, so honestly reporting "not issued" and letting
    # the caller's own retry pick up the current settings_map is simpler
    # than reconstructing it mid-function, and this path is not enumeration-
    # sensitive the same way prepare_reset_email's start is (the account's
    # existence was already established by the time control reaches here).
    fresh_base_url_row = (await session.execute(
        select(SystemSetting.key, SystemSetting.value)
        .where(SystemSetting.key == "app_base_url")
    )).one_or_none()
    fresh_base_url = (
        (fresh_base_url_row.value if fresh_base_url_row is not None else None) or ""
    ).strip()
    if fresh_base_url != base_url:
        logger.info(
            "Password reset for user %s abandoned: app_base_url changed "
            "while this request was in flight",
            user.id,
        )
        await session.commit()
        return None

    kind = (
        PasswordResetKind.welcome if welcome
        else PasswordResetKind.admin if admin_initiated
        else PasswordResetKind.self_service
    )

    # Rate limit per account, using the token rows themselves as the ledger —
    # no extra table, and no dependency on Valkey (which is optional here).
    #
    # Restricted to self-service rows. The ledger governs the *public*
    # endpoint only, so counting admin and welcome tokens would let five
    # admin resets exhaust a user's forgot-password quota and lock them out
    # of self-service recovery — the throttle turning into the denial it
    # exists to prevent. The same restriction keeps a long-lived admin (24h)
    # or welcome (7d) token from being picked as `outstanding` below, which
    # would hand an anonymous request that token's expiry instead of the
    # 1-hour self-service TTL.
    window_start = now - timedelta(seconds=RESET_REQUEST_WINDOW_SECONDS)
    recent = (await session.execute(
        select(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.created_at >= window_start,
            PasswordResetToken.kind == PasswordResetKind.self_service,
        )
        .order_by(PasswordResetToken.created_at.desc())
    )).scalars().all()

    # An admin-initiated reset bypasses the throttle deliberately. The limits
    # exist to stop an anonymous caller denying a user their recovery link;
    # an authenticated admin responding to a suspected compromise is the
    # opposite situation, and must never be blocked by whatever request
    # volume an attacker has already generated against that account.
    if not (admin_initiated or welcome) and len(recent) >= RESET_REQUESTS_PER_HOUR:
        logger.info("Password reset rate limit reached for user %s", user.id)
        # Release the account lock taken above before returning. Nothing on
        # this path is worth keeping, and the caller does not commit here — so
        # without this the lock is held for the rest of the request.
        # forgot_password then keeps it across its constant-time sleep, which
        # reintroduces exactly what that sleep exists to prevent: concurrent
        # requests for a throttled *real* account serialize behind each other
        # while requests for unknown addresses do not, and the difference is
        # measurable. It is also a public write-lock DoS — an unauthenticated
        # caller can pin a row lock (and on SQLite block unrelated writers
        # outright) for 250ms per request, at will.
        #
        # Committing, rather than rolling back, because the lock write is
        # inert (is_active = is_active) so there is nothing to undo, and a
        # rollback would discard whatever the *caller* had pending — the
        # admin-initiated path in particular calls this after committing its
        # own changes, and reaching into its transaction to unwind it would
        # be both surprising and wrong.
        await session.commit()
        return None

    if welcome:
        expires_at = now + timedelta(minutes=WELCOME_TOKEN_TTL_MINUTES)
    elif admin_initiated:
        # Always a full, fresh admin window — never inherited from whatever
        # short-lived self-service token happened to be outstanding, which
        # could otherwise expire minutes after the admin acted.
        expires_at = now + timedelta(minutes=ADMIN_RESET_TOKEN_TTL_MINUTES)
    else:
        outstanding = next(
            (r for r in recent if r.used_at is None and r.expires_at > now), None
        )
        if outstanding is not None and (
            now - outstanding.created_at
        ).total_seconds() < RESET_REQUEST_COOLDOWN_SECONDS:
            # Within the cooldown: keep the existing link and send nothing.
            #
            # An earlier version reissued here, keeping the original expiry, on
            # the reasoning that "the newest email always works". That does not
            # hold: sends are detached (see dispatch_reset_email), so two
            # emails can arrive in either order, and the one the user opens
            # last may carry a token a later transaction already retired.
            # Reproduced — the final delivered link returned 400. Reissuing on
            # every request therefore *is* the recovery-denial this cooldown
            # exists to prevent, just moved from the database into the mail
            # queue.
            #
            # Suppressing instead means the one link already in flight stays
            # the valid one, however many times the endpoint is called. The
            # caller cannot distinguish this from a successful send — the
            # response is uniform either way — so it leaks nothing.
            logger.info(
                "Password reset request for user %s suppressed: a link issued "
                "%.0fs ago is still valid",
                user.id,
                (now - outstanding.created_at).total_seconds(),
            )
            # Release the account lock; see the rate-limit branch above for
            # why this commits rather than rolls back.
            await session.commit()
            return None

        expires_at = now + timedelta(minutes=RESET_TOKEN_TTL_MINUTES)

    # Only ever one live link per user: leaving the old one valid would mean
    # several working credentials sitting in an inbox at once.
    #
    # Retired by stamping used_at, *not* by deleting the row. The rate limit
    # above counts rows in the window, so deleting the previous attempt would
    # erase the very ledger it reads — every request would see a clean slate
    # and the hourly cap could never fire. A retired row is already unusable
    # (consume_reset_token rejects any non-NULL used_at) and the scheduler
    # prunes it once it is well past expiry.
    #
    # Scoped asymmetrically, by who asked:
    #
    #   * admin and welcome issuance retires everything. An admin acting on a
    #     suspected compromise must leave exactly one usable link, and they
    #     are authenticated, so superseding a self-service token is their
    #     call to make.
    #
    #   * a *public* request retires only self_service tokens. It must not be
    #     able to destroy a live admin (24h) or welcome (7d) link: those are
    #     issued to someone whose password is already invalidated, so an
    #     anonymous caller who knows the address could otherwise replace that
    #     link with a 1-hour token and repeat — leaving the recipient opening
    #     stale mail with no other way in. That is precisely the
    #     recovery-denial this throttle exists to prevent, and it also
    #     contradicts the ledger query above, which already treats admin and
    #     welcome tokens as none of the public endpoint's business.
    #
    # The one-live-link invariant is preserved within each of those scopes: a
    # user can briefly hold one admin link and one self-service link, which is
    # the price of not letting anonymous requests revoke privileged ones.
    # Re-check the deadline immediately before the writes.
    #
    # The earlier check sits before the settings lock; everything between can
    # still consume the budget — a lock wait that ends in a timeout burns up
    # to FORGOT_PASSWORD_LOCK_TIMEOUT_SECONDS before proceeding. Checking only
    # once let a contended request continue past its budget and answer late,
    # which is the timing signal the floor exists to remove.
    if deadline is not None and time.perf_counter() >= deadline:
        logger.info(
            "Password reset for user %s abandoned: budget exhausted before "
            "the token could be written",
            user.id,
        )
        await session.rollback()
        return None

    retire = update(PasswordResetToken).where(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at.is_(None),
    )
    if not (admin_initiated or welcome):
        retire = retire.where(
            PasswordResetToken.kind == PasswordResetKind.self_service
        )
    await session.execute(retire.values(used_at=now))

    raw_token, token_hash = generate_reset_token()
    session.add(PasswordResetToken(
        token_hash=token_hash,
        user_id=user.id,
        created_at=now,
        expires_at=expires_at,
        kind=kind,
    ))
    await session.commit()

    if welcome:
        ttl = WELCOME_TOKEN_TTL_MINUTES
    elif admin_initiated:
        ttl = ADMIN_RESET_TOKEN_TTL_MINUTES
    else:
        ttl = RESET_TOKEN_TTL_MINUTES
    msg = build_password_reset_email(
        reset_url=build_reset_url(base_url, raw_token),
        display_name=user.display_name,
        recipient=user.email,
        from_addr=smtp_cfg.from_addr,
        expires_minutes=ttl,
        admin_initiated=admin_initiated,
        welcome=welcome,
    )
    return msg, smtp_cfg, token_hash


async def send_reset_email(
    msg: EmailMessage,
    smtp_cfg: SmtpConfig,
    recipient: str,
    user_id: int,
) -> bool:
    """Send a prepared reset email, best-effort. True if it went out
    cleanly, False for any reason to doubt that — never distinguished more
    finely than that (a confirmed failure and a merely-unconfirmed one are
    both just "not sent"; see DispatchOutcome/AdminActionResultEvent for how
    callers report this onward). Never raises: an unreachable or
    misconfigured SMTP server must not turn forgot-password into an
    account-existence oracle, and a background task has no response left to
    fail anyway. Callers never roll back or delete anything on a falsy
    return — the account/token stay exactly as they were, and a human (or a
    fresh reset) decides what happens next.

    A failed send leaves the token row in place deliberately: it is already
    committed, useless to anyone who never received the link, and expires on
    its own. Deleting it would only mean a user whose mail was merely delayed
    finds their link already dead.

    Every caller — the public forgot-password backlog and the admin/welcome
    dispatch_reset_email paths alike — shares the same bounded SMTP executor
    (see EmailService.send).
    """
    try:
        await EmailService(smtp_cfg).send(msg, [recipient])
    except Exception:
        logger.warning("Failed to send password reset email to user %s", user_id, exc_info=True)
        return False
    return True


# Every forgot-password response is padded to this duration, whatever the
# request actually did. Two separate leaks need it:
#
#   * only the registered path issues a token (a DELETE, an INSERT and a
#     commit) — a ~2.4ms signal, small but stable enough to extract by
#     sampling one address repeatedly;
#   * only a real, active account reaches prepare_reset_email, which takes a
#     per-user write lock. Under a *concurrent burst* those requests queue on
#     that lock while requests for an unknown address never touch it. If the
#     queue outlasts the floor, latency discloses account existence again.
#
# The floor must therefore be long enough for that queue to drain inside the
# padded window, not merely longer than the single-request cost. Measured on
# PostgreSQL, max-latency ratio of a burst against a real address versus an
# unknown one:
#
#     floor    N=25     N=50
#     0.25s    1.64x    1.25x     leaks
#     0.50s    1.20x    1.62x     leaks
#     1.00s    1.06x    1.06x     flat, medians identical (1001ms vs 1001ms)
#
# 1s is the smallest value tested that stays flat as the burst grows. It is a
# noticeable wait on a form submission, but this endpoint is used once when
# someone has lost their password, and the alternative is a working
# enumeration oracle.
FORGOT_PASSWORD_MIN_SECONDS = 1.0

# Headroom reserved inside the floor. The existence-dependent work must finish
# with time to spare, so the padding sleep — not lock queueing — is always
# what determines when the response goes out.
#
# The floor alone is not a bound: it keeps the queue inside the window only
# while the queue happens to be short enough. Measured on PostgreSQL with no
# ceiling, median response for a registered address versus an unknown one:
#
#     N=50    1001ms vs 1001ms    1.00x
#     N=150   1002ms vs 1001ms    1.00x
#     N=300   1254ms vs 1001ms    1.25x   ← oracle restored
#
# A burst larger or slower than whatever was last measured pushes past the
# floor again, so the work is capped rather than trusted to be fast.
# Ceiling on how long issuance waits for the per-account lock, comfortably
# inside FORGOT_PASSWORD_MIN_SECONDS so a queued request gives up rather than
# delaying the response past the floor.
FORGOT_PASSWORD_LOCK_TIMEOUT_SECONDS = 0.5


# How long shutdown waits for in-flight reset emails. Long enough for a send
# already past the SMTP connect to finish, short enough not to hold up a
# restart if the relay is wedged.
DRAIN_TIMEOUT_SECONDS = 10.0

# Headroom reserved inside the floor: issuance must finish with time to
# spare so the padding sleep, not the work, decides when the response
# goes out.
FORGOT_PASSWORD_WORK_MARGIN_SECONDS = 0.15

# Ceiling on the existence-dependent work inside forgot-password, well under
# FORGOT_PASSWORD_MIN_SECONDS so it always finishes inside the padded window.
#
# Only a real, active account reaches prepare_reset_email, which takes a
# per-user write lock. Under a concurrent burst those requests queue on that
# lock while requests for an unknown address — which never touch it — do not.
# Once the queue exceeds the floor, response latency discloses account
# existence again: measured on PostgreSQL at 430ms vs 252ms for a burst of
# ten, and the gap widens with burst size.
#
# Bounding the work means a queued request gives up rather than overrunning
# the floor. Giving up is safe: it declines to issue *this* link, which is
# indistinguishable from the throttling the endpoint already applies, and the
# user can retry. The alternative — making unknown addresses do equivalent
# lock work — would hand any anonymous caller a way to generate write-lock
# contention against arbitrary accounts.


async def pad_to_constant_time(started_at: float) -> None:
    """Sleep until FORGOT_PASSWORD_MIN_SECONDS have elapsed since started_at.

    Called on *every* exit path of forgot-password — including the ones that
    do nothing at all — so response time reveals nothing about whether the
    address matched an account, whether that account was active, or whether
    the feature is enabled. If the handler somehow overran the floor there is
    nothing to pad and this returns immediately; that case is a latency
    outlier for both paths alike, not a per-address signal.
    """
    elapsed = time.perf_counter() - started_at
    if elapsed < FORGOT_PASSWORD_MIN_SECONDS:
        await asyncio.sleep(FORGOT_PASSWORD_MIN_SECONDS - elapsed)
    else:
        # Overran the floor — a latency outlier, not a per-address signal, so
        # yield rather than returning sooner relative to the loop than a
        # padded request would.
        await asyncio.sleep(0)


# The cap on concurrent sends lives in core/email.py, enforced by the SMTP
# executor's own size. A semaphore here would not hold: asyncio.wait_for below
# cancels the coroutine and releases it, while run_in_executor cannot cancel
# the worker thread — measured at 20 concurrent threads against a cap of 4.
# Re-exported so callers and tests have one name for the limit.
MAX_CONCURRENT_SENDS = email_MAX_CONCURRENT_SENDS

# Ceiling on *queued-or-running* sends, process-wide — distinct from
# MAX_CONCURRENT_SENDS, which only bounds the executor's own thread count.
# Each entry in _pending_sends holds a task, its coroutine frame, an
# EmailMessage, and a closure, for up to smtp_cfg.timeout * 3 (the task-level
# deadline in dispatch_reset_email) regardless of the four-worker cap on
# threads actually running: the per-account throttle bounds one address, not
# a burst of one request each against many distinct registered addresses,
# and the executor's own admission has no limit on its work queue. Measured
# directly: 2000 dispatched sends held roughly 33KB each — about 65MB — with
# every thread-level cap already in place and unrelated to this one.
MAX_PENDING_SENDS = 1000

# Separate admission cap for admin-reset/welcome-link dispatch attempts,
# checked BEFORE calling dispatch_reset_email. This is an ADDITIONAL gate
# an admin/welcome send must also clear — it does NOT isolate that traffic
# from the shared _pending_sends/MAX_PENDING_SENDS pool underneath: an
# admitted admin/welcome send still calls dispatch_reset_email, which adds
# its own task to _pending_sends (see dispatch_reset_email's own admission
# check) and can itself be refused there if the public forgot_password
# backlog has already saturated it — this cap only ever narrows admission
# further, never substitutes for or exempts from the shared one. Nor does
# admin/welcome traffic get isolated the other way: an admitted admin send
# occupies a real _pending_sends slot too, the same pool forgot_password
# draws from. A previous version of this comment (and dispatch_admin_
# action's own docstring) claimed mutual isolation between the two pools;
# that was inaccurate — already covered by
# test_admission_refused_by_dispatch_reset_emails_own_shared_cap_returns_200
# (tests/test_password_reset.py), which saturates _pending_sends via
# MAX_PENDING_SENDS=0 while _pending_admin_sends is nowhere near its own
# cap, and still gets admission_refused. Low-volume, admin-triggered
# traffic; 50 is a rough backstop, not a tuned figure.
MAX_PENDING_ADMIN_SENDS = 50
_pending_admin_sends: set[object] = set()

# Strong references to in-flight fire-and-forget send tasks. asyncio only
# holds a *weak* reference to a running task, so without this the garbage
# collector can drop one mid-await and the email is silently never sent.
#
# Its length also doubles as the admission check above — a dict/set slot
# reservation is exactly the resource being bounded, so there is nothing a
# separate counter would track that this doesn't already.
_pending_sends: set[asyncio.Task] = set()

# Bounds the completion-query phase (the still_live/account_deleted re-check
# after a confirmed send) independently of the send's own smtp_cfg.timeout *
# 3 bound — this is an ordinary indexed DB point-query, not SMTP I/O, so it
# should never be allowed to hold the task open for the SMTP-sized worst
# case if the database itself is slow/unreachable.
COMPLETION_QUERY_TIMEOUT_SECONDS = 10.0


class DispatchOutcome(NamedTuple):
    """Passed to dispatch_reset_email's on_complete callback. still_live/
    account_deleted are independently nullable — None on either means the
    completion query itself failed or timed out, distinct from a confirmed
    False."""
    sent: bool
    still_live: bool | None
    account_deleted: bool | None
    user_id: int


async def drain_pending_sends(timeout: float | None = None) -> int:
    """Wait for in-flight reset emails to finish. Returns how many were left.

    Called from the application's shutdown lifespan. A strong reference stops
    the garbage collector dropping these tasks, but it does not enrol them in
    the shutdown sequence — a normal worker restart cancels them after the
    endpoint has already answered 202. The token stays live and holds the
    cooldown, so the user is told to check their inbox, receives nothing, and
    cannot re-request. Reproduced directly: 202 returned, send cancelled, zero
    emails delivered, retry suppressed.

    Bounded by `timeout` (default: one send budget) so a hung relay cannot
    stall shutdown indefinitely — SmtpConfig.timeout already bounds each send,
    and dispatch_reset_email caps the task, so this is the outer limit rather
    than the only one. Anything still running when it expires is abandoned;
    that is a genuinely lost email, but it is bounded and logged rather than
    silent.
    """
    if not _pending_sends:
        return 0

    pending = list(_pending_sends)
    logger.info("Draining %d in-flight password reset email(s)", len(pending))
    _, still_running = await asyncio.wait(
        pending, timeout=timeout if timeout is not None else DRAIN_TIMEOUT_SECONDS
    )
    if still_running:
        logger.warning(
            "%d password reset email(s) did not finish before shutdown and "
            "were abandoned; their tokens remain valid so the recipients can "
            "request a new link",
            len(still_running),
        )
    return len(still_running)


# Throttles the "backlog full" warning below to at most once every 10s while
# the backlog stays saturated. A sustained burst against MAX_PENDING_SENDS
# would otherwise log once per dropped request — a log-volume amplification
# that turns the fix for one resource-exhaustion vector into a milder version
# of the same problem on the logging pipeline instead.
_LAST_BACKLOG_FULL_WARNING = 0.0
_BACKLOG_FULL_WARNING_INTERVAL_SECONDS = 10.0


def dispatch_reset_email(
    msg: EmailMessage,
    smtp_cfg: SmtpConfig,
    recipient: str,
    user_id: int,
    token_hash: str,
    *,
    on_complete: Callable[[DispatchOutcome], None] | None = None,
    on_release: Callable[[], None] | None = None,
) -> bool:
    """Start sending in the background and return immediately.

    Used by the public forgot-password endpoint, which must take the same
    time whether or not the address is registered. A FastAPI BackgroundTask
    is *not* sufficient here: those run inside the ASGI request lifecycle, so
    the client still waits for them to finish — measured directly, a 500ms
    background task delayed the response by the full 500ms. Only a detached
    task actually decouples delivery from the response.

    Returns True if a task was created, False if admission was refused by
    the shared _pending_sends/MAX_PENDING_SENDS cap — the one authoritative
    admission signal for the shared pool. forgot_password ignores the
    return value, exactly as it ignored the old bare None.

    on_complete, when given, is invoked with the send's outcome once it
    resolves — success, confirmed failure, or timeout on the send itself,
    or a completion-query failure/timeout after a confirmed send. Invoked
    exactly once per admitted call, never when admission is refused (no
    task exists to attach it to). Any exception on_complete itself raises
    is caught and logged, never allowed to propagate out of the detached
    task.

    on_release, when given, is for a caller-owned admission slot reserved
    *before* this call (api/users.py and api/auth.py's _pending_admin_sends
    gate). It is attached via the task's own `add_done_callback`, exactly
    like `_pending_sends.discard` below, so it fires on success, on
    exception, **and on cancellation**. on_complete alone is not sufficient
    for that job: it is invoked from inside `_bounded`, which deliberately
    does not catch CancelledError (swallowing cancellation would be its own
    bug), so a task cancelled mid-send — a worker restart, or shutdown
    cancelling the detached task — never reaches it and the caller's slot
    would leak for the lifetime of the process. Attaching it here rather
    than leaving each caller to wire its own done-callback keeps both pools'
    cancellation-safety at the same layer; the asymmetry this fixes arose
    precisely from solving it at two different ones. Like on_complete, an
    exception it raises is caught and logged; it is never called when
    admission is refused (the caller releases its own slot on that path,
    since no task exists).

    Admission is bounded and non-blocking (see MAX_PENDING_SENDS): a burst
    against MAX_PENDING_SENDS distinct *registered* addresses is enough to
    exhaust it, since each is a separate account clearing its own throttle
    independently — the per-account cooldown and hourly cap only bound one
    address, not a burst spread across many. At capacity this drops the send
    outright rather than queueing it, which must not become a blocking wait
    for a slot: that would delay the response and reinstate the timing
    oracle this endpoint exists to avoid. The token this call's caller
    already committed is unaffected — dropping the send only means this
    request's recipient does not get an email attempt this time, the same
    outcome a genuine SMTP failure already produces silently elsewhere.
    """
    if len(_pending_sends) >= MAX_PENDING_SENDS:
        global _LAST_BACKLOG_FULL_WARNING
        now = time.monotonic()
        if now - _LAST_BACKLOG_FULL_WARNING >= _BACKLOG_FULL_WARNING_INTERVAL_SECONDS:
            _LAST_BACKLOG_FULL_WARNING = now
            logger.warning(
                "Password reset email backlog full (cap %d) — dropping "
                "sends until it drains; most recently for user %s",
                MAX_PENDING_SENDS, user_id,
            )
        return False

    async def _run_completion_query() -> tuple[bool | None, bool | None]:
        """Returns (still_live, account_deleted). Opens a fresh session —
        the caller's request-scoped session (if any) is long closed by the
        time a backgrounded send resolves."""
        from app.core.database import AsyncSessionLocal
        async with AsyncSessionLocal() as session:
            row = (await session.execute(
                select(PasswordResetToken.id, PasswordResetToken.used_at)
                .where(PasswordResetToken.token_hash == token_hash)
            )).one_or_none()
            if row is None or row.used_at is not None:
                still_live = False
            else:
                still_live = True
            account_deleted = False
            if not still_live:
                exists = (await session.execute(
                    select(User.id).where(User.id == user_id)
                )).scalar_one_or_none()
                account_deleted = exists is None
            return still_live, account_deleted

    async def _bounded() -> None:
        # Belt and braces over SmtpConfig.timeout, which already bounds each
        # socket operation. A send that still overruns — a transport that
        # ignores the timeout, or a stall between operations — would otherwise
        # hold an executor thread and a _pending_sends slot for the lifetime
        # of the process. This endpoint is public and detaches every send, so
        # an unreachable relay must not be able to accumulate them.
        #
        # The wait is generous: several socket timeouts plus TLS and auth can
        # legitimately add up, and abandoning a send that would have succeeded
        # costs the user their link.
        outcome: DispatchOutcome
        try:
            # Queueing happens in the SMTP executor, which is bounded to
            # MAX_CONCURRENT_SENDS workers — so this await simply waits its
            # turn without occupying anything. Dispatch itself stays
            # non-blocking, which matters: a blocking dispatch would delay the
            # response and reinstate the timing oracle.
            sent = await asyncio.wait_for(
                send_reset_email(msg, smtp_cfg, recipient, user_id),
                timeout=smtp_cfg.timeout * 3,
            )
        except TimeoutError:
            # run_in_executor cannot actually cancel the worker thread, so the
            # thread may linger until its own socket timeout fires. What this
            # guarantees is that the *task* completes, releasing its
            # _pending_sends slot rather than pinning one indefinitely.
            logger.warning(
                "Password reset email to user %s abandoned: send did not "
                "complete within %.0fs",
                user_id,
                smtp_cfg.timeout * 3,
            )
            outcome = DispatchOutcome(
                sent=False, still_live=False, account_deleted=False,
                user_id=user_id,
            )
        else:
            if not sent:
                outcome = DispatchOutcome(
                    sent=False, still_live=False, account_deleted=False,
                    user_id=user_id,
                )
            else:
                try:
                    still_live, account_deleted = await asyncio.wait_for(
                        _run_completion_query(),
                        timeout=COMPLETION_QUERY_TIMEOUT_SECONDS,
                    )
                except Exception:
                    logger.warning(
                        "Password reset completion query failed for user "
                        "%s after a confirmed send — reporting sent=True, "
                        "still_live=None",
                        user_id, exc_info=True,
                    )
                    still_live, account_deleted = None, None
                outcome = DispatchOutcome(
                    sent=True, still_live=still_live,
                    account_deleted=account_deleted, user_id=user_id,
                )
        if on_complete is not None:
            try:
                on_complete(outcome)
            except Exception:
                logger.warning(
                    "on_complete callback raised for user %s", user_id,
                    exc_info=True,
                )

    def _release(_task: asyncio.Task) -> None:
        if on_release is None:
            return
        try:
            on_release()
        except Exception:
            logger.warning(
                "on_release callback raised for user %s", user_id, exc_info=True,
            )

    task = asyncio.create_task(_bounded())
    _pending_sends.add(task)
    task.add_done_callback(_pending_sends.discard)
    task.add_done_callback(_release)
    return True


def dispatch_admin_action(
    msg: EmailMessage,
    smtp_cfg: SmtpConfig,
    recipient: str,
    user_id: int,
    token_hash: str,
    *,
    admin_id: int,
    action: Literal["admin_reset", "welcome_link"],
    op_id: str,
    notify: Callable[[int, dict], None],
) -> bool:
    """Admin-reset/welcome-link admission, dispatch, and SSE notification —
    one call, one place, for both api/users.py's reset_password and
    api/auth.py's register.

    Owns the entire _pending_admin_sends lifecycle (the admin-specific
    admission gate, checked *before* calling into dispatch_reset_email) so
    neither caller touches that set directly, or reimplements the same
    reservation/cleanup/notification sequence.

    This gate is ADDITIONAL, not isolating: passing it does not exempt the
    send from dispatch_reset_email's own shared _pending_sends/
    MAX_PENDING_SENDS cap immediately below, which a saturated public-path
    (forgot_password) backlog can still be at — admission_refused either
    way, from the caller's point of view. Nor is admin/welcome traffic
    isolated from that shared pool in the other direction: an admitted
    admin/welcome send still occupies a real _pending_sends slot via
    dispatch_reset_email, the same pool forgot_password draws from. See
    MAX_PENDING_ADMIN_SENDS's own comment for the reasoning and the
    existing test that already covers this
    (test_admission_refused_by_dispatch_reset_emails_own_shared_cap_returns_200).

    Returns True if a send was actually admitted (caller should report a
    202/in-flight response), False if admission was refused by either cap
    (caller should report the response's confirmed-not-sent shape) — a
    `notify` event is emitted for both outcomes and every eventual
    completion, so `notify`'s own recipient (`admin_id`) always learns what
    happened via the SSE `admin_action_result` event; the boolean return is
    only for building the *synchronous* HTTP response, not itself the
    channel either caller should rely on for the final outcome.

    `notify` is injected (rather than imported from app.api.alerts) so this
    service module carries no dependency on the API layer — the same
    dependency-injection pattern dispatch_reset_email already uses for
    on_complete/on_release.

    `op_id` is minted by the caller (it appears in the HTTP response body
    too, for the frontend's own reconciliation, before this function is
    ever called) rather than here, so the caller can build its response
    consistently regardless of which branch below is taken.

    The event handed to `notify` is always built via build_admin_action_
    result_event (schemas/__init__.py) — one of six typed variants, never a
    raw dict assembled here — then serialized at this boundary via
    model_dump(mode="json"), since notify's own queue is a plain dict queue
    shared with unrelated alert-broadcast events (app/api/alerts.py) that
    have no schema of their own to share this one's type with.
    """
    def _emit(*, attempted: bool, sent: bool | None = None,
               still_live: bool | None = None,
               account_deleted: bool | None = None) -> None:
        event = build_admin_action_result_event(
            op_id=op_id, action=action, target_email=recipient,
            attempted=attempted, sent=sent,
            still_live=still_live, account_deleted=account_deleted,
        )
        notify(admin_id, event.model_dump(mode="json"))

    if len(_pending_admin_sends) >= MAX_PENDING_ADMIN_SENDS:
        _emit(attempted=False)
        return False

    # dispatch_reset_email has no task handle to give back — only a bool —
    # so admission is tracked here via a plain sentinel object rather than
    # the real task. Reserved *before* the call so a burst arriving while
    # this dispatch is still being admitted sees the slot as taken; released
    # via on_release, which dispatch_reset_email attaches to the task's own
    # add_done_callback so it also fires if the task is *cancelled*
    # (on_complete does not — see dispatch_reset_email's own docstring).
    admin_task_token = object()
    _pending_admin_sends.add(admin_task_token)

    def _on_release() -> None:
        _pending_admin_sends.discard(admin_task_token)

    def _on_complete(outcome: DispatchOutcome) -> None:
        _emit(
            attempted=True, sent=outcome.sent,
            still_live=outcome.still_live, account_deleted=outcome.account_deleted,
        )

    admitted = dispatch_reset_email(
        msg, smtp_cfg, recipient, user_id, token_hash,
        on_complete=_on_complete,
        on_release=_on_release,
    )
    if not admitted:
        # dispatch_reset_email's own shared-pool cap (MAX_PENDING_SENDS)
        # refused admission — no task was ever created, so on_complete
        # never fires and the reservation above must be released here.
        _pending_admin_sends.discard(admin_task_token)
        _emit(attempted=False)
        return False

    return True


async def consume_reset_token(
    session: AsyncSession, token_hash: str
) -> tuple[PasswordResetToken, User] | None:
    """Atomically claim a usable token and return it with its user, or None.

    None covers every failure mode — unknown, already used, expired, or
    belonging to a deactivated account — deliberately, so the endpoint cannot
    leak which one applied.

    The claim is a single conditional UPDATE stamping `used_at` where it is
    still NULL, and the row count decides the winner: exactly one concurrent
    caller can match, because the second sees the first's write. This is what
    makes the token genuinely single-use.

    The owning account is locked first, before the token, so this path and
    prepare_reset_email always take the same two tables in the same order
    (users, then password_reset_tokens). Opposite orders deadlock — see the
    comment on the lock write below.

    It deliberately does *not* rely on SELECT ... FOR UPDATE. **SQLite ignores
    FOR UPDATE entirely**, and SQLite is this project's default database — so
    a locking read leaves the race wide open in the default deployment while
    looking correct on PostgreSQL. Reproduced directly: two sessions both
    claimed one token and committed different passwords, the second silently
    overwriting the first, so a leaked link still worked after the legitimate
    user had already reset. A conditional UPDATE is atomic on both backends
    because a single statement is.

    Note this stamps `used_at` *before* the password is changed, unlike the
    earlier read-then-write version. The two are not equivalent under
    concurrency, and burning a token on a request that then fails is the
    strictly safer trade: the user re-requests a link, whereas the
    alternative hands a second caller a live token. The caller must still
    commit — an uncommitted claim rolls back with the rest of its
    transaction and the token stays usable.
    """
    # Which user this token belongs to, read without locking anything, purely
    # so the account lock below can be taken first.
    owner_id = (await session.execute(
        select(PasswordResetToken.user_id)
        .where(PasswordResetToken.token_hash == token_hash)
    )).scalar_one_or_none()
    if owner_id is None:
        return None

    # Lock the account *before* the token, matching prepare_reset_email's
    # order. Both paths touch the same two tables — issuance locks the user
    # then writes tokens; this path claims a token then writes the user's
    # password — so taking them in opposite orders lets two overlapping
    # requests deadlock. Reproduced on PostgreSQL as a DeadlockDetected abort
    # that killed the password reset while issuance succeeded, leaving the
    # user's link consumed-but-unused: locked out of the very reset they were
    # completing. A single consistent order (users, then
    # password_reset_tokens) removes the cycle.
    #
    # An inert write rather than SELECT ... FOR UPDATE, for the same reason as
    # in prepare_reset_email: SQLite ignores FOR UPDATE, and it is the default
    # database here.
    await session.execute(
        update(User).where(User.id == owner_id).values(is_active=User.is_active)
    )

    # Read *after* acquiring the lock above, immediately before the claim it
    # gates — not before the owner lookup. Acquiring the lock can block for
    # an arbitrary duration behind another concurrent claim or write to the
    # same account row (this project's own FORGOT_PASSWORD_LOCK_TIMEOUT_SECONDS
    # exists because that wait is real, not theoretical). A `now` captured
    # earlier goes stale for exactly as long as that wait lasts, and the
    # conditional UPDATE below compares against whatever `now` it was given,
    # not against the time it actually executes. Reproduced directly: a
    # token due to expire in ~300ms, a concurrent holder keeping the account
    # lock for ~450ms, and a `now` captured before the lock wait — the claim
    # still succeeded ~155ms after the token's real expiry, because it was
    # comparing expires_at against a timestamp from before the wait rather
    # than the moment of the actual write.
    now = utcnow()

    claimed = await session.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(used_at=now)
    )
    if claimed.rowcount != 1:
        # Nothing of ours is committed — the inert lock write above is
        # discarded with the rest of this transaction.
        await session.rollback()
        return None

    row = (await session.execute(
        select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash)
    )).scalar_one()

    user = await session.get(User, row.user_id)
    if not user or not user.is_active:
        # Claimed, but unusable. Roll the stamp back so a deactivated account
        # that is later re-enabled can still use the link it was sent, rather
        # than silently burning it.
        await session.rollback()
        return None
    return row, user
