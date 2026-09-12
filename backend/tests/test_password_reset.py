"""Self-service password reset flow.

Every test here stubs EmailService.send rather than sending — the flow's
behaviour under test is which tokens get issued, consumed, and rejected, not
SMTP transport, which test_email.py already covers.
"""
import asyncio
import time
from datetime import UTC, timedelta
from email.message import EmailMessage
from typing import ClassVar

import pytest
import pytest_asyncio
import sqlalchemy as sa
from sqlalchemy import event, select, update

from app.core.config import settings as app_settings
from app.core.email import (
    EmailService,
    SmtpConfig,
    _interactive_send_executor,
    _send_executor,
    shutdown_send_executor,
)
from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.models import (
    PasswordResetKind,
    PasswordResetToken,
    SettingValueType,
    SystemSetting,
    User,
    UserRole,
    utcnow,
)
from app.services.password_reset import (
    ADMIN_RESET_TOKEN_TTL_MINUTES,
    FORGOT_PASSWORD_LOCK_TIMEOUT_SECONDS,
    FORGOT_PASSWORD_MIN_SECONDS,
    MAX_CONCURRENT_SENDS,
    MAX_PENDING_SENDS,
    RESET_REQUEST_COOLDOWN_SECONDS,
    RESET_REQUEST_WINDOW_SECONDS,
    RESET_REQUESTS_PER_HOUR,
    RESET_TOKEN_TTL_MINUTES,
    WELCOME_TOKEN_TTL_MINUTES,
    _pending_sends,
    consume_reset_token,
    dispatch_reset_email,
    drain_pending_sends,
    set_password,
)

# Captured at import, before `captured_emails` can replace it. The
# concurrency tests need the genuine method: it is what dispatches to the
# bounded SMTP executor.
_REAL_EMAIL_SEND = EmailService.send

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def captured_emails(monkeypatch):
    """Capture outgoing mail instead of sending it. Returns the list of
    (EmailMessage, recipients) pairs sent during the test."""
    sent: list[tuple] = []

    async def fake_send(self, msg, recipients, *, interactive=False):
        sent.append((msg, recipients))

    monkeypatch.setattr("app.core.email.EmailService.send", fake_send)
    return sent


async def _age_tokens(db, seconds: int) -> None:
    """Backdate every reset token so the next request falls outside the
    cooldown. Requests inside it are suppressed entirely, so a test that
    needs several links issued has to let time pass between them."""
    # Shifted in Python, not SQL: UtcDateTime strips tzinfo on bind, so a
    # column-minus-interval expression reaches it as a timedelta and fails.
    rows = (await db.execute(select(PasswordResetToken))).scalars().all()
    for row in rows:
        row.created_at = row.created_at - timedelta(seconds=seconds)
    await db.commit()


async def _set(db, key: str, value: str | None, vtype=SettingValueType.string) -> None:
    existing = await db.get(SystemSetting, key)
    if existing:
        existing.value = value
        existing.value_type = vtype
    else:
        db.add(SystemSetting(key=key, value=value, value_type=vtype, updated_at=utcnow()))
    await db.commit()


@pytest_asyncio.fixture
async def smtp_configured(db):
    await _set(db, "smtp_host", "smtp.example.com")
    await _set(db, "smtp_from", "pa-central@example.com")
    await _set(db, "app_base_url", "https://pa.example.com")


@pytest_asyncio.fixture
async def self_service_on(db, smtp_configured):
    await _set(db, "self_service_password_reset", "true", SettingValueType.bool)


@pytest_asyncio.fixture
async def reset_user(db) -> User:
    user = User(
        email="resetme@example.com",
        display_name="Reset Me",
        hashed_password=hash_password("originalpassword"),
        role=UserRole.viewer,
        is_active=True,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


def _token_from_email(sent) -> str:
    body = sent[-1][0].get_content()
    # The token lives in the URL fragment, which is never sent to the server.
    line = next(ln for ln in body.splitlines() if "reset-password#token=" in ln)
    return line.split("token=", 1)[1].strip()


# ── Config endpoint ───────────────────────────────────────────────────────────

class TestPasswordResetConfig:
    async def test_reports_disabled_by_default(self, client):
        r = await client.get("/api/auth/password-reset-config")
        assert r.status_code == 200
        assert r.json()["self_service_enabled"] is False

    async def test_reports_enabled_when_configured(self, client, self_service_on):
        r = await client.get("/api/auth/password-reset-config")
        assert r.json()["self_service_enabled"] is True

    @pytest.mark.parametrize("cleared", ["smtp_host", "app_base_url"])
    @pytest.mark.parametrize("value", ["", "   "])
    async def test_disabled_when_a_dependency_is_cleared_despite_the_flag(
        self, client, db, self_service_on, cleared, value
    ):
        """The flag alone must not turn the flow on.

        A reset link needs somewhere to send from *and* somewhere to point.
        The write-path guard refuses to enable without both, but a row can be
        cleared afterwards by something it does not control — a direct
        database edit, a restore, a migration.

        `app_base_url` was missing from this gate: the config endpoint said
        enabled, the login page offered "Forgot password?", and the request
        then issued nothing because require_app_base_url() rejected it
        downstream. Whitespace-only is covered too, since a blank-looking
        value is the same as absent.
        """
        await _set(db, cleared, value)
        r = await client.get("/api/auth/password-reset-config")
        assert r.json()["self_service_enabled"] is False

    @pytest.mark.parametrize(
        "bad_url",
        [
            "ftp://pa.example.com",
            "pa.example.com",
            "https://",
            "https://pa.example.com?next=/x",
            "https://pa.example.com#frag",
            "https://pa.example.com/settings",
            "not a url",
            # Unlike the bare "not a url" above (rejected for having no
            # http(s) scheme at all — a different check), this one has a
            # valid scheme and urlparse still returns a non-empty
            # "hostname" for it ("not a url", spaces intact) — an ordinary
            # non-IP hostname as far as ipaddress.ip_address() is concerned.
            # Confirmed unreachable: socket.getaddrinfo("not a url", 443)
            # fails outright, so this was accepted as usable while nothing
            # could ever resolve it.
            "https://not a url",
        ],
    )
    async def test_disabled_when_app_base_url_is_non_empty_but_malformed(
        self, client, db, self_service_on, bad_url
    ):
        """Non-empty is not the same as usable. self_service_reset_enabled()
        originally checked only presence, not shape — the actual shape check
        (looks_like_public_url) lived solely in the PATCH write-path
        validator and in require_app_base_url()'s read-time issuance gate,
        so a value that reached storage some other way (a direct database
        edit, a restore, a row predating the shape check) could be non-empty
        and still make this endpoint disagree with what issuance would
        actually do. See TestRegisterAgreesWithSelfServiceGate for the
        concrete consequence: register() consulted this same flag to decide
        whether to demand a welcome link, and did so incorrectly."""
        await _set(db, "app_base_url", bad_url)
        r = await client.get("/api/auth/password-reset-config")
        assert r.json()["self_service_enabled"] is False, (
            f"app_base_url={bad_url!r} still reported the feature as enabled"
        )

    @pytest.mark.parametrize("cleared", ["smtp_host", "app_base_url"])
    async def test_a_cleared_dependency_means_no_email_and_no_token(
        self, client, db, self_service_on, reset_user, captured_emails, cleared
    ):
        """The config endpoint and the endpoint's behaviour must agree — the
        bug was that one advertised what the other silently refused."""
        await _set(db, cleared, "")

        r = await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        assert r.status_code == 202
        assert captured_emails == []

        live = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().all()
        assert live == []

    async def test_requires_no_authentication(self, client):
        r = await client.get("/api/auth/password-reset-config")
        assert r.status_code == 200

    @pytest.mark.parametrize(
        "bad_url",
        [
            "ftp://pa.example.com",
            "pa.example.com",
            "https://",
            # A query or fragment lands before the appended path, so the
            # reset route and token are swallowed into it.
            "https://pa.example.com?next=/x",
            "https://pa.example.com#frag",
            # A non-root path is swallowed the same way — the frontend's
            # router only matches "/reset-password" at the root.
            "https://pa.example.com/settings",
            "not a url",
            # Unlike the bare "not a url" above (rejected for having no
            # http(s) scheme at all — a different check), this one has a
            # valid scheme and urlparse still returns a non-empty
            # "hostname" for it ("not a url", spaces intact) — an ordinary
            # non-IP hostname as far as ipaddress.ip_address() is concerned.
            # Confirmed unreachable: socket.getaddrinfo("not a url", 443)
            # fails outright, so this was accepted as usable while nothing
            # could ever resolve it.
            "https://not a url",
        ],
    )
    async def test_a_malformed_app_base_url_means_no_email_and_no_token(
        self, client, db, self_service_on, reset_user, captured_emails, bad_url
    ):
        """require_app_base_url originally checked only "is this non-empty",
        while the shape check lived solely in the PATCH validator — so a
        value that reached storage some other way (a direct database write,
        a restore, a row predating this validation) advertised the feature
        as enabled and let issuance build a broken link, exactly as
        test_a_cleared_dependency_means_no_email_and_no_token above covers
        for the *empty* case. Written directly rather than through
        self._patch, since going through the PATCH endpoint would just
        exercise the write-time validator this finding is about the read
        side lacking a copy of.

        self_service_reset_enabled() (checked by forgot_password before
        prepare_reset_email is even called) now applies the same shape
        check too, so this assertion no longer isolates
        require_app_base_url()'s own copy specifically — either gate
        refusing produces the same observable outcome asserted here. Both
        gates sharing looks_like_public_url() is the point: this test only
        needs the *outcome* to hold, not which layer produced it.
        """
        await _set(db, "app_base_url", bad_url)

        r = await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        assert r.status_code == 202
        assert captured_emails == [], (
            f"a malformed app_base_url ({bad_url!r}) still resulted in an "
            "email being sent"
        )

        live = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().all()
        assert live == [], (
            f"a malformed app_base_url ({bad_url!r}) still resulted in a "
            "token being issued"
        )

    async def test_a_malformed_app_base_url_falls_back_to_a_generated_password(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """self_service_reset_enabled() now applies the same shape check
        require_app_base_url() does (see TestRegisterAgreesWithSelfServiceGate
        and the shared looks_like_public_url()), so with a malformed URL the
        admin-reset endpoint's `if self_service_reset_enabled(...)` branch is
        never entered at all — the same as if the feature were off outright.
        It falls back to generating a password and returning it, exactly as
        the disabled-feature path does, rather than reaching
        require_app_base_url()'s own check inside that branch (now
        unreachable here: the two checks agree, so one being True guarantees
        the other does not raise).

        This replaces an earlier version of this test that expected a 400
        from require_app_base_url() — that was the previous fix's own
        boundary, reachable only because the outer gate did not yet validate
        shape. Asserting a 400 here now would mean re-litigating for the
        bug this fix closes.
        """
        await _set(db, "app_base_url", "ftp://pa.example.com")

        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["password"], "expected a generated password to relay"
        assert body["reset_link_sent"] is False
        assert captured_emails == []

        await db.refresh(reset_user)
        assert verify_password(body["password"], reset_user.hashed_password)


# ── Forgot password ───────────────────────────────────────────────────────────

class TestForgotPassword:
    async def test_sends_link_to_known_address(self, client, db, self_service_on, reset_user, captured_emails):
        r = await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        assert r.status_code == 202
        assert len(captured_emails) == 1
        msg, recipients = captured_emails[0]
        assert recipients == [reset_user.email]
        assert "reset-password#token=" in msg.get_content()

        rows = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.user_id == reset_user.id)
        )).scalars().all()
        assert len(rows) == 1
        assert rows[0].used_at is None

    async def test_link_uses_configured_app_base_url(self, client, self_service_on, reset_user, captured_emails):
        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        assert "https://pa.example.com/reset-password#token=" in captured_emails[0][0].get_content()

    async def test_the_token_is_in_the_fragment_not_the_query_string(
        self, client, self_service_on, reset_user, captured_emails
    ):
        """A query parameter would put the raw credential in reverse-proxy
        and access logs and in Referer headers, for as long as the token
        lives — a day for an admin reset, a week for a welcome link. A
        fragment is never sent to the server at all."""
        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        body = captured_emails[0][0].get_content()

        assert "/reset-password#token=" in body
        assert "?token=" not in body, (
            "the raw token is in the query string, where every request log "
            "will record it"
        )

    async def test_raw_token_is_not_stored(self, client, db, self_service_on, reset_user, captured_emails):
        """Only the hash is persisted — a DB read must not yield a usable link."""
        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        raw = _token_from_email(captured_emails)
        row = (await db.execute(select(PasswordResetToken))).scalar_one()
        assert row.token_hash != raw
        assert len(row.token_hash) == 64

    async def test_a_stored_from_addr_containing_crlf_does_not_leak_existence(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """build_password_reset_email (core/email.py) assigns smtp_from
        straight to EmailMessage()["From"] — Python's own email module
        raises ValueError for a value containing a carriage return or line
        feed (a header-injection vector). A value reaching storage some
        other way than PATCH (a restore, a direct edit — self_service_on's
        own smtp_from is never routed through the write-time validator
        this test bypasses on purpose) previously raised uncaught only
        once a real, active account actually reached issuance: an unknown
        address never calls build_smtp_config at all, so it kept returning
        the padded 202 while a real account's request 500'd — an
        account-existence oracle by status code identical in shape to the
        DBAPIError-only lock-contention bug prepare_reset_email's own
        docstring already describes, just via an exception type that guard
        does not catch. Reproduced directly before this fix.
        """
        await _set(db, "smtp_from", "pa\r\nBcc: evil@example.com")

        known = await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        unknown = await client.post(
            "/api/auth/forgot-password", json={"email": "nobody-crlf@example.com"}
        )
        assert known.status_code == unknown.status_code == 202, (
            f"known={known.status_code} unknown={unknown.status_code} — a "
            "malicious smtp_from value must not distinguish a real account "
            "from an unknown one by status code"
        )
        assert known.json() == unknown.json()
        assert captured_emails == []

    async def test_unknown_address_returns_same_response_without_sending(
        self, client, self_service_on, reset_user, captured_emails
    ):
        """No account enumeration: identical status and body, no email.

        `reset_user` is required, not incidental — without it the "known"
        address does not exist and both requests take the unknown-address
        path, so the responses match trivially and nothing about a real
        account is verified.
        """
        # Read before the request: forgot-password rolls back its session to
        # release the connection during padding, which expires this instance.
        email = reset_user.email

        known = await client.post("/api/auth/forgot-password", json={"email": email})
        # Guard the premise: this must be the registered-address path.
        assert len(captured_emails) == 1, (
            "no email was sent for the known address — this test is comparing "
            "two unknown-address responses"
        )

        unknown = await client.post(
            "/api/auth/forgot-password", json={"email": "nobody@example.com"}
        )
        assert unknown.status_code == known.status_code == 202
        assert unknown.json() == known.json()

        # Still one: the unknown address sent nothing. `all(...)` over the
        # captured list would pass vacuously when empty, so the count is
        # asserted rather than only the recipients.
        assert len(captured_emails) == 1
        assert captured_emails[0][1] == [email]

    async def test_inactive_user_gets_no_link(self, client, db, self_service_on, reset_user, captured_emails):
        reset_user.is_active = False
        await db.commit()
        r = await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        assert r.status_code == 202
        assert captured_emails == []

    async def test_no_op_when_feature_disabled(self, client, db, smtp_configured, reset_user, captured_emails):
        r = await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        assert r.status_code == 202
        assert captured_emails == []
        assert (await db.execute(select(PasswordResetToken))).scalars().all() == []

    async def test_a_repeat_request_inside_the_cooldown_sends_nothing(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """The link already in flight stays the valid one.

        Reissuing here would leave the user holding two emails whose delivery
        order is not guaranteed — sends are detached — so the one they open
        last could carry an already-retired token. Reproduced before this
        changed: the final delivered link returned 400.
        """
        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        assert len(captured_emails) == 1
        first = _token_from_email(captured_emails)

        r = await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        assert r.status_code == 202
        assert len(captured_emails) == 1, "a second email was sent inside the cooldown"

        live = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().all()
        assert len(live) == 1

        # The link the user actually received still works.
        used = await client.post(
            "/api/auth/reset-password",
            json={"token": first, "new_password": "a-brand-new-password"},
        )
        assert used.status_code == 204

    async def test_a_new_link_is_issued_once_the_cooldown_lapses(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """Suppression is a cooldown, not a lockout — a user who genuinely
        lost the first email must be able to ask again."""
        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        first = _token_from_email(captured_emails)

        await _age_tokens(db, seconds=RESET_REQUEST_COOLDOWN_SECONDS + 30)

        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        assert len(captured_emails) == 2
        second = _token_from_email(captured_emails)
        assert second != first

        # The superseded row is retired (used_at stamped), not deleted — it
        # stays as the rate-limit ledger — and only the newest link works.
        live = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().all()
        assert len(live) == 1

        stale = await client.post(
            "/api/auth/reset-password",
            json={"token": first, "new_password": "a-brand-new-password"},
        )
        assert stale.status_code == 400

    async def test_requires_no_authentication(self, client, self_service_on, reset_user):
        r = await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        assert r.status_code == 202

    async def test_smtp_failure_does_not_reveal_account_existence(
        self, client, self_service_on, reset_user, monkeypatch
    ):
        """An unreachable SMTP server must not make a registered address
        answer differently from an unknown one — a 500 here would be a
        cleaner enumeration oracle than any timing difference."""
        async def boom(self, msg, recipients, *, interactive=False):
            raise OSError("connection refused")

        monkeypatch.setattr("app.core.email.EmailService.send", boom)

        known = await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        unknown = await client.post("/api/auth/forgot-password", json={"email": "nobody@example.com"})
        assert known.status_code == unknown.status_code == 202
        assert known.json() == unknown.json()


# ── Response timing must not reveal account existence ─────────────────────────

class TestForgotPasswordTiming:
    """forgot-password must take the same time whether or not the address is
    registered.

    Two distinct leaks are covered here, because fixing either alone leaves a
    working oracle:

    1. Awaiting the SMTP send inside the request. Measured at ~520ms for a
       registered address against ~3ms for an unknown one — a ~180x gap
       readable from a single request pair. Note a FastAPI BackgroundTask
       does *not* fix this: those run inside the ASGI request lifecycle, so
       the client still waits. The send is detached instead.
    2. The token DELETE/INSERT/commit that only the registered path performs
       — ~2.4ms, too small to read in one request but stable enough to
       extract by sampling one address repeatedly. Closed by padding every
       response to a constant floor.
    """

    async def _time_post(self, client, email: str, samples: int = 5) -> float:
        """Mean seconds per request, after a warm-up request."""
        await client.post("/api/auth/forgot-password", json={"email": email})
        start = time.perf_counter()
        for _ in range(samples):
            await client.post("/api/auth/forgot-password", json={"email": email})
        return (time.perf_counter() - start) / samples

    async def test_registered_and_unknown_addresses_take_the_same_time(
        self, client, self_service_on, reset_user, monkeypatch
    ):
        """The end-to-end guarantee, with a deliberately slow SMTP server.

        A 300ms send is well over the constant-time floor, so if delivery were
        ever awaited inside the request again this fails immediately rather
        than merely drifting.
        """
        async def slow_send(self, msg, recipients, *, interactive=False):
            await asyncio.sleep(0.3)

        monkeypatch.setattr("app.core.email.EmailService.send", slow_send)

        known = await self._time_post(client, reset_user.email)
        unknown = await self._time_post(client, "nobody@example.com")

        assert known < unknown * 1.5, (
            f"timing oracle: a registered address took {known * 1000:.0f}ms vs "
            f"{unknown * 1000:.0f}ms for an unknown one"
        )

    async def test_the_send_is_not_awaited_in_the_request(
        self, client, self_service_on, reset_user, monkeypatch
    ):
        """Pins the mechanism, not just the outcome: a send far slower than
        the floor must not extend the response at all."""
        send_started = asyncio.Event()

        async def very_slow_send(self, msg, recipients, *, interactive=False):
            send_started.set()
            await asyncio.sleep(5)

        monkeypatch.setattr("app.core.email.EmailService.send", very_slow_send)

        start = time.perf_counter()
        r = await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        elapsed = time.perf_counter() - start

        assert r.status_code == 202
        assert elapsed < 2.0, (
            f"the response waited {elapsed:.1f}s on a 5s send — delivery is "
            "back on the response path"
        )

    @pytest.mark.parametrize(
        "email,enabled",
        [
            ("resetme@example.com", True),   # issues a token
            ("nobody@example.com", True),    # unknown address
            ("nobody@example.com", False),   # feature disabled
        ],
    )
    async def test_no_transaction_is_held_across_the_padding(
        self, client, db, self_service_on, reset_user, monkeypatch, email, enabled
    ):
        """The padding must not be served while holding a pooled connection.

        Every path runs at least one SELECT, which opens a transaction, and
        get_db does not close the session until after the response — so
        without an explicit release an unauthenticated caller pins a
        connection for the full 250ms and enough concurrent requests exhaust
        the pool. Measured before the fix: in_transaction() was True through
        the whole sleep on the unknown-address path.

        Parametrised over all three exits because only the token-issuing one
        commits on its own; the others were left open.
        """
        if not enabled:
            await _set(db, "self_service_password_reset", "false", SettingValueType.bool)

        import app.services.password_reset as pr
        real_pad = pr.pad_to_constant_time
        seen: dict[str, bool] = {}

        async def watching_pad(started_at: float) -> None:
            seen["in_transaction"] = db.in_transaction()
            await real_pad(started_at)

        monkeypatch.setattr("app.api.auth.pad_to_constant_time", watching_pad)

        r = await client.post("/api/auth/forgot-password", json={"email": email})
        assert r.status_code == 202
        assert seen["in_transaction"] is False, (
            "a database transaction is open across the padding interval — "
            "concurrent anonymous requests can exhaust the connection pool"
        )

    async def test_every_response_meets_the_constant_time_floor(
        self, client, self_service_on
    ):
        """The floor must apply to the cheap path too — that is the whole
        point of it. An unknown address does almost no work, so without
        padding it returns in ~2ms."""
        start = time.perf_counter()
        r = await client.post(
            "/api/auth/forgot-password", json={"email": "nobody@example.com"}
        )
        elapsed = time.perf_counter() - start

        assert r.status_code == 202
        assert elapsed >= FORGOT_PASSWORD_MIN_SECONDS * 0.9, (
            f"response returned in {elapsed * 1000:.0f}ms, below the "
            f"{FORGOT_PASSWORD_MIN_SECONDS * 1000:.0f}ms floor"
        )

    async def test_floor_applies_when_the_feature_is_disabled(
        self, client, smtp_configured
    ):
        """Whether the feature is on is itself not worth leaking per-request,
        and this path exits earliest of all."""
        start = time.perf_counter()
        r = await client.post(
            "/api/auth/forgot-password", json={"email": "nobody@example.com"}
        )
        elapsed = time.perf_counter() - start

        assert r.status_code == 202
        assert elapsed >= FORGOT_PASSWORD_MIN_SECONDS * 0.9


# ── Single-use enforcement on SQLite (the default database) ───────────────────

class TestTokenClaimIsAtomicOnSqlite:
    """A reset token must be consumable exactly once *on SQLite too*.

    The original fix used SELECT ... FOR UPDATE, which SQLite ignores
    outright — so the race stayed wide open in this project's default
    deployment while the PostgreSQL test reported it fixed. Reproduced
    directly on a SQLite file database: two sessions both claimed one token
    and committed different passwords, the second silently overwriting the
    first.

    These run on the suite's ordinary SQLite engine deliberately. The
    PostgreSQL equivalents live in test_postgres_behaviour.py; both are
    needed, because each backend gets the guarantee by a different mechanism
    and only one of them was ever covered.
    """

    async def _seed(self, db, token_hash: str = "f" * 64) -> int:
        user = User(
            email="atomic@example.com", display_name="Atomic",
            hashed_password=hash_password("originalpassword"),
            role=UserRole.viewer, is_active=True,
        )
        db.add(user)
        await db.flush()
        db.add(PasswordResetToken(
            token_hash=token_hash, user_id=user.id,
            created_at=utcnow(), expires_at=utcnow() + timedelta(minutes=60),
        ))
        await db.commit()
        return user.id

    async def test_a_second_claim_is_refused(self, db):
        """The core guarantee, independent of transaction interleaving: once
        a token is claimed, claiming it again returns None."""
        await self._seed(db)

        first = await consume_reset_token(db, "f" * 64)
        assert first is not None
        await db.commit()

        second = await consume_reset_token(db, "f" * 64)
        assert second is None, "a consumed token was claimed a second time"

    async def test_the_claim_stamps_used_at_itself(self, db):
        """The claim is the write — callers must not need a second statement
        to retire the token, since a read-then-write pair is exactly the
        non-atomic shape this replaced."""
        await self._seed(db)

        claimed = await consume_reset_token(db, "f" * 64)
        assert claimed is not None
        row, _user = claimed
        assert row.used_at is not None

    async def test_an_expired_token_cannot_be_claimed(self, db):
        """Expiry is enforced inside the same conditional UPDATE, not by a
        separate check that a concurrent writer could race past."""
        await self._seed(db)
        await db.execute(
            update(PasswordResetToken).values(
                expires_at=utcnow() - timedelta(minutes=1)
            )
        )
        await db.commit()

        assert await consume_reset_token(db, "f" * 64) is None

    async def test_an_unknown_token_is_refused(self, db):
        await self._seed(db)
        assert await consume_reset_token(db, "0" * 64) is None

    async def test_a_deactivated_users_token_is_not_burned(self, db):
        """The claim stamps used_at before the account is checked, so a
        rejected claim must roll that back — otherwise a user disabled and
        re-enabled would find the link they were sent already spent."""
        user_id = await self._seed(db)
        user = await db.get(User, user_id)
        user.is_active = False
        await db.commit()

        assert await consume_reset_token(db, "f" * 64) is None

        user = await db.get(User, user_id)
        user.is_active = True
        await db.commit()

        recovered = await consume_reset_token(db, "f" * 64)
        assert recovered is not None, "the link was burned by the rejected claim"

    async def test_an_uncommitted_claim_leaves_the_token_usable(self, db):
        """The claim only becomes final when the caller commits — a request
        that fails partway must not spend the token."""
        await self._seed(db)

        assert await consume_reset_token(db, "f" * 64) is not None
        await db.rollback()

        assert await consume_reset_token(db, "f" * 64) is not None, (
            "a rolled-back claim consumed the token anyway"
        )

    async def test_the_expiry_cutoff_is_read_after_the_lock_is_acquired(
        self, tmp_path
    ):
        """consume_reset_token used to capture `now` before locking the
        account, then compare a token's expires_at against that stale
        value inside the claim. Acquiring the account lock can block for
        an arbitrary duration behind another concurrent writer to the same
        row — this project's own FORGOT_PASSWORD_LOCK_TIMEOUT_SECONDS
        exists because that wait is real — so a token due to expire during
        the wait would still be compared against the earlier, pre-wait
        timestamp and accepted despite having genuinely expired by the
        time the claim actually executes.

        Deterministic proof, not a real-time race: a genuinely separate
        raw connection takes `BEGIN IMMEDIATE` on the account's row before
        the claim starts, so it must wait to acquire the same lock. The
        claim is launched as a background task and confirmed still
        blocked (not merely fast) before the token's expiry passes. Only
        once the token has genuinely expired is the lock released. If
        `now` is read before the lock (the bug), the claim compares
        against a timestamp from before expiry and wrongly succeeds; if
        read after (the fix), it compares against a timestamp from after
        expiry and correctly returns None.
        """
        import sqlalchemy as sa
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from app.core.database import Base, sqlite_on_checkin, sqlite_on_connect

        url = f"sqlite+aiosqlite:///{tmp_path}/expiry_lock.db"
        engine = create_async_engine(url, connect_args={"check_same_thread": False})
        event.listens_for(engine.sync_engine, "connect")(sqlite_on_connect)
        event.listens_for(engine.sync_engine, "checkin")(sqlite_on_checkin)
        holder_engine = create_async_engine(url, connect_args={"check_same_thread": False})
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(engine, expire_on_commit=False)

            expires_at = utcnow() + timedelta(seconds=1)
            async with factory() as s:
                user = User(
                    email="expiry-lock@example.com", display_name="Expiry Lock",
                    hashed_password=hash_password("originalpassword"),
                    role=UserRole.viewer, is_active=True,
                )
                s.add(user)
                await s.flush()
                s.add(PasswordResetToken(
                    token_hash="d" * 64, user_id=user.id,
                    created_at=utcnow(), expires_at=expires_at,
                ))
                await s.commit()

            # Held before the claim starts, so its own lock acquisition
            # must wait on this connection releasing it.
            holder = holder_engine.connect()
            conn = await holder.start()
            await conn.execute(sa.text("BEGIN IMMEDIATE"))

            async def run_claim():
                async with factory() as s:
                    result = await consume_reset_token(s, "d" * 64)
                    if result is not None:
                        await s.commit()
                    return result

            claim_task = asyncio.create_task(run_claim())
            await asyncio.sleep(0.1)
            assert not claim_task.done(), (
                "the claim completed before the lock was even released — "
                "it is not actually waiting on the held connection, so "
                "this test cannot prove anything about the fix"
            )
            assert utcnow() < expires_at, (
                "the token already expired before the lock was even "
                "released — this test cannot distinguish the fix from "
                "the bug; widen the margin above"
            )

            # Release only once the token has genuinely expired — the
            # claim can only proceed after this point.
            await asyncio.sleep(1.1)
            assert utcnow() > expires_at, (
                "the token has not actually expired yet — widen the "
                "margin above"
            )
            await conn.commit()

            try:
                result = await asyncio.wait_for(claim_task, timeout=5.0)
            except TimeoutError:
                pytest.fail(
                    "the claim did not complete within 5s of the lock "
                    "being released — it is stuck rather than proceeding"
                )

            assert result is None, (
                "an expired token was claimed successfully — the expiry "
                "cutoff was read before the lock wait rather than after it"
            )
        finally:
            await holder.close()
            await holder_engine.dispose()
            await engine.dispose()


# ── Sends are bounded process-wide ────────────────────────────────────────────

class TestSendConcurrencyIsBounded:
    """Detached sends must not saturate asyncio's shared default executor.

    The per-account throttle bounds requests for *one* user and says nothing
    about a burst across distinct accounts. Every match enqueues a blocking
    smtplib call on the shared executor (20 workers by default), and with an
    unreachable relay each holds a worker for the whole SMTP timeout — so
    unrelated executor work elsewhere in the process queues behind them.
    Measured before the semaphore: an unrelated task waited 1.8s behind 30
    queued 2s sends, scaling with SmtpConfig.timeout.

    The task-level timeout guarantees eventual recovery but not the absence of
    exhaustion, because the work is created before anything checks capacity.
    """

    @staticmethod
    def _real_send(monkeypatch) -> None:
        """Undo the file-wide `captured_emails` fixture for this test.

        That autouse fixture replaces `EmailService.send` outright, which is
        exactly the method that hands work to the bounded SMTP executor — so
        with it in place these tests reach no executor at all and measure
        nothing. (They did: patching `_send_sync` under it recorded zero
        calls.) Restore the real `send` so the cap under test is the one
        production uses, then patch the blocking inner function.
        """
        monkeypatch.setattr(
            "app.core.email.EmailService.send", _REAL_EMAIL_SEND
        )

    @staticmethod
    def _config() -> SmtpConfig:
        return SmtpConfig(
            host="smtp.example.com", port=587, username=None, password=None,
            from_addr="pa-central@example.com", tls_mode="none", timeout=30.0,
        )

    async def test_concurrent_sends_are_capped(self, monkeypatch):
        self._real_send(monkeypatch)
        # Patch _send_sync, not send: the cap is the SMTP executor's own size,
        # so a fake `send` that never reaches the executor would bypass the
        # very thing under test. (It did — this test passed against an
        # unbounded implementation until it was pointed at the real path.)
        import threading

        live = 0
        peak = 0
        lock = threading.Lock()

        def tracked(msg, recipients, cfg, socket_timeout):
            nonlocal live, peak
            with lock:
                live += 1
                peak = max(peak, live)
            time.sleep(0.05)
            with lock:
                live -= 1

        monkeypatch.setattr(
            "app.core.email.EmailService._send_sync", staticmethod(tracked)
        )

        for i in range(30):
            dispatch_reset_email(EmailMessage(), self._config(), f"u{i}@example.com", i)
        await asyncio.gather(*list(_pending_sends))

        assert peak <= MAX_CONCURRENT_SENDS, (
            f"{peak} sends ran at once against a cap of {MAX_CONCURRENT_SENDS}"
        )
        assert peak > 1, "the cap serialised everything — sends should overlap"

    async def test_a_cancelled_send_cannot_leak_a_worker(self, monkeypatch):
        """The cap must survive the task timeout firing.

        `asyncio.wait_for` cancels the coroutine, but `run_in_executor` cannot
        cancel the worker thread — so a semaphore released on cancellation
        stops accounting for a thread that is still running. Measured with
        that design: 20 concurrent threads against a cap of 4, saturating the
        default executor. The bound is structural now: the SMTP executor has
        exactly MAX_CONCURRENT_SENDS workers, so a leaked coroutine cannot
        create a thread that is not one of them.
        """
        self._real_send(monkeypatch)
        import threading

        live = 0
        peak = 0
        lock = threading.Lock()

        def blocking(msg, recipients, cfg, socket_timeout):
            nonlocal live, peak
            with lock:
                live += 1
                peak = max(peak, live)
            # Outlives the task budget (timeout * 3) so every send is
            # cancelled while its thread is still working.
            time.sleep(1.5)
            with lock:
                live -= 1

        monkeypatch.setattr(
            "app.core.email.EmailService._send_sync", staticmethod(blocking)
        )
        config = SmtpConfig(
            host="smtp.example.com", port=587, username=None, password=None,
            from_addr="pa-central@example.com", tls_mode="none", timeout=0.1,
        )

        for i in range(20):
            dispatch_reset_email(EmailMessage(), config, f"u{i}@example.com", i)
        await asyncio.gather(*list(_pending_sends), return_exceptions=True)
        await asyncio.sleep(0.4)

        assert peak <= MAX_CONCURRENT_SENDS, (
            f"{peak} SMTP threads ran at once against a cap of "
            f"{MAX_CONCURRENT_SENDS} — cancelled sends are leaking workers"
        )
        # Wait for the detached threads rather than sleeping a guessed
        # interval — the executor is shared for the process, so leaving them
        # running would bleed into later tests.
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(_send_executor(), lambda: None)

    async def test_dispatch_never_blocks(self, monkeypatch):
        """The semaphore is acquired *inside* the task. Acquiring before
        creating it would make a send backlog delay the response, putting the
        timing oracle back."""
        async def slow(self, msg, recipients, *, interactive=False):
            await asyncio.sleep(0.2)

        monkeypatch.setattr("app.core.email.EmailService.send", slow)

        started = time.perf_counter()
        for i in range(30):
            dispatch_reset_email(EmailMessage(), self._config(), f"u{i}@example.com", i)
        elapsed = time.perf_counter() - started

        assert elapsed < 0.05, (
            f"dispatching 30 sends took {elapsed * 1000:.0f}ms — it is blocking "
            "on the semaphore and would delay the response"
        )
        for task in list(_pending_sends):
            task.cancel()
        await asyncio.gather(*list(_pending_sends), return_exceptions=True)

    async def test_a_send_backlog_does_not_starve_the_executor(self, monkeypatch):
        """The property that matters operationally: other features using
        run_in_executor must not queue behind a wave of reset emails."""
        # Patch _send_sync so the work lands on the *SMTP* executor, which is
        # the point: unrelated `run_in_executor` callers use the default one
        # and must not queue behind reset emails at all.
        def blocking(msg, recipients, cfg, socket_timeout):
            time.sleep(1.0)

        monkeypatch.setattr(
            "app.core.email.EmailService._send_sync", staticmethod(blocking)
        )

        for i in range(30):
            dispatch_reset_email(EmailMessage(), self._config(), f"u{i}@example.com", i)
        await asyncio.sleep(0.3)

        loop = asyncio.get_running_loop()
        started = time.perf_counter()
        await loop.run_in_executor(None, lambda: None)
        waited = time.perf_counter() - started

        for task in list(_pending_sends):
            task.cancel()
        await asyncio.gather(*list(_pending_sends), return_exceptions=True)

        assert waited < 0.5, (
            f"an unrelated executor task waited {waited:.2f}s behind queued "
            "reset emails"
        )


class TestPendingSendBacklogIsBounded:
    """The four-worker executor bounds *running* threads, but nothing bounded
    how many sends could be *queued* ahead of it.

    Each entry in _pending_sends holds a task, its coroutine frame, an
    EmailMessage, and a closure for up to smtp_cfg.timeout * 3 — the
    per-account throttle (cooldown + hourly cap) bounds one address, not a
    burst spread across many distinct *registered* addresses, each clearing
    its own throttle independently. Measured directly before this cap
    existed: 2000 dispatched sends against an unreachable relay held roughly
    33KB each, ~65MB, growing linearly with burst size and bounded only by
    smtp_cfg.timeout * 3 (90s by default) — during which an attacker could
    keep dispatching. At 100k requests that is several GB.
    """

    @staticmethod
    def _config() -> SmtpConfig:
        return SmtpConfig(
            host="smtp.example.com", port=587, username=None, password=None,
            from_addr="pa-central@example.com", tls_mode="none", timeout=30.0,
        )

    async def test_dispatch_never_exceeds_the_cap(self, monkeypatch):
        async def never_returns(self, msg, recipients, *, interactive=False):
            await asyncio.sleep(3600)

        monkeypatch.setattr("app.core.email.EmailService.send", never_returns)

        for i in range(MAX_PENDING_SENDS * 3):
            dispatch_reset_email(EmailMessage(), self._config(), f"u{i}@example.com", i)

        assert len(_pending_sends) == MAX_PENDING_SENDS, (
            f"{len(_pending_sends)} sends pending against a cap of "
            f"{MAX_PENDING_SENDS} — a burst across distinct addresses is "
            "not bounded"
        )

        for task in list(_pending_sends):
            task.cancel()
        await asyncio.sleep(0.05)

    async def test_dispatch_at_capacity_still_does_not_block(self, monkeypatch):
        """The admission check itself must not become the blocking wait it
        exists to avoid — a dispatch call that blocks on a full backlog
        would delay the response and reinstate the timing oracle, exactly
        the failure mode MAX_CONCURRENT_SENDS's own non-blocking dispatch
        was built to prevent."""
        async def never_returns(self, msg, recipients, *, interactive=False):
            await asyncio.sleep(3600)

        monkeypatch.setattr("app.core.email.EmailService.send", never_returns)

        for i in range(MAX_PENDING_SENDS):
            dispatch_reset_email(EmailMessage(), self._config(), f"u{i}@example.com", i)
        assert len(_pending_sends) == MAX_PENDING_SENDS

        started = time.perf_counter()
        for i in range(50):
            dispatch_reset_email(
                EmailMessage(), self._config(), f"over{i}@example.com", i
            )
        elapsed = time.perf_counter() - started

        assert elapsed < 0.05, (
            f"dispatching 50 sends against a full backlog took {elapsed:.3f}s "
            "— admission is blocking instead of dropping immediately"
        )
        assert len(_pending_sends) == MAX_PENDING_SENDS, (
            "sends beyond the cap were admitted instead of dropped"
        )

        for task in list(_pending_sends):
            task.cancel()
        await asyncio.sleep(0.05)

    async def test_a_dropped_send_does_not_prevent_a_later_one(self, monkeypatch):
        """The cap is on the backlog, not a permanent circuit-breaker — once
        it drains, dispatch must resume admitting sends normally."""
        delivered: list[str] = []

        async def instant(self, msg, recipients, *, interactive=False):
            delivered.append(recipients[0])

        monkeypatch.setattr("app.core.email.EmailService.send", instant)

        # Fill the backlog with sends that block, so the very next dispatch
        # is refused.
        async def never_returns(self, msg, recipients, *, interactive=False):
            await asyncio.sleep(3600)

        monkeypatch.setattr("app.core.email.EmailService.send", never_returns)
        for i in range(MAX_PENDING_SENDS):
            dispatch_reset_email(EmailMessage(), self._config(), f"u{i}@example.com", i)

        dispatch_reset_email(
            EmailMessage(), self._config(), "dropped@example.com", -1
        )
        assert "dropped@example.com" not in delivered

        for task in list(_pending_sends):
            task.cancel()
        await asyncio.sleep(0.05)
        assert not _pending_sends, "cancelled sends did not clear the backlog"

        monkeypatch.setattr("app.core.email.EmailService.send", instant)
        dispatch_reset_email(
            EmailMessage(), self._config(), "later@example.com", -2
        )
        await asyncio.gather(*list(_pending_sends))
        assert delivered == ["later@example.com"]

    async def test_a_sustained_burst_logs_once_not_once_per_drop(
        self, monkeypatch, caplog
    ):
        """The admission check must not itself become a resource-exhaustion
        vector: logging once per dropped send under a sustained burst would
        turn the fix for one kind of exhaustion (memory) into a milder
        version of another (log volume). Reset to force the warning to be
        eligible immediately — the throttle's timestamp is process-global
        wall-clock state, so an earlier test firing it within the last 10s
        would otherwise make this test's first drop silently not log,
        independent of whether the throttling logic is even correct.
        """
        import logging as _logging

        monkeypatch.setattr(
            "app.services.password_reset._LAST_BACKLOG_FULL_WARNING", 0.0
        )

        async def never_returns(self, msg, recipients, *, interactive=False):
            await asyncio.sleep(3600)

        monkeypatch.setattr("app.core.email.EmailService.send", never_returns)

        for i in range(MAX_PENDING_SENDS):
            dispatch_reset_email(EmailMessage(), self._config(), f"u{i}@example.com", i)

        with caplog.at_level(_logging.WARNING, logger="app.services.password_reset"):
            for i in range(500):
                dispatch_reset_email(
                    EmailMessage(), self._config(), f"over{i}@example.com", i
                )

        backlog_warnings = [
            r for r in caplog.records if "backlog full" in r.message
        ]
        assert len(backlog_warnings) == 1, (
            f"{len(backlog_warnings)} backlog-full warnings logged for 500 "
            "dropped sends in one burst — should be throttled to one"
        )

        for task in list(_pending_sends):
            task.cancel()
        await asyncio.sleep(0.05)


class TestInteractiveSendsAreNotStarvedByThePublicBacklog:
    """Admin-reset and welcome-registration emails are awaited synchronously
    by an HTTP handler (issue_reset_token), unlike forgot-password's
    detached dispatch — but both used to share the exact same four-worker
    executor. A public backlog of up to MAX_PENDING_SENDS queued sends could
    sit ahead of an admin-reset's own send, each potentially taking the full
    SmtpConfig.timeout to fail — leaving the admin's request hanging for far
    longer than any single SMTP timeout would suggest, and after the
    target's password has *already* been invalidated (set_password commits
    before issue_reset_token is even called). Reproduced directly: an
    inline send waited 5.45s behind just 40 queued 0.5s jobs on the shared
    pool, scaling linearly with backlog depth.

    Fixed with a second, small executor reserved for sends an HTTP request
    is waiting on synchronously (EmailService.send(..., interactive=True),
    used only by issue_reset_token). These tests saturate the *public*
    pool's queue and confirm an interactive send still completes in
    roughly its own send time, not the backlog's.
    """

    async def test_a_saturated_public_backlog_does_not_delay_an_interactive_send(
        self, monkeypatch
    ):
        # Restore the genuine `send` first: the file-wide `captured_emails`
        # autouse fixture replaces it for every test, and it is exactly the
        # method that dispatches to an executor at all — under it, patching
        # _send_sync is never reached and this test measures the fixture's
        # instant fake instead of real behaviour. Confirmed directly: this
        # test passed in 0.09s even with the interactive/public split
        # reverted, because the fake short-circuited before either executor
        # was ever involved.
        monkeypatch.setattr("app.core.email.EmailService.send", _REAL_EMAIL_SEND)

        import threading

        release = threading.Event()

        def hangs_until_released(msg, recipients, cfg, socket_timeout):
            release.wait(5.0)

        monkeypatch.setattr(
            "app.core.email.EmailService._send_sync", staticmethod(hangs_until_released)
        )

        loop = asyncio.get_running_loop()
        public_executor = _send_executor()
        # Occupy every public worker, then queue more behind them so the
        # public pool's queue is genuinely non-empty, not just its workers.
        occupying = [
            loop.run_in_executor(public_executor, EmailService._send_sync, None, None, None, None)
            for _ in range(MAX_CONCURRENT_SENDS)
        ]
        queued = [
            loop.run_in_executor(public_executor, EmailService._send_sync, None, None, None, None)
            for _ in range(20)
        ]

        try:
            def instant(msg, recipients, cfg, socket_timeout):
                return None

            monkeypatch.setattr(
                "app.core.email.EmailService._send_sync", staticmethod(instant)
            )

            cfg = SmtpConfig(
                host="smtp.example.com", port=587, username=None, password=None,
                from_addr="pa-central@example.com", tls_mode="none", timeout=30.0,
            )
            # Bounded rather than a bare await: if the interactive/public
            # split regresses, this send genuinely queues behind the public
            # backlog and would otherwise hang the test for the full
            # release.wait(5.0) on every occupying/queued job in turn,
            # rather than failing with a clear assertion. Confirmed
            # directly: without this bound, the equivalent reproduction
            # took 11.8s to return under the reverted (shared-executor)
            # implementation.
            started = time.perf_counter()
            try:
                await asyncio.wait_for(
                    EmailService(cfg).send(
                        EmailMessage(), ["admin-target@example.com"], interactive=True
                    ),
                    timeout=2.0,
                )
            except TimeoutError:
                pytest.fail(
                    "an interactive send did not complete within 2s while "
                    "the public pool's queue was saturated — it is "
                    "contending for the same executor instead of using its "
                    "own"
                )
            elapsed = time.perf_counter() - started

            assert elapsed < 1.0, (
                f"an interactive send took {elapsed:.2f}s while the public "
                "pool's queue was saturated — it is contending for the "
                "same executor instead of using its own"
            )
        finally:
            release.set()
            await asyncio.gather(*occupying, *queued, return_exceptions=True)

    async def test_interactive_and_public_pools_are_genuinely_separate_executors(self):
        assert _interactive_send_executor() is not _send_executor(), (
            "interactive sends are using the same executor object as "
            "public sends — the separation is not real"
        )

    async def test_an_admin_reset_completes_quickly_despite_a_public_backlog(
        self, client, db, admin_token, self_service_on, reset_user, monkeypatch
    ):
        """The concrete HTTP-level consequence: an admin containing a
        suspected compromise must not be left waiting on an unrelated
        public backlog, especially since the target's password is already
        invalidated by the time this request reaches the send at all."""
        # See test_a_saturated_public_backlog_does_not_delay_an_interactive_send
        # above for why this is required: the file-wide captured_emails
        # fixture replaces EmailService.send for every test, which would
        # otherwise make this endpoint's real send path (and therefore the
        # interactive/public routing under test) unreachable.
        monkeypatch.setattr("app.core.email.EmailService.send", _REAL_EMAIL_SEND)

        import threading

        release = threading.Event()

        def hangs_until_released(msg, recipients, cfg, socket_timeout):
            release.wait(5.0)

        monkeypatch.setattr(
            "app.core.email.EmailService._send_sync", staticmethod(hangs_until_released)
        )

        loop = asyncio.get_running_loop()
        public_executor = _send_executor()
        occupying = [
            loop.run_in_executor(public_executor, EmailService._send_sync, None, None, None, None)
            for _ in range(MAX_CONCURRENT_SENDS)
        ]
        queued = [
            loop.run_in_executor(public_executor, EmailService._send_sync, None, None, None, None)
            for _ in range(20)
        ]

        try:
            def instant(msg, recipients, cfg, socket_timeout):
                return None

            monkeypatch.setattr(
                "app.core.email.EmailService._send_sync", staticmethod(instant)
            )

            # Bounded, not a bare await — see the sibling test above for why:
            # a regression here means this request genuinely queues behind
            # the public backlog, which would otherwise hang the test rather
            # than fail it cleanly.
            started = time.perf_counter()
            try:
                r = await asyncio.wait_for(
                    client.post(
                        f"/api/users/{reset_user.id}/reset-password",
                        headers={"Authorization": f"Bearer {admin_token}"},
                    ),
                    timeout=2.0,
                )
            except TimeoutError:
                pytest.fail(
                    "the admin-reset request did not complete within 2s "
                    "with a saturated public backlog — it is queueing "
                    "behind unrelated public sends instead of using its "
                    "own executor"
                )
            elapsed = time.perf_counter() - started

            assert r.status_code == 200
            assert elapsed < 1.0, (
                f"the admin-reset request took {elapsed:.2f}s with a "
                "saturated public backlog — it should complete in roughly "
                "its own send time, not the backlog's"
            )
        finally:
            release.set()
            await asyncio.gather(*occupying, *queued, return_exceptions=True)


# ── In-flight sends survive shutdown ──────────────────────────────────────────

class TestShutdownDrainsPendingSends:
    """Detached sends must finish before the loop goes away.

    A strong reference stops the garbage collector dropping these tasks, but
    it does not enrol them in the shutdown sequence: a worker restart cancels
    them after the endpoint has already answered 202. The token stays live and
    holds the cooldown, so the recipient is told to check their inbox,
    receives nothing, and cannot re-request. Reproduced before the drain: 202
    returned, send cancelled, zero emails delivered, retry suppressed.
    """

    async def _configure(self, db) -> None:
        await _set(db, "smtp_host", "smtp.example.com")
        await _set(db, "smtp_from", "pa-central@example.com")
        await _set(db, "app_base_url", "https://pa.example.com")
        await _set(db, "self_service_password_reset", "true", SettingValueType.bool)

    async def test_a_slow_send_completes_during_the_drain(
        self, client, db, self_service_on, reset_user, monkeypatch
    ):
        """The send outlives the response; the drain must still let it land."""
        delivered: list[list[str]] = []

        async def slow_send(self, msg, recipients, *, interactive=False):
            # Must outlive the response, which is padded to
            # FORGOT_PASSWORD_MIN_SECONDS: a send that finishes inside that
            # window completes on its own and the drain is never exercised.
            await asyncio.sleep(FORGOT_PASSWORD_MIN_SECONDS + 0.5)
            delivered.append(recipients)

        monkeypatch.setattr("app.core.email.EmailService.send", slow_send)

        r = await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        assert r.status_code == 202
        assert not delivered, "the send finished inside the response window"
        assert _pending_sends, "no send was left in flight to drain"

        remaining = await drain_pending_sends(timeout=5.0)
        assert remaining == 0, "the drain gave up on an in-flight send"
        assert delivered, "the email was lost despite draining"

    async def test_the_drain_is_bounded(
        self, client, db, self_service_on, reset_user, monkeypatch
    ):
        """A wedged relay must not stall shutdown indefinitely. The send is
        abandoned and reported, not waited on forever."""
        async def never_returns(self, msg, recipients, *, interactive=False):
            await asyncio.sleep(3600)

        monkeypatch.setattr("app.core.email.EmailService.send", never_returns)

        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )

        started = time.perf_counter()
        remaining = await drain_pending_sends(timeout=0.2)
        elapsed = time.perf_counter() - started

        assert remaining == 1
        assert elapsed < 2.0, f"drain took {elapsed:.1f}s — it is not bounded"

        for task in list(_pending_sends):
            task.cancel()

    async def test_draining_nothing_is_a_no_op(self):
        assert await drain_pending_sends(timeout=0.1) == 0


class TestShutdownExecutorDoesNotOutliveItsBudget:
    """`drain_pending_sends` bounds the *coroutines* awaiting SMTP sends; it
    says nothing about the *threads* those coroutines are waiting on.

    `dispatch_reset_email` gives each send a task-level timeout, so a
    genuinely wedged relay is abandoned at the coroutine level well inside
    `drain_pending_sends`'s own window — the case covered by
    `test_the_drain_is_bounded` above. But abandoning the coroutine does not
    stop the executor thread underneath it: a thread blocked in a
    synchronous smtplib call has no cancellation point, so it keeps running
    regardless of what the coroutine awaiting it decided to do.
    `ThreadPoolExecutor.shutdown(wait=False, cancel_futures=True)` — the
    previous implementation — returns immediately without stopping that
    thread, and Python's own interpreter shutdown then blocks on it anyway
    (worker threads are non-daemon by design), so a restart that waits for
    the process to exit cleanly stays alive regardless of what
    `drain_pending_sends`'s bound advertised. Reproduced directly: a
    ThreadPoolExecutor thread still running kept a bare Python process alive
    for its full runtime, well after `shutdown(wait=False)` had returned and
    the rest of the script had finished.
    """

    async def test_it_waits_for_a_thread_that_finishes_in_time(self, monkeypatch):
        import threading

        live = threading.Event()

        def slow(msg, recipients, cfg, socket_timeout):
            live.set()
            time.sleep(0.3)

        monkeypatch.setattr(
            "app.core.email.EmailService._send_sync", staticmethod(slow)
        )

        loop = asyncio.get_running_loop()
        executor = _send_executor()
        fut = loop.run_in_executor(executor, EmailService._send_sync, None, None, None, None)
        await asyncio.get_running_loop().run_in_executor(None, live.wait, 1.0)

        started = time.perf_counter()
        await shutdown_send_executor(timeout=2.0)
        elapsed = time.perf_counter() - started

        assert fut.done(), "shutdown returned before the thread actually finished"
        assert 0.2 < elapsed < 1.0, (
            f"shutdown took {elapsed:.2f}s — it neither waited for the real "
            "0.3s completion nor is this a case that should have timed out"
        )

    async def test_it_gives_up_at_its_own_bound_rather_than_blocking(
        self, monkeypatch, caplog
    ):
        """The thread cannot be stopped — that is the whole finding — so the
        only thing this function can honestly do is stop *waiting* on time
        and say so. Must not silently pretend to have stopped anything."""
        import logging
        import threading

        live = threading.Event()
        release = threading.Event()

        def hangs(msg, recipients, cfg, socket_timeout):
            live.set()
            release.wait(5.0)

        monkeypatch.setattr(
            "app.core.email.EmailService._send_sync", staticmethod(hangs)
        )

        loop = asyncio.get_running_loop()
        executor = _send_executor()
        fut = loop.run_in_executor(executor, EmailService._send_sync, None, None, None, None)
        await asyncio.get_running_loop().run_in_executor(None, live.wait, 1.0)

        started = time.perf_counter()
        with caplog.at_level(logging.WARNING, logger="app.core.email"):
            await shutdown_send_executor(timeout=0.3)
        elapsed = time.perf_counter() - started

        assert elapsed < 1.0, (
            f"shutdown blocked for {elapsed:.2f}s waiting on an unstoppable "
            "thread instead of giving up at its own bound"
        )
        assert any("did not shut down within" in r.message for r in caplog.records), (
            "gave up silently — an operator needs to know a thread was left "
            "running past the advertised shutdown bound"
        )
        assert not fut.done(), "the thread should still be running — it was never stoppable"

        release.set()
        await fut

    async def test_a_task_level_timeout_alone_does_not_free_the_thread(
        self, client, db, self_service_on, reset_user, monkeypatch
    ):
        """The scenario the finding actually describes end to end: a send
        wedges, dispatch_reset_email's own task-level timeout abandons the
        coroutine well inside drain_pending_sends's window (as
        test_the_drain_is_bounded already covers), and the finding is that
        this alone proves nothing about the thread. It must still be
        running afterwards, and only the bounded executor shutdown above —
        not the drain — is in a position to notice and report that.
        """
        import threading

        # Restore the genuine `send` first: the file-wide `captured_emails`
        # autouse fixture replaces it for every test, and it is exactly the
        # method that dispatches to `_send_sync` on the executor — under it
        # a patched `_send_sync` is never reached at all, `send` returns
        # instantly, and the coroutine finishes before the drain ever runs.
        # (It did: this test recorded remaining == 0 the first time.)
        monkeypatch.setattr("app.core.email.EmailService.send", _REAL_EMAIL_SEND)

        live = threading.Event()
        release = threading.Event()

        def hangs(msg, recipients, cfg, socket_timeout):
            live.set()
            release.wait(5.0)

        monkeypatch.setattr(
            "app.core.email.EmailService._send_sync", staticmethod(hangs)
        )

        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        await asyncio.get_running_loop().run_in_executor(None, live.wait, 1.0)

        remaining = await drain_pending_sends(timeout=0.2)
        assert remaining == 1, "the coroutine should have been abandoned, not finished"

        executor = _send_executor()
        assert executor._threads, (
            "the SMTP thread should still be running — the drain only "
            "abandons the coroutine waiting on it, not the thread itself"
        )

        release.set()
        for task in list(_pending_sends):
            task.cancel()
        await asyncio.get_running_loop().run_in_executor(
            executor, lambda: None
        )

    async def test_giving_up_cancels_queued_work_but_not_running_work(
        self, monkeypatch
    ):
        """`executor.shutdown(wait=True)` alone drains the whole queue, not
        just the jobs already running when shutdown was called — its
        non-daemon worker threads keep pulling the next queued item even
        after this function's own bounded wait has given up and logged a
        warning. With a large backlog (see MAX_PENDING_SENDS) and an
        unavailable relay, that means hundreds of queued sends still run to
        completion one by one, each taking up to SmtpConfig.timeout, long
        after the log already said shutdown gave up. Reproduced directly:
        20 queued 0.3s jobs on 2 workers took 3.0s to fully drain even
        though the bounded wait gave up at 1.0s.

        `cancel_futures=True` fixes the queued side without touching jobs
        already running — those remain covered by the tests above, which
        must still pass with this change in place.
        """
        import threading

        live = threading.Event()
        release = threading.Event()

        def hangs_until_released(msg, recipients, cfg, socket_timeout):
            live.set()
            release.wait(5.0)

        monkeypatch.setattr(
            "app.core.email.EmailService._send_sync",
            staticmethod(hangs_until_released),
        )

        loop = asyncio.get_running_loop()
        executor = _send_executor()
        # Occupy every worker so nothing else can start...
        running = [
            loop.run_in_executor(executor, EmailService._send_sync, None, None, None, None)
            for _ in range(MAX_CONCURRENT_SENDS)
        ]
        await asyncio.get_running_loop().run_in_executor(None, live.wait, 1.0)

        # ...then queue a backlog behind them that can never even begin
        # before the shutdown timeout below expires.
        queued = [
            loop.run_in_executor(executor, EmailService._send_sync, None, None, None, None)
            for _ in range(20)
        ]

        started = time.perf_counter()
        await shutdown_send_executor(timeout=0.3)
        elapsed = time.perf_counter() - started

        assert elapsed < 1.0, (
            f"shutdown took {elapsed:.2f}s to return — it should give up at "
            "its own bound regardless of queue depth"
        )
        assert all(f.cancelled() for f in queued), (
            "queued-but-not-yet-started sends were not cancelled — they "
            "would still run to completion one by one after shutdown "
            "already gave up and logged a warning"
        )
        assert not any(f.cancelled() for f in running), (
            "already-running sends were cancelled — only queued work should "
            "be dropped; running work stays covered by the bounded wait"
        )

        release.set()
        await asyncio.gather(*running, return_exceptions=True)


# ── SQLite contention must not leak existence ─────────────────────────────────

class TestSqliteContentionDoesNotLeakExistence:
    """A contended write on SQLite must still answer 202.

    Only a registered address reaches the account-row write, so if contention
    there raises while an unknown address returns a padded 202, the status
    code discloses account existence. SQLite is the default database here, so
    this is the deployment that matters most.

    The PostgreSQL equivalent (SQLSTATE 55P03) is covered in
    test_postgres_behaviour.py. Both are needed: the two backends signal
    contention differently, and an earlier comment in the source wrongly
    asserted SQLite could not exhibit this at all — on the reasoning that it
    serialises writers globally, which misses that only one path writes.
    Reproduced before the fix: registered raised OperationalError
    ("database is locked"), unknown returned 202.
    """

    async def _configure(self, factory) -> None:
        async with factory() as s:
            for key, value, vtype in (
                ("smtp_host", "smtp.example.com", SettingValueType.string),
                ("app_base_url", "https://pa.example.com", SettingValueType.string),
                ("self_service_password_reset", "true", SettingValueType.bool),
            ):
                s.add(SystemSetting(
                    key=key, value=value, value_type=vtype, updated_at=utcnow()
                ))
            s.add(User(
                email="contended@example.com", display_name="Contended",
                hashed_password=hash_password("originalpassword"),
                role=UserRole.viewer, is_active=True,
            ))
            await s.commit()

    async def test_a_held_write_lock_still_answers_202(self, tmp_path, monkeypatch):
        """Its own file-backed database and a real second connection holding a
        write: the shared in-memory test fixtures cannot express this."""
        import sqlalchemy as sa
        from httpx import ASGITransport, AsyncClient
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from app.core.database import Base, get_db
        from app.main import app

        async def no_send(self, msg, recipients, *, interactive=False):
            return None

        monkeypatch.setattr("app.core.email.EmailService.send", no_send)

        url = f"sqlite+aiosqlite:///{tmp_path}/contended.db"
        # Engine-default connect_args on purpose: the short bound is applied
        # per-transaction by prepare_reset_email, not on the engine. Setting
        # it here would hide a regression where that scoping is lost.
        engine = create_async_engine(
            url, connect_args={"check_same_thread": False}
        )
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)
        await self._configure(factory)

        async def override():
            async with factory() as session:
                yield session

        app.dependency_overrides[get_db] = override

        holder_engine = create_async_engine(
            url, connect_args={"check_same_thread": False}
        )
        holder = holder_engine.connect()
        conn = await holder.start()
        await conn.execute(sa.text("BEGIN IMMEDIATE"))

        # Held well past the constant-time floor, but inside SQLite's 5s
        # default. Two constraints pin this window:
        #   * longer than the floor, or the floor absorbs the wait and the two
        #     cases are indistinguishable (measured 1.06s vs 1.21s at a 1.1s
        #     hold — a real difference, but not a separable one);
        #   * shorter than SQLite's default, or the request errors either way
        #     and the test stops being about the *bound*.
        async def release_well_past_the_floor() -> None:
            await asyncio.sleep(FORGOT_PASSWORD_MIN_SECONDS + 1.5)
            await conn.rollback()

        releasing = asyncio.create_task(release_well_past_the_floor())
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                started = time.perf_counter()
                registered = await client.post(
                    "/api/auth/forgot-password",
                    json={"email": "contended@example.com"},
                )
                registered_seconds = time.perf_counter() - started

                started = time.perf_counter()
                unknown = await client.post(
                    "/api/auth/forgot-password", json={"email": "nobody@example.com"}
                )
                unknown_seconds = time.perf_counter() - started
        finally:
            await releasing
            # holder.close() before disposing the engine: the low-level
            # `.connect()` + `await .start()` pair used above doesn't check
            # the connection back in on its own the way `async with
            # engine.connect()` would — disposing the engine's pool without
            # first closing this checked-out connection leaves it to the
            # garbage collector, which finalizes it later (on whatever test
            # happens to be running at the time) and logs SQLAlchemy's
            # "non-checked-in connection" warning. Every sibling test in
            # this file using the same holder/holder_engine pattern already
            # closes holder first; this one was missing it.
            await holder.close()
            await holder_engine.dispose()
            app.dependency_overrides.pop(get_db, None)
            await engine.dispose()

        assert registered.status_code == unknown.status_code == 202, (
            "SQLite write contention leaked account existence: "
            f"registered={registered.status_code} unknown={unknown.status_code}"
        )
        assert registered.json() == unknown.json()

        # Status alone is not sufficient: without the per-transaction bound the
        # request simply *waits out* the held lock and still returns 202 — the
        # signal moves into latency instead. The constant-time floor must be
        # what decides when this responds, so the registered request cannot run
        # materially longer than the unknown one.
        assert registered_seconds < unknown_seconds * 1.3, (
            f"a contended registered request took {registered_seconds:.2f}s "
            f"versus {unknown_seconds:.2f}s for an unknown one — it waited on "
            "the lock instead of giving up inside the floor"
        )

    async def test_the_lock_bound_fits_inside_the_response_floor(self):
        """A wait longer than the floor would put the latency back, even with
        the error handled."""
        assert 0 < FORGOT_PASSWORD_LOCK_TIMEOUT_SECONDS < FORGOT_PASSWORD_MIN_SECONDS

    async def test_unrelated_writes_keep_the_default_busy_timeout(self, tmp_path):
        """The short bound belongs to reset issuance, not the application.

        Applying it in the engine's connect_args gave *every* SQLite write
        this endpoint's deadline: an unrelated write behind a 0.8s transaction
        failed at 0.5s where it had previously succeeded after 1.08s. It is
        set per-transaction instead, and restored afterwards because the
        pragma is connection-scoped and connections are pooled.
        """
        import sqlalchemy as sa
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from app.core.database import Base

        url = f"sqlite+aiosqlite:///{tmp_path}/unrelated.db"
        setup = create_async_engine(url, connect_args={"check_same_thread": False})
        async with setup.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        await setup.dispose()

        # Assert on the *real* engine's behaviour, not a private attribute:
        # a fresh connection's effective busy_timeout is what every unrelated
        # write in the application actually gets. create_connect_args() looks
        # like the right source but is derived from the URL and never sees
        # connect_args at all — checking it passed happily with a 0.5s
        # timeout configured.
        from app.core.database import engine as app_engine

        try:
            async with app_engine.connect() as probe:
                effective = (await probe.execute(sa.text("PRAGMA busy_timeout"))).scalar_one()
            assert effective >= FORGOT_PASSWORD_LOCK_TIMEOUT_SECONDS * 1000 * 2, (
                f"the shared engine's busy_timeout is {effective}ms — close to "
                "this endpoint's deadline, which would apply it to every write "
                "in the application"
            )
        finally:
            # This is the application's own module-level engine, never
            # touched by the rest of the suite (conftest's db/client
            # fixtures override get_db with a separate test engine
            # entirely) — so the connection opened above is the first
            # ever made on its pool, binding that pool to *this* test's
            # event loop. pytest-asyncio uses a function-scoped loop per
            # test by default, so once this test ends that loop closes
            # while the pooled connection is still checked in, and the
            # garbage collector finalizes it later — on whatever test
            # happens to be running when that GC pass occurs — logging
            # SQLAlchemy's "non-checked-in connection" warning. Disposing
            # deterministically here, on the same loop that opened it,
            # releases the connection cleanly instead of leaving that to
            # chance; the engine transparently rebuilds its pool if
            # anything uses it again.
            await app_engine.dispose()

        engine = create_async_engine(url, connect_args={"check_same_thread": False})
        holder_engine = create_async_engine(
            url, connect_args={"check_same_thread": False}
        )
        holder = holder_engine.connect()
        held = await holder.start()
        await held.execute(sa.text("BEGIN IMMEDIATE"))

        async def release() -> None:
            # Longer than FORGOT_PASSWORD_LOCK_TIMEOUT_SECONDS: a write given
            # the reset bound would fail here, one on the default must not.
            await asyncio.sleep(0.8)
            await held.rollback()

        releasing = asyncio.create_task(release())
        factory = async_sessionmaker(engine, expire_on_commit=False)
        try:
            async with factory() as session:
                session.add(User(
                    email="unrelated@example.com", display_name="Unrelated",
                    hashed_password=hash_password("password123456"),
                    role=UserRole.viewer, is_active=True,
                ))
                await session.commit()
        finally:
            await releasing
            await holder.close()
            await holder_engine.dispose()
            await engine.dispose()

    async def test_the_real_engine_is_wired_to_restore_on_checkin(self):
        """The functional test above proves `sqlite_on_checkin` restores the
        pragma *when attached* — it deliberately attaches the real function
        itself to a throwaway engine, so it cannot be fooled by a copy that
        drifted from `database.py`. It cannot, by construction, prove that
        `database.py` actually attaches that listener to the application's
        own engine; a version that defined the function correctly and simply
        never registered it for `checkin` would still pass that test. This
        one closes that gap directly: registration is checked as a fact about
        the app's own `engine.sync_engine`, not re-derived behaviourally.

        Skipped on PostgreSQL deployments, where none of this applies — the
        lock bound there is `SET LOCAL lock_timeout`, transaction-scoped by
        Postgres itself, with nothing to leak across checkin.
        """
        from app.core.database import engine as app_engine
        from app.core.database import sqlite_on_checkin

        if app_engine.sync_engine.dialect.name != "sqlite":
            pytest.skip("SQLite-specific: PostgreSQL's lock_timeout needs no checkin restore")

        assert event.contains(app_engine.sync_engine, "checkin", sqlite_on_checkin), (
            "sqlite_on_checkin is not registered for 'checkin' on the "
            "application's real engine — busy_timeout narrowed by reset "
            "issuance will leak to whatever request reuses the connection"
        )

    async def test_the_short_bound_does_not_outlive_the_request(
        self, tmp_path
    ):
        """The pragma is connection-scoped, so it must not reach the next
        session that reuses the same physical connection.

        Restored on pool checkin (`sqlite_on_checkin` in core/database.py),
        not in the ORM layer: every attempt to do it there — a `finally` in
        issuance, an endpoint helper, the session's own connection — broke 25
        unrelated tests, because the extra statement expires the identity map
        and the next attribute access on a held ORM instance becomes a lazy
        load outside the greenlet (MissingGreenlet).

        Exercises the *real* listener functions against a throwaway engine,
        not a re-implementation of them — a copy could drift from
        `database.py` and this would keep passing after that drifted. The
        suite's `client`/`db` fixtures cannot be used here: they bind to
        their own session-scoped engine in conftest.py with its own
        `connect`-only pragma listener, entirely separate from
        `app.core.database.engine`, so a request made through them would
        prove nothing about the code under test.

        A pool capped at one connection, rather than polling for reuse,
        because with more than one live connection "the pragma looks
        restored" and "the connection issuance used was never touched" are
        indistinguishable from outside — which is exactly how an earlier
        version of this test stayed green with no checkin listener at all.
        Reproduced with that gap: 500ms inherited on reuse where 5000ms
        (the driver's default) was expected.
        """
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
        from sqlalchemy.pool import StaticPool

        from app.core.database import Base, sqlite_on_checkin, sqlite_on_connect
        from app.services.password_reset import prepare_reset_email

        engine = create_async_engine(
            f"sqlite+aiosqlite:///{tmp_path}/reuse.db",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        event.listens_for(engine.sync_engine, "connect")(sqlite_on_connect)
        event.listens_for(engine.sync_engine, "checkin")(sqlite_on_checkin)

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)

        settings_map = {
            "smtp_host": "smtp.example.com",
            "smtp_from": "pa-central@example.com",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        }

        async with factory() as s:
            user = User(
                email="reuse@example.com", display_name="Reuse",
                hashed_password=hash_password("originalpassword"),
                role=UserRole.viewer, is_active=True,
            )
            s.add(user)
            # prepare_reset_email's own settings-row re-check now refuses
            # unless the *stored* self_service_password_reset row agrees
            # with settings_map above — a genuinely absent row is no longer
            # treated as "don't refuse" (see
            # TestDisableRacesIssuanceOnPostgres's null-clear test), so this
            # setup step must seed a matching row rather than relying on
            # settings_map alone.
            s.add(SystemSetting(
                key="self_service_password_reset", value="true",
                value_type=SettingValueType.bool, updated_at=utcnow(),
            ))
            # prepare_reset_email now also re-reads app_base_url under the
            # same lock and refuses unless it agrees with settings_map above
            # (see TestDisableRacesIssuanceOnPostgres's base-url-change
            # tests) — the identical reasoning as the self_service_password_reset
            # seed just above, applied to the second field this function
            # re-checks.
            s.add(SystemSetting(
                key="app_base_url", value="https://pa.example.com",
                value_type=SettingValueType.string, updated_at=utcnow(),
            ))
            await s.commit()
            user_id = user.id

        try:
            async with factory() as s:
                issued = await prepare_reset_email(
                    s, await s.get(User, user_id), settings_map
                )
            assert issued is not None, "setup issuance was unexpectedly refused"

            # StaticPool holds exactly one DBAPI connection for the engine's
            # lifetime, so this session is handed the very connection
            # issuance just narrowed and returned.
            async with factory() as s:
                effective = (
                    await s.execute(sa.text("PRAGMA busy_timeout"))
                ).scalar_one()
        finally:
            await engine.dispose()

        assert effective >= FORGOT_PASSWORD_LOCK_TIMEOUT_SECONDS * 1000 * 2, (
            f"the reused connection has busy_timeout={effective}ms — this "
            "endpoint's bound is leaking to unrelated work that reuses it"
        )

    async def test_checkin_survives_an_invalidated_connection(self, tmp_path):
        """`checkin` fires with `dbapi_conn=None` when the connection was
        invalidated rather than cleanly returned — `Connection.invalidate()`,
        or a driver-level disconnect the pool detects. The listener must not
        assume a live DBAPI connection is always there to restore a pragma
        on. Reproduced: `AttributeError: 'NoneType' object has no attribute
        'cursor'` from `.cursor()` called unconditionally, raised out of
        `await connection.invalidate()` itself, since pool listeners run
        synchronously inline with the call that triggers them.
        """
        from sqlalchemy.ext.asyncio import create_async_engine
        from sqlalchemy.pool import StaticPool

        from app.core.database import sqlite_on_checkin, sqlite_on_connect

        engine = create_async_engine(
            f"sqlite+aiosqlite:///{tmp_path}/invalidate.db",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        event.listens_for(engine.sync_engine, "connect")(sqlite_on_connect)
        event.listens_for(engine.sync_engine, "checkin")(sqlite_on_checkin)

        try:
            async with engine.connect() as conn:
                await conn.execute(sa.text("SELECT 1"))
                # Raises inline if the checkin listener assumes a live
                # connection — this is the call the finding reproduced it
                # through, not a synthetic call to the listener itself.
                await conn.invalidate()
        finally:
            await engine.dispose()


# ── Throttling: repeat requests must not deny recovery ────────────────────────

class TestForgotPasswordThrottling:
    """POST /auth/forgot-password is public and keyed only on an email
    address, so anyone who knows a user's address can call it repeatedly.

    Unthrottled, that is a recovery-denial attack rather than mere mail spam:
    each request supersedes the previous token, so every link the victim
    actually receives is dead by the time they click it. Reproduced before
    the fix — 6 requests sent 6 emails and left the victim's held link
    rejected with 400.
    """

    async def _request(self, client, email: str):
        return await client.post("/api/auth/forgot-password", json={"email": email})

    async def _request_past_cooldown(self, client, db, email: str):
        """One request, with prior tokens backdated so the cooldown does not
        suppress it. Lets a test reach the hourly cap, which is the limit
        under test here — the cooldown has its own coverage above."""
        await _age_tokens(db, seconds=RESET_REQUEST_COOLDOWN_SECONDS + 30)
        return await self._request(client, email)

    async def test_hourly_cap_bounds_emails_to_one_address(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        for _ in range(RESET_REQUESTS_PER_HOUR + 4):
            await self._request_past_cooldown(client, db, reset_user.email)

        assert len(captured_emails) == RESET_REQUESTS_PER_HOUR, (
            f"{len(captured_emails)} emails sent for "
            f"{RESET_REQUESTS_PER_HOUR + 4} requests — the cap is not holding"
        )

    async def test_victim_can_still_recover_with_their_newest_link(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """The point of the whole fix: however many requests an attacker
        fires, the most recent email the user holds must still work."""
        for _ in range(RESET_REQUESTS_PER_HOUR + 4):
            await self._request_past_cooldown(client, db, reset_user.email)

        newest = _token_from_email(captured_emails)
        r = await client.post(
            "/api/auth/reset-password",
            json={"token": newest, "new_password": "a-brand-new-password"},
        )
        assert r.status_code == 204

        await db.refresh(reset_user)
        assert verify_password("a-brand-new-password", reset_user.hashed_password)

    async def test_only_one_link_is_live_at_a_time(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """Superseded links must stop working — several live credentials in
        one inbox is the failure mode the reissue exists to avoid."""
        await self._request(client, reset_user.email)
        first = _token_from_email(captured_emails)
        await self._request_past_cooldown(client, db, reset_user.email)
        second = _token_from_email(captured_emails)
        assert first != second

        live = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().all()
        assert len(live) == 1

        r = await client.post(
            "/api/auth/reset-password",
            json={"token": first, "new_password": "a-brand-new-password"},
        )
        assert r.status_code == 400

    async def test_repeat_requests_cannot_extend_a_token_s_life(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """Otherwise an attacker could keep a link alive indefinitely by
        re-requesting.

        Asserts the token is untouched, not merely that its expiry matches:
        the cooldown suppresses reissuance entirely, so an earlier version of
        this test compared a row against itself and passed against any
        expiry logic at all.
        """
        await self._request(client, reset_user.email)
        before = (await db.execute(
            select(PasswordResetToken.id, PasswordResetToken.expires_at)
            .where(PasswordResetToken.used_at.is_(None))
        )).one()

        for _ in range(3):
            await self._request(client, reset_user.email)

        after = (await db.execute(
            select(PasswordResetToken.id, PasswordResetToken.expires_at)
            .where(PasswordResetToken.used_at.is_(None))
        )).one()

        assert after.id == before.id, "a repeat request inside the cooldown issued a new token"
        assert after.expires_at == before.expires_at, (
            "the outstanding link's deadline moved — repeat requests can "
            "extend a token's life"
        )
        assert len(captured_emails) == 1

    async def test_a_link_issued_after_the_cooldown_gets_its_own_full_window(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """Once the cooldown lapses a new token *is* issued, and it must get a
        fresh TTL rather than inheriting the superseded one's deadline."""
        await self._request(client, reset_user.email)
        await _age_tokens(db, seconds=RESET_REQUEST_COOLDOWN_SECONDS + 30)

        await self._request(client, reset_user.email)
        fresh = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().one()

        remaining = (fresh.expires_at - utcnow()).total_seconds() / 60
        assert remaining > RESET_TOKEN_TTL_MINUTES - 5

    async def test_retired_tokens_are_kept_as_the_rate_limit_ledger(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """The cap counts rows in the window, so superseded attempts must be
        retired (used_at stamped) rather than deleted — deleting them erases
        the ledger and the cap can never fire."""
        for _ in range(3):
            await self._request_past_cooldown(client, db, reset_user.email)

        rows = (await db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.user_id == reset_user.id
            )
        )).scalars().all()
        assert len(rows) == 3, "superseded attempts were deleted, not retired"
        assert sum(1 for r in rows if r.used_at is None) == 1

    async def test_a_fresh_request_after_the_window_gets_a_full_ttl(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """A user coming back after the window has lapsed gets a normal-length
        link, not a stub inherited from the superseded one."""
        await self._request(client, reset_user.email)

        # Age everything out of both the cooldown and the hourly window.
        await db.execute(
            update(PasswordResetToken).values(
                created_at=utcnow() - timedelta(seconds=RESET_REQUEST_WINDOW_SECONDS + 60),
                expires_at=utcnow() - timedelta(minutes=1),
            )
        )
        await db.commit()

        await self._request(client, reset_user.email)
        fresh = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().one()

        remaining = (fresh.expires_at - utcnow()).total_seconds()
        assert remaining > (RESET_TOKEN_TTL_MINUTES - 5) * 60, (
            f"fresh request got only {remaining / 60:.0f} minutes"
        )

    async def test_throttling_is_per_account_not_global(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """One user exhausting their quota must not block anyone else's
        recovery — a global limiter would turn this into a fleet-wide DoS.

        The first account's requests are spaced past the cooldown so its
        *hourly cap* is genuinely reached. Firing them back-to-back instead
        leaves every one after the first suppressed by the cooldown, so the
        quota is never spent and the cap is never consulted — the assertion
        then passes even against a globally-shared cap, which was true of an
        earlier version of this test.
        """
        other = User(
            email="other@example.com", display_name="Other",
            hashed_password=hash_password("originalpassword"),
            role=UserRole.viewer, is_active=True,
        )
        db.add(other)
        await db.commit()

        for _ in range(RESET_REQUESTS_PER_HOUR + 2):
            await self._request_past_cooldown(client, db, reset_user.email)
        before = len(captured_emails)

        # Exactly at the cap, so a shared counter would refuse this outright.
        assert before == RESET_REQUESTS_PER_HOUR, (
            f"the first account sent {before} emails against a cap of "
            f"{RESET_REQUESTS_PER_HOUR} — its quota was not actually exhausted, "
            "so this test would not detect a global limiter"
        )

        await self._request(client, other.email)
        assert len(captured_emails) == before + 1, (
            "a second account was blocked by the first's rate limit"
        )

    async def test_concurrent_requests_cannot_exceed_the_cap(
        self, tmp_path, self_service_on, captured_emails
    ):
        """Counting, retiring and inserting are three statements. Without
        serialization overlapping requests all read the same pre-write count,
        all pass the cap and all insert — measured at six emails against a cap
        of five, with five simultaneously-valid links where the invariant is
        one.

        Uses its own file-backed SQLite database and one session per caller:
        the suite's shared `client`/`db` fixtures route every request through
        a single session, which cannot express concurrent transactions at all.
        SQLite is the default database and ignores FOR UPDATE, so only an
        actual write serializes here — the PostgreSQL side is covered
        separately in test_postgres_behaviour.py.
        """
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from app.core.database import Base
        from app.services.password_reset import prepare_reset_email

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/burst.db")
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(engine, expire_on_commit=False)

            async with factory() as s:
                user = User(
                    email="burst@example.com", display_name="Burst",
                    hashed_password=hash_password("originalpassword"),
                    role=UserRole.viewer, is_active=True,
                )
                s.add(user)
                # prepare_reset_email's settings-row re-check now refuses
                # unless the *stored* self_service_password_reset and
                # app_base_url rows agree with settings_map below — a
                # genuinely absent/differing row is no longer treated as
                # "don't refuse" (see TestDisableRacesIssuanceOnPostgres's
                # null-clear and base-url-change tests).
                s.add(SystemSetting(
                    key="self_service_password_reset", value="true",
                    value_type=SettingValueType.bool, updated_at=utcnow(),
                ))
                s.add(SystemSetting(
                    key="app_base_url", value="https://pa.example.com",
                    value_type=SettingValueType.string, updated_at=utcnow(),
                ))
                await s.commit()
                user_id = user.id

            settings_map = {
                "smtp_host": "smtp.example.com",
                "smtp_from": "pa-central@example.com",
                "app_base_url": "https://pa.example.com",
                "self_service_password_reset": "true",
            }

            async def attempt():
                async with factory() as s:
                    u = await s.get(User, user_id)
                    return await prepare_reset_email(s, u, settings_map)

            results = await asyncio.gather(
                *[attempt() for _ in range(RESET_REQUESTS_PER_HOUR + 3)],
                return_exceptions=True,
            )
            issued = sum(
                1 for r in results
                if not isinstance(r, BaseException) and r is not None
            )
            assert issued <= RESET_REQUESTS_PER_HOUR, (
                f"{issued} links issued under concurrency against a cap of "
                f"{RESET_REQUESTS_PER_HOUR} — issuance is not serialized"
            )
            # A concurrent burst is bounded by the *cooldown*: only the first
            # request finds no outstanding link. Asserted exactly, so this is
            # not mistaken for hourly-cap coverage — the cap has its own test
            # (test_hourly_cap_bounds_emails_to_one_address), and removing it
            # entirely used to leave this one green.
            assert issued == 1, (
                f"{issued} links issued from one burst — the cooldown should "
                "have suppressed all but the first"
            )

            async with factory() as s:
                live = (await s.execute(
                    select(PasswordResetToken)
                    .where(PasswordResetToken.used_at.is_(None))
                )).scalars().all()
            assert len(live) == 1, (
                f"{len(live)} links valid at once — concurrent issuance left "
                "several working credentials in the inbox"
            )
        finally:
            await engine.dispose()

    async def test_serializing_write_does_not_alter_the_user(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """The lock is a self-assigning no-op UPDATE — it must not actually
        change the account it locks."""
        before = (reset_user.is_active, reset_user.role, reset_user.email,
                  reset_user.hashed_password)

        await self._request(client, reset_user.email)

        await db.refresh(reset_user)
        assert (reset_user.is_active, reset_user.role, reset_user.email,
                reset_user.hashed_password) == before

    async def test_admin_resets_do_not_consume_the_public_quota(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """The ledger governs the public endpoint only. Counting admin
        tokens would let a handful of admin resets exhaust a user's
        forgot-password quota — the throttle becoming the denial it exists to
        prevent."""
        for _ in range(RESET_REQUESTS_PER_HOUR):
            r = await client.post(
                f"/api/users/{reset_user.id}/reset-password",
                headers={"Authorization": f"Bearer {admin_token}"},
            )
            assert r.status_code == 200
        before = len(captured_emails)

        await self._request(client, reset_user.email)
        assert len(captured_emails) == before + 1, (
            "admin resets consumed the public forgot-password quota"
        )

    async def test_welcome_tokens_do_not_consume_the_public_quota(
        self, client, db, admin_token, self_service_on, captured_emails
    ):
        """Same for the welcome flow — a newly created account must not start
        life with its recovery quota already spent."""
        r = await client.post(
            "/api/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"email": "fresh@example.com", "display_name": "Fresh", "role": "viewer"},
        )
        assert r.status_code == 201
        before = len(captured_emails)

        for _ in range(RESET_REQUESTS_PER_HOUR):
            await self._request_past_cooldown(client, db, "fresh@example.com")

        assert len(captured_emails) == before + RESET_REQUESTS_PER_HOUR, (
            "the welcome token ate into the account's own reset quota"
        )

    async def test_a_self_service_link_never_inherits_a_longer_expiry(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """An admin link lives 24 hours and a welcome link 7 days. If either
        can be picked as the outstanding token, an anonymous request inherits
        that window instead of the 1-hour self-service TTL — measured at 7
        days before the kind column existed."""
        await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        await self._request(client, reset_user.email)

        # Scoped to the self-service row: the admin link deliberately survives
        # a public request now (see
        # test_a_public_request_cannot_destroy_an_admin_link), so both are
        # live and this must name the one under test.
        row = (await db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.kind == PasswordResetKind.self_service,
            )
        )).scalars().one()
        remaining_minutes = (row.expires_at - utcnow()).total_seconds() / 60
        assert remaining_minutes <= RESET_TOKEN_TTL_MINUTES + 1, (
            f"self-service link got {remaining_minutes:.0f} minutes — it "
            "inherited a longer-lived token's expiry"
        )

    async def test_a_public_request_cannot_destroy_an_admin_link(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """An admin link is issued to someone whose password is *already*
        invalidated. If an anonymous forgot-password request could retire it,
        anyone knowing the address could replace a live 24-hour link with a
        1-hour one and repeat — leaving the recipient opening stale mail with
        no other way in. Reproduced before this was scoped: one public request
        left the admin link answering 400.
        """
        await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        admin_link = _token_from_email(captured_emails)

        await self._request(client, reset_user.email)

        # Both live: the price of not letting anonymous requests revoke
        # privileged ones.
        live = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().all()
        assert {row.kind for row in live} == {
            PasswordResetKind.admin, PasswordResetKind.self_service
        }

        r = await client.post(
            "/api/auth/reset-password",
            json={"token": admin_link, "new_password": "chosen-by-the-user"},
        )
        assert r.status_code == 204, "the public request destroyed the admin link"

    async def test_a_public_request_cannot_destroy_a_welcome_link(
        self, client, db, admin_token, self_service_on, captured_emails
    ):
        """Same for a new account, whose only credential is its welcome link
        — destroying it strands the user completely."""
        r = await client.post(
            "/api/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"email": "fresh@example.com", "display_name": "Fresh",
                  "role": "viewer"},
        )
        assert r.status_code == 201
        welcome_link = _token_from_email(captured_emails)

        await self._request(client, "fresh@example.com")

        used = await client.post(
            "/api/auth/reset-password",
            json={"token": welcome_link, "new_password": "chosen-by-the-user"},
        )
        assert used.status_code == 204, "the public request destroyed the welcome link"

    async def test_a_public_request_still_supersedes_its_own_link(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """Scoping must not leave several *self-service* links live at once —
        that was the original invariant and it still holds within the kind."""
        await self._request(client, reset_user.email)
        first = _token_from_email(captured_emails)
        await self._request_past_cooldown(client, db, reset_user.email)

        live = (await db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.kind == PasswordResetKind.self_service,
            )
        )).scalars().all()
        assert len(live) == 1

        stale = await client.post(
            "/api/auth/reset-password",
            json={"token": first, "new_password": "a-brand-new-password"},
        )
        assert stale.status_code == 400

    async def test_an_admin_reset_still_supersedes_a_self_service_link(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """The asymmetry runs one way only: an authenticated admin acting on a
        suspected compromise must leave exactly one usable link, so their
        issuance retires everything — including tokens of *other* kinds, which
        a public request deliberately spares.

        Note where that actually comes from: `set_password` retires every
        outstanding token before issuance runs, so on this path the retirement
        clause below has nothing left to spare. Scoping it by kind is
        therefore unobservable *here* — verified by mutation. The clause still
        carries `admin_initiated or welcome` because welcome issuance
        (register) does not call `set_password`, and because a future caller
        of prepare_reset_email that skips it would depend on it.
        """
        await client.post(
            "/api/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"email": "alsofresh@example.com", "display_name": "Fresh",
                  "role": "viewer"},
        )
        await self._request(client, reset_user.email)
        public_link = _token_from_email(captured_emails)

        # A welcome token for this same user, so there is a non-self_service
        # row for the admin reset to supersede.
        await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        # A second admin reset: the first left an admin token, and this must
        # retire it along with anything else outstanding for this user.
        await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        live = (await db.execute(
            select(PasswordResetToken).where(
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.user_id == reset_user.id,
            )
        )).scalars().all()
        assert len(live) == 1, (
            f"{len(live)} links live for this user after an admin reset "
            f"({[r.kind.value for r in live]}) — admin issuance must retire "
            "every kind"
        )
        assert live[0].kind is PasswordResetKind.admin

        stale = await client.post(
            "/api/auth/reset-password",
            json={"token": public_link, "new_password": "a-brand-new-password"},
        )
        assert stale.status_code == 400

    async def test_the_public_cap_still_applies_within_its_own_kind(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """Scoping the ledger must not weaken the cap it enforces."""
        for _ in range(RESET_REQUESTS_PER_HOUR + 3):
            await self._request_past_cooldown(client, db, reset_user.email)

        assert len(captured_emails) == RESET_REQUESTS_PER_HOUR

    async def test_the_link_the_user_receives_last_is_always_usable(
        self, client, db, self_service_on, reset_user, monkeypatch
    ):
        """Sends are detached, so two emails can arrive in either order. If a
        burst issued a token per request, the message the user opens last
        could carry one a later transaction already retired — reproduced as a
        400 on the final delivered link. Suppressing inside the cooldown
        means there is only ever one link in flight.
        """
        delivered: list[str] = []
        calls = {"n": 0}

        async def out_of_order_send(self, msg, recipients, *, interactive=False):
            calls["n"] += 1
            # First send is slow (greylisting, a busy relay), so a later one
            # would overtake it.
            await asyncio.sleep(0.25 if calls["n"] == 1 else 0.01)
            body = msg.get_content()
            delivered.append(
                next(
                    line for line in body.splitlines() if "token=" in line
                ).split("token=", 1)[1].strip()
            )

        monkeypatch.setattr("app.core.email.EmailService.send", out_of_order_send)

        for _ in range(4):
            await self._request(client, reset_user.email)
        await asyncio.sleep(0.6)

        assert len(delivered) == 1, (
            f"{len(delivered)} emails in flight — their arrival order is not "
            "guaranteed, so the last one read may carry a retired token"
        )

        r = await client.post(
            "/api/auth/reset-password",
            json={"token": delivered[-1], "new_password": "a-brand-new-password"},
        )
        assert r.status_code == 204, (
            "the last email the user received carried a dead token"
        )

    async def test_suppressed_requests_look_identical_to_the_caller(
        self, client, self_service_on, reset_user, captured_emails
    ):
        """Suppression must not become an oracle: a request that sent nothing
        has to be indistinguishable from one that did."""
        first = await self._request(client, reset_user.email)
        suppressed = await self._request(client, reset_user.email)
        unknown = await self._request(client, "nobody@example.com")

        assert first.status_code == suppressed.status_code == unknown.status_code == 202
        assert first.json() == suppressed.json() == unknown.json()
        assert len(captured_emails) == 1

    async def test_response_is_identical_once_throttled(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """Throttling must not become an enumeration oracle — a rate-limited
        address must look exactly like an unknown one.

        The quota is filled with requests spaced past the cooldown so the
        *hourly throttle* branch is the one under test. Firing them
        back-to-back leaves every request after the first answered by
        cooldown suppression instead, which makes this a duplicate of
        test_suppressed_requests_look_identical_to_the_caller and blind to a
        throttle-specific leak — true of an earlier version of this test.
        """
        for _ in range(RESET_REQUESTS_PER_HOUR):
            await self._request_past_cooldown(client, db, reset_user.email)

        assert len(captured_emails) == RESET_REQUESTS_PER_HOUR, (
            f"only {len(captured_emails)} emails sent — the hourly quota was "
            "not filled, so this test would not reach the throttle branch"
        )

        # Past the cooldown as well, so this is refused by the cap rather than
        # suppressed by the cooldown.
        await _age_tokens(db, seconds=RESET_REQUEST_COOLDOWN_SECONDS + 30)
        throttled = await self._request(client, reset_user.email)
        assert len(captured_emails) == RESET_REQUESTS_PER_HOUR, (
            "the request under test was not actually throttled"
        )

        unknown = await self._request(client, "nobody@example.com")
        assert throttled.status_code == unknown.status_code == 202
        assert throttled.json() == unknown.json()


class TestIssuanceLockDoesNotCorruptSettingsAuditTrail:
    """prepare_reset_email takes a lock on the self_service_password_reset
    row before issuing a token, so a concurrent disable and a concurrent
    issuance deterministically order against each other (see
    TestDisableRacesIssuanceOnPostgres). The lock is meant to be an inert
    write — self-assigning value_type to itself, not the primary key and
    not updated_at.

    SQLAlchemy applies a column's Python-side onupdate= default to a Core
    update() statement whenever the table has one, regardless of which
    columns are named in .values() — self-assigning a *different* column
    does not exempt updated_at from it. Using the ORM's update() construct
    for this lock therefore rewrote the setting's updated_at to the current
    time on every single issuance, including from anonymous forgot-password
    requests that never touched the setting at all — silently corrupting
    the "when was this last changed by an admin" audit trail the column
    exists to record. Fixed with raw SQL (text()), which bypasses
    SQLAlchemy's onupdate machinery entirely.
    """

    async def test_a_public_request_does_not_touch_the_settings_timestamp(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        row = await db.get(SystemSetting, "self_service_password_reset")
        original_updated_at = row.updated_at

        r = await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        assert r.status_code == 202

        await db.refresh(row)
        assert row.updated_at == original_updated_at, (
            "an anonymous forgot-password request rewrote "
            "self_service_password_reset's updated_at — the issuance lock "
            "is supposed to be a no-op write, not an audit-trail mutation"
        )

    async def test_an_unknown_address_does_not_touch_the_settings_timestamp(
        self, client, db, self_service_on
    ):
        """The lock is only taken on the registered-address path (see
        prepare_reset_email) — this asserts the unknown-address path, which
        never reaches it, is unaffected as a baseline, and that the
        registered-address test above is not passing by some coincidence
        of both paths already leaving the timestamp untouched for other
        reasons."""
        row = await db.get(SystemSetting, "self_service_password_reset")
        original_updated_at = row.updated_at

        r = await client.post(
            "/api/auth/forgot-password", json={"email": "nobody@example.com"}
        )
        assert r.status_code == 202

        await db.refresh(row)
        assert row.updated_at == original_updated_at

    async def test_the_lock_seeds_an_absent_row_with_its_real_type(
        self, tmp_path
    ):
        """The precondition this class's own docstring names for an absent
        row here — "a row deleted directly, or any future caller reaching
        this function without going through" the PATCH endpoint's own
        precondition — reached via a bare call to prepare_reset_email
        against a database where self_service_password_reset genuinely has
        no row yet, exactly like TestSqliteContentionDoesNotLeakExistence's
        own throwaway-engine tests above.

        The raw INSERT this lock uses hardcoded value_type='string' even
        though KEY_TYPES (api/system_settings.py) declares this key as
        bool, so the first-ever issuance against a fresh database used to
        leave the row with the wrong type. Reproduced directly against the
        unfixed code: this exact call left the row with
        value_type="string".
        """
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from app.core.database import Base
        from app.services.password_reset import _prepare_reset_email

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/fresh.db")
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(engine, expire_on_commit=False)

            async with factory() as s:
                user = User(
                    email="fresh-db@example.com", display_name="Fresh",
                    hashed_password=hash_password("originalpassword"),
                    role=UserRole.viewer, is_active=True,
                )
                s.add(user)
                s.add(SystemSetting(
                    key="smtp_host", value="smtp.example.com",
                    value_type=SettingValueType.string, updated_at=utcnow(),
                ))
                s.add(SystemSetting(
                    key="smtp_from", value="pa-central@example.com",
                    value_type=SettingValueType.string, updated_at=utcnow(),
                ))
                s.add(SystemSetting(
                    key="app_base_url", value="https://pa.example.com",
                    value_type=SettingValueType.string, updated_at=utcnow(),
                ))
                await s.commit()
                user_id = user.id

            async with factory() as s:
                assert await s.get(SystemSetting, "self_service_password_reset") is None, (
                    "test premise: the flag must have no row yet"
                )
                settings_map = {
                    "smtp_host": "smtp.example.com",
                    "smtp_from": "pa-central@example.com",
                    "app_base_url": "https://pa.example.com",
                    "self_service_password_reset": "true",
                }
                await _prepare_reset_email(
                    s, await s.get(User, user_id), settings_map, welcome=False,
                )

            async with factory() as s:
                row = await s.get(SystemSetting, "self_service_password_reset")
            assert row is not None
            assert row.value_type == SettingValueType.bool, (
                "the lock's absent-row upsert seeded the wrong value_type — "
                f"got {row.value_type!r}, expected bool"
            )
        finally:
            await engine.dispose()


# ── Reset password ────────────────────────────────────────────────────────────

class TestResetPassword:
    async def test_full_flow_changes_password(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        token = _token_from_email(captured_emails)

        r = await client.post(
            "/api/auth/reset-password", json={"token": token, "new_password": "a-brand-new-password"}
        )
        assert r.status_code == 204

        await db.refresh(reset_user)
        assert verify_password("a-brand-new-password", reset_user.hashed_password)
        assert not verify_password("originalpassword", reset_user.hashed_password)

    async def test_token_is_single_use(self, client, self_service_on, reset_user, captured_emails):
        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        token = _token_from_email(captured_emails)

        first = await client.post(
            "/api/auth/reset-password", json={"token": token, "new_password": "first-new-password"}
        )
        assert first.status_code == 204
        second = await client.post(
            "/api/auth/reset-password", json={"token": token, "new_password": "second-new-password"}
        )
        assert second.status_code == 400

    async def test_expired_token_is_rejected(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        token = _token_from_email(captured_emails)

        row = (await db.execute(select(PasswordResetToken))).scalar_one()
        row.expires_at = utcnow() - timedelta(minutes=1)
        await db.commit()

        r = await client.post(
            "/api/auth/reset-password", json={"token": token, "new_password": "a-brand-new-password"}
        )
        assert r.status_code == 400
        await db.refresh(reset_user)
        assert verify_password("originalpassword", reset_user.hashed_password)

    async def test_unknown_token_is_rejected(self, client, self_service_on):
        r = await client.post(
            "/api/auth/reset-password",
            json={"token": "not-a-real-token", "new_password": "a-brand-new-password"},
        )
        assert r.status_code == 400

    async def test_token_for_deactivated_user_is_rejected(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        token = _token_from_email(captured_emails)
        reset_user.is_active = False
        await db.commit()

        r = await client.post(
            "/api/auth/reset-password", json={"token": token, "new_password": "a-brand-new-password"}
        )
        assert r.status_code == 400

    async def test_short_password_is_rejected(self, client, self_service_on, reset_user, captured_emails):
        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        token = _token_from_email(captured_emails)
        r = await client.post(
            "/api/auth/reset-password", json={"token": token, "new_password": "short"}
        )
        assert r.status_code == 422

    async def test_a_password_over_the_bcrypt_limit_is_rejected(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """bcrypt hashes only the first 72 bytes of its input and raises
        ValueError past that. Reproduced before this schema-level guard
        existed: this request reached set_password -> hash_password ->
        bcrypt.hashpw() unvalidated and would have crashed with an
        unhandled 500 instead of a clean validation error, leaving the
        token unconsumed and the password unchanged either way — asserted
        explicitly, since a genuinely broken reset should not silently
        succeed at the same time as reporting failure.
        """
        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        token = _token_from_email(captured_emails)

        r = await client.post(
            "/api/auth/reset-password",
            json={"token": token, "new_password": "a" * 100},
        )
        assert r.status_code == 422

        await db.refresh(reset_user)
        assert verify_password("originalpassword", reset_user.hashed_password), (
            "an over-length password should be rejected before the "
            "password is touched"
        )

        # The token must still be usable — the rejected attempt did not
        # consume it, so the user isn't locked out by their own typo.
        r = await client.post(
            "/api/auth/reset-password",
            json={"token": token, "new_password": "a-brand-new-password"},
        )
        assert r.status_code == 204

    async def test_an_issued_link_survives_the_feature_being_disabled(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """Consumption is not gated on the issuance setting.

        The sharp case: an admin reset invalidates the password and emails a
        link, an admin then switches the feature off, and the user is left
        with a dead password and a link that answers 503 — no way in at all.
        Disabling revokes outstanding tokens explicitly instead, so a link
        that still exists is one that still works.
        """
        await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        link = _token_from_email(captured_emails)
        await db.refresh(reset_user)
        assert not verify_password("originalpassword", reset_user.hashed_password)

        # Disable by a route that does not go through PATCH, so this test
        # covers the endpoint's own behaviour rather than the revocation.
        await _set(db, "self_service_password_reset", "false", SettingValueType.bool)

        r = await client.post(
            "/api/auth/reset-password",
            json={"token": link, "new_password": "chosen-by-the-user"},
        )
        assert r.status_code == 204, (
            "a delivered link was refused, stranding a user whose password "
            "was already invalidated"
        )
        await db.refresh(reset_user)
        assert verify_password("chosen-by-the-user", reset_user.hashed_password)

    async def test_an_unknown_token_is_still_rejected_when_disabled(
        self, client, smtp_configured
    ):
        """Ungating consumption must not make the endpoint permissive — an
        unknown token is still a 400, not a way to probe."""
        r = await client.post(
            "/api/auth/reset-password",
            json={"token": "anything", "new_password": "a-brand-new-password"},
        )
        assert r.status_code == 400

    async def test_requires_no_authentication(self, client, self_service_on, reset_user, captured_emails):
        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        token = _token_from_email(captured_emails)
        r = await client.post(
            "/api/auth/reset-password", json={"token": token, "new_password": "a-brand-new-password"}
        )
        assert r.status_code == 204

    async def test_totp_remains_enabled_after_reset(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """A reset changes the password only — 2FA is not bypassed or cleared,
        so the user still faces the TOTP challenge at next login."""
        reset_user.totp_enabled = True
        reset_user.totp_secret = "BASE32SECRET234A"
        await db.commit()

        await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        token = _token_from_email(captured_emails)
        await client.post(
            "/api/auth/reset-password", json={"token": token, "new_password": "a-brand-new-password"}
        )

        await db.refresh(reset_user)
        assert reset_user.totp_enabled is True
        assert reset_user.totp_secret == "BASE32SECRET234A"


# ── send_reset_email is best-effort, never raises ─────────────────────────────

class TestSendResetEmailIsBestEffortAndNeverRaises:
    """send_reset_email reports a plain bool — True for a clean send, False
    for any reason to doubt delivery, deliberately not distinguished more
    finely than that (see its own docstring): a caller no longer takes any
    destructive, irreversible action on this value, so there is nothing
    left for a finer distinction to protect. What still matters is that it
    never raises, whatever shape the underlying failure takes — a hang
    after the server accepts the message, or an outright disconnect.
    """

    @staticmethod
    def _accept_data_then_hang(sock) -> None:
        """A relay that accepts the connection, the envelope, and the full
        DATA payload, then hangs before sending the final "250 OK"
        acknowledgment — exercises the timeout path end to end."""
        conn, _ = sock.accept()
        conn.sendall(b"220 test.local ESMTP\r\n")
        buf = b""
        while True:
            buf += conn.recv(4096)
            if not buf.endswith(b"\r\n"):
                continue
            line, buf = buf, b""
            if line.upper().startswith((b"EHLO", b"HELO")):
                conn.sendall(b"250-test.local\r\n250 OK\r\n")
            elif line.upper().startswith((b"MAIL FROM", b"RCPT TO")):
                conn.sendall(b"250 OK\r\n")
            elif line.upper().startswith(b"DATA"):
                conn.sendall(b"354 Start mail input\r\n")
            elif line.endswith(b"\r\n.\r\n") or line == b".\r\n":
                time.sleep(10)
                return

    @staticmethod
    def _accept_then_disconnect(sock) -> None:
        """A relay that closes the connection outright partway through."""
        conn, _ = sock.accept()
        conn.sendall(b"220 test.local ESMTP\r\n")
        buf = b""
        while True:
            data = conn.recv(4096)
            if not data:
                return
            buf += data
            if buf.upper().startswith((b"EHLO", b"HELO")):
                conn.sendall(b"250-test.local\r\n250 OK\r\n")
                buf = b""
            elif buf.upper().startswith(b"MAIL FROM"):
                conn.close()
                return

    async def test_a_relay_that_hangs_after_accepting_the_message_reports_false_not_raise(
        self, tmp_path, monkeypatch
    ):
        import socket
        import threading

        from app.core.email import build_password_reset_email
        from app.services.password_reset import send_reset_email

        # The file-wide captured_emails autouse fixture replaces
        # EmailService.send with a fake that never touches a real socket —
        # exactly the method this test needs to exercise for real, or the
        # fake server below is never engaged at all.
        monkeypatch.setattr("app.core.email.EmailService.send", _REAL_EMAIL_SEND)

        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        threading.Thread(
            target=self._accept_data_then_hang, args=(srv,), daemon=True
        ).start()
        try:
            cfg = SmtpConfig(
                host="127.0.0.1", port=port, username=None, password=None,
                from_addr="a@example.com", tls_mode="none", timeout=1.0,
            )
            msg = build_password_reset_email(
                reset_url="https://pa.example.com/reset-password#token=x",
                display_name="Test", recipient="r@example.com",
                from_addr="a@example.com", expires_minutes=60,
            )
            sent = await send_reset_email(
                msg, cfg, "r@example.com", 1, interactive=True
            )
            assert sent is False
        finally:
            srv.close()

    async def test_a_relay_that_disconnects_outright_reports_false_not_raise(
        self, tmp_path, monkeypatch
    ):
        import socket
        import threading

        from app.core.email import build_password_reset_email
        from app.services.password_reset import send_reset_email

        monkeypatch.setattr("app.core.email.EmailService.send", _REAL_EMAIL_SEND)

        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        threading.Thread(
            target=self._accept_then_disconnect, args=(srv,), daemon=True
        ).start()
        try:
            cfg = SmtpConfig(
                host="127.0.0.1", port=port, username=None, password=None,
                from_addr="a@example.com", tls_mode="none", timeout=5.0,
            )
            msg = build_password_reset_email(
                reset_url="https://pa.example.com/reset-password#token=x",
                display_name="Test", recipient="r@example.com",
                from_addr="a@example.com", expires_minutes=60,
            )
            sent = await send_reset_email(
                msg, cfg, "r@example.com", 1, interactive=True
            )
            assert sent is False
        finally:
            srv.close()


# ── Admin-initiated reset switches behaviour ──────────────────────────────────

class TestAdminResetPassword:
    async def test_generates_password_when_self_service_disabled(
        self, client, db, admin_token, reset_user, captured_emails
    ):
        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["reset_link_sent"] is False
        assert body["password"]
        assert captured_emails == []

        await db.refresh(reset_user)
        assert verify_password(body["password"], reset_user.hashed_password)

    async def test_emails_link_when_self_service_enabled(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["reset_link_sent"] is True
        assert body["password"] is None
        assert len(captured_emails) == 1
        assert captured_emails[0][1] == [reset_user.email]

        # The old password must be dead already. The primary use is
        # containment after a suspected compromise, so waiting for the user
        # to click the link would leave an attacker's access intact for as
        # long as the mail sat unread.
        await db.refresh(reset_user)
        assert not verify_password("originalpassword", reset_user.hashed_password)

    async def test_emailed_link_completes_the_reset(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        token = _token_from_email(captured_emails)
        r = await client.post(
            "/api/auth/reset-password", json={"token": token, "new_password": "a-brand-new-password"}
        )
        assert r.status_code == 204
        await db.refresh(reset_user)
        assert verify_password("a-brand-new-password", reset_user.hashed_password)

    async def test_rejects_disabled_account_when_self_service_enabled(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        reset_user.is_active = False
        await db.commit()
        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 400
        assert captured_emails == []

    async def test_smtp_failure_is_reported_to_the_admin(
        self, client, db, admin_token, self_service_on, reset_user, monkeypatch
    ):
        """Unlike forgot-password, the admin path has no enumeration concern —
        they already know the account exists — so a failed send must be
        reported rather than silently swallowed."""
        async def boom(self, msg, recipients, *, interactive=False):
            raise OSError("connection refused")

        monkeypatch.setattr("app.core.email.EmailService.send", boom)

        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 502
        assert "invalidated" in r.json()["detail"]

        # Containment holds even when delivery fails: the old password must
        # be dead regardless, and the admin is told so explicitly rather than
        # being left to assume nothing happened.
        await db.refresh(reset_user)
        assert not verify_password("originalpassword", reset_user.hashed_password)

    async def test_a_timed_out_send_is_reported_as_a_502(
        self, client, db, admin_token, self_service_on, reset_user, monkeypatch
    ):
        """EmailService.send's own overall deadline abandons the coroutine on
        timeout, not the underlying smtplib call — the link may still be
        delivered after this response goes out (see send_reset_email's own
        docstring for why this is deliberately not distinguished from a
        confirmed failure any more). This endpoint takes no destructive
        action either way — the password is already invalidated above,
        unconditionally, before any send is attempted — so a timeout just
        gets the same 502 a confirmed failure would, telling the admin
        delivery is not confirmed.
        """
        async def times_out(self, msg, recipients, *, interactive=False):
            raise TimeoutError()

        monkeypatch.setattr("app.core.email.EmailService.send", times_out)

        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 502
        assert "could not be confirmed" in r.json()["detail"]

        await db.refresh(reset_user)
        assert not verify_password("originalpassword", reset_user.hashed_password)

    async def test_invalidated_password_is_not_guessable(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """The replacement must be a random value nobody holds — not a
        predictable placeholder, and not returned to the admin. Only the
        emailed link can set a usable password."""
        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.json()["password"] is None

        await db.refresh(reset_user)
        for guess in ("", "originalpassword", reset_user.email, "password"):
            assert not verify_password(guess, reset_user.hashed_password)

    async def test_link_is_long_lived(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """The user did not ask for this mail and may not read it for hours,
        and they are locked out until they do — so the admin link gets a much
        longer window than a self-service one."""
        await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        row = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().one()

        remaining_minutes = (row.expires_at - utcnow()).total_seconds() / 60
        assert remaining_minutes > RESET_TOKEN_TTL_MINUTES * 2, (
            f"admin link expires in {remaining_minutes:.0f} min — no longer "
            "than a self-service one"
        )
        assert remaining_minutes > ADMIN_RESET_TOKEN_TTL_MINUTES - 5

    async def test_bypasses_the_forgot_password_throttle(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """An attacker who has burned the account's public quota must not be
        able to block an admin from acting on a compromise.

        The public requests are spaced past the cooldown so the quota is
        genuinely exhausted. Back-to-back they create a single ledger row —
        every request after the first is suppressed by the cooldown — so the
        cap is never reached and the admin path never exercises its bypass:
        an earlier version of this test passed with the bypass removed
        entirely.
        """
        for _ in range(RESET_REQUESTS_PER_HOUR):
            await _age_tokens(db, seconds=RESET_REQUEST_COOLDOWN_SECONDS + 30)
            await client.post(
                "/api/auth/forgot-password", json={"email": reset_user.email}
            )
        before = len(captured_emails)
        assert before == RESET_REQUESTS_PER_HOUR, (
            f"only {before} public emails sent — the quota was not exhausted, "
            "so this test would not reach the throttle the admin path bypasses"
        )

        # Confirm the public endpoint is now refusing, so the admin reset
        # below is genuinely stepping over a live limit.
        await _age_tokens(db, seconds=RESET_REQUEST_COOLDOWN_SECONDS + 30)
        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        assert len(captured_emails) == before, "the public endpoint was not throttled"

        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        assert len(captured_emails) == before + 1, (
            "the admin reset was swallowed by the public rate limit"
        )

    async def test_admin_link_does_not_inherit_a_short_self_service_expiry(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """A self-service token outstanding at the moment the admin acts must
        not cap the admin link's life — otherwise it could expire minutes
        after being issued."""
        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        row = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().one()

        remaining_minutes = (row.expires_at - utcnow()).total_seconds() / 60
        assert remaining_minutes > ADMIN_RESET_TOKEN_TTL_MINUTES - 5

    async def test_email_says_the_password_has_already_changed(
        self, client, admin_token, self_service_on, reset_user, captured_emails
    ):
        """The self-service wording ("ignore this if you didn't request it")
        would be actively misleading here — the recipient is locked out."""
        await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        msg = captured_emails[-1][0]
        body = msg.get_content()

        assert "no longer works" in body
        assert "you can ignore this email" not in body
        assert "administrator" in body.lower()

    async def test_emailed_link_restores_access(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """End to end: locked out by the admin, back in via the link."""
        await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        token = _token_from_email(captured_emails)
        r = await client.post(
            "/api/auth/reset-password",
            json={"token": token, "new_password": "chosen-by-the-user"},
        )
        assert r.status_code == 204

        await db.refresh(reset_user)
        assert verify_password("chosen-by-the-user", reset_user.hashed_password)

    async def test_falls_back_to_a_generated_password_without_a_base_url(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """With no base URL the feature is off (self_service_reset_enabled
        requires one), so the admin endpoint takes its documented no-link
        fallback rather than failing.

        That is the better outcome than the 400 this previously returned: the
        admin is not stuck, they get a working credential to relay, and the
        compromised password is still invalidated. No half-state — either a
        link is emailed or a password is handed back, never neither.
        """
        await _set(db, "app_base_url", "")

        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

        body = r.json()
        assert body["reset_link_sent"] is False
        assert body["password"], "neither a link nor a password was produced"
        assert captured_emails == []

        # Containment still holds, and the relayed password works.
        await db.refresh(reset_user)
        assert not verify_password("originalpassword", reset_user.hashed_password)
        assert verify_password(body["password"], reset_user.hashed_password)

        # No token was issued, since no usable link could be built.
        live = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().all()
        assert live == []

    async def test_deleting_a_user_removes_their_pending_reset_token(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """An outstanding link for a deleted account would be a standing
        credential — the FK cascade must clear it."""
        await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        user_id = reset_user.id
        assert (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.user_id == user_id)
        )).scalars().all()

        r = await client.delete(
            f"/api/users/{user_id}", headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert r.status_code == 204

        remaining = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.user_id == user_id)
        )).scalars().all()
        assert remaining == []

    async def test_an_undeliverable_address_falls_back_to_a_generated_password(
        self, client, db, admin_token, self_service_on, captured_emails
    ):
        """admin@localhost and similar are refused by real SMTP servers, and
        that is knowable from the address alone before anything is touched
        — filter_deliverable_recipients' own check. Checked as a preflight,
        before set_password, and falls back to the same generated-password
        path as a missing app_base_url: no link can ever be built for this
        address, so self-service is exactly as unusable for this one
        account as it is for the whole deployment in that case.

        This used to invalidate the password first and report a 502 for
        this scenario — reachable for a real deployment via the built-in
        bootstrap admin (main.py's bootstrap_admin), created at exactly
        admin@localhost. An admin resetting their own password without
        having first changed that address would have their password
        invalidated *and* their own session revoked (set_password bumps
        token_epoch) for an account that could never receive the
        replacement link — locked out with no path back except direct
        database recovery. Reproduced directly before this fix.
        """
        user = User(
            email="root@localhost",
            display_name="Local Root",
            hashed_password=hash_password("originalpassword"),
            role=UserRole.viewer,
            is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

        r = await client.post(
            f"/api/users/{user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["reset_link_sent"] is False
        assert body["password"], "neither a link nor a password was produced"
        assert captured_emails == []

        # Containment still holds, and the relayed password works.
        await db.refresh(user)
        assert not verify_password("originalpassword", user.hashed_password)
        assert verify_password(body["password"], user.hashed_password)

        # No token was issued, since no usable link could ever be built.
        live = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().all()
        assert live == []

    async def test_a_self_reset_with_an_undeliverable_address_does_not_lock_out_the_admin(
        self, client, db, admin_token, self_service_on
    ):
        """The concrete scenario the finding is about: the built-in
        bootstrap admin, still at admin@localhost, resetting their own
        password. Before this fix: password invalidated, own bearer token
        revoked (set_password bumps token_epoch), no email possible — a
        deployment locked out with no path back except direct database
        recovery. Confirmed the admin's own current session survives to
        keep making requests, and the returned password actually
        authenticates.
        """
        import sqlalchemy as sa

        from app.core.security import decode_access_token

        admin = (await db.execute(
            sa.select(User).where(User.role == UserRole.admin)
        )).scalars().first()
        admin.email = "admin@localhost"
        await db.commit()
        await db.refresh(admin)

        decoded = decode_access_token(admin_token)
        assert decoded is not None
        old_epoch = decoded[1]
        assert old_epoch == admin.token_epoch, (
            "test setup problem: admin_token's embedded epoch does not "
            "match the account's current epoch"
        )

        r = await client.post(
            f"/api/users/{admin.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200, (
            f"expected the generated-password fallback (200), got "
            f"{r.status_code} — an admin resetting their own undeliverable "
            "account should never be told the operation failed with "
            "nothing to show for it"
        )
        body = r.json()
        assert body["password"], "no password was returned to relay"

        await db.refresh(admin)
        assert verify_password(body["password"], admin.hashed_password), (
            "the returned password does not actually authenticate — the "
            "admin has no way back in"
        )
        # Old sessions are correctly revoked as part of containment — this
        # is not the lockout the finding is about, which is the admin
        # having *no* way back in at all, not merely needing to use the
        # freshly-returned password instead of their old bearer token.
        assert admin.token_epoch != old_epoch

    async def test_a_stored_from_addr_containing_crlf_falls_back_instead_of_500ing(
        self, client, db, admin_token, self_service_on
    ):
        """build_password_reset_email (core/email.py) assigns smtp_from
        straight to EmailMessage()["From"] — Python's own email module
        raises ValueError for a value containing a carriage return or line
        feed, and that assignment happens after set_password has already
        invalidated the target's password. self_service_reset_enabled()
        now refuses this configuration up front, so this endpoint takes
        the same outer disabled-feature branch as a missing smtp_host —
        the generated-password fallback — rather than ever reaching
        set_password with a config that would raise partway through.
        Reproduced directly before this fix: an unhandled 500, with the
        password already invalidated and no link ever built to relay
        instead.
        """
        await _set(db, "smtp_from", "pa\r\nBcc: evil@example.com")
        user = User(
            email="crlf-victim@example.com", display_name="CRLF Victim",
            hashed_password=hash_password("originalpassword"),
            role=UserRole.viewer, is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

        r = await client.post(
            f"/api/users/{user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200, (
            f"expected the generated-password fallback (200), got "
            f"{r.status_code} — a malicious smtp_from crashed issuance "
            "instead of the feature reporting itself unavailable up front"
        )
        body = r.json()
        assert body["password"], "no password was returned to relay"

        await db.refresh(user)
        assert verify_password(body["password"], user.hashed_password), (
            "the returned password does not actually authenticate"
        )

    async def test_a_concurrent_admin_reset_that_supersedes_the_token_is_reported_not_sent(
        self, tmp_path
    ):
        """prepare_reset_email commits its token and releases the per-account
        lock *before* the caller sends anything — issue_reset_token's send
        happens entirely outside that transaction. A second admin-initiated
        reset for the same user can therefore retire the first token between
        the first commit and the first send completing: both calls report a
        committed token, but only one is still live once both have run.
        Without a re-check after sending, issue_reset_token (and therefore
        the endpoint) reports the superseded send as a success — an admin is
        told a link went out, and it did, but the token inside it is already
        dead.

        Uses its own file-backed SQLite database and one session per admin
        action, like test_concurrent_requests_cannot_exceed_the_cap above:
        the suite's shared client/db fixtures route every request through a
        single session and cannot express two overlapping transactions.
        EmailService.send is monkeypatched to perform the *second* reset's
        full database work while the *first* is still "sending" — this is
        the actual interleaving two real concurrent HTTP requests would
        produce, not merely two calls in some order.
        """
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from app.core.database import Base
        from app.services.password_reset import issue_reset_token

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/race.db")
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(engine, expire_on_commit=False)

            async with factory() as s:
                user = User(
                    email="admin-race@example.com", display_name="Admin Race",
                    hashed_password=hash_password("originalpassword"),
                    role=UserRole.viewer, is_active=True,
                )
                s.add(user)
                # See test_concurrent_requests_cannot_exceed_the_cap above:
                # issue_reset_token's settings-row re-check now refuses
                # unless stored rows agree with settings_map below.
                s.add(SystemSetting(
                    key="self_service_password_reset", value="true",
                    value_type=SettingValueType.bool, updated_at=utcnow(),
                ))
                s.add(SystemSetting(
                    key="app_base_url", value="https://pa.example.com",
                    value_type=SettingValueType.string, updated_at=utcnow(),
                ))
                await s.commit()
                user_id = user.id

            settings_map = {
                "smtp_host": "smtp.example.com",
                "smtp_from": "pa-central@example.com",
                "app_base_url": "https://pa.example.com",
                "self_service_password_reset": "true",
            }

            already_raced = False

            async def send_that_races_a_second_reset_once(self, msg, recipients, *, interactive=False):
                # Runs while request A's session still holds A's committed
                # token as the only row — exactly the window between A's
                # commit and A's send completing in the real endpoint. Fires
                # only for A's own send: B's issue_reset_token call reaches
                # this same patched method for its own send, and must not
                # recurse into a third reset.
                nonlocal already_raced
                if already_raced:
                    return
                already_raced = True
                async with factory() as s:
                    u = await s.get(User, user_id)
                    await issue_reset_token(
                        s, u, settings_map, admin_initiated=True
                    )

            with pytest.MonkeyPatch.context() as mp:
                mp.setattr(
                    "app.core.email.EmailService.send",
                    send_that_races_a_second_reset_once,
                )
                async with factory() as s:
                    u = await s.get(User, user_id)
                    result_a = await issue_reset_token(
                        s, u, settings_map, admin_initiated=True
                    )

            assert result_a.sent is True, "the SMTP send itself did succeed"
            assert result_a.still_live is False, (
                "request A reported its send as successful, but request B "
                "retired A's token before A's send completed — the admin "
                "was told a usable link went out when it did not"
            )

            async with factory() as s:
                rows = (await s.execute(
                    select(PasswordResetToken).where(PasswordResetToken.user_id == user_id)
                )).scalars().all()
            live = [r for r in rows if r.used_at is None]
            assert len(rows) == 2, f"expected one token per reset, found {len(rows)}"
            assert len(live) == 1, (
                f"{len(live)} live tokens after two admin resets — the "
                "one-live-link invariant must still hold"
            )
        finally:
            await engine.dispose()

    async def test_the_account_deleted_while_sending_is_reported_not_sent(
        self, tmp_path
    ):
        """The post-send re-check reads `used_at` with a single-column
        `select(PasswordResetToken.used_at)...scalar_one_or_none()` — but a
        live token also has `used_at IS NULL`, so that call returns `None`
        for *both* "the row is live" and "the row does not exist at all".
        PasswordResetToken.user_id has `ondelete="CASCADE"`, so deleting the
        account (DELETE /users/{id}, a second admin action or the same
        admin double-clicking) while this send is still in flight removes
        the token row entirely — and the old check read that missing row
        exactly like a live one, reporting success for a link with no
        account left to authenticate against.

        Same technique as the concurrent-reset test above: EmailService.send
        is monkeypatched to delete the account from a second session while
        the first request's send is still "in progress" — the actual
        interleaving a real concurrent DELETE would produce, not merely two
        calls in sequence (which would not reproduce this: by the time a
        second call started, the first would already have returned).

        Registers the same connect/checkin listeners the application's real
        engine uses (see core/database.py) to turn on
        `PRAGMA foreign_keys = ON` — SQLite ignores FK actions, including
        `ondelete="CASCADE"`, on a connection that never sets this, and a
        bare `create_async_engine(...)` in a test does not inherit it from
        anywhere. Without this, the cascade this test exists to exercise
        silently never fires and the token row survives the user's
        deletion untouched — confirmed directly: this test failed with
        `sent is True` on a first draft that skipped the pragma.
        """
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from app.core.database import Base, sqlite_on_checkin, sqlite_on_connect
        from app.services.password_reset import issue_reset_token

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/deleted.db")
        event.listens_for(engine.sync_engine, "connect")(sqlite_on_connect)
        event.listens_for(engine.sync_engine, "checkin")(sqlite_on_checkin)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(engine, expire_on_commit=False)

            async with factory() as s:
                user = User(
                    email="deleted-mid-send@example.com", display_name="Deleted Mid Send",
                    hashed_password=hash_password("originalpassword"),
                    role=UserRole.viewer, is_active=True,
                )
                s.add(user)
                # See test_concurrent_requests_cannot_exceed_the_cap above:
                # issue_reset_token's settings-row re-check now refuses
                # unless stored rows agree with settings_map below.
                s.add(SystemSetting(
                    key="self_service_password_reset", value="true",
                    value_type=SettingValueType.bool, updated_at=utcnow(),
                ))
                s.add(SystemSetting(
                    key="app_base_url", value="https://pa.example.com",
                    value_type=SettingValueType.string, updated_at=utcnow(),
                ))
                await s.commit()
                user_id = user.id

            settings_map = {
                "smtp_host": "smtp.example.com",
                "smtp_from": "pa-central@example.com",
                "app_base_url": "https://pa.example.com",
                "self_service_password_reset": "true",
            }

            async def delete_account_mid_send(self, msg, recipients, *, interactive=False):
                # Runs while the outer session still holds the just-committed
                # token as the only row — exactly the window between that
                # commit and the send completing in the real endpoint.
                async with factory() as s:
                    u = await s.get(User, user_id)
                    await s.delete(u)
                    await s.commit()

            with pytest.MonkeyPatch.context() as mp:
                mp.setattr(
                    "app.core.email.EmailService.send", delete_account_mid_send
                )
                async with factory() as s:
                    u = await s.get(User, user_id)
                    result = await issue_reset_token(
                        s, u, settings_map, admin_initiated=True
                    )

            assert result.sent is True, "the SMTP send itself did succeed"
            assert result.still_live is False, (
                "issue_reset_token reported the token as still live, but the "
                "account (and its cascade-deleted token) no longer existed "
                "by the time the send completed — a missing row and a live "
                "row both read as None from a single-column used_at select"
            )

            async with factory() as s:
                remaining = (await s.execute(
                    select(PasswordResetToken).where(PasswordResetToken.user_id == user_id)
                )).scalars().all()
            assert remaining == [], "the token row should be gone, cascade-deleted with the user"
        finally:
            await engine.dispose()


# ── A malformed smtp_port must not restore account enumeration by status ────
# ── code, and must not invalidate an admin-reset target's password before ───
# ── discovering delivery is impossible ───────────────────────────────────────

class TestMalformedSmtpPortDoesNotLeakExistenceOrLockOutAdminResets:
    """`build_smtp_config` used a bare `int(smtp_port or "587")`. A legacy
    row, one restored from a backup, or a value written directly to the
    database can hold something PATCH's own int-and-range validation would
    have refused — a non-numeric string, or an out-of-range port.

    forgot_password only reaches build_smtp_config (via prepare_reset_email)
    for a real, active account: an unknown address returns the padded 202
    without ever calling it. An uncaught ValueError there therefore surfaced
    only for a real account, diverging from the identical-looking 202 an
    unknown address gets — an account-existence oracle by status code, the
    exact bug class prepare_reset_email's own docstring says it exists to
    prevent (there, for lock contention; here, for the same exception type
    the read side never accounted for).

    On the admin-reset path (api/users.py's reset_password),
    self_service_reset_enabled() previously never looked at smtp_port at
    all, so it reported the feature usable regardless. set_password ran
    and committed before issue_reset_token discovered delivery was
    impossible, turning a config typo into an unrecoverable lockout instead
    of the generated-password fallback the disabled-feature path already
    provides.
    """

    @pytest_asyncio.fixture
    async def self_service_on_with_bad_port(self, db, self_service_on):
        await _set(db, "smtp_port", "not-a-port")

    async def test_forgot_password_answers_202_for_a_real_account(
        self, client, self_service_on_with_bad_port, reset_user, captured_emails
    ):
        r = await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        assert r.status_code == 202
        assert captured_emails == []

    async def test_forgot_password_answers_identically_for_a_real_and_an_unknown_account(
        self, client, self_service_on_with_bad_port, reset_user, captured_emails
    ):
        known = await client.post("/api/auth/forgot-password", json={"email": reset_user.email})
        unknown = await client.post(
            "/api/auth/forgot-password", json={"email": "nobody@example.com"}
        )
        assert known.status_code == unknown.status_code == 202
        assert known.json() == unknown.json()
        assert captured_emails == []

    async def test_password_reset_config_reports_the_feature_unavailable(
        self, client, self_service_on_with_bad_port
    ):
        r = await client.get("/api/auth/password-reset-config")
        assert r.status_code == 200
        assert r.json()["self_service_enabled"] is False

    async def test_admin_reset_falls_back_to_a_generated_password_without_invalidating_first(
        self, client, db, admin_token, self_service_on_with_bad_port, reset_user, captured_emails
    ):
        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200, (
            "an uncaught ValueError from the malformed port would surface "
            "as a 500 here, after the password had already been invalidated"
        )
        body = r.json()
        assert body["reset_link_sent"] is False
        assert body["password"]
        assert captured_emails == []

        await db.refresh(reset_user)
        assert verify_password(body["password"], reset_user.hashed_password)


# ── A password change must revoke tokens already issued, not just the ────────
# ── password itself ───────────────────────────────────────────────────────────

class TestTokenEpochRevocation:
    """create_access_token embeds only sub/exp, and get_current_user checked
    only that the user exists and is active — so a bearer token obtained
    before a password reset kept working for its full 8-hour lifetime
    regardless of the reset. That directly undermines admin-reset's actual
    purpose: containing a suspected compromise. An attacker holding a live
    JWT was untouched by the very action meant to lock them out.

    set_password now bumps User.token_epoch atomically with the password
    change; the epoch is embedded in every token issued afterwards and
    checked against the user's *current* value on every request. This is
    deliberately coarse — one bump invalidates every session for that user,
    not a specific one — since there is no per-session record to revoke
    individually (a session store was the alternative; this project does not
    require Valkey, so a DB-backed epoch was chosen instead).
    """

    async def _get_me(self, client, token: str):
        return await client.get(
            "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
        )

    async def test_a_token_issued_before_self_service_reset_is_rejected(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        old_token = create_access_token(reset_user.id, reset_user.token_epoch)
        assert (await self._get_me(client, old_token)).status_code == 200

        r = await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        assert r.status_code == 202
        raw = _token_from_email(captured_emails)
        r = await client.post(
            "/api/auth/reset-password",
            json={"token": raw, "new_password": "a-brand-new-password"},
        )
        assert r.status_code == 204

        r = await self._get_me(client, old_token)
        assert r.status_code == 401, (
            "a token issued before the self-service reset still authenticated "
            "after it — the reset did not actually end the old session"
        )

    async def test_a_token_issued_before_an_admin_reset_is_rejected(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """The case the finding names directly: admin-initiated reset exists
        to contain a suspected compromise, which means revoking whatever
        session the attacker is holding — not just the password they can no
        longer log in with next time."""
        old_token = create_access_token(reset_user.id, reset_user.token_epoch)
        assert (await self._get_me(client, old_token)).status_code == 200

        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

        r = await self._get_me(client, old_token)
        assert r.status_code == 401, (
            "a token issued before the admin-initiated reset still "
            "authenticated afterwards — compromise containment did not "
            "actually revoke the attacker's session"
        )

    async def test_a_token_issued_before_a_patch_password_change_is_rejected(
        self, client, db, admin_token, reset_user
    ):
        """PATCH /users/{id} with a password is the third path through
        set_password (self-service reset and admin-reset are the other two)
        — all three must revoke, since all three go through the same
        function precisely so a fix here covers every path without
        per-endpoint wiring."""
        old_token = create_access_token(reset_user.id, reset_user.token_epoch)
        assert (await self._get_me(client, old_token)).status_code == 200

        r = await client.patch(
            f"/api/users/{reset_user.id}",
            json={"password": "a-brand-new-password"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

        r = await self._get_me(client, old_token)
        assert r.status_code == 401

    async def test_the_new_token_from_the_same_reset_still_works(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """Revocation must be scoped to *stale* tokens, not to the user —
        the request that performs the reset is itself authenticated in the
        admin-reset and PATCH cases, and login immediately after a
        self-service reset must succeed."""
        r = await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        assert r.status_code == 202
        raw = _token_from_email(captured_emails)
        await client.post(
            "/api/auth/reset-password",
            json={"token": raw, "new_password": "a-brand-new-password"},
        )

        await db.refresh(reset_user)
        new_token = create_access_token(reset_user.id, reset_user.token_epoch)
        assert (await self._get_me(client, new_token)).status_code == 200

    async def test_an_admins_own_token_survives_resetting_someone_else(
        self, client, db, admin_token, reset_user, captured_emails
    ):
        """The epoch is per-user. Resetting one account's password must not
        collaterally revoke the admin's own session — or anyone else's."""
        assert (await self._get_me(client, admin_token)).status_code == 200

        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

        assert (await self._get_me(client, admin_token)).status_code == 200, (
            "resetting another user's password revoked the admin's own "
            "session — the epoch bump is not scoped to the right user"
        )

    async def test_the_api_key_path_is_unaffected_by_a_password_reset(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """get_current_user_or_api_key's other branch (X-API-Key) has no JWT
        and therefore no epoch to check — an API key's own is_active flag is
        its independent revocation mechanism. Confirms the epoch check on
        the JWT branch does not somehow reject the API-key branch too."""
        from app.core.security import generate_api_key, hash_api_key
        from app.models import ApiKey

        raw_key, _ = generate_api_key()
        db.add(ApiKey(
            name="ci", key_hash=hash_api_key(raw_key), user_id=reset_user.id,
            is_active=True,
        ))
        await db.commit()

        r = await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        assert r.status_code == 202
        raw_reset = _token_from_email(captured_emails)
        await client.post(
            "/api/auth/reset-password",
            json={"token": raw_reset, "new_password": "a-brand-new-password"},
        )

        r = await client.get("/api/scans", headers={"X-API-Key": raw_key})
        assert r.status_code == 200

    async def test_a_stale_token_is_rejected_on_the_jwt_or_api_key_dependency(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """get_current_user_or_api_key re-implements the same epoch check
        separately from get_current_user (it has to: one path has no JWT to
        check at all), which means the two can drift independently — a fix
        to one does not guarantee the other was fixed too. GET /api/scans
        uses this dependency and accepts a bearer token, unlike the
        API-key-only case covered above."""
        old_token = create_access_token(reset_user.id, reset_user.token_epoch)
        assert (
            await client.get(
                "/api/scans", headers={"Authorization": f"Bearer {old_token}"}
            )
        ).status_code == 200

        r = await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        assert r.status_code == 202
        raw = _token_from_email(captured_emails)
        await client.post(
            "/api/auth/reset-password",
            json={"token": raw, "new_password": "a-brand-new-password"},
        )

        r = await client.get(
            "/api/scans", headers={"Authorization": f"Bearer {old_token}"}
        )
        assert r.status_code == 401, (
            "a stale JWT still authenticated through "
            "get_current_user_or_api_key's token branch after a reset"
        )

    async def test_a_stale_token_on_the_sse_stream_is_rejected(
        self, client, db, monkeypatch, reset_user
    ):
        """stream_alerts in alerts.py authenticates by hand rather than
        through get_current_user (it needs to close its DB session before
        opening the SSE stream), and it looks the user up via
        `from app.core.database import AsyncSessionLocal` *inside the
        function body* rather than through the get_db dependency the test
        client overrides — so by default it would hit a different, real
        database engine than the one reset_user lives on, not this test's
        in-memory one. Because that import happens fresh on every call
        (it's inside the function, not at module scope), monkeypatching
        `app.core.database.AsyncSessionLocal` itself — not
        `app.api.alerts.AsyncSessionLocal` — reaches it, which is what makes
        a genuine end-to-end HTTP test of this endpoint possible at all.

        Only the rejection path is exercised here, not a live stream: a
        successful connection opens an unterminating SSE generator
        (`event_generator`'s 25s keepalive loop), which hangs an HTTP test
        client waiting for the response body to complete — confirmed
        directly. The 401 case returns a plain Response before that
        generator is ever constructed, so it completes immediately and is
        the case this finding is actually about.
        """
        class _SameSessionNoOpContext:
            async def __aenter__(self):
                return db
            async def __aexit__(self, *exc):
                return None

        monkeypatch.setattr(
            "app.core.database.AsyncSessionLocal",
            lambda: _SameSessionNoOpContext(),
        )

        old_token = create_access_token(reset_user.id, reset_user.token_epoch)
        reset_user.token_epoch += 1  # what set_password does
        await db.commit()

        # Bounded rather than a bare await: if the epoch check regresses,
        # the token authenticates successfully and stream_alerts opens a
        # real SSE stream, whose generator only exits on client disconnect
        # or its own 25s keepalive timeout — either way this call would
        # hang rather than fail, and a hung CI job is worse than a fast
        # assertion failure. Confirmed directly: removing the check under
        # test made this call hang, not merely return the wrong status.
        try:
            r = await asyncio.wait_for(
                client.get(
                    "/api/alerts/stream",
                    headers={"Authorization": f"Bearer {old_token}"},
                ),
                timeout=2.0,
            )
        except TimeoutError:
            pytest.fail(
                "the request did not complete within 2s — a stale token "
                "opened a real SSE stream instead of being rejected, which "
                "hangs rather than fails cleanly"
            )
        assert r.status_code == 401, (
            "a token issued before a password reset still authenticated on "
            "the SSE stream — stream_alerts' own epoch check did not fire"
        )

    async def test_an_already_open_stream_is_closed_after_a_mid_stream_reset(
        self, client, db, monkeypatch
    ):
        """The connect-time check above only runs once, before the
        StreamingResponse starts — a stream that connects successfully
        *before* a reset then never looks at the epoch again for the rest
        of its lifetime. Every other request bearing the same JWT starts
        401ing the moment token_epoch changes, but an already-open stream
        kept delivering alerts indefinitely, undermining exactly the
        containment guarantee token_epoch exists to provide. Reproduced
        directly before this fix: a stream opened, the epoch was bumped
        mid-stream, and the stream kept running with no way to observe it
        had been revoked short of the client disconnecting on its own.

        event_generator now re-checks the epoch periodically
        (SSE_EPOCH_RECHECK_INTERVAL_SECONDS) and ends the stream once it no
        longer matches — monkeypatched short here so the test does not need
        to wait out the real 25s interval.
        """
        import app.api.alerts as alerts_mod

        monkeypatch.setattr(alerts_mod, "SSE_EPOCH_RECHECK_INTERVAL_SECONDS", 0.2)

        user = User(
            email="ssemidstream@example.com", display_name="SSE Mid Stream",
            hashed_password=hash_password("originalpassword1"),
            role=UserRole.viewer, is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

        class _SameSessionNoOpContext:
            async def __aenter__(self):
                return db
            async def __aexit__(self, *exc):
                return None

        monkeypatch.setattr(
            "app.core.database.AsyncSessionLocal",
            lambda: _SameSessionNoOpContext(),
        )

        token = create_access_token(user.id, user.token_epoch)

        async def bump_epoch_mid_stream() -> None:
            # After the stream has connected but before the first
            # revalidation interval elapses — simulating a password reset
            # that happens while the connection is already established.
            await asyncio.sleep(0.05)
            user.token_epoch += 1
            await db.commit()

        bumper = asyncio.create_task(bump_epoch_mid_stream())

        try:
            async with asyncio.timeout(3.0):
                async with client.stream(
                    "GET", "/api/alerts/stream",
                    headers={"Authorization": f"Bearer {token}"},
                ) as r:
                    assert r.status_code == 200, (
                        "the stream should connect successfully before the "
                        "epoch is bumped"
                    )
                    body = ""
                    async for chunk in r.aiter_text():
                        body += chunk
                        # The stream ending on its own (aiter_text simply
                        # stopping) is the actual assertion — reaching here
                        # at all confirms it did not run forever.
        except TimeoutError:
            pytest.fail(
                "the stream did not close within 3s after the epoch was "
                "bumped mid-stream — an already-open connection outlives a "
                "password reset indefinitely"
            )
        finally:
            await bumper

        assert "connected" in body, (
            "the stream never delivered its initial event — this test "
            "proves nothing about mid-stream revocation without it"
        )

    async def test_an_already_open_stream_is_closed_once_its_token_expires(
        self, client, db, monkeypatch
    ):
        """still_authorized() re-checked token_epoch and is_active
        periodically, but never re-decoded the token itself — so it never
        looked at `exp` again after the connect-time decode_access_token
        call. A stream opened moments before its token's natural expiry
        therefore kept delivering alerts indefinitely afterward, as long as
        the account stayed active and the password was never changed:
        unlike a password reset or deactivation, plain expiry left nothing
        in the database for the periodic DB-only check to notice.

        Every ordinary HTTP endpoint re-decodes the token on every request
        (see get_current_user), so expiry is naturally re-checked
        constantly there — this stream is the one place in the codebase
        that authenticates once and then holds the connection open, which
        is exactly why it needs its own re-decode, not just a database
        re-check.

        Same structure as test_an_already_open_stream_is_closed_after_a_mid_stream_reset
        above: a short revalidation interval so the test does not wait out
        the real 25s, and a token that is still valid at connect time but
        expires a moment later — analogous to bumping the epoch mid-stream,
        but exercising the exp claim specifically rather than token_epoch.

        The revalidation interval is 2s, not as short as the epoch test's
        0.2s: `exp` is a whole-second NumericDate and jose's own comparison
        truncates "now" to whole seconds too (see _validate_exp), so a
        1-second expires_delta can still read as valid for close to another
        full second afterward — confirmed empirically, expiry lands
        reliably by ~1.5s after issuance, not at the nominal 1s mark. The
        interval only has to exceed that slack; it does not need to be tiny,
        since this test's timeout budget (below) is what actually bounds
        its runtime.
        """
        import app.api.alerts as alerts_mod

        monkeypatch.setattr(alerts_mod, "SSE_EPOCH_RECHECK_INTERVAL_SECONDS", 2.0)

        user = User(
            email="sseexpiry@example.com", display_name="SSE Expiry",
            hashed_password=hash_password("originalpassword1"),
            role=UserRole.viewer, is_active=True,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

        class _SameSessionNoOpContext:
            async def __aenter__(self):
                return db
            async def __aexit__(self, *exc):
                return None

        monkeypatch.setattr(
            "app.core.database.AsyncSessionLocal",
            lambda: _SameSessionNoOpContext(),
        )

        # Still valid when the connection opens, expires well before the
        # first revalidation interval elapses — token_epoch and is_active
        # never change at all in this test, so only a re-decode of the
        # token itself can catch this.
        token = create_access_token(
            user.id, user.token_epoch, expires_delta=timedelta(seconds=1)
        )

        try:
            async with asyncio.timeout(6.0):
                async with client.stream(
                    "GET", "/api/alerts/stream",
                    headers={"Authorization": f"Bearer {token}"},
                ) as r:
                    assert r.status_code == 200, (
                        "the stream should connect successfully before the "
                        "token expires"
                    )
                    body = ""
                    async for chunk in r.aiter_text():
                        body += chunk
                        # The stream ending on its own is the assertion —
                        # reaching here at all confirms it did not run
                        # forever past the token's expiry.
        except TimeoutError:
            pytest.fail(
                "the stream did not close within 6s of its token expiring — "
                "an already-open connection outlives its own token "
                "indefinitely as long as the account stays active"
            )

        assert "connected" in body, (
            "the stream never delivered its initial event — this test "
            "proves nothing about expiry revalidation without it"
        )

    async def test_concurrent_password_changes_do_not_lose_an_epoch_increment(
        self, tmp_path
    ):
        """`user.token_epoch += 1` reads the ORM attribute, computes in
        Python, and writes it back — two concurrent password changes can
        both read the same starting value and both write the same result,
        silently losing one increment. Reproduced directly before the fix:
        two concurrent set_password calls both read epoch 0 and both
        committed epoch 1, so a token minted between the two writes
        (carrying epoch 1) remained valid after the *second* password
        change — exactly the revocation this column exists to guarantee.

        Own file-backed database and one session per caller, like the other
        true-concurrency tests in this file: the suite's shared `client`/`db`
        fixtures route every request through a single session, which cannot
        express two overlapping transactions at all. The PostgreSQL side
        (TestTokenEpochIncrementIsAtomicOnPostgres in
        test_postgres_behaviour.py) is needed too, for the usual reason —
        SQLite's single-writer-lock story does not prove the UPDATE
        statement itself is atomic under genuinely concurrent transactions.
        """
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from app.core.database import Base

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/epoch_race.db")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        factory = async_sessionmaker(engine, expire_on_commit=False)

        async with factory() as s:
            user = User(
                email="epochrace@example.com", display_name="EpochRace",
                hashed_password=hash_password("originalpassword"),
                role=UserRole.viewer, is_active=True,
            )
            s.add(user)
            await s.commit()
            user_id = user.id

        barrier = asyncio.Event()

        async def change(password: str) -> int:
            async with factory() as s:
                u = await s.get(User, user_id)
                await barrier.wait()  # force both to read before either writes
                await set_password(s, u, password)
                await s.commit()
                return u.token_epoch

        try:
            t1 = asyncio.create_task(change("password-one-11"))
            t2 = asyncio.create_task(change("password-two-11"))
            await asyncio.sleep(0.05)
            barrier.set()
            r1, r2 = await asyncio.gather(t1, t2)

            async with factory() as s:
                final = await s.get(User, user_id)
        finally:
            await engine.dispose()

        assert final.token_epoch == 2, (
            f"two concurrent password changes left token_epoch="
            f"{final.token_epoch} — a lost update means a token minted "
            "between the two writes would survive the second change"
        )
        assert {r1, r2} == {1, 2}, (
            "expected distinct epochs {1, 2}, got "
            f"{{{r1}, {r2}}} — a repeated value means both writers computed "
            "the same increment from the same starting point"
        )

    async def _totp_user(self, db, *, enabled: bool = True):
        import pyotp

        from app.core.security import generate_totp_secret

        secret = generate_totp_secret()
        user = User(
            email="totpuser@example.com", display_name="Totp User",
            hashed_password=hash_password("originalpassword1"),
            role=UserRole.viewer, is_active=True,
            totp_secret=secret if enabled else None,
            totp_enabled=enabled,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user, pyotp.TOTP(secret)

    async def test_a_totp_challenge_issued_before_a_reset_is_rejected(
        self, client, db, admin_token, monkeypatch
    ):
        """The finding this covers: totp_verify never re-checked the
        password, and the challenge token carried no epoch — so an attacker
        who already knows the password (the exact precondition for the
        "suspected compromise" admin-reset exists to contain) could log in,
        obtain a challenge, and complete it *after* an admin's reset,
        walking away with a fresh, fully valid bearer token. Reproduced
        directly before this fix: login succeeded, the admin reset
        completed, and the pre-reset challenge still exchanged for a token
        carrying the post-reset epoch.
        """
        monkeypatch.setattr(app_settings, "debug", False)
        user, totp = await self._totp_user(db)

        r = await client.post("/api/auth/login", json={
            "email": user.email, "password": "originalpassword1",
        })
        assert r.status_code == 200
        challenge = r.json()["totp_session_token"]

        r = await client.post(
            f"/api/users/{user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

        r = await client.post("/api/auth/totp/verify", json={
            "totp_session_token": challenge, "code": totp.now(),
        })
        assert r.status_code == 401, (
            "a TOTP challenge issued before an admin password reset still "
            "exchanged for a token after it — the reset did not actually "
            "end this in-flight login"
        )

    async def test_a_totp_challenge_survives_an_unrelated_users_reset(
        self, client, db, admin_token, monkeypatch
    ):
        """The epoch check must compare against *this* user's epoch, not
        reject every outstanding challenge process-wide."""
        monkeypatch.setattr(app_settings, "debug", False)
        user, totp = await self._totp_user(db)
        other = User(
            email="otheruser@example.com", display_name="Other",
            hashed_password=hash_password("otherpassword1"),
            role=UserRole.viewer, is_active=True,
        )
        db.add(other)
        await db.commit()
        await db.refresh(other)

        r = await client.post("/api/auth/login", json={
            "email": user.email, "password": "originalpassword1",
        })
        assert r.status_code == 200
        challenge = r.json()["totp_session_token"]

        r = await client.post(
            f"/api/users/{other.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

        r = await client.post("/api/auth/totp/verify", json={
            "totp_session_token": challenge, "code": totp.now(),
        })
        assert r.status_code == 200, (
            "resetting an unrelated user's password rejected this user's "
            "own in-flight TOTP challenge"
        )

    async def test_a_totp_setup_challenge_issued_before_a_reset_is_rejected(
        self, client, db, admin_token, monkeypatch
    ):
        """The setup-confirmation branch (a brand-new account enrolling
        TOTP for the first time) shares the same challenge mechanism and
        needs the same check — verified separately since it is a distinct
        code path in totp_verify (is_setup=True)."""
        monkeypatch.setattr(app_settings, "debug", False)
        user = User(
            email="newtotp@example.com", display_name="New Totp",
            hashed_password=hash_password("originalpassword1"),
            role=UserRole.viewer, is_active=True, totp_enabled=False,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

        r = await client.post("/api/auth/login", json={
            "email": user.email, "password": "originalpassword1",
        })
        assert r.status_code == 200
        body = r.json()
        assert body["totp_setup_required"] is True
        challenge = body["totp_session_token"]

        await db.refresh(user)
        import pyotp
        totp = pyotp.TOTP(user.totp_secret)

        r = await client.post(
            f"/api/users/{user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

        r = await client.post("/api/auth/totp/verify", json={
            "totp_session_token": challenge, "code": totp.now(),
        })
        assert r.status_code == 401

        await db.refresh(user)
        assert user.totp_enabled is False, (
            "the rejected setup-confirm should not have enabled TOTP anyway"
        )

    async def test_a_totp_challenge_completed_before_any_reset_still_works(
        self, client, db, monkeypatch
    ):
        """The legitimate path must be unaffected — most logins complete
        their TOTP challenge with no reset happening in between."""
        monkeypatch.setattr(app_settings, "debug", False)
        user, totp = await self._totp_user(db)

        r = await client.post("/api/auth/login", json={
            "email": user.email, "password": "originalpassword1",
        })
        assert r.status_code == 200
        challenge = r.json()["totp_session_token"]

        r = await client.post("/api/auth/totp/verify", json={
            "totp_session_token": challenge, "code": totp.now(),
        })
        assert r.status_code == 200
        assert "access_token" in r.json()

    async def test_the_challenge_actually_embeds_the_epoch_not_a_default(
        self, client, db, admin_token, monkeypatch
    ):
        """A user with a fresh epoch of 0 cannot distinguish "the claim was
        embedded and equals 0" from "the claim was never embedded and
        decode_totp_session_token's own default of 0 was used instead" —
        every other test above uses a freshly created user for exactly that
        reason, so none of them can tell the two apart. Bumping the epoch
        past 0 *before* issuing the challenge closes that gap: only a
        genuinely embedded, non-default value can match here.
        """
        monkeypatch.setattr(app_settings, "debug", False)
        user, totp = await self._totp_user(db)

        # Get the epoch to a non-zero, known value before the challenge this
        # test actually exercises is ever issued. A PATCH with an
        # admin-chosen password (rather than admin-reset's generated one) so
        # the login attempt below still has a password it knows.
        r = await client.patch(
            f"/api/users/{user.id}",
            json={"password": "a-known-new-password-11"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        await db.refresh(user)
        assert user.token_epoch > 0, "setup should have bumped the epoch"

        r = await client.post("/api/auth/login", json={
            "email": user.email, "password": "a-known-new-password-11",
        })
        assert r.status_code == 200
        challenge = r.json()["totp_session_token"]

        # No further reset here — the epoch this challenge was issued under
        # is still current, so it must succeed. If the epoch were never
        # embedded (decode falling back to its own default of 0), this
        # would be rejected as stale despite nothing having changed since
        # the challenge was issued.
        r = await client.post("/api/auth/totp/verify", json={
            "totp_session_token": challenge, "code": totp.now(),
        })
        assert r.status_code == 200, (
            "a challenge issued at a non-zero epoch, with no reset since, "
            "was rejected — the epoch embedded in the challenge does not "
            "match what totp_verify expects, or was never embedded at all"
        )

    async def test_a_challenge_token_with_a_malformed_epoch_claim_is_rejected_not_500(
        self, client, db
    ):
        """decode_totp_session_token's int(payload.get("epc", 0)) raised
        ValueError uncaught for a non-numeric claim — not a JWTError, since
        the token's signature is genuine (signed with the app's own secret
        key here, exactly like a real challenge). totp_verify's own guard
        (`if not decoded: raise HTTPException(401, ...)`) never ran, so
        this reached the client as an unhandled 500 instead of the
        documented "Invalid or expired session" response. See
        TestTotpSessionToken in test_security.py for the function-level
        coverage of the same defect — this is the HTTP-level consequence
        the finding was actually about.
        """
        from datetime import datetime

        from jose import jwt

        user, totp = await self._totp_user(db)

        malformed = jwt.encode(
            {
                "sub": str(user.id),
                "exp": datetime.now(UTC) + timedelta(minutes=5),
                "totp": True, "setup": False,
                "epc": "not-a-number",
            },
            app_settings.secret_key,
            algorithm=app_settings.algorithm,
        )

        r = await client.post("/api/auth/totp/verify", json={
            "totp_session_token": malformed, "code": totp.now(),
        })
        assert r.status_code == 401, (
            f"expected the documented 401 for an invalid session, got "
            f"{r.status_code} — a malformed claim inside a validly-signed "
            "token is reaching the client as an unhandled error"
        )
        assert "session" in r.json()["detail"].lower()


# ── New users get a welcome link instead of an admin-set password ─────────────

class TestWelcomeEmailOnRegister:
    """With self-service enabled, a new account is handed over by emailing the
    user a link to set their own password.

    Same principle as the admin reset: where the user can choose their own
    credential, none should pass through the admin — or through whatever chat
    message the admin would otherwise relay it in.
    """

    NEW_USER: ClassVar[dict[str, str]] = {
        "email": "newcomer@example.com",
        "display_name": "New Comer",
        "role": "viewer",
    }

    async def _register(self, client, admin_token, **overrides):
        return await client.post(
            "/api/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={**self.NEW_USER, **overrides},
        )

    async def test_sends_a_welcome_link_and_takes_no_password(
        self, client, db, admin_token, self_service_on, captured_emails
    ):
        r = await self._register(client, admin_token)
        assert r.status_code == 201

        assert len(captured_emails) == 1
        msg, recipients = captured_emails[0]
        assert recipients == [self.NEW_USER["email"]]
        assert "reset-password#token=" in msg.get_content()

    async def test_rejects_an_admin_supplied_password(
        self, client, admin_token, self_service_on, captured_emails
    ):
        """Rejected, not ignored — otherwise the API is a way around the UI's
        removal of the field, and the admin would believe they had set a
        password that in fact does nothing."""
        r = await self._register(client, admin_token, password="admin-chosen-pw")
        assert r.status_code == 400
        assert "welcome link" in r.json()["detail"]
        assert captured_emails == []

    async def test_the_new_account_has_no_usable_password(
        self, client, db, admin_token, self_service_on, captured_emails
    ):
        """The stored hash must be a random value nobody holds — the account
        is live from creation, so a blank or predictable one would be a way
        in."""
        await self._register(client, admin_token)
        user = (await db.execute(
            select(User).where(User.email == self.NEW_USER["email"])
        )).scalar_one()

        for guess in ("", "password", user.email, user.display_name):
            assert not verify_password(guess, user.hashed_password)

    async def test_welcome_link_sets_the_first_password(
        self, client, db, admin_token, self_service_on, captured_emails
    ):
        """End to end: created by an admin, signed in via the emailed link."""
        await self._register(client, admin_token)
        token = _token_from_email(captured_emails)

        r = await client.post(
            "/api/auth/reset-password",
            json={"token": token, "new_password": "chosen-by-the-user"},
        )
        assert r.status_code == 204

        user = (await db.execute(
            select(User).where(User.email == self.NEW_USER["email"])
        )).scalar_one()
        await db.refresh(user)
        assert verify_password("chosen-by-the-user", user.hashed_password)

    async def test_welcome_link_is_long_lived(
        self, client, db, admin_token, self_service_on, captured_emails
    ):
        """A new user may be onboarded before they start, or be on leave —
        the longest window of the three flows."""
        await self._register(client, admin_token)
        row = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().one()

        remaining_minutes = (row.expires_at - utcnow()).total_seconds() / 60
        assert remaining_minutes > ADMIN_RESET_TOKEN_TTL_MINUTES
        assert remaining_minutes > WELCOME_TOKEN_TTL_MINUTES - 5

    async def test_email_introduces_the_account_rather_than_reporting_a_change(
        self, client, admin_token, self_service_on, captured_emails
    ):
        """There is no previous password to mention — the reset wording would
        confuse someone who has never had an account."""
        await self._register(client, admin_token)
        body = captured_emails[-1][0].get_content()

        assert "created a PA Central account" in body
        assert "no longer works" not in body
        assert "you can ignore this email" not in body

    async def test_a_failed_send_does_not_roll_the_account_back(
        self, client, db, admin_token, self_service_on, monkeypatch
    ):
        """The welcome send is best-effort (see send_reset_email's own
        docstring for why): register() no longer deletes the account for
        any reason to doubt delivery, confirmed or otherwise. An earlier
        version tried to distinguish a confirmed SMTP failure from a merely
        unconfirmed one so it could still roll back on the former — that
        grew increasingly fragile (smtplib itself collapses some ambiguous
        disconnects into the same exception a clean one raises) for a
        decision a human admin is better placed to make: check whether the
        user actually got the email, and create a fresh account or trigger
        a reset once the situation is understood.
        """
        async def boom(self, msg, recipients, *, interactive=False):
            raise OSError("connection refused")

        monkeypatch.setattr("app.core.email.EmailService.send", boom)

        r = await self._register(client, admin_token)
        assert r.status_code == 201, (
            f"expected 201 (best-effort: the account survives a send "
            f"failure), got {r.status_code}"
        )
        assert r.json()["welcome_email_sent"] is False

        user = (await db.execute(
            select(User).where(User.email == self.NEW_USER["email"])
        )).scalar_one_or_none()
        assert user is not None, "the account was rolled back despite the best-effort model"

    async def test_a_timed_out_send_does_not_roll_the_account_back(
        self, client, db, admin_token, self_service_on, monkeypatch
    ):
        """EmailService.send's own overall deadline abandons the coroutine
        on timeout, not the underlying smtplib call — the message may
        still be sent and actually delivered afterward (see
        EmailService.send's own docstring). Whether this counts as
        "confirmed failed" or merely "unconfirmed" no longer matters here:
        register() treats both identically now, and the account survives
        either way.
        """
        async def times_out(self, msg, recipients, *, interactive=False):
            raise TimeoutError()

        monkeypatch.setattr("app.core.email.EmailService.send", times_out)

        r = await self._register(client, admin_token)
        assert r.status_code == 201
        assert r.json()["welcome_email_sent"] is False

        user = (await db.execute(
            select(User).where(User.email == self.NEW_USER["email"])
        )).scalar_one_or_none()
        assert user is not None, (
            "the account was deleted on a mere timeout — the welcome send "
            "may still have been delivered after this response, to an "
            "account that no longer existed"
        )

    async def test_welcome_email_sent_is_true_on_a_clean_send(
        self, client, db, admin_token, self_service_on, captured_emails
    ):
        r = await self._register(client, admin_token)
        assert r.status_code == 201
        assert r.json()["welcome_email_sent"] is True
        assert r.json()["welcome_link_still_valid"] is True

    async def test_welcome_email_sent_is_none_when_self_service_is_off(
        self, client, admin_token, smtp_configured, captured_emails
    ):
        """No email is ever attempted without self-service on — the field
        must not silently read as False (which would look like a failed
        send that never happened)."""
        r = await self._register(client, admin_token, password="admin-chosen-pw")
        assert r.status_code == 201
        assert r.json()["welcome_email_sent"] is None
        assert r.json()["welcome_link_still_valid"] is None

    async def test_a_concurrent_admin_deletion_returns_a_conflict_not_a_500(
        self, client, db, admin_token, self_service_on, monkeypatch
    ):
        """A concurrent admin DELETE /users/{id} racing the welcome send —
        simulated here by deleting the row from inside the monkeypatched
        send, using the same shared `db` session register() itself uses —
        leaves nothing for register()'s own existence check to find. This
        must surface as a clean 409, not an unhandled 500 from constructing
        a response around a row that no longer exists.
        """
        async def concurrent_admin_deletion(self, msg, recipients, *, interactive=False):
            user = (await db.execute(
                select(User).where(User.email == "newcomer@example.com")
            )).scalar_one()
            await db.delete(user)
            await db.commit()

        monkeypatch.setattr(
            "app.core.email.EmailService.send", concurrent_admin_deletion
        )

        r = await self._register(client, admin_token)
        assert r.status_code == 409, (
            f"expected 409 (the account was deleted by another admin while "
            f"the welcome send was in flight), got {r.status_code}"
        )

        user = (await db.execute(
            select(User).where(User.email == self.NEW_USER["email"])
        )).scalar_one_or_none()
        assert user is None, (
            "no account should exist — it was deleted by the concurrent "
            "admin action"
        )

    async def test_a_concurrent_settings_disable_reports_the_link_as_invalid(
        self, client, db, admin_token, self_service_on, monkeypatch
    ):
        """Disabling self-service reset (or clearing its SMTP config) while
        this send is in flight retires *every* outstanding token system-wide
        (api/system_settings.py's turning_off/losing_smtp sweep) without
        touching whether this specific email happened to send successfully
        — genuinely reachable as result.sent=True, result.still_live=False,
        with the account itself untouched. welcome_email_sent alone used to
        report this exactly like a clean, fully successful invite: the
        admin saw "invite emailed" with no signal that the link inside it
        was already dead by the time it arrived.

        The account still is not rolled back for this (best-effort, same
        as everywhere else in this class) — only the response's own
        warning signal changes.
        """
        async def disable_self_service_mid_send(self, msg, recipients, *, interactive=False):
            row = (await db.execute(
                select(SystemSetting).where(SystemSetting.key == "self_service_password_reset")
            )).scalar_one()
            row.value = "false"
            await db.execute(
                update(PasswordResetToken)
                .where(PasswordResetToken.used_at.is_(None))
                .values(used_at=utcnow())
            )
            await db.commit()

        monkeypatch.setattr(
            "app.core.email.EmailService.send", disable_self_service_mid_send
        )

        r = await self._register(client, admin_token)
        assert r.status_code == 201, (
            f"expected 201 (best-effort: the account survives), got {r.status_code}"
        )
        body = r.json()
        assert body["welcome_email_sent"] is True, (
            "the send itself did succeed and must still be reported as such"
        )
        assert body["welcome_link_still_valid"] is False, (
            "the token was swept by the concurrent disable, but the "
            "response gave no signal that the just-sent link is already dead"
        )

        user = (await db.execute(
            select(User).where(User.email == self.NEW_USER["email"])
        )).scalar_one_or_none()
        assert user is not None, "the account must survive — this is not destructive"

    async def test_password_is_still_required_when_self_service_is_off(
        self, client, admin_token, smtp_configured, captured_emails
    ):
        """No SMTP, no link — the admin must supply a credential, as before."""
        missing = await self._register(client, admin_token)
        assert missing.status_code == 400
        assert "password is required" in missing.json()["detail"]

        ok = await self._register(client, admin_token, password="admin-chosen-pw")
        assert ok.status_code == 201
        assert captured_emails == []

    async def test_a_stored_from_addr_containing_crlf_requires_a_password_instead_of_500ing(
        self, client, db, admin_token, self_service_on, captured_emails
    ):
        """build_password_reset_email (core/email.py) assigns smtp_from
        straight to EmailMessage()["From"] — Python's own email module
        raises ValueError for a value containing a carriage return or line
        feed, and that assignment happens after the new user row has
        already been committed. self_service_reset_enabled() now refuses
        this configuration up front, so register() treats it exactly like
        self-service being off entirely: a password is required, and no
        welcome link is ever attempted. Reproduced directly before this
        fix: the new user row committed, then an unhandled 500 with no
        way to complete or retry the registration cleanly (a subsequent
        attempt hit 409 Email already registered against the orphaned
        row).
        """
        await _set(db, "smtp_from", "pa\r\nBcc: evil@example.com")

        missing = await self._register(client, admin_token)
        assert missing.status_code == 400, (
            f"expected the documented 'password is required' response, got "
            f"{missing.status_code} — a malicious smtp_from crashed "
            "registration instead of the feature reporting itself "
            "unavailable up front"
        )
        assert "password is required" in missing.json()["detail"]

        ok = await self._register(client, admin_token, password="admin-chosen-pw-1")
        assert ok.status_code == 201
        assert captured_emails == []

    async def test_duplicate_email_still_conflicts(
        self, client, admin_token, self_service_on, reset_user, captured_emails
    ):
        r = await self._register(client, admin_token, email=reset_user.email)
        assert r.status_code == 409
        assert captured_emails == []


class TestRegisterAgreesWithSelfServiceGate:
    """register() decides whether to demand a welcome link (and reject any
    admin-supplied password) by consulting self_service_reset_enabled() —
    the same flag GET /password-reset-config reports. If that flag lies
    about whether a welcome link can actually be sent, register() acts on
    the lie: it forces the welcome-link path, issuance then fails for the
    exact reason the flag should have already reflected, and the whole
    account creation rolls back with a 502 — an admin who could have simply
    supplied a password was told not to, then told account creation failed
    anyway. Reproduced directly: with a non-empty but malformed
    app_base_url, self_service_reset_enabled() returned True.
    """

    async def test_register_allows_a_password_when_the_base_url_is_malformed(
        self, client, db, admin_token
    ):
        await _set(db, "smtp_host", "smtp.example.com")
        await _set(db, "app_base_url", "ftp://pa.example.com")
        await _set(db, "self_service_password_reset", "true", SettingValueType.bool)

        r = await client.post(
            "/api/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "email": "newcomer2@example.com", "display_name": "New Comer 2",
                "role": "viewer", "password": "admin-chosen-password-11",
            },
        )
        assert r.status_code == 201, (
            f"registration was refused a password despite the welcome-link "
            f"path being unusable: {r.text}"
        )

    async def test_register_does_not_promise_a_welcome_link_it_cannot_send(
        self, client, db, admin_token, captured_emails
    ):
        """Without the fix, omitting the password here (as the broken gate
        would have demanded) leads to a 502 and a rolled-back account —
        this asserts the account is created successfully instead, which is
        only possible because register() correctly saw the feature as
        unusable and required a password."""
        await _set(db, "smtp_host", "smtp.example.com")
        await _set(db, "app_base_url", "https://pa.example.com?next=/x")
        await _set(db, "self_service_password_reset", "true", SettingValueType.bool)

        r = await client.post(
            "/api/auth/register",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "email": "newcomer3@example.com", "display_name": "New Comer 3",
                "role": "viewer", "password": "admin-chosen-password-11",
            },
        )
        assert r.status_code == 201
        assert captured_emails == []


# ── Disabling the feature revokes outstanding links ───────────────────────────

class TestDisablingRevokesOutstandingLinks:
    """Switching self-service reset off retires outstanding tokens.

    The endpoint no longer refuses links while the feature is off — that
    stranded users whose password was already invalidated. Revocation has to
    happen at the point of disabling instead, and it has to be a real write:
    the old gate left the rows live, so re-enabling the setting revived every
    link that had been refused in the meantime.
    """

    async def _patch(self, client, admin_token, updates):
        return await client.patch(
            "/api/system-settings",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"updates": updates},
        )

    async def test_turning_it_off_retires_outstanding_links(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        link = _token_from_email(captured_emails)

        r = await self._patch(
            client, admin_token, {"self_service_password_reset": "false"}
        )
        assert r.status_code == 200

        live = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().all()
        assert live == [], "outstanding links were left live"

        used = await client.post(
            "/api/auth/reset-password",
            json={"token": link, "new_password": "a-brand-new-password"},
        )
        assert used.status_code == 400

    async def test_re_enabling_does_not_revive_revoked_links(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """The failure the old gate had: refusing a link without retiring it
        meant the same link worked again the moment the setting came back."""
        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        link = _token_from_email(captured_emails)

        await self._patch(client, admin_token, {"self_service_password_reset": "false"})
        await self._patch(client, admin_token, {"self_service_password_reset": "true"})

        r = await client.post(
            "/api/auth/reset-password",
            json={"token": link, "new_password": "a-brand-new-password"},
        )
        assert r.status_code == 400, "a revoked link was revived by re-enabling"

    async def test_clearing_the_smtp_host_also_revokes(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """self_service_reset_enabled() treats a missing host as off, so
        clearing it is the same revocation by another route."""
        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        link = _token_from_email(captured_emails)

        r = await self._patch(
            client, admin_token,
            {"smtp_host": "", "self_service_password_reset": "false"},
        )
        assert r.status_code == 200

        used = await client.post(
            "/api/auth/reset-password",
            json={"token": link, "new_password": "a-brand-new-password"},
        )
        assert used.status_code == 400

    async def test_an_unrelated_settings_save_does_not_revoke(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """Revocation must be tied to actually disabling the feature — an
        unrelated edit must not silently kill a user's pending link."""
        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        link = _token_from_email(captured_emails)

        r = await self._patch(client, admin_token, {"smtp_from": "new@example.com"})
        assert r.status_code == 200

        used = await client.post(
            "/api/auth/reset-password",
            json={"token": link, "new_password": "a-brand-new-password"},
        )
        assert used.status_code == 204

    async def test_changing_the_app_base_url_also_revokes(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """consume_reset_token takes only the raw token hash — redemption is
        not bound to which app_base_url the link was originally built
        against (build_reset_url embeds the token in the URL *fragment*,
        never sent to any server, but still readable by whatever page
        loads at that address). If app_base_url is later changed — rotating
        domains, correcting a typo, moving environments — every link
        already emailed still points at the *old* address and is still
        redeemable against this deployment regardless. Should that old
        origin ever be retired or fall under someone else's control, its
        own JavaScript could read the token out of the fragment and redeem
        it here. Changing the URL must therefore retire outstanding tokens
        exactly like turning the feature off or losing SMTP does.
        """
        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        link = _token_from_email(captured_emails)

        r = await self._patch(
            client, admin_token, {"app_base_url": "https://new.pa.example.com"},
        )
        assert r.status_code == 200

        live = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().all()
        assert live == [], "a link built for the old app_base_url was left live"

        used = await client.post(
            "/api/auth/reset-password",
            json={"token": link, "new_password": "a-brand-new-password"},
        )
        assert used.status_code == 400

    async def test_resubmitting_the_same_app_base_url_does_not_revoke(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """The frontend always resubmits every field's current value on
        save, not just the ones the admin actually edited — the same
        resubmission-noise concern turning_off/losing_smtp already guard
        against for their own fields. Resubmitting the identical
        app_base_url alongside an unrelated change must not revoke a link
        that has nothing to do with either field."""
        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        link = _token_from_email(captured_emails)

        r = await self._patch(
            client, admin_token,
            {"app_base_url": "https://pa.example.com", "smtp_from": "new@example.com"},
        )
        assert r.status_code == 200

        used = await client.post(
            "/api/auth/reset-password",
            json={"token": link, "new_password": "a-brand-new-password"},
        )
        assert used.status_code == 204

    async def test_clearing_smtp_host_while_reset_is_already_off_does_not_touch_its_timestamp(
        self, client, db, admin_token
    ):
        """The sweep lock on self_service_password_reset self-assigns
        value_type to itself, believing that touches nothing else. It does:
        SystemSetting.updated_at has onupdate=utcnow, and SQLAlchemy applies
        a column's Python-side onupdate default to any Core update()
        statement on that table regardless of which columns are named in
        .values() — self-assigning a *different* column does not exempt
        updated_at from it. With the setting already off, clearing
        smtp_host takes this same lock via the losing_smtp branch purely to
        keep issuance and disabling ordered against each other — it must
        not silently rewrite an audit timestamp for a setting this request
        never actually changed. prepare_reset_email's own copy of this lock
        (services/password_reset.py) hit the identical bug; both are fixed
        the same way, with raw SQL bypassing the ORM's onupdate machinery.
        """
        await _set(db, "self_service_password_reset", "false", SettingValueType.bool)
        await _set(db, "smtp_host", "smtp.example.com")

        row = await db.get(SystemSetting, "self_service_password_reset")
        original_updated_at = row.updated_at

        r = await self._patch(client, admin_token, {"smtp_host": ""})
        assert r.status_code == 200

        await db.refresh(row)
        assert row.updated_at == original_updated_at, (
            "clearing smtp_host while self_service_password_reset was "
            "already off rewrote that unrelated setting's updated_at — the "
            "sweep lock is supposed to be a no-op write, not an "
            "audit-trail mutation"
        )

    async def test_resubmitting_the_already_off_flag_alongside_an_unrelated_change_does_not_revoke(
        self, client, db, admin_token, reset_user
    ):
        """turning_off used to fire whenever `self_service_password_reset`
        was present in the request body and its submitted value was false —
        with no check that the *stored* value had actually been true
        before. SystemSettings.tsx always resubmits the current checkbox
        state on every save (a bool is never "unset" from the UI's point of
        view), so with the feature already off, saving something entirely
        unrelated — retention days here — still included
        self_service_password_reset: "false" in the PATCH body and swept
        every outstanding token, including ones with nothing to do with the
        fields the admin thought they were changing. Distinct from
        test_an_unrelated_settings_save_does_not_revoke above, which never
        mentions self_service_password_reset in its own request at all —
        this test specifically covers the case where it's resubmitted
        alongside genuinely unrelated changes, matching how this project's
        own frontend actually builds every save request.
        """
        # self_service_password_reset already off (default: absent/no row).
        # A token seeded directly, independent of forgot_password (which
        # only issues one when self-service is enabled) — an admin-reset or
        # welcome token would have committed the same way, and the sweep
        # doesn't filter by kind.
        await _set(db, "smtp_host", "smtp.example.com")
        user_id = reset_user.id
        token = PasswordResetToken(
            token_hash="f" * 64, user_id=user_id,
            created_at=utcnow(), expires_at=utcnow() + timedelta(hours=1),
        )
        db.add(token)
        await db.commit()

        r = await self._patch(client, admin_token, {
            "finding_retention_days": "400",
            "self_service_password_reset": "false",
        })
        assert r.status_code == 200

        await db.refresh(token)
        assert token.used_at is None, (
            "an unrelated save that merely resubmitted the already-off "
            "flag retired a token that had nothing to do with this request"
        )

    async def test_resubmitting_an_already_empty_smtp_host_does_not_revoke(
        self, client, db, admin_token, reset_user
    ):
        """Same gap as the flag itself, for losing_smtp: resubmitting
        smtp_host="" when it was already empty must not count as clearing
        it. Any client that always includes an unchanged empty field in its
        PATCH body — not only this project's own frontend, which omits
        untouched keys but would hit this if a future edit ever resubmitted
        an empty smtp_host alongside other changes — must not retire tokens
        it never actually affected."""
        # self_service_password_reset and smtp_host both already off/empty.
        user_id = reset_user.id
        token = PasswordResetToken(
            token_hash="9" * 64, user_id=user_id,
            created_at=utcnow(), expires_at=utcnow() + timedelta(hours=1),
        )
        db.add(token)
        await db.commit()

        r = await self._patch(client, admin_token, {
            "finding_retention_days": "400",
            "smtp_host": "",
        })
        assert r.status_code == 200

        await db.refresh(token)
        assert token.used_at is None, (
            "resubmitting an already-empty smtp_host retired a token that "
            "had nothing to do with this request"
        )

    async def test_a_genuine_transition_still_revokes_even_alongside_an_unrelated_change(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """The fix above must not overcorrect into never sweeping when a
        request genuinely changes both an unrelated field and the flag in
        the same PATCH."""
        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        link = _token_from_email(captured_emails)

        r = await self._patch(client, admin_token, {
            "finding_retention_days": "400",
            "self_service_password_reset": "false",
        })
        assert r.status_code == 200

        used = await client.post(
            "/api/auth/reset-password",
            json={"token": link, "new_password": "a-brand-new-password"},
        )
        assert used.status_code == 400, (
            "a genuine on-to-off transition, bundled with an unrelated "
            "change in the same request, failed to revoke outstanding links"
        )

    async def test_a_typo_in_the_flag_does_not_revoke_outstanding_links(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """An earlier version canonicalised any unrecognised value for
        self_service_password_reset to "false" and accepted it with 200 —
        so a typo such as "tru" was stored as false and, because the
        feature was genuinely on, also satisfied turning_off, revoking
        every outstanding link on a request that both looked successful
        and did not do what the admin intended (leave the flag on, or
        even turn it further on). Fixed by rejecting any value outside
        the documented true/false forms with 400 instead of silently
        treating it as false."""
        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        link = _token_from_email(captured_emails)

        r = await self._patch(
            client, admin_token, {"self_service_password_reset": "tru"}
        )
        assert r.status_code == 400

        used = await client.post(
            "/api/auth/reset-password",
            json={"token": link, "new_password": "a-brand-new-password"},
        )
        assert used.status_code == 204, (
            "a typo in the flag revoked an outstanding link instead of "
            "being rejected outright"
        )

    async def test_was_reset_on_is_read_under_the_lock_not_before_it(self, tmp_path):
        """was_reset_on/had_smtp_host used to be read *before*
        patch_settings acquired its settings-row lock, with the lock only
        taken later, gated on turning_off/losing_smtp — which are
        themselves computed from that unlocked read. That is circular: a
        concurrent request that commits an enable + issues a token in the
        gap between this request's unlocked read and its own later write
        is invisible to it. Concretely: request A reads
        self_service_password_reset as already false, is delayed;
        request B enables the feature and commits a fresh token; A resumes
        and writes false again — a real true-to-false transition just
        happened, but A's stale pre-lock snapshot never saw the "true" and
        skipped revocation. Fixed by acquiring the lock unconditionally at
        the very top of patch_settings, before was_reset_on/had_smtp_host
        are read at all.

        Deterministic proof, not asyncio.gather (same reasoning as the
        other lock tests in this file): a genuinely separate raw
        connection takes BEGIN IMMEDIATE on the settings row first.
        patch_settings itself (not a hand-written mirror of its logic —
        that would only prove the mirror is correct, not the real
        function) is launched as a background task and confirmed still
        blocked before the holder does anything further. The holder then
        — while still holding the lock — enables the feature and commits
        a fresh token, simulating exactly the concurrent request B
        represents, before finally releasing the lock. If the fix holds,
        patch_settings can only proceed once B's commit is already
        visible, sees a real true-to-false transition, and must therefore
        revoke B's token; the pre-fix code read before ever taking a
        lock, so it would already have computed its (stale) turning_off
        long before B's commit even happened, and left the token live.
        """
        import sqlalchemy as sa
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        from app.api.system_settings import patch_settings
        from app.core.database import Base, sqlite_on_checkin, sqlite_on_connect
        from app.schemas import SystemSettingPatch

        url = f"sqlite+aiosqlite:///{tmp_path}/stale_snapshot.db"
        engine = create_async_engine(url, connect_args={"check_same_thread": False})
        event.listens_for(engine.sync_engine, "connect")(sqlite_on_connect)
        event.listens_for(engine.sync_engine, "checkin")(sqlite_on_checkin)
        holder_engine = create_async_engine(url, connect_args={"check_same_thread": False})
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(engine, expire_on_commit=False)

            async with factory() as s:
                admin = User(
                    email="stale-snapshot-admin@example.com", display_name="Admin",
                    hashed_password=hash_password("password123456"),
                    role=UserRole.admin, is_active=True,
                )
                target = User(
                    email="stale-snapshot@example.com", display_name="Stale Snapshot",
                    hashed_password=hash_password("password123456"),
                    role=UserRole.viewer, is_active=True,
                )
                s.add(admin)
                s.add(target)
                s.add(SystemSetting(
                    key="self_service_password_reset", value="false",
                    value_type=SettingValueType.bool,
                ))
                await s.commit()
                admin_id, target_id = admin.id, target.id

            # Held before patch_settings starts, so its own lock
            # acquisition must wait on this connection releasing it.
            holder = holder_engine.connect()
            conn = await holder.start()
            await conn.execute(sa.text("BEGIN IMMEDIATE"))

            async def run_patch_settings():
                async with factory() as s:
                    admin = await s.get(User, admin_id)
                    # Resubmits the current (at-request-time) false value —
                    # exactly the shape SystemSettings.tsx always sends.
                    body = SystemSettingPatch(updates={"self_service_password_reset": "false"})
                    return await patch_settings(body, s, admin)

            patch_task = asyncio.create_task(run_patch_settings())
            await asyncio.sleep(0.2)
            assert not patch_task.done(), (
                "patch_settings completed before the lock was even "
                "released — it is not actually waiting on the held "
                "connection, so this test cannot prove anything about "
                "the fix"
            )

            # While still holding the lock: enable the feature and issue a
            # token, exactly what a concurrent request B represents.
            await conn.execute(
                sa.text(
                    "UPDATE system_settings SET value = 'true' "
                    "WHERE key = :key"
                ),
                {"key": "self_service_password_reset"},
            )
            await conn.execute(
                sa.text(
                    "INSERT INTO password_reset_tokens "
                    "(token_hash, user_id, created_at, expires_at, used_at, kind) "
                    "VALUES (:h, :uid, :c, :e, NULL, 'admin')"
                ),
                {
                    # ISO strings, not datetime objects: this raw sa.text()
                    # bind goes straight to aiosqlite/sqlite3's own
                    # parameter binding, bypassing SQLAlchemy's column-type
                    # bind-processing (UtcDateTime/DateTime) that the ORM
                    # path uses everywhere else — sqlite3's own default
                    # datetime adapter is deprecated as of Python 3.12 and
                    # warns on every raw datetime object passed as a param.
                    # SQLite's DateTime comparisons are lexicographic, so an
                    # ISO 8601 string sorts identically to the datetime it
                    # represents — nothing downstream needs the object form.
                    "h": "b" * 64, "uid": target_id,
                    "c": utcnow().isoformat(), "e": (utcnow() + timedelta(hours=1)).isoformat(),
                },
            )
            await conn.commit()

            try:
                await asyncio.wait_for(patch_task, timeout=5.0)
            except TimeoutError:
                pytest.fail(
                    "patch_settings did not complete within 5s of the "
                    "lock being released — it is stuck rather than "
                    "proceeding"
                )

            async with factory() as s:
                row = (await s.execute(
                    sa.select(PasswordResetToken).where(
                        PasswordResetToken.token_hash == "b" * 64
                    )
                )).scalar_one()
            assert row.used_at is not None, (
                "the token committed by a concurrent request while "
                "patch_settings was blocked on the lock was not revoked — "
                "patch_settings read stale pre-lock state (the flag "
                "still 'false') instead of waiting for the lock to "
                "actually clear the concurrent 'true'"
            )
        finally:
            await holder.close()
            await holder_engine.dispose()
            await engine.dispose()


# ── A password change invalidates outstanding links ───────────────────────────

class TestPasswordChangeRetiresOutstandingLinks:
    """Every path that changes a password must retire outstanding reset links.

    Token usability is decided by `used_at` and expiry alone, so a link issued
    beforehand stays valid afterwards. Reproduced end to end: a link was
    issued, the user changed their password via PATCH /users/{id}, and the
    stale link then returned 204 and replaced the credential they had just
    chosen — a full account takeover from a link that was never used.

    Account *creation* paths (register, the bootstrap admin) are exempt by
    construction: no user exists yet, so there can be no outstanding token.
    """

    async def _issue_link(self, client, email: str, captured_emails) -> str:
        await client.post("/api/auth/forgot-password", json={"email": email})
        return _token_from_email(captured_emails)

    async def _use_link(self, client, token: str, password: str = "a-brand-new-password"):
        return await client.post(
            "/api/auth/reset-password",
            json={"token": token, "new_password": password},
        )

    async def test_self_service_change_via_patch_retires_the_link(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        stale = await self._issue_link(client, reset_user.email, captured_emails)

        token = create_access_token(reset_user.id, reset_user.token_epoch)
        r = await client.patch(
            f"/api/users/{reset_user.id}",
            json={"password": "user-chosen-password"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200

        assert (await self._use_link(client, stale)).status_code == 400

        await db.refresh(reset_user)
        assert verify_password("user-chosen-password", reset_user.hashed_password), (
            "the stale link overwrote the password the user chose"
        )

    async def test_admin_change_via_patch_retires_the_link(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        stale = await self._issue_link(client, reset_user.email, captured_emails)

        r = await client.patch(
            f"/api/users/{reset_user.id}",
            json={"password": "admin-set-password"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200

        assert (await self._use_link(client, stale)).status_code == 400

        await db.refresh(reset_user)
        assert verify_password("admin-set-password", reset_user.hashed_password)

    async def test_generated_password_fallback_retires_the_link(
        self, client, db, admin_token, smtp_configured, reset_user, captured_emails
    ):
        """The no-SMTP path returns a password for the admin to relay. A link
        issued while self-service was on must not survive it."""
        # Issue a link while the feature is on, then turn it off so the admin
        # endpoint takes the generated-password branch.
        await _set(db, "self_service_password_reset", "true", SettingValueType.bool)
        stale = await self._issue_link(client, reset_user.email, captured_emails)
        await _set(db, "self_service_password_reset", "false", SettingValueType.bool)

        r = await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert r.status_code == 200
        generated = r.json()["password"]
        assert generated

        # Turn it back on so the reset endpoint is reachable at all.
        await _set(db, "self_service_password_reset", "true", SettingValueType.bool)
        assert (await self._use_link(client, stale)).status_code == 400

        await db.refresh(reset_user)
        assert verify_password(generated, reset_user.hashed_password), (
            "the stale link overwrote the password relayed to the user"
        )

    async def test_completing_a_reset_retires_other_outstanding_links(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """An admin reset issued while a self-service link is outstanding
        leaves the newer one live; using it must kill the older one too."""
        public_link = await self._issue_link(client, reset_user.email, captured_emails)
        await client.post(
            f"/api/users/{reset_user.id}/reset-password",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        admin_link = _token_from_email(captured_emails)

        assert (await self._use_link(client, admin_link, "chosen-by-the-user")).status_code == 204
        assert (await self._use_link(client, public_link, "ATTACKER-CHOSEN")).status_code == 400

        await db.refresh(reset_user)
        assert verify_password("chosen-by-the-user", reset_user.hashed_password)

    async def test_no_live_tokens_remain_after_a_password_change(
        self, client, db, self_service_on, reset_user, captured_emails
    ):
        """The invariant behind all of the above, asserted directly."""
        await self._issue_link(client, reset_user.email, captured_emails)

        token = create_access_token(reset_user.id, reset_user.token_epoch)
        await client.patch(
            f"/api/users/{reset_user.id}",
            json={"password": "user-chosen-password"},
            headers={"Authorization": f"Bearer {token}"},
        )

        live = (await db.execute(
            select(PasswordResetToken).where(PasswordResetToken.used_at.is_(None))
        )).scalars().all()
        assert live == []

    async def test_a_change_does_not_retire_another_users_links(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """Retirement is per account — one user changing their password must
        not invalidate anyone else's pending link."""
        other = User(
            email="bystander@example.com", display_name="Bystander",
            hashed_password=hash_password("originalpassword"),
            role=UserRole.viewer, is_active=True,
        )
        db.add(other)
        await db.commit()

        bystander_link = await self._issue_link(client, other.email, captured_emails)

        await client.patch(
            f"/api/users/{reset_user.id}",
            json={"password": "unrelated-change"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

        assert (await self._use_link(client, bystander_link)).status_code == 204


# ── Settings gating: the flag requires an SMTP host ───────────────────────────

class TestSelfServiceSettingGating:
    async def _patch(self, client, admin_token, updates):
        return await client.patch(
            "/api/system-settings",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"updates": updates},
        )

    async def test_cannot_enable_without_smtp_host(self, client, admin_token):
        r = await self._patch(client, admin_token, {"self_service_password_reset": "true"})
        assert r.status_code == 400
        assert "SMTP host" in r.json()["detail"]

    async def test_can_enable_when_smtp_host_already_stored(self, client, admin_token, smtp_configured):
        r = await self._patch(client, admin_token, {"self_service_password_reset": "true"})
        assert r.status_code == 200

    async def test_can_enable_and_set_smtp_host_in_one_request(self, client, admin_token):
        """The guard must read the body, not just the stored row — otherwise
        configuring SMTP and enabling the flag together would be rejected."""
        r = await self._patch(client, admin_token, {
            "smtp_host": "smtp.example.com",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        })
        assert r.status_code == 200

    async def test_cannot_enable_while_clearing_smtp_host(self, client, admin_token, smtp_configured):
        """Clearing SMTP in the same PATCH that enables the flag must fail,
        even though a host is currently stored."""
        r = await self._patch(client, admin_token, {
            "smtp_host": "",
            "self_service_password_reset": "true",
        })
        assert r.status_code == 400

    async def test_cannot_enable_without_an_app_base_url(
        self, client, db, admin_token
    ):
        """A reset link needs somewhere to point. Without this the feature
        enabled cleanly and then emailed links to the Vite dev origin —
        unusable on any real deployment, and destructive on the admin path,
        which invalidates the password before sending."""
        await _set(db, "smtp_host", "smtp.example.com")

        r = await self._patch(
            client, admin_token, {"self_service_password_reset": "true"}
        )
        assert r.status_code == 400
        assert "App Base URL" in r.json()["detail"]

    async def test_can_enable_with_smtp_and_base_url_in_one_request(
        self, client, admin_token
    ):
        r = await self._patch(client, admin_token, {
            "smtp_host": "smtp.example.com",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        })
        assert r.status_code == 200

    async def test_cannot_enable_while_clearing_the_app_base_url(
        self, client, db, admin_token, smtp_configured
    ):
        r = await self._patch(client, admin_token, {
            "app_base_url": "",
            "self_service_password_reset": "true",
        })
        assert r.status_code == 400
        assert "App Base URL" in r.json()["detail"]

    @pytest.mark.parametrize("bad_port", ["not-a-port", "0", "-1", "65536", "999999"])
    async def test_cannot_enable_with_an_unusable_port_in_the_same_request(
        self, client, admin_token, bad_port
    ):
        """self_service_reset_enabled() (core/smtp_settings.py) refuses the
        feature when smtp_port is not a usable TCP port — this gate did not
        check it at all, so a PATCH like this one used to succeed while the
        config endpoint immediately reported the feature unavailable.
        Reproduced directly before this fix: status 200 here, followed by
        GET /password-reset-config reporting self_service_enabled: false.
        """
        r = await self._patch(client, admin_token, {
            "smtp_host": "smtp.example.com",
            "app_base_url": "https://pa.example.com",
            "smtp_port": bad_port,
            "self_service_password_reset": "true",
        })
        assert r.status_code == 400
        assert "SMTP port" in r.json()["detail"]

    async def test_cannot_enable_while_an_unusable_port_is_already_stored(
        self, client, db, admin_token, smtp_configured
    ):
        """The same gap, but for a port that reached storage some other way
        (a legacy row, a restore, a direct edit) rather than through this
        request — _effective() must read the stored value, not just the
        submitted one, exactly as it already does for smtp_host and
        app_base_url."""
        await _set(db, "smtp_port", "not-a-port", SettingValueType.int)

        r = await self._patch(
            client, admin_token, {"self_service_password_reset": "true"}
        )
        assert r.status_code == 400
        assert "SMTP port" in r.json()["detail"]

    async def test_cannot_enable_while_an_unusable_tls_mode_is_already_stored(
        self, client, db, admin_token, smtp_configured
    ):
        """The same gap as smtp_port above, for smtp_tls_mode: the
        per-key validation in the update loop only inspects keys present
        in *this* request's body, so a bad tls_mode already stored some
        other way (a legacy row, a restore, a direct edit, or simply one
        set before this validation existed) let this gate report 200 for
        a PATCH that only touched self_service_password_reset, while
        self_service_reset_enabled() immediately reported the feature
        unavailable. Reproduced directly before this fix."""
        await _set(db, "smtp_tls_mode", "start-tls")

        r = await self._patch(
            client, admin_token, {"self_service_password_reset": "true"}
        )
        assert r.status_code == 400
        assert "TLS mode" in r.json()["detail"]

    async def test_a_padded_stored_tls_mode_can_still_enable(
        self, client, db, admin_token, smtp_configured
    ):
        """_effective() strips whitespace before calling
        parse_smtp_tls_mode() at PATCH time, so a stored " starttls "
        (leading/trailing whitespace from a legacy row or a direct edit)
        used to pass this gate — but parse_smtp_tls_mode() itself did not
        strip, so self_service_reset_enabled() (the same function, called
        unstripped at read time) rejected the identical value. PATCH
        returned 200; the very next GET /password-reset-config reported
        the feature unavailable. Fixed by stripping inside
        parse_smtp_tls_mode() itself, so every caller normalises
        identically rather than only the ones that remember to strip
        first. Reproduced directly before this fix."""
        await _set(db, "smtp_tls_mode", " starttls ")

        r = await self._patch(
            client, admin_token, {"self_service_password_reset": "true"}
        )
        assert r.status_code == 200

        r2 = await client.get("/api/auth/password-reset-config")
        assert r2.json()["self_service_enabled"] is True

    async def test_cannot_enable_while_an_unusable_from_addr_is_already_stored(
        self, client, db, admin_token, smtp_configured
    ):
        """The same gap as smtp_port/smtp_tls_mode above, for smtp_from:
        a value containing CR/LF already stored some other way let this
        gate report 200 for a PATCH that only touched
        self_service_password_reset, while self_service_reset_enabled()
        immediately reported the feature unavailable — and the very next
        real reset attempt would have raised an uncaught ValueError deep
        inside issuance (see TestSmtpFromAddrIsValidated in
        test_email.py). Reproduced directly before this fix."""
        await _set(db, "smtp_from", "pa\r\nBcc: evil@example.com")

        r = await self._patch(
            client, admin_token, {"self_service_password_reset": "true"}
        )
        assert r.status_code == 400
        assert "From address" in r.json()["detail"]

    async def test_can_enable_with_a_valid_stored_tls_mode_and_from_addr(
        self, client, db, admin_token, smtp_configured
    ):
        """Positive control for the two checks above: _effective() must
        read a good stored value through, not just reject a bad one."""
        await _set(db, "smtp_tls_mode", "ssl")
        await _set(db, "smtp_from", "pa-central@example.com")

        r = await self._patch(
            client, admin_token, {"self_service_password_reset": "true"}
        )
        assert r.status_code == 200

    async def test_can_enable_with_smtp_port_absent(
        self, client, admin_token
    ):
        """smtp_port has a usable default (587) — not configuring it at all
        must not block enabling the feature, the same as any other field
        with a default."""
        r = await self._patch(client, admin_token, {
            "smtp_host": "smtp.example.com",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        })
        assert r.status_code == 200

    async def test_can_enable_with_a_valid_port_in_the_same_request(
        self, client, admin_token
    ):
        r = await self._patch(client, admin_token, {
            "smtp_host": "smtp.example.com",
            "app_base_url": "https://pa.example.com",
            "smtp_port": "2525",
            "self_service_password_reset": "true",
        })
        assert r.status_code == 200

    @pytest.mark.parametrize(
        "bad_url",
        [
            "ftp://pa.example.com",
            "pa.example.com",
            "https://",
            "://x",
            # A query or fragment lands before the appended path, so the
            # reset route and token are swallowed into it.
            "https://pa.example.com/#home",
            "https://pa.example.com#frag",
            "https://pa.example.com/?a=b",
            "https://pa.example.com?next=/x",
            # urlparse validates the port lazily — it succeeds on all of
            # these and only raises when .port is read, so without forcing
            # that read they pass and produce unopenable links.
            "https://pa.example.com:notaport",
            "https://pa.example.com:99999",
            "https://pa.example.com:-1",
            "https://pa.example.com:0",
            # A non-root path: build_reset_url appends "/reset-password"
            # directly onto this value, so "/settings" becomes
            # ".../settings/reset-password" — syntactically valid, but the
            # frontend's router (App.tsx) only registers "/reset-password"
            # at the root, so this falls through the catch-all route and
            # redirects to "/" before the recipient's link can ever be used.
            "https://pa.example.com/settings",
            "https://pa.example.com/a/b/c",
            # A valid scheme, but urlparse still returns a non-empty
            # "hostname" containing the literal space — ipaddress.ip_address()
            # then raises (not an IP literal) and the fallback treated this
            # exactly like an ordinary hostname. Confirmed unreachable:
            # socket.getaddrinfo("not a url", 443) fails outright.
            "https://not a url",
        ],
    )
    async def test_rejects_a_malformed_app_base_url(
        self, client, db, admin_token, bad_url
    ):
        """A non-http(s) scheme or a missing host produces a link the
        recipient cannot open, in any environment."""
        await _set(db, "smtp_host", "smtp.example.com")

        r = await self._patch(client, admin_token, {
            "app_base_url": bad_url,
            "self_service_password_reset": "true",
        })
        assert r.status_code == 400
        assert "not a usable public address" in r.json()["detail"]

    @pytest.mark.parametrize(
        "loopback_url",
        [
            "http://localhost:5173",
            "http://127.0.0.1:8000",
            "http://0.0.0.0:8000",
            "http://LOCALHOST:3000",
            # An exact-string set only ever covers 127.0.0.1 — the whole
            # 127.0.0.0/8 range is loopback, not just that one address.
            # Reproduced directly against the old set: both passed as
            # "public" in production.
            "http://127.0.0.2:8000",
            "http://127.1.2.3:8000",
            # Non-canonical IPv6 spellings of the same loopback/unspecified
            # addresses an exact-string set only matches in one canonical
            # form ("::1", not "0:0:0:0:0:0:0:1"; "::" is unspecified, not
            # loopback, but must be rejected the same way).
            "http://[0:0:0:0:0:0:0:1]:8000",
            "http://[0000:0000:0000:0000:0000:0000:0000:0001]:8000",
            "http://[::]:8000",
            "http://[0000::]:8000",
        ],
    )
    async def test_rejects_a_loopback_app_base_url_in_production(
        self, client, db, admin_token, loopback_url, monkeypatch
    ):
        """A loopback address is only reachable on the machine running the
        server, so in production it produces a link nobody who receives the
        email can open.

        The suite runs under DEBUG, where loopback is deliberately allowed —
        so this has to turn DEBUG off explicitly, or it would assert nothing.
        """
        monkeypatch.setattr(app_settings, "debug", False)
        await _set(db, "smtp_host", "smtp.example.com")

        r = await self._patch(client, admin_token, {
            "app_base_url": loopback_url,
            "self_service_password_reset": "true",
        })
        assert r.status_code == 400
        assert "not a usable public address" in r.json()["detail"]
        assert "DEBUG" in r.json()["detail"]

    @pytest.mark.parametrize(
        "loopback_url",
        [
            "http://localhost:5173",
            "http://127.0.0.1:8000",
            "http://127.0.0.2:8000",
            "http://[0:0:0:0:0:0:0:1]:8000",
        ],
    )
    async def test_allows_a_loopback_app_base_url_under_debug(
        self, client, db, admin_token, loopback_url, monkeypatch
    ):
        """On a developer's machine the app genuinely is on localhost, so the
        link is correct there. Rejecting it made the feature impossible to
        exercise locally."""
        monkeypatch.setattr(app_settings, "debug", True)
        await _set(db, "smtp_host", "smtp.example.com")

        r = await self._patch(client, admin_token, {
            "app_base_url": loopback_url,
            "self_service_password_reset": "true",
        })
        assert r.status_code == 200

    async def test_rejects_a_plain_http_app_base_url_in_production(
        self, client, db, admin_token, monkeypatch
    ):
        """The reset token travels in the URL fragment specifically so it
        never reaches the network — but that guarantee only holds if the
        channel serving the page and the subsequent password-change POST
        is itself trustworthy. Over plain HTTP an on-path attacker can
        rewrite the served JavaScript to read the fragment, or capture the
        plaintext POST carrying the new password. A public (non-loopback)
        http:// URL used to pass this check unconditionally — only the
        loopback/unspecified branches consulted DEBUG, scheme never did.

        The suite runs under DEBUG, where plain HTTP is deliberately
        allowed — so this has to turn DEBUG off explicitly, or it would
        assert nothing."""
        monkeypatch.setattr(app_settings, "debug", False)
        await _set(db, "smtp_host", "smtp.example.com")

        r = await self._patch(client, admin_token, {
            "app_base_url": "http://pa.example.com",
            "self_service_password_reset": "true",
        })
        assert r.status_code == 400
        assert "not a usable public address" in r.json()["detail"]

    async def test_allows_a_plain_http_app_base_url_under_debug(
        self, client, db, admin_token, monkeypatch
    ):
        """On a developer's machine there is no on-path attacker to worry
        about, and the dev server is plain HTTP — rejecting it made the
        feature impossible to exercise locally."""
        monkeypatch.setattr(app_settings, "debug", True)
        await _set(db, "smtp_host", "smtp.example.com")

        r = await self._patch(client, admin_token, {
            "app_base_url": "http://pa.example.com",
            "self_service_password_reset": "true",
        })
        assert r.status_code == 200

    @pytest.mark.parametrize(
        "good_url",
        [
            "https://pa.example.com",
            "https://pa.example.com:8080",
            "https://pa.internal",
            # Boundary ports either side of the rejected values above.
            "https://pa.example.com:1",
            "https://pa.example.com:65535",
            # A bare trailing slash is a root path, not a subpath —
            # build_reset_url's rstrip('/') already normalises this before
            # appending "/reset-password", so it must stay accepted rather
            # than being caught by the same check that rejects "/settings".
            "https://pa.example.com/",
        ],
    )
    async def test_accepts_a_plausible_deployment_url(
        self, client, db, admin_token, good_url
    ):
        """The check is shallow on purpose — it cannot know what is actually
        reachable, and must not reject a valid internal hostname."""
        await _set(db, "smtp_host", "smtp.example.com")

        r = await self._patch(client, admin_token, {
            "app_base_url": good_url,
            "self_service_password_reset": "true",
        })
        assert r.status_code == 200

    # The endpoint accepts partial updates, so validating only when the
    # request mentions the flag left a gap: enable correctly, then PATCH one
    # dependency to an unusable value. The write succeeded while the config
    # endpoint still advertised the feature as on, so forgot-password either
    # sent nothing or built a broken link.

    async def _enable_properly(self, client, admin_token):
        r = await self._patch(client, admin_token, {
            "smtp_host": "smtp.example.com",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        })
        assert r.status_code == 200

    @pytest.mark.parametrize(
        "later_url",
        [
            "",
            "not-a-url",
            "ftp://pa.example.com",
            "https://pa.example.com?next=/x",
            "https://pa.example.com#frag",
            # Trailing slash before the fragment/query — a plausible paste
            # from a browser address bar, and a different urlparse shape from
            # the two above.
            "https://pa.example.com/#home",
            "https://pa.example.com/?a=b",
            "https://pa.example.com:notaport",
            "https://pa.example.com:99999",
            "https://not a url",
        ],
    )
    async def test_a_later_partial_patch_cannot_break_the_base_url(
        self, client, admin_token, later_url
    ):
        await self._enable_properly(client, admin_token)

        r = await self._patch(client, admin_token, {"app_base_url": later_url})
        assert r.status_code == 400

    async def test_a_later_partial_patch_cannot_clear_the_smtp_host(
        self, client, admin_token
    ):
        await self._enable_properly(client, admin_token)

        r = await self._patch(client, admin_token, {"smtp_host": ""})
        assert r.status_code == 400
        assert "SMTP host" in r.json()["detail"]

    @pytest.mark.parametrize("bad_port", ["not-a-port", "0", "-1", "65536"])
    async def test_a_later_partial_patch_cannot_set_an_unusable_port(
        self, client, admin_token, bad_port
    ):
        """The endpoint accepts partial updates, so validating smtp_port
        only when the request also mentions the flag would leave the same
        gap test_a_later_partial_patch_cannot_break_the_base_url exists to
        close for app_base_url: enable correctly, then PATCH just the port
        to something unusable while the flag itself is never mentioned
        again."""
        await self._enable_properly(client, admin_token)

        r = await self._patch(client, admin_token, {"smtp_port": bad_port})
        assert r.status_code == 400
        assert "SMTP port" in r.json()["detail"]

    async def test_a_later_partial_patch_cannot_set_a_loopback_url_in_production(
        self, client, admin_token, monkeypatch
    ):
        await self._enable_properly(client, admin_token)
        monkeypatch.setattr(app_settings, "debug", False)

        r = await self._patch(
            client, admin_token, {"app_base_url": "http://localhost:5173"}
        )
        assert r.status_code == 400

    async def test_a_query_or_fragment_breaks_the_link_shape(
        self, client, db, admin_token, self_service_on, reset_user, captured_emails
    ):
        """Why those two are rejected: build_reset_url appends the path, so a
        query or fragment in the base URL lands before it and the result is
        structurally broken."""
        from app.services.password_reset import build_reset_url

        assert build_reset_url("https://pa.example.com?next=/x", "T") == (
            "https://pa.example.com?next=/x/reset-password#token=T"
        )
        assert build_reset_url("https://pa.example.com#frag", "T") == (
            "https://pa.example.com#frag/reset-password#token=T"
        )
        # The reported shape: with a trailing slash, rstrip("/") removes it
        # and the route lands inside the existing fragment.
        assert build_reset_url("https://pa.example.com/#home", "T") == (
            "https://pa.example.com/#home/reset-password#token=T"
        )

    async def test_unrelated_partial_updates_still_work_while_enabled(
        self, client, admin_token
    ):
        """The guard must not make the page unusable — editing a setting that
        has nothing to do with password reset has to keep working."""
        await self._enable_properly(client, admin_token)

        r = await self._patch(client, admin_token, {"smtp_from": "new@example.com"})
        assert r.status_code == 200

    async def test_the_dependencies_can_be_changed_to_other_valid_values(
        self, client, admin_token
    ):
        """Blocking bad values must not block good ones — an admin moving the
        deployment to a new hostname has to be able to say so."""
        await self._enable_properly(client, admin_token)

        r = await self._patch(
            client, admin_token, {"app_base_url": "https://pa2.example.com"}
        )
        assert r.status_code == 200

        r = await self._patch(client, admin_token, {"smtp_host": "smtp2.example.com"})
        assert r.status_code == 200

    async def test_disabling_needs_no_smtp_host(self, client, admin_token):
        r = await self._patch(client, admin_token, {"self_service_password_reset": "false"})
        assert r.status_code == 200

    @pytest.mark.parametrize("supplied", ["true", "1", "yes", "on", "TRUE", " Yes "])
    async def test_accepted_true_values_are_canonicalised_on_write(
        self, client, admin_token, smtp_configured, supplied
    ):
        """TRUE_VALUES accepts several spellings, so without canonicalising
        the same setting could be stored in several shapes meaning the same
        thing — and every reader would have to reimplement that exact set to
        agree. The frontend's did not: it matched "true" alone, so a setting
        saved as "yes" showed as off and was overwritten with "false" by any
        unrelated save."""
        r = await self._patch(
            client, admin_token, {"self_service_password_reset": supplied}
        )
        assert r.status_code == 200

        row = next(
            s for s in r.json() if s["key"] == "self_service_password_reset"
        )
        assert row["value"] == "true", (
            f"{supplied!r} was stored as {row['value']!r} rather than canonical 'true'"
        )

    @pytest.mark.parametrize("supplied", ["false", "0", "no", "off", "FALSE", " Off "])
    async def test_documented_false_values_are_canonicalised_to_false(
        self, client, admin_token, smtp_configured, supplied
    ):
        r = await self._patch(
            client, admin_token, {"self_service_password_reset": supplied}
        )
        assert r.status_code == 200
        row = next(
            s for s in r.json() if s["key"] == "self_service_password_reset"
        )
        assert row["value"] == "false"

    @pytest.mark.parametrize("supplied", ["", "nonsense", "tru", "flase", "yesno"])
    async def test_an_unrecognised_value_is_rejected_rather_than_silently_stored_as_false(
        self, client, admin_token, smtp_configured, supplied
    ):
        """An earlier version canonicalised anything not in TRUE_VALUES to
        "false" and accepted it with 200 — self_service_password_reset is
        the only SettingValueType.bool key that exists, and the sweep
        further down (turning_off) keys off exactly this stored value, so a
        typo such as "tru" was stored as false and, while the feature was
        genuinely on, also satisfied turning_off — silently revoking every
        outstanding reset and welcome link on a request the admin believed
        had done something else entirely (or nothing at all). Reproduced
        directly before this fix: PATCHing self_service_password_reset="tru"
        against a genuinely-enabled feature returned 200, stored "false",
        and stamped every live token's used_at."""
        r = await self._patch(
            client, admin_token, {"self_service_password_reset": supplied}
        )
        assert r.status_code == 400
        assert "self_service_password_reset" in r.json()["detail"]

    async def test_a_non_canonical_stored_value_is_still_honoured_at_runtime(
        self, client, db, admin_token, reset_user, captured_emails
    ):
        """Canonicalising only fixes new writes. A row already holding "yes" —
        or written straight to the database — must still enable the flow, or
        the fix would silently switch off deployments it was meant to
        protect."""
        await _set(db, "smtp_host", "smtp.example.com")
        await _set(db, "smtp_from", "pa-central@example.com")
        await _set(db, "app_base_url", "https://pa.example.com")
        await _set(db, "self_service_password_reset", "yes", SettingValueType.bool)

        r = await client.get("/api/auth/password-reset-config")
        assert r.json()["self_service_enabled"] is True

        await client.post(
            "/api/auth/forgot-password", json={"email": reset_user.email}
        )
        assert len(captured_emails) == 1

    async def test_stored_as_bool_type(self, client, admin_token, smtp_configured):
        await self._patch(client, admin_token, {"self_service_password_reset": "true"})
        r = await client.get(
            "/api/system-settings", headers={"Authorization": f"Bearer {admin_token}"}
        )
        row = next(s for s in r.json() if s["key"] == "self_service_password_reset")
        assert row["value_type"] == "bool"
        assert row["value"] == "true"

    @pytest.mark.parametrize(
        "bad_host",
        [
            "not a host",
            "bad\x01host",
            "trailing\tws",
            "line\nbreak",
            "carriage\rreturn",
            "\x7fdel",
            " ",
        ],
    )
    async def test_cannot_enable_with_a_syntactically_impossible_host_in_the_same_request(
        self, client, admin_token, bad_host
    ):
        """build_smtp_config and self_service_reset_enabled (core/smtp_settings.py)
        used to accept any non-empty smtp_host, including a value
        socket.getaddrinfo can never resolve on any network — a PATCH like
        this one used to succeed while the very next
        GET /password-reset-config reported the feature unavailable, and a
        real reset attempt failed only once send was actually attempted
        (after the token was already committed, and — on the admin-reset
        path — after the target's password was already invalidated).
        Reproduced directly before this fix."""
        r = await self._patch(client, admin_token, {
            "smtp_host": bad_host,
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        })
        assert r.status_code == 400
        assert "SMTP host" in r.json()["detail"]

    async def test_cannot_enable_while_a_syntactically_impossible_host_is_already_stored(
        self, client, db, admin_token, smtp_configured
    ):
        """The same gap as smtp_port/smtp_tls_mode/smtp_from above, for
        smtp_host: a value that reached storage some other way (a legacy
        row, a restore, a direct edit) let this gate report 200 for a PATCH
        that only touched self_service_password_reset, while
        self_service_reset_enabled() immediately reported the feature
        unavailable. Reproduced directly before this fix."""
        await _set(db, "smtp_host", "not a host")

        r = await self._patch(
            client, admin_token, {"self_service_password_reset": "true"}
        )
        assert r.status_code == 400
        assert "SMTP host" in r.json()["detail"]

    async def test_can_enable_with_a_valid_host_in_the_same_request(
        self, client, admin_token
    ):
        """Positive control: a normal hostname must still pass."""
        r = await self._patch(client, admin_token, {
            "smtp_host": "mail.example.com",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        })
        assert r.status_code == 200

    async def test_can_enable_with_an_ip_literal_host(
        self, client, admin_token
    ):
        """cfg.host is passed straight to smtplib.SMTP(), which accepts an
        IP literal exactly as readily as a hostname — this must not be
        mistaken for a syntactically impossible value."""
        r = await self._patch(client, admin_token, {
            "smtp_host": "192.168.1.50",
            "app_base_url": "https://pa.example.com",
            "self_service_password_reset": "true",
        })
        assert r.status_code == 200


class TestPasswordResetReadiness:
    """GET /system-settings/password-reset-readiness.

    SystemSettings.tsx previously derived its own "can this be enabled"
    guess from only smtp_host and app_base_url being non-empty
    (canEnableReset), which agreed with neither patch_settings()'s own
    enabling gate nor self_service_reset_enabled(): a malformed base URL,
    an out-of-range port, an unrecognised TLS mode, or a From address
    containing CR/LF all left the toggle looking enableable (or the
    feature looking active) while the backend disagreed. This endpoint
    runs the identical shared validators against the currently stored
    values so the frontend can show the real reason instead of guessing.
    """

    async def _get(self, client, admin_token):
        return await client.get(
            "/api/system-settings/password-reset-readiness",
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    async def test_unauthenticated_request_is_rejected(self, client):
        r = await client.get("/api/system-settings/password-reset-readiness")
        assert r.status_code == 401

    async def test_non_admin_request_is_rejected(self, client, viewer_token):
        r = await client.get(
            "/api/system-settings/password-reset-readiness",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )
        assert r.status_code == 403

    async def test_a_fresh_database_is_not_ready_and_says_why(
        self, client, admin_token
    ):
        r = await self._get(client, admin_token)
        assert r.status_code == 200
        body = r.json()
        assert body["ready"] is False
        assert any("SMTP host" in reason for reason in body["reasons"])
        assert any("App Base URL" in reason for reason in body["reasons"])

    async def test_fully_configured_is_ready_with_no_reasons(
        self, client, admin_token, smtp_configured
    ):
        r = await self._get(client, admin_token)
        assert r.status_code == 200
        body = r.json()
        assert body["ready"] is True
        assert body["reasons"] == []

    async def test_an_unusable_port_is_reported(
        self, client, db, admin_token, smtp_configured
    ):
        await _set(db, "smtp_port", "99999", SettingValueType.int)
        r = await self._get(client, admin_token)
        body = r.json()
        assert body["ready"] is False
        assert any("SMTP port" in reason for reason in body["reasons"])

    async def test_an_unusable_tls_mode_is_reported(
        self, client, db, admin_token, smtp_configured
    ):
        await _set(db, "smtp_tls_mode", "start-tls")
        r = await self._get(client, admin_token)
        body = r.json()
        assert body["ready"] is False
        assert any("TLS mode" in reason for reason in body["reasons"])

    async def test_an_unusable_from_addr_is_reported(
        self, client, db, admin_token, smtp_configured
    ):
        await _set(db, "smtp_from", "pa\r\nBcc: evil@example.com")
        r = await self._get(client, admin_token)
        body = r.json()
        assert body["ready"] is False
        assert any("From address" in reason for reason in body["reasons"])

    async def test_a_malformed_base_url_is_reported(
        self, client, db, admin_token, smtp_configured
    ):
        await _set(db, "app_base_url", "https://pa.example.com?next=/x")
        r = await self._get(client, admin_token)
        body = r.json()
        assert body["ready"] is False
        assert any("App Base URL" in reason for reason in body["reasons"])

    async def test_a_production_http_base_url_is_reported(
        self, client, db, admin_token, smtp_configured, monkeypatch
    ):
        """The same gap the checkbox itself had before the HTTPS-enforcement
        fix: a plain http:// public URL is unusable outside DEBUG, and this
        endpoint must agree rather than reporting ready."""
        monkeypatch.setattr(app_settings, "debug", False)
        await _set(db, "app_base_url", "http://pa.example.com")
        r = await self._get(client, admin_token)
        body = r.json()
        assert body["ready"] is False
        assert any("App Base URL" in reason for reason in body["reasons"])

    async def test_multiple_problems_all_get_reported(
        self, client, db, admin_token, smtp_configured
    ):
        await _set(db, "smtp_port", "not-a-port", SettingValueType.int)
        await _set(db, "smtp_tls_mode", "start-tls")
        r = await self._get(client, admin_token)
        body = r.json()
        assert body["ready"] is False
        assert len(body["reasons"]) >= 2

    async def test_a_syntactically_impossible_host_is_reported(
        self, client, db, admin_token, smtp_configured
    ):
        """The same gap as smtp_port/smtp_tls_mode/smtp_from/app_base_url
        above, for smtp_host: a value socket.getaddrinfo can never resolve
        on any network used to be reported ready, with the failure only
        discovered once a real reset attempt tried to send."""
        await _set(db, "smtp_host", "not a host")
        r = await self._get(client, admin_token)
        body = r.json()
        assert body["ready"] is False
        assert any("SMTP host" in reason for reason in body["reasons"])
