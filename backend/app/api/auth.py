import logging
import time

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    create_totp_session_token,
    decode_totp_session_token,
    generate_password,
    generate_totp_secret,
    get_totp_uri,
    hash_password,
    hash_reset_token,
    verify_password,
    verify_totp,
)
from app.core.smtp_settings import load_settings_map, self_service_reset_enabled
from app.models import User
from app.schemas import (
    ForgotPasswordRequest,
    LoginRequest,
    PasswordResetConfigOut,
    RegisterOut,
    ResetPasswordRequest,
    TokenResponse,
    TotpChallengeResponse,
    TotpDisableRequest,
    TotpVerifyRequest,
    UserCreate,
    UserOut,
)
from app.services.password_reset import (
    FORGOT_PASSWORD_MIN_SECONDS,
    FORGOT_PASSWORD_WORK_MARGIN_SECONDS,
    consume_reset_token,
    dispatch_reset_email,
    issue_reset_token,
    pad_to_constant_time,
    prepare_reset_email,
    set_password,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])


def _check_credentials(user: User | None, password: str) -> User:
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Account disabled")
    return user


@router.post("/token", response_model=TokenResponse)
async def login_form(
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """OAuth2 password flow for Swagger UI (DEBUG mode only).

    In production (DEBUG=false) this endpoint is disabled — all clients must
    use POST /auth/login + POST /auth/totp/verify to ensure TOTP enrolment.
    In DEBUG mode it still rejects accounts that have TOTP already enabled.
    """
    if not settings.debug:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Form-based login is disabled — use POST /auth/login",
        )
    result = await db.execute(select(User).where(User.email == form.username))
    user = _check_credentials(result.scalar_one_or_none(), form.password)
    if user.totp_enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="TOTP is enabled on this account — use the /auth/login JSON flow",
        )
    return TokenResponse(access_token=create_access_token(user.id, user.token_epoch))


@router.post("/login")
async def login_json(
    body: LoginRequest, db: AsyncSession = Depends(get_db)
) -> TokenResponse | TotpChallengeResponse:
    """JSON login. Returns either a bearer token or a TOTP challenge.

    When DEBUG=1, TOTP is skipped entirely and a token is issued immediately.
    Never enable DEBUG in production.
    """
    result = await db.execute(select(User).where(User.email == body.email))
    user = _check_credentials(result.scalar_one_or_none(), body.password)

    if settings.debug:
        return TokenResponse(access_token=create_access_token(user.id, user.token_epoch))

    if not user.totp_enabled:
        # TOTP not yet set up — require enrolment before issuing token
        secret = generate_totp_secret()
        user.totp_secret = secret
        await db.commit()
        session_token = create_totp_session_token(user.id, user.token_epoch, setup=True)
        return TotpChallengeResponse(
            totp_required=True,
            totp_setup_required=True,
            totp_session_token=session_token,
            totp_uri=get_totp_uri(secret, user.email),
        )

    # TOTP enabled — challenge
    session_token = create_totp_session_token(user.id, user.token_epoch, setup=False)
    return TotpChallengeResponse(
        totp_required=True,
        totp_setup_required=False,
        totp_session_token=session_token,
        totp_uri=None,
    )


@router.post("/totp/verify", response_model=TokenResponse)
async def totp_verify(body: TotpVerifyRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    """Complete a TOTP challenge (both setup-confirm and normal login).

    The challenge token embeds the epoch that was current when the password
    was verified in login_json. If that no longer matches the user's current
    epoch, a password change happened *during* the challenge window — the
    5-minute gap between a correct password check and this call — and the
    challenge must not be honoured despite carrying a valid TOTP code.
    Without this, an admin resetting a compromised password to end an
    attacker's access does not actually stop an attacker who already
    obtained a challenge (and who, in a fully compromised account, likely
    also controls the TOTP secret) from completing it afterward and walking
    away with a fresh, fully valid bearer token. Reproduced end to end:
    login succeeds, admin resets the password, the pre-reset challenge is
    still exchanged successfully for a token carrying the post-reset epoch.
    """
    decoded = decode_totp_session_token(body.totp_session_token)
    if not decoded:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session")
    user_id, is_setup, challenge_epoch = decoded
    user = await db.get(User, user_id)
    if not user or not user.is_active or not user.totp_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    if challenge_epoch != user.token_epoch:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session")
    if not verify_totp(user.totp_secret, body.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")
    if is_setup:
        user.totp_enabled = True
        await db.commit()
    return TokenResponse(access_token=create_access_token(user.id, user.token_epoch))


@router.post("/totp/disable", status_code=204)
async def totp_disable(
    body: TotpDisableRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user),
) -> None:
    """Disable TOTP for the current user. Requires a valid current TOTP code."""
    if not user.totp_enabled or not user.totp_secret:
        raise HTTPException(status_code=400, detail="TOTP is not enabled")
    if not verify_totp(user.totp_secret, body.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")
    user.totp_secret = None
    user.totp_enabled = False
    await db.commit()


@router.get("/totp/status")
async def totp_status(user: User = Depends(get_current_user)) -> dict[str, bool]:
    return {"totp_enabled": user.totp_enabled}


@router.get("/me", response_model=UserOut)
async def me(user: User = Depends(get_current_user)) -> UserOut:
    return user


@router.post("/register", response_model=RegisterOut, status_code=201)
async def register(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> RegisterOut:
    """Admin-only: create a new user.

    With self-service reset enabled the new account gets a **welcome link**
    emailed to it and no admin-chosen password at all — the same principle as
    the admin reset: where the user can set their own credential, none should
    pass through the admin (or through a chat message on its way to them). A
    password supplied here is rejected rather than ignored, so the API cannot
    be used to sidestep that.

    With it disabled (no SMTP to deliver a link) a password is required, as
    before, since there is no other way to hand the account over.

    The welcome send is best-effort: this endpoint never rolls the account
    back on a delivery problem, whatever the cause (confirmed SMTP failure,
    a timeout, an ambiguous mid-transfer disconnect — see
    send_reset_email's own docstring for why those are deliberately not
    distinguished any more finely than "not confirmed sent"). An earlier
    version tried to tell those apart and delete the account only on a
    "definitely no way in" outcome — which chased an increasingly narrow,
    increasingly fragile edge case (smtplib itself collapses a socket
    timeout waiting on the final acknowledgment into the same exception a
    clean disconnect raises) for a decision that a human admin is better
    placed to make anyway: check whether the user actually got the email,
    and trigger a fresh reset if they did not, once the situation is
    understood. `welcome_email_sent` on the response is exactly that
    signal, not a verdict.
    """
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    settings_map = await load_settings_map(db)
    self_service = self_service_reset_enabled(settings_map)

    if self_service and body.password is not None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Self-service password reset is enabled — new users set their "
                "own password via an emailed welcome link. Omit 'password'."
            ),
        )
    if not self_service and body.password is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "A password is required: self-service password reset is not "
                "enabled, so there is no way to email a welcome link."
            ),
        )

    # With self-service on, the stored value is a random one nobody holds —
    # only the welcome link can set a usable password. Never left blank or
    # predictable: the account exists and is active from this moment, so an
    # empty or guessable hash would be a live way in.
    user = User(
        email=body.email,
        display_name=body.display_name,
        hashed_password=hash_password(body.password or generate_password()),
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    welcome_email_sent = None
    welcome_link_still_valid = None
    if self_service:
        # Best-effort: the welcome send is never grounds to roll this
        # account back, whatever went wrong (see this function's own
        # docstring). The one thing still worth checking for is a
        # concurrent admin deleting the account outright (DELETE
        # /users/{id}) while the send was in flight — there is no row left
        # to return as RegisterOut in that case, so it needs its own
        # response rather than silently constructing one from a stale
        # in-memory `user` object.
        result = await issue_reset_token(db, user, settings_map, welcome=True)
        welcome_email_sent = result.sent
        # Reported unconditionally, not only when the account was deleted
        # outright below — `still_live=False` while the account survives
        # means some concurrent event retired *this specific token* without
        # touching the account at all. Most commonly: self-service reset
        # (or its SMTP configuration) being disabled while this send was in
        # flight, which sweeps every outstanding token system-wide (see
        # api/system_settings.py's turning_off/losing_smtp) — a genuinely
        # sent welcome_email_sent=True email whose link is already dead by
        # the time it arrives. Reproduced directly: a sweep run mid-send
        # left sent=True, still_live=False, an untouched account, and this
        # field previously carried no signal of any of that — the admin
        # saw a plain "invite emailed" success with nothing to act on.
        welcome_link_still_valid = result.still_live
        if not result.still_live:
            still_exists = (await db.execute(
                select(User.id).where(User.id == user.id)
            )).scalar_one_or_none()
            if still_exists is None:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "The user was not created: the account was deleted "
                        "by another admin while the welcome link was being "
                        "sent."
                    ),
                )
    return RegisterOut.model_validate(user).model_copy(
        update={
            "welcome_email_sent": welcome_email_sent,
            "welcome_link_still_valid": welcome_link_still_valid,
        }
    )


# ── Self-service password reset ───────────────────────────────────────────────

@router.get("/password-reset-config", response_model=PasswordResetConfigOut)
async def password_reset_config(db: AsyncSession = Depends(get_db)) -> PasswordResetConfigOut:
    """Public: whether the login page should offer "Forgot password?".

    Unauthenticated by necessity — a locked-out user cannot authenticate to
    ask. It discloses only whether a deployment-wide feature is switched on,
    which is already evident from the login page either way.
    """
    settings_map = await load_settings_map(db)
    return PasswordResetConfigOut(self_service_enabled=self_service_reset_enabled(settings_map))


@router.post("/forgot-password", status_code=202)
async def forgot_password(
    body: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)
) -> dict[str, bool]:
    """Public: request a password reset link.

    Always returns the same 202 response regardless of whether the address
    belongs to an account, whether that account is active, or whether the
    feature is enabled at all. Anything else turns this endpoint into an
    account-existence oracle. The response body is a fixed constant for the
    same reason — it must not vary with what happened server-side.

    **Delivery is detached, never awaited here.** An identical body does not
    hide an SMTP round-trip: waiting for one made a registered address take
    ~520ms against ~3ms for an unknown one, a ~180x difference that is
    trivially observable and a cleaner oracle than any response content. Only
    the token write — which both paths perform equally cheaply — happens
    before the response.

    A FastAPI BackgroundTask would *not* fix this: those run inside the ASGI
    request lifecycle, so the client waits for them anyway (measured
    directly). dispatch_reset_email detaches the send instead.

    Detaching the send leaves a smaller residue — only the registered path
    writes a token, worth ~2.4ms — so every response is additionally padded
    to a constant FORGOT_PASSWORD_MIN_SECONDS. Both differences have to go:
    the first is trivially observable in one request, the second extractable
    by sampling one address repeatedly.
    """
    started_at = time.perf_counter()
    settings_map = await load_settings_map(db)
    if self_service_reset_enabled(settings_map):
        result = await db.execute(select(User).where(User.email == body.email))
        user = result.scalar_one_or_none()
        if user and user.is_active:
            # Bounded, because only this branch runs — and only for a real
            # active account. prepare_reset_email takes a per-user write lock,
            # so a concurrent burst against a registered address queues on it
            # while the same burst against an unknown address does not. Left
            # unbounded that queue overruns the constant-time floor and
            # latency discloses account existence again (measured at 430ms vs
            # 252ms for ten concurrent requests on PostgreSQL).
            #
            # On timeout the link is simply not issued this time, which is
            # what the throttle does anyway and is invisible to the caller.
            #
            # Deadline, not a timeout: prepare_reset_email checks it at
            # safe points and returns cleanly, because cancelling it mid-await
            # would leave this session unusable (MissingGreenlet on the very
            # rollback meant to clean up).
            prepared = await prepare_reset_email(
                db, user, settings_map,
                deadline=started_at + FORGOT_PASSWORD_MIN_SECONDS
                - FORGOT_PASSWORD_WORK_MARGIN_SECONDS,
            )
            if prepared:
                msg, smtp_cfg, _token_hash = prepared
                dispatch_reset_email(msg, smtp_cfg, user.email, user.id)

    # Release the connection before sleeping. Every path above runs at least
    # one SELECT, which opens a transaction, and get_db does not close the
    # session until after the response — so without this an unauthenticated
    # caller holds a pooled connection for the full padding interval, and
    # enough concurrent requests exhaust the pool. The token-issuing paths
    # have already committed; this ends the read-only transaction the
    # disabled, unknown-address and inactive-user paths leave open.
    #
    # rollback() rather than commit(): nothing on the remaining paths has
    # written anything, so there is deliberately nothing to persist here.
    await db.rollback()

    await pad_to_constant_time(started_at)
    return {"ok": True}


@router.post("/reset-password", status_code=204)
async def reset_password(
    body: ResetPasswordRequest, db: AsyncSession = Depends(get_db)
) -> None:
    """Public: consume a reset token and set a new password.

    Unlike forgot-password this does report failure — the user is acting on a
    link they hold, so "this link is no longer valid" is the only useful
    answer and reveals nothing about which accounts exist.

    **Deliberately not gated on self_service_reset_enabled.** That setting
    governs *issuance*; a token that already exists was delivered under
    whatever policy applied then, and refusing it now strands people the
    feature was switched off around. The sharp case: an admin reset
    invalidates the password and emails a link, an admin then disables the
    setting (or clears SMTP), and the user is left with a dead password and a
    link answering 503 — no way in at all. Same for a new account whose only
    credential is its welcome link.

    Turning the feature off retires outstanding tokens instead (see
    api/system_settings.py), which is both the honest way to revoke them and
    the only one that sticks: gating here left the rows live, so re-enabling
    the setting revived every link that had been refused in the meantime.
    """
    consumed = await consume_reset_token(db, hash_reset_token(body.token))
    if not consumed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This reset link is invalid or has expired",
        )
    _token_row, user = consumed
    # consume_reset_token already stamped this token's used_at as part of its
    # atomic claim; set_password retires any *other* outstanding link for the
    # account, so completing a reset invalidates every older one. Committing
    # here makes the stamp and the password change durable together.
    await set_password(db, user, body.new_password)
    await db.commit()
