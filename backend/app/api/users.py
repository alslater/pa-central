from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.alerts import notify_user
from app.api.deps import get_current_user, require_admin
from app.core.database import get_db
from app.core.email import filter_deliverable_recipients
from app.core.security import create_access_token, generate_password
from app.core.smtp_settings import load_settings_map, self_service_reset_enabled
from app.models import PasswordResetKind, PasswordResetToken, User, utcnow
from app.schemas import PasswordResetOut, SelfPasswordChangeOut, UserOut, UserUpdate
from app.services.password_reset import (
    MissingAppBaseUrl,
    dispatch_admin_action,
    prepare_reset_email,
    require_app_base_url,
    set_password,
)

router = APIRouter(prefix="/users", tags=["users"])


async def _outstanding_welcome_token_user_ids(
    db: AsyncSession, user_ids: list[int]
) -> set[int]:
    """Which of `user_ids` hold an unused, unexpired welcome token.

    One query whatever the number of users, so list_users does not become an
    N+1 pattern, and restricted to `user_ids` so the single-user callers pay
    only for a one-element `IN`.

    Shared by every endpoint that returns a UserOut, not just list_users.
    `UserOut.has_outstanding_welcome_token` is a schema default of False, so
    any handler returning a bare ORM row silently reports False regardless of
    the real state — which flipped an admin's "Resend welcome email" button to
    "Reset password" after an unrelated PATCH. Computing it in one place means
    a new UserOut-returning endpoint has one obvious thing to call rather than
    a query to remember to duplicate.
    """
    if not user_ids:
        return set()
    result = await db.execute(
        select(PasswordResetToken.user_id).where(
            PasswordResetToken.user_id.in_(user_ids),
            PasswordResetToken.kind == PasswordResetKind.welcome,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > utcnow(),
        )
    )
    return set(result.scalars().all())


async def _user_out(db: AsyncSession, user: User) -> UserOut:
    """UserOut for a single user with has_outstanding_welcome_token resolved.

    Deliberately NOT used by api/auth.py's `me()` (GET /auth/me), unlike
    every other UserOut-returning endpoint — see that function's own
    comment: being authenticated at all and holding an unused welcome
    token for that SAME account are mutually exclusive by construction,
    so the real value there is always False regardless of what this
    query would say. This module-private helper is for endpoints that
    can report on a DIFFERENT user than the caller (an admin viewing or
    editing someone else's row), where that invariant doesn't hold.
    """
    outstanding_ids = await _outstanding_welcome_token_user_ids(db, [user.id])
    return UserOut.model_validate(user).model_copy(
        update={"has_outstanding_welcome_token": user.id in outstanding_ids}
    )


@router.get("", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> list[UserOut]:
    result = await db.execute(select(User).order_by(User.display_name))
    users = result.scalars().all()

    outstanding_ids = await _outstanding_welcome_token_user_ids(
        db, [u.id for u in users]
    )
    return [
        UserOut.model_validate(u).model_copy(
            update={"has_outstanding_welcome_token": u.id in outstanding_ids}
        )
        for u in users
    ]


@router.get("/{user_id}", response_model=UserOut)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current: User = Depends(get_current_user),
) -> UserOut:
    from app.models import UserRole
    if current.role != UserRole.admin and current.id != user_id:
        raise HTTPException(403, "Forbidden")
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    return await _user_out(db, user)


@router.patch("/{user_id}", response_model=UserOut | SelfPasswordChangeOut)
async def update_user(
    user_id: int,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current: User = Depends(get_current_user),
) -> UserOut | SelfPasswordChangeOut:
    from app.models import UserRole
    # Check permission before DB lookup to avoid leaking whether user_id exists
    if current.role != UserRole.admin:
        if current.id != user_id:
            raise HTTPException(403, "Forbidden")
        body = UserUpdate(display_name=body.display_name, password=body.password)
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    data = body.model_dump(exclude_none=True)
    new_password = data.pop("password", None)
    for k, v in data.items():
        setattr(user, k, v)
    changed_own_password = False
    if new_password is not None:
        # Via set_password so any outstanding reset link is retired: one
        # issued before this change would otherwise still work afterwards,
        # letting whoever holds it overwrite the password just chosen.
        await set_password(db, user, new_password)
        # Caller and target are the same account (an admin changing their
        # own password through this endpoint, or the non-admin self-change
        # path above) — see the SelfPasswordChangeOut branch below for why
        # that specific combination needs a replacement token.
        changed_own_password = current.id == user_id
    await db.commit()
    await db.refresh(user)
    if changed_own_password:
        # set_password just bumped token_epoch (see its own docstring: this
        # is what makes a password change actually revoke sessions), which
        # invalidates the very bearer token that authenticated this
        # request — an admin changing someone *else's* password doesn't
        # touch their own session, but here caller and target are the same
        # account, so without a replacement the caller's next API call
        # 401s with nothing to explain why. Minted from user.token_epoch,
        # which set_password already refreshed in-memory via RETURNING, so
        # this is the post-change value even before the commit above.
        return SelfPasswordChangeOut(
            **(await _user_out(db, user)).model_dump(),
            access_token=create_access_token(user.id, user.token_epoch),
        )
    return await _user_out(db, user)


@router.delete("/{user_id}", status_code=204, response_class=Response)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current: User = Depends(require_admin),
) -> Response:
    if current.id == user_id:
        raise HTTPException(403, "Cannot delete your own account")
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    await db.delete(user)
    await db.commit()
    return Response(status_code=204)


@router.post("/{user_id}/reset-totp", response_model=UserOut)
async def reset_totp(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> UserOut:
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    user.totp_secret = None
    user.totp_enabled = False
    await db.commit()
    await db.refresh(user)
    return await _user_out(db, user)


@router.post(
    "/{user_id}/reset-password",
    response_model=PasswordResetOut,
    responses={
        202: {
            "model": PasswordResetOut,
            "description": (
                "The password change is already applied; the notification "
                "email send is still in flight and its outcome is reported "
                "later via SSE."
            ),
        },
    },
)
async def reset_password(
    user_id: int,
    response: Response,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_admin),
) -> PasswordResetOut:
    """Admin-initiated password reset.

    Always invalidates the current password immediately — the primary use is
    containment after a suspected compromise, so leaving the old password
    working until the user got round to clicking a link would let an
    attacker keep their access for as long as the mail sat unread.

    With self-service reset enabled, a reset link (or, if the target user
    never used their original welcome link, a resent welcome email — see
    the outstanding-welcome-token check below) is dispatched in the
    background; this endpoint returns as soon as the invalidation is
    committed, without waiting for the send. The outcome (sent / not
    confirmed / account no longer exists) is reported later to this admin
    via the SSE `admin_action_result` event on `GET /api/alerts/stream`.

    A 202 response means the password change has already been applied and a
    send is genuinely still in flight; only the notification email's
    outcome is pending. Every other response (200) is already fully
    resolved by the time it is returned.

    With self-service reset disabled (no SMTP to deliver a link), it falls
    back to generating a password and returning it once for the admin to
    relay out-of-band.
    """
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found")

    settings_map = await load_settings_map(db)
    if self_service_reset_enabled(settings_map):
        if not user.is_active:
            raise HTTPException(400, "Cannot send a reset link to a disabled account")

        # Refuse a knowable misconfiguration *before* touching the password.
        # The invalidate-first ordering below is right for a delivery failure
        # — containment outranks a lockout — but a missing app_base_url is not
        # a delivery failure: no link could ever be built, so invalidating
        # would lock the user out with nothing to recover with.
        try:
            require_app_base_url(settings_map)
        except MissingAppBaseUrl:
            raise HTTPException(
                400,
                "The App Base URL is not set, so no usable reset link can be "
                "built. The password has not been changed — set it in System "
                "Settings and try again.",
            ) from None

        # Read *before* set_password touches anything: set_password retires
        # every outstanding token for this user (stamps used_at), including
        # the very welcome token this check exists to detect — reading it
        # afterward would always see used_at already set and never resend a
        # welcome link at all. See spec §5: resend the original welcome
        # email, not an admin-reset email, when the target never used it —
        # an admin-reset email tells the recipient "your password no longer
        # works", which is actively misleading for someone who never had a
        # working password to begin with, still being onboarded rather than
        # locked out.
        outstanding_welcome = (await db.execute(
            select(PasswordResetToken.id).where(
                PasswordResetToken.user_id == user.id,
                PasswordResetToken.kind == PasswordResetKind.welcome,
                PasswordResetToken.used_at.is_(None),
                PasswordResetToken.expires_at > utcnow(),
            )
        )).scalar_one_or_none() is not None

        # Same reasoning as the App Base URL check above, for the other half
        # of "can a link even be built": whether *this user's own address* is
        # deliverable at all. filter_deliverable_recipients rejects a
        # non-fully-qualified domain (e.g. admin@localhost) outright — a real
        # SMTP server would too — and that is knowable from the address alone,
        # before anything is sent. The built-in bootstrap admin
        # (main.py's bootstrap_admin) is created at exactly this address, so
        # an admin resetting their own password without having changed it
        # first would otherwise have had their password invalidated and their
        # own session revoked (set_password bumps token_epoch) for an account
        # that can never receive the link that was supposed to replace it —
        # a genuine deployment locked out with no path back except direct
        # database recovery, reproduced directly.
        #
        # Falls back to generating a password, exactly like the disabled-
        # feature branch below and the app_base_url case above — this
        # address specifically can never receive a link, so self-service is
        # exactly as unusable for this one account as it is for the whole
        # deployment when app_base_url is missing. An HTTPException here (an
        # earlier version of this fix) left the admin with no immediate
        # containment action at all for an account they may be resetting
        # because of a suspected compromise; the generated-password fallback
        # still contains it and hands back a working credential in the same
        # response.
        if not filter_deliverable_recipients([user.email]):
            password = generate_password()
            await set_password(db, user, password)
            await db.commit()
            return PasswordResetOut(password=password, reset_link_sent=False)

        # Invalidate first, and commit before attempting delivery. A failed
        # send must still leave the old password dead: for a suspected
        # compromise, containment outranks the risk of a user needing a
        # second admin action to get back in. The replacement is a random
        # value nobody holds — only the emailed link can set a usable one.
        # set_password also retires any outstanding link, so an older one
        # cannot be used to re-take the account this reset is containing.
        # The new reset token is issued after this, so it survives.
        await set_password(db, user, generate_password())
        await db.commit()

        prepared = await prepare_reset_email(
            db, user, settings_map,
            welcome=outstanding_welcome, admin_initiated=not outstanding_welcome,
        )
        if not prepared:
            # Preparation failed (SMTP unconfigured after all, rate-limited,
            # or a lock-contention abandonment) — the password is still
            # invalidated above, but nothing was ever dispatched, so there is
            # no op_id to correlate and no SSE event will ever arrive.
            return PasswordResetOut(password=None, reset_link_sent=False, op_id=None)

        msg, smtp_cfg, token_hash = prepared
        op_id = str(uuid4())
        action = "welcome_link" if outstanding_welcome else "admin_reset"

        # Admission, dispatch, and SSE notification are all owned by
        # dispatch_admin_action — see its own docstring for why this lives
        # in the service layer rather than here (the admin-specific
        # _pending_admin_sends gate, kept independent of dispatch_reset_
        # email's own shared MAX_PENDING_SENDS cap, used to be duplicated
        # verbatim between this handler and auth.py's register).
        admitted = dispatch_admin_action(
            msg, smtp_cfg, user.email, user.id, token_hash,
            admin_id=admin.id, action=action, op_id=op_id, notify=notify_user,
        )
        if not admitted:
            # False for the same reason in every refusal case dispatch_
            # admin_action can produce: no task exists, so nothing is
            # pending, and no further SSE outcome will arrive beyond the
            # attempted=False event it already emitted.
            return PasswordResetOut(password=None, reset_link_sent=False, op_id=op_id)

        response.status_code = 202
        return PasswordResetOut(password=None, reset_link_sent=None, op_id=op_id)

    password = generate_password()
    await set_password(db, user, password)
    await db.commit()
    return PasswordResetOut(password=password, reset_link_sent=False)
