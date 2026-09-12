from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_admin
from app.core.database import get_db
from app.core.email import filter_deliverable_recipients
from app.core.security import create_access_token, generate_password
from app.core.smtp_settings import load_settings_map, self_service_reset_enabled
from app.models import User
from app.schemas import PasswordResetOut, SelfPasswordChangeOut, UserOut, UserUpdate
from app.services.password_reset import (
    MissingAppBaseUrl,
    issue_reset_token,
    require_app_base_url,
    set_password,
)

router = APIRouter(prefix="/users", tags=["users"])


@router.get("", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> list[UserOut]:
    result = await db.execute(select(User).order_by(User.display_name))
    return result.scalars().all()


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
    return user


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
            **UserOut.model_validate(user).model_dump(),
            access_token=create_access_token(user.id, user.token_epoch),
        )
    return user


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
    return user


@router.post("/{user_id}/reset-password", response_model=PasswordResetOut)
async def reset_password(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> PasswordResetOut:
    """Admin-initiated password reset.

    The primary use is containment after a suspected compromise, so this
    **always invalidates the current password immediately**, by both routes.
    Leaving the old password working until the user got round to clicking a
    link would let an attacker keep their access for as long as the mail sat
    unread — precisely what the admin acted to stop.

    With self-service reset enabled the password is replaced with an unusable
    random value and the user is emailed a link to choose a new one. That
    link is long-lived (ADMIN_RESET_TOKEN_TTL_MINUTES, a day) and bypasses
    the forgot-password throttle: the user did not ask for this mail, may not
    read it for hours, and must not be blocked by request volume an attacker
    has already aimed at their account.

    With it disabled (no SMTP to deliver a link), it falls back to generating
    a password and returning it once for the admin to relay out-of-band.
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
        # would lock the user out with nothing to recover with. Checked here
        # rather than relying on issue_reset_token's own guard, which runs
        # after that point.
        try:
            require_app_base_url(settings_map)
        except MissingAppBaseUrl:
            raise HTTPException(
                400,
                "The App Base URL is not set, so no usable reset link can be "
                "built. The password has not been changed — set it in System "
                "Settings and try again.",
            ) from None

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
        # database recovery, reproduced directly. Checked here rather than
        # relying on issue_reset_token's own guard (which runs after
        # set_password) for the identical reason app_base_url is.
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

        # This endpoint is indifferent between every one of
        # issue_reset_token's reasons for an unusable link: a send failure
        # (confirmed or merely unconfirmed — see send_reset_email's own
        # docstring for why those are deliberately not distinguished any
        # more finely than "not sent"), or a concurrent admin reset for the
        # same user retiring this token before the send completed. All of
        # them leave the recipient without a usable link, best-effort:
        # nothing here is destructive beyond the password invalidation
        # above, which already happened regardless of the send outcome, so
        # the response just tells the admin to check delivery and, if
        # needed, reset again.
        result = await issue_reset_token(db, user, settings_map, admin_initiated=True)
        if not (result.sent and result.still_live):
            raise HTTPException(
                502,
                "The password has been invalidated, but delivery of the "
                "reset link could not be confirmed — check with the user, "
                "and reset again if a new link is needed.",
            )
        return PasswordResetOut(password=None, reset_link_sent=True)

    password = generate_password()
    await set_password(db, user, password)
    await db.commit()
    return PasswordResetOut(password=password, reset_link_sent=False)
