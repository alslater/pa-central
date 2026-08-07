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
    generate_totp_secret,
    get_totp_uri,
    hash_password,
    verify_password,
    verify_totp,
)
from app.models import User
from app.schemas import (
    LoginRequest,
    TokenResponse,
    TotpChallengeResponse,
    TotpDisableRequest,
    TotpVerifyRequest,
    UserCreate,
    UserOut,
)

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
    return TokenResponse(access_token=create_access_token(user.id))


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
        return TokenResponse(access_token=create_access_token(user.id))

    if not user.totp_enabled:
        # TOTP not yet set up — require enrolment before issuing token
        secret = generate_totp_secret()
        user.totp_secret = secret
        await db.commit()
        session_token = create_totp_session_token(user.id, setup=True)
        return TotpChallengeResponse(
            totp_required=True,
            totp_setup_required=True,
            totp_session_token=session_token,
            totp_uri=get_totp_uri(secret, user.email),
        )

    # TOTP enabled — challenge
    session_token = create_totp_session_token(user.id, setup=False)
    return TotpChallengeResponse(
        totp_required=True,
        totp_setup_required=False,
        totp_session_token=session_token,
        totp_uri=None,
    )


@router.post("/totp/verify", response_model=TokenResponse)
async def totp_verify(body: TotpVerifyRequest, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    """Complete a TOTP challenge (both setup-confirm and normal login)."""
    decoded = decode_totp_session_token(body.totp_session_token)
    if not decoded:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired session")
    user_id, is_setup = decoded
    user = await db.get(User, user_id)
    if not user or not user.is_active or not user.totp_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid session")
    if not verify_totp(user.totp_secret, body.code):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid TOTP code")
    if is_setup:
        user.totp_enabled = True
        await db.commit()
    return TokenResponse(access_token=create_access_token(user.id))


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


@router.post("/register", response_model=UserOut, status_code=201)
async def register(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
) -> UserOut:
    """Admin-only: create a new user."""
    existing = await db.execute(select(User).where(User.email == body.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(
        email=body.email,
        display_name=body.display_name,
        hashed_password=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user
