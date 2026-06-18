import secrets
import hashlib
from datetime import timedelta
from typing import Any

import bcrypt
import pyotp
from jose import JWTError, jwt

from app.core.config import settings
from app.models import utcnow


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def create_access_token(subject: Any, expires_delta: timedelta | None = None) -> str:
    expire = utcnow() + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    return jwt.encode(
        {"sub": str(subject), "exp": expire},
        settings.secret_key,
        algorithm=settings.algorithm,
    )


def decode_access_token(token: str) -> str | None:
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        if payload.get("totp"):
            return None  # TOTP session tokens must not be accepted as access tokens
        return payload.get("sub")
    except JWTError:
        return None


def generate_api_key() -> tuple[str, str]:
    """Return (raw_key, hashed_key). Store only the hash; show raw once."""
    raw = "pa_" + secrets.token_urlsafe(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="PA Central")


def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def create_totp_session_token(user_id: int, setup: bool = False) -> str:
    """Short-lived token (5 min) that carries only the TOTP challenge context."""
    expire = utcnow() + timedelta(minutes=5)
    return jwt.encode(
        {"sub": str(user_id), "exp": expire, "totp": True, "setup": setup},
        settings.secret_key,
        algorithm=settings.algorithm,
    )


def decode_totp_session_token(token: str) -> tuple[int, bool] | None:
    """Returns (user_id, is_setup) or None if invalid."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        if not payload.get("totp"):
            return None
        return int(payload["sub"]), bool(payload.get("setup"))
    except JWTError:
        return None
