import hashlib
import secrets
from datetime import timedelta
from typing import Any

import bcrypt
import pyotp
from jose import JWTError, jwt

from app.core.config import settings
from app.models import utcnow

# bcrypt's own hard limit — it hashes only the first 72 bytes of its input,
# and (since bcrypt 4.1) raises ValueError past that rather than silently
# truncating. UTF-8 *bytes*, not characters: a password of ordinary-looking
# non-ASCII characters can exceed this well under a naive character-count
# limit (40 "é" is 80 bytes). Enforced here, not just via Field(max_length=)
# on the Pydantic schemas that accept a password, because OAuth2's
# form-based login (POST /auth/token) uses OAuth2PasswordRequestForm, which
# is not a Pydantic model this codebase controls and so cannot carry the
# same declarative bound — verified directly: an over-length password there
# reached bcrypt.checkpw() and crashed with an unhandled 500.
MAX_PASSWORD_BYTES = 72


class PasswordTooLong(ValueError):
    """A password's UTF-8 encoding exceeds bcrypt's 72-byte hashing limit.

    Raised rather than truncating. bcrypt used to truncate silently, which is
    its own hazard: two different passwords sharing the same 72-byte prefix
    then hash identically, so a check that truncates *both* sides during
    verification would treat a long, unrelated password as a match. Rejecting
    up front avoids ever relying on that truncation, for hashing or checking.
    """


def _encode_password(plain: str) -> bytes:
    encoded = plain.encode("utf-8")
    if len(encoded) > MAX_PASSWORD_BYTES:
        raise PasswordTooLong(
            f"password exceeds {MAX_PASSWORD_BYTES} bytes when UTF-8 encoded"
        )
    return encoded


def verify_password(plain: str, hashed: str) -> bool:
    try:
        encoded = _encode_password(plain)
    except PasswordTooLong:
        # Not a match, not a crash — an attacker submitting a long guess (or
        # a legitimate account whose stored hash predates this length being
        # enforced at write time) gets the same "invalid credentials" outcome
        # as any other wrong password, not a 500 that discloses the length
        # limit that a correct guess just failed to clear.
        return False
    return bcrypt.checkpw(encoded, hashed.encode())


def hash_password(plain: str) -> str:
    return bcrypt.hashpw(_encode_password(plain), bcrypt.gensalt()).decode()


def create_access_token(
    subject: Any, token_epoch: int, expires_delta: timedelta | None = None
) -> str:
    """`token_epoch` must be the issuing user's current User.token_epoch.

    Embedding it is what lets a password change revoke every bearer token
    issued before it: decode_access_token compares this against the user's
    *current* epoch on every request, so bumping the column in set_password
    invalidates all of them atomically with the password change, without
    needing a session store or a per-token record to look up.
    """
    expire = utcnow() + (
        expires_delta or timedelta(minutes=settings.access_token_expire_minutes)
    )
    return jwt.encode(
        {"sub": str(subject), "exp": expire, "epc": token_epoch},
        settings.secret_key,
        algorithm=settings.algorithm,
    )


def decode_access_token(token: str) -> tuple[str, int] | None:
    """Returns (user_id, token_epoch) from the token, or None if invalid.

    The caller (get_current_user) still has to compare the returned epoch
    against the user's current one — this only decodes what the token
    claims, since checking it requires a database lookup this function
    doesn't have.

    `int(payload.get("epc", 0))` raises ValueError/TypeError for a
    non-numeric `epc` claim, which JWTError does not cover — signature
    verification only proves the token was signed with this app's key, not
    that every claim inside it has the shape this function expects. Caught
    alongside JWTError so a validly-signed-but-malformed claim is treated
    as an invalid token, not an unhandled 500.
    """
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        if payload.get("totp"):
            return None  # TOTP session tokens must not be accepted as access tokens
        sub = payload.get("sub")
        if sub is None:
            return None
        return sub, int(payload.get("epc", 0))
    except (JWTError, TypeError, ValueError):
        return None


def generate_api_key() -> tuple[str, str]:
    """Return (raw_key, hashed_key). Store only the hash; show raw once."""
    raw = "pa_" + secrets.token_urlsafe(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def generate_password() -> str:
    """Random password meeting the 12-char minimum enforced elsewhere. Shown once; only the hash is stored."""
    return secrets.token_urlsafe(16)


def hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_reset_token() -> tuple[str, str]:
    """Return (raw_token, hashed_token) for a password reset link.

    Only the hash is persisted; the raw token exists solely in the emailed
    URL. 32 bytes of urandom is well beyond guessing range for a token with a
    one-hour lifetime, and mirrors generate_api_key's construction.
    """
    raw = secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def hash_reset_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=email, issuer_name="PA Central")


def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def create_totp_session_token(user_id: int, token_epoch: int, setup: bool = False) -> str:
    """Short-lived token (5 min) that carries the TOTP challenge context.

    `token_epoch` must be the user's User.token_epoch at the moment the
    password was verified (issuance time), not read again later — it is
    what lets totp_verify detect a password reset that happened *during*
    the challenge window. login_json only reaches this after
    _check_credentials has already confirmed the password, so a challenge
    issued here is inherently "the password was correct as of now"; without
    binding that fact to the epoch that was current then, the challenge
    outlives the very credential it was supposed to attest to.
    """
    expire = utcnow() + timedelta(minutes=5)
    return jwt.encode(
        {
            "sub": str(user_id), "exp": expire, "totp": True, "setup": setup,
            "epc": token_epoch,
        },
        settings.secret_key,
        algorithm=settings.algorithm,
    )


def decode_totp_session_token(token: str) -> tuple[int, bool, int] | None:
    """Returns (user_id, is_setup, token_epoch) or None if invalid.

    `token_epoch` defaults to 0 for a token that predates this claim
    existing — such a token cannot have survived a password reset (any
    reset bumps the epoch to at least 1), so it needs no special handling
    beyond the caller's usual epoch comparison. The 5-minute lifetime of
    these tokens means the transition window closed on its own well before
    this code shipped.

    `int(payload["sub"])` and `int(payload.get("epc", 0))` raise
    ValueError/TypeError for a non-numeric claim, and `payload["sub"]`
    raises KeyError if the claim is missing entirely — none of which is a
    JWTError, since signature verification only proves the token was
    signed with this app's key, not that its claims have the shape this
    function expects. Left uncaught, any of these reached totp_verify
    (api/auth.py) as an unhandled exception: its own guard
    (`if not decoded: raise HTTPException(401, ...)`) never runs, so the
    documented "Invalid or expired session" response becomes an unhandled
    500 instead. Caught alongside JWTError so a malformed claim is treated
    the same as any other invalid token.
    """
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        if not payload.get("totp"):
            return None
        return int(payload["sub"]), bool(payload.get("setup")), int(payload.get("epc", 0))
    except (JWTError, TypeError, ValueError, KeyError):
        return None
