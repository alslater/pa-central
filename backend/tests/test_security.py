"""Tests for security utility functions."""
import pytest
from jose import jwt

from app.core.config import settings
from app.core.security import (
    MAX_PASSWORD_BYTES,
    PasswordTooLong,
    create_access_token,
    create_totp_session_token,
    decode_access_token,
    decode_totp_session_token,
    generate_api_key,
    hash_api_key,
    hash_password,
    verify_password,
)


class TestPasswordHashing:
    def test_verify_correct_password(self):
        hashed = hash_password("mypassword")
        assert verify_password("mypassword", hashed)

    def test_reject_wrong_password(self):
        hashed = hash_password("mypassword")
        assert not verify_password("wrongpassword", hashed)

    def test_hashes_are_unique(self):
        h1 = hash_password("same")
        h2 = hash_password("same")
        assert h1 != h2  # bcrypt salts differ


class TestPasswordLengthLimit:
    """bcrypt hashes only the first 72 bytes of its input and (since bcrypt
    4.1, this project pins 5.0.0) raises ValueError past that rather than
    silently truncating. Reproduced before this guard existed: a 100-char
    password on POST /auth/login reached bcrypt.checkpw() unvalidated and
    crashed the request with an unhandled 500 — not a validation error.

    The Pydantic-level rejection (app/schemas/__init__.py) is the primary
    defence for JSON endpoints; these tests cover core.security's own guard,
    which is what protects OAuth2PasswordRequestForm-based login
    (POST /auth/token) — not a Pydantic model this codebase controls, so it
    cannot carry the schema-level check at all.
    """

    def test_hash_password_accepts_exactly_the_limit(self):
        hash_password("a" * MAX_PASSWORD_BYTES)

    def test_hash_password_rejects_one_byte_over(self):
        with pytest.raises(PasswordTooLong):
            hash_password("a" * (MAX_PASSWORD_BYTES + 1))

    def test_hash_password_counts_utf8_bytes_not_characters(self):
        """"é" is 2 bytes in UTF-8 — 40 of them is 80 bytes, well over the
        limit, but only 40 characters: a naive character-count check would
        wrongly accept this."""
        multibyte = "é" * 40
        assert len(multibyte) == 40
        assert len(multibyte.encode("utf-8")) == 80
        with pytest.raises(PasswordTooLong):
            hash_password(multibyte)

    def test_verify_password_fails_closed_on_an_overlong_guess(self):
        """Must not crash, and must not disclose the length limit via a
        different error than an ordinary wrong password would produce —
        both return False, indistinguishable to the caller."""
        hashed = hash_password("realpassword123")
        assert verify_password("a" * (MAX_PASSWORD_BYTES + 1), hashed) is False

    def test_verify_password_still_accepts_a_correct_password_at_the_limit(self):
        boundary_password = "a" * MAX_PASSWORD_BYTES
        hashed = hash_password(boundary_password)
        assert verify_password(boundary_password, hashed) is True


class TestJwtTokens:
    def test_decode_returns_subject_and_epoch(self):
        token = create_access_token(42, token_epoch=3)
        decoded = decode_access_token(token)
        assert decoded == ("42", 3)

    def test_decode_invalid_token_returns_none(self):
        assert decode_access_token("not.a.token") is None

    def test_decode_empty_string_returns_none(self):
        assert decode_access_token("") is None

    def test_decode_tampered_token_returns_none(self):
        token = create_access_token(1, token_epoch=0)
        tampered = token[:-5] + "XXXXX"
        assert decode_access_token(tampered) is None

    def test_a_token_from_a_different_epoch_decodes_but_carries_it(self):
        """decode_access_token only reports what the token claims — it has no
        database access to compare against the user's *current* epoch, so a
        stale token still decodes successfully here. Rejecting it is
        get_current_user's job (see TestTokenEpochRevocation in
        test_password_reset.py), not this function's."""
        token = create_access_token(7, token_epoch=5)
        assert decode_access_token(token) == ("7", 5)

    def _sign(self, claims: dict) -> str:
        """A validly-signed token carrying arbitrary claims — bypasses
        create_access_token/create_totp_session_token, which never produce
        a malformed claim, to exercise what decode_*_token does with a
        token whose *signature* is genuine but whose claim shapes are not."""
        return jwt.encode(claims, settings.secret_key, algorithm=settings.algorithm)

    def test_decode_access_token_rejects_a_non_numeric_epc_claim(self):
        """int(payload.get("epc", 0)) raises ValueError for a non-numeric
        claim — not a JWTError, since the signature itself verifies fine.
        Left uncaught, this reached get_current_user as an unhandled
        exception instead of the documented 401."""
        import datetime
        exp = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
        token = self._sign({"sub": "123", "exp": exp, "epc": "not-a-number"})
        assert decode_access_token(token) is None


class TestTotpSessionToken:
    """decode_totp_session_token shares decode_access_token's exact
    ValueError/TypeError/KeyError hazard for a validly-signed token with
    malformed claims — plus its own KeyError case, since it reads
    payload["sub"] directly rather than via .get(). Reproduced directly
    before this fix: each of these raised uncaught out of
    decode_totp_session_token, and reached POST /auth/totp/verify as an
    unhandled 500 instead of the documented 401 "Invalid or expired
    session" — see
    test_a_challenge_token_with_a_malformed_epoch_claim_is_rejected_not_500
    in test_password_reset.py's TestTokenEpochRevocation for that
    HTTP-level consequence."""

    def _sign(self, claims: dict) -> str:
        return jwt.encode(claims, settings.secret_key, algorithm=settings.algorithm)

    def _totp_claims(self, **overrides) -> dict:
        import datetime
        exp = datetime.datetime.now(datetime.UTC) + datetime.timedelta(minutes=5)
        claims = {"sub": "1", "exp": exp, "totp": True, "setup": False, "epc": 0}
        claims.update(overrides)
        return claims

    def test_decode_returns_subject_setup_and_epoch(self):
        token = create_totp_session_token(42, token_epoch=3, setup=True)
        assert decode_totp_session_token(token) == (42, True, 3)

    def test_decode_invalid_token_returns_none(self):
        assert decode_totp_session_token("not.a.token") is None

    def test_decode_a_non_totp_token_returns_none(self):
        token = create_access_token(1, token_epoch=0)
        assert decode_totp_session_token(token) is None

    def test_rejects_a_non_numeric_epc_claim(self):
        token = self._sign(self._totp_claims(epc="not-a-number"))
        assert decode_totp_session_token(token) is None

    def test_rejects_a_non_numeric_sub_claim(self):
        token = self._sign(self._totp_claims(sub="not-an-integer"))
        assert decode_totp_session_token(token) is None

    def test_rejects_a_token_with_no_sub_claim_at_all(self):
        claims = self._totp_claims()
        del claims["sub"]
        token = self._sign(claims)
        assert decode_totp_session_token(token) is None


@pytest.mark.asyncio
class TestMalformedAccessTokenClaimEndToEnd:
    """The unit-level fix (TestJwtTokens above) proves decode_access_token
    itself no longer raises — this proves the actual HTTP-level
    consequence the finding was about: get_current_user's own
    `if not decoded: raise HTTPException(401, ...)` guard only runs if
    decode_access_token returns cleanly. Before the fix, this request
    reached the endpoint as an unhandled ValueError (a 500), not the
    documented 401."""

    def _sign(self, claims: dict) -> str:
        return jwt.encode(claims, settings.secret_key, algorithm=settings.algorithm)

    async def test_a_bearer_token_with_a_malformed_epoch_claim_is_401_not_500(self, client):
        import datetime
        exp = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
        token = self._sign({"sub": "1", "exp": exp, "epc": "not-a-number"})

        r = await client.get(
            "/api/system-settings", headers={"Authorization": f"Bearer {token}"}
        )
        assert r.status_code == 401, (
            f"expected the documented 401 for an invalid token, got "
            f"{r.status_code} — a malformed claim inside a validly-signed "
            "token is reaching the client as an unhandled error"
        )


class TestApiKeyGeneration:
    def test_raw_key_has_pa_prefix(self):
        raw, _ = generate_api_key()
        assert raw.startswith("pa_")

    def test_raw_key_is_unique(self):
        r1, _ = generate_api_key()
        r2, _ = generate_api_key()
        assert r1 != r2

    def test_hash_is_deterministic(self):
        raw, hashed = generate_api_key()
        assert hash_api_key(raw) == hashed

    def test_different_raws_produce_different_hashes(self):
        _r1, h1 = generate_api_key()
        _r2, h2 = generate_api_key()
        assert h1 != h2

    def test_raw_key_not_derivable_from_hash(self):
        raw, hashed = generate_api_key()
        assert raw not in hashed
        assert len(hashed) == 64  # sha256 hex digest
