"""Tests for security utility functions."""
from app.core.security import (
    hash_password, verify_password,
    create_access_token, decode_access_token,
    generate_api_key, hash_api_key,
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


class TestJwtTokens:
    def test_decode_returns_subject(self):
        token = create_access_token(42)
        sub = decode_access_token(token)
        assert sub == "42"

    def test_decode_invalid_token_returns_none(self):
        assert decode_access_token("not.a.token") is None

    def test_decode_empty_string_returns_none(self):
        assert decode_access_token("") is None

    def test_decode_tampered_token_returns_none(self):
        token = create_access_token(1)
        tampered = token[:-5] + "XXXXX"
        assert decode_access_token(tampered) is None


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
        r1, h1 = generate_api_key()
        r2, h2 = generate_api_key()
        assert h1 != h2

    def test_raw_key_not_derivable_from_hash(self):
        raw, hashed = generate_api_key()
        assert raw not in hashed
        assert len(hashed) == 64  # sha256 hex digest
