"""Tests for AES-256-GCM encryption utility."""
import pytest

from app.core.encryption import EncryptionError, decrypt_value, encrypt_value


def test_encrypt_decrypt_roundtrip():
    key = "a" * 32
    plaintext = "super-secret-password"
    ciphertext = encrypt_value(plaintext, key)
    assert ciphertext != plaintext
    assert decrypt_value(ciphertext, key) == plaintext


def test_different_encryptions_of_same_value_differ():
    key = "a" * 32
    c1 = encrypt_value("secret", key)
    c2 = encrypt_value("secret", key)
    assert c1 != c2  # random nonce means different ciphertext each time


def test_wrong_key_raises():
    key1 = "a" * 32
    key2 = "b" * 32
    ciphertext = encrypt_value("secret", key1)
    with pytest.raises(EncryptionError):
        decrypt_value(ciphertext, key2)


def test_tampered_ciphertext_raises():
    key = "a" * 32
    ciphertext = encrypt_value("secret", key)
    tampered = ciphertext[:-4] + "xxxx"
    with pytest.raises(EncryptionError):
        decrypt_value(tampered, key)


def test_key_padded_to_32_bytes():
    short_key = "short"
    plaintext = "value"
    ciphertext = encrypt_value(plaintext, short_key)
    assert decrypt_value(ciphertext, short_key) == plaintext
