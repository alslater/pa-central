"""AES-256-GCM symmetric encryption for secret settings values."""
import base64
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class EncryptionError(Exception):
    pass


def _derive_key(key: str) -> bytes:
    """Derive a 32-byte AES key from an arbitrary-length passphrase via HKDF-SHA256."""
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"pa-central-settings",
    ).derive(key.encode())


def encrypt_value(plaintext: str, key: str) -> str:
    """Encrypt plaintext with AES-256-GCM. Returns base64-encoded nonce+ciphertext."""
    aes = AESGCM(_derive_key(key))
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def decrypt_value(ciphertext: str, key: str) -> str:
    """Decrypt a value produced by encrypt_value. Raises EncryptionError on failure."""
    try:
        raw = base64.b64decode(ciphertext.encode())
        nonce, ct = raw[:12], raw[12:]
        aes = AESGCM(_derive_key(key))
        return aes.decrypt(nonce, ct, None).decode()
    except Exception as exc:
        raise EncryptionError("Decryption failed") from exc
