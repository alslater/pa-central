"""Tests for Valkey lock helpers. Requires Redis/Valkey on localhost:6379."""
import socket

import pytest

from app.core.valkey import acquire_lock, get_valkey, release_lock

TEST_KEY = "test:valkey:lock_test"
VALKEY_URL = "redis://localhost:6379"


def _valkey_available() -> bool:
    try:
        with socket.create_connection(("localhost", 6379), timeout=1):
            return True
    except OSError:
        return False


valkey_required = pytest.mark.skipif(
    not _valkey_available(),
    reason="Redis/Valkey not available on localhost:6379",
)


@pytest.fixture(autouse=True)
async def cleanup():
    yield
    if not _valkey_available():
        return
    r = get_valkey(VALKEY_URL)
    await r.delete(TEST_KEY)
    await r.aclose()


@valkey_required
async def test_acquire_lock_succeeds_when_free():
    r = get_valkey(VALKEY_URL)
    acquired = await acquire_lock(r, TEST_KEY, ttl_seconds=10)
    assert acquired is True
    await r.aclose()


@valkey_required
async def test_acquire_lock_fails_when_held():
    r = get_valkey(VALKEY_URL)
    await acquire_lock(r, TEST_KEY, ttl_seconds=10)
    acquired_again = await acquire_lock(r, TEST_KEY, ttl_seconds=10)
    assert acquired_again is False
    await r.aclose()


@valkey_required
async def test_release_lock_allows_reacquire():
    r = get_valkey(VALKEY_URL)
    await acquire_lock(r, TEST_KEY, ttl_seconds=10)
    await release_lock(r, TEST_KEY)
    acquired = await acquire_lock(r, TEST_KEY, ttl_seconds=10)
    assert acquired is True
    await r.aclose()


@valkey_required
async def test_release_nonexistent_lock_is_safe():
    r = get_valkey(VALKEY_URL)
    await release_lock(r, "test:valkey:nonexistent")
    await r.aclose()
