"""Async Valkey/Redis client and lock primitives."""
from redis.asyncio import Redis


def get_valkey(url: str) -> Redis:
    return Redis.from_url(url, decode_responses=True)


async def acquire_lock(r: Redis, key: str, ttl_seconds: int) -> bool:
    """SET NX with TTL. Returns True if lock acquired, False if already held."""
    return await r.set(key, "1", nx=True, ex=ttl_seconds) is not None


async def release_lock(r: Redis, key: str) -> None:
    await r.delete(key)
