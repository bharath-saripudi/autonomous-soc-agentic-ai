"""Redis cache service for IOC reputation lookups and session data.

Implements get/set with TTL, cache hit tracking, and bulk operations.
Default TTL: 3600 seconds (1 hour) for IOC lookups.
"""

import json
from typing import Any, Dict, Optional

import redis.asyncio as aioredis
import structlog

from src.config import get_settings

logger = structlog.get_logger()


class RedisCache:
    """Async Redis cache with TTL and hit-rate tracking."""

    def __init__(self, ttl: int = 3600):
        settings = get_settings()
        self.client = aioredis.from_url(
            settings.redis_url,
            decode_responses=True,
        )
        self.default_ttl = ttl
        self._hits = 0
        self._misses = 0

    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached value. Returns None on miss."""
        try:
            value = await self.client.get(key)
            if value:
                self._hits += 1
                return json.loads(value)
            self._misses += 1
            return None
        except Exception as e:
            logger.error("redis_get_error", key=key, error=str(e))
            self._misses += 1
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Store value with TTL. Returns True on success."""
        try:
            serialized = json.dumps(value, default=str)
            await self.client.setex(
                key,
                ttl or self.default_ttl,
                serialized,
            )
            return True
        except Exception as e:
            logger.error("redis_set_error", key=key, error=str(e))
            return False

    async def delete(self, key: str) -> bool:
        """Remove a cached key."""
        try:
            await self.client.delete(key)
            return True
        except Exception as e:
            logger.error("redis_delete_error", key=key, error=str(e))
            return False

    async def exists(self, key: str) -> bool:
        """Check if a key exists in cache."""
        try:
            return bool(await self.client.exists(key))
        except Exception:
            return False

    @property
    def hit_rate(self) -> float:
        """Calculate cache hit rate as percentage."""
        total = self._hits + self._misses
        if total == 0:
            return 0.0
        return round((self._hits / total) * 100, 2)

    @property
    def stats(self) -> Dict[str, Any]:
        """Return cache statistics."""
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate_pct": self.hit_rate,
        }

    async def health_check(self) -> bool:
        """Verify Redis connection is alive."""
        try:
            return await self.client.ping()
        except Exception:
            return False

    async def close(self):
        """Close the Redis connection."""
        await self.client.close()


# ── Singleton instance ──
_cache_instance: Optional[RedisCache] = None


def get_cache(ttl: int = 3600) -> RedisCache:
    """Get or create the singleton Redis cache instance."""
    global _cache_instance
    if _cache_instance is None:
        _cache_instance = RedisCache(ttl=ttl)
    return _cache_instance