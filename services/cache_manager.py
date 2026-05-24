"""Unified cache layer — single source of truth for all network data.

All modules read from CacheManager instead of calling WinAPI directly.
Invalidated by RouteChangeListener / EventTracer via RefreshScheduler.

Features:
- Thread-safe (RLock)
- Version number per key
- Dynamic TTL (extend on error)
- Cache stats (hit rate, miss rate)
- Background refresh (stale-while-revalidate)
- Snapshot/rollback foundation (for future sqlite persistence)
"""

import copy
import logging
import threading
import time
from typing import Any, Callable, Optional

from services.task_manager import get_task_manager
from services.winapi_network import (
    get_routes, get_interfaces, get_interface_ipv4_info,
)

logger = logging.getLogger(__name__)

_EMPTY = object()


class CacheEntry:
    __slots__ = (
        "key", "value", "ttl", "base_ttl", "created_at",
        "version", "last_error", "error_count", "fetched_count",
        "background_pending",
    )

    def __init__(self, key: str, value: Any, ttl: float, version: int = 0):
        self.key = key
        self.value = value
        self.ttl = ttl
        self.base_ttl = ttl
        self.created_at = time.monotonic()
        self.version = version
        self.last_error: Optional[str] = None
        self.error_count = 0
        self.fetched_count = 0
        self.background_pending = False

    @property
    def expired(self) -> bool:
        return time.monotonic() - self.created_at > self.ttl

    @property
    def age(self) -> float:
        return time.monotonic() - self.created_at

    def touch(self):
        self.created_at = time.monotonic()

    def is_empty(self) -> bool:
        return self.value is _EMPTY


class CacheStats:
    __slots__ = ("hits", "misses", "errors", "background_refreshes")

    def __init__(self):
        self.hits = 0
        self.misses = 0
        self.errors = 0
        self.background_refreshes = 0

    @property
    def total(self) -> int:
        return self.hits + self.misses

    @property
    def hit_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.hits / self.total

    @property
    def miss_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.misses / self.total

    def __repr__(self) -> str:
        return (f"CacheStats(hits={self.hits}, misses={self.misses}, "
                f"errors={self.errors}, bg_refresh={self.background_refreshes}, "
                f"hit_rate={self.hit_rate:.1%})")


class CacheManager:
    """Thread-safe TTL cache for network data.

    All data sources register their fetcher callbacks here.
    Listeners call invalidate() on route/interface changes.
    """

    def __init__(self):
        self._lock = threading.RLock()
        self._entries: dict[str, CacheEntry] = {}
        self._fetchers: dict[str, Callable] = {}
        self._version_counter = 0
        self._stats = CacheStats()

        self.register("routes", get_routes, ttl=2.0)
        self.register("interfaces", get_interfaces, ttl=5.0)
        self.register("iface_ipv4_info", get_interface_ipv4_info, ttl=5.0)

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register(self, key: str, fetcher: Callable, ttl: float = 2.0):
        with self._lock:
            self._fetchers[key] = fetcher
            if key not in self._entries:
                self._entries[key] = CacheEntry(key, _EMPTY, ttl, 0)

    @property
    def registered_keys(self) -> list[str]:
        with self._lock:
            return list(self._fetchers.keys())

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def _next_version(self) -> int:
        self._version_counter += 1
        return self._version_counter

    def _fetch(self, key: str, entry: CacheEntry):
        """Call the fetcher, update entry in-place (caller must hold lock)."""
        fetcher = self._fetchers.get(key)
        if fetcher is None:
            raise KeyError(f"Unknown cache key: {key}")
        try:
            new_value = fetcher()
            entry.value = new_value
            entry.version = self._next_version()
            entry.last_error = None
            entry.error_count = 0
            entry.ttl = entry.base_ttl
            entry.fetched_count += 1
            entry.touch()
            logger.log(5, "Cache refreshed: %s (v%d)", key, entry.version)
        except Exception as e:
            entry.last_error = str(e)
            entry.error_count += 1
            entry.ttl = min(entry.base_ttl * (1 + entry.error_count), 60.0)
            logger.warning("Cache fetch failed for '%s' (x%d): %s",
                           key, entry.error_count, e)
            if entry.is_empty():
                raise
            self._stats.errors += 1

    def get(self, key: str, force_refresh: bool = False) -> Any:
        """Get cached value. Auto-fetches if expired or force_refresh.

        On fetch error, returns stale value if available; raises if empty.
        """
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                raise KeyError(f"Unknown cache key: {key}")

            if entry.is_empty() or force_refresh or entry.expired:
                self._stats.misses += 1
                self._fetch(key, entry)
            else:
                self._stats.hits += 1

            return entry.value

    def get_or_refresh(self, key: str) -> Any:
        """Stale-while-revalidate: return cached value immediately,
        refresh asynchronously in background if stale.

        Never blocks on background refresh. Best for UI rendering.
        """
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                raise KeyError(f"Unknown cache key: {key}")

            if entry.is_empty():
                self._stats.misses += 1
                self._fetch(key, entry)
                return entry.value

            if entry.expired and not entry.background_pending:
                entry.background_pending = True
                self._refresh_background(key)

            self._stats.hits += 1
            return entry.value

    @property
    def stats(self) -> CacheStats:
        with self._lock:
            s = CacheStats()
            s.hits = self._stats.hits
            s.misses = self._stats.misses
            s.errors = self._stats.errors
            s.background_refreshes = self._stats.background_refreshes
            return s

    def entry_info(self, key: str) -> Optional[dict]:
        """Get info about a cached entry without accessing its value."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            return {
                "version": entry.version,
                "age": entry.age,
                "ttl": entry.ttl,
                "expired": entry.expired,
                "error_count": entry.error_count,
                "last_error": entry.last_error,
                "fetched_count": entry.fetched_count,
                "is_empty": entry.is_empty(),
            }

    # ------------------------------------------------------------------
    # Background refresh
    # ------------------------------------------------------------------

    def _refresh_background(self, key: str):
        """Submit a background refresh task for the given key."""
        self._stats.background_refreshes += 1
        tm = get_task_manager()

        def _bg():
            with self._lock:
                entry = self._entries.get(key)
                if entry is None:
                    return
                try:
                    self._fetch(key, entry)
                finally:
                    entry.background_pending = False

        tm.submit(fn=_bg, task_id=f"cache-bg-{key}", timeout=30)

    # ------------------------------------------------------------------
    # Write / Invalidate
    # ------------------------------------------------------------------

    def invalidate(self, key: str):
        """Mark cache entry as expired. Next get() will re-fetch."""
        with self._lock:
            entry = self._entries.get(key)
            if entry:
                entry.created_at = 0
                logger.log(5, "Cache invalidated: %s", key)

    def invalidate_all(self):
        """Mark all cache entries as expired."""
        with self._lock:
            for entry in self._entries.values():
                entry.created_at = 0
        logger.debug("All cache invalidated")

    def set(self, key: str, value: Any):
        """Directly populate cache (for pre-loaded data)."""
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                raise KeyError(f"Unknown cache key: {key}")
            entry.value = value
            entry.version = self._next_version()
            entry.last_error = None
            entry.error_count = 0
            entry.fetched_count += 1
            entry.touch()

    # ------------------------------------------------------------------
    # Warmup
    # ------------------------------------------------------------------

    def warmup(self):
        """Pre-fetch all registered data sources in TaskManager pool."""
        def _warm():
            for key in list(self._fetchers.keys()):
                try:
                    self.get(key, force_refresh=True)
                except Exception as e:
                    logger.warning("Cache warmup '%s' failed: %s", key, e)

        tm = get_task_manager()
        tm.submit(fn=_warm, task_id="cache-warmup", timeout=30)

    # ------------------------------------------------------------------
    # Snapshot / Rollback (foundation for future sqlite persistence)
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        """Serialize all cache entries (value, version, ttl, timestamp).

        Use this for sqlite persistence or export.
        """
        with self._lock:
            snap = {}
            for key, entry in self._entries.items():
                if not entry.is_empty():
                    snap[key] = {
                        "value": copy.deepcopy(entry.value),
                        "version": entry.version,
                        "ttl": entry.base_ttl,
                        "created_at": entry.created_at,
                        "fetched_count": entry.fetched_count,
                    }
            return {
                "version": self._version_counter,
                "entries": snap,
                "timestamp": time.time(),
            }

    def rollback(self, snapshot: dict):
        """Restore cache state from a snapshot.

        Invalidates keys not in snapshot; restores matching keys.
        """
        with self._lock:
            snap_entries = snapshot.get("entries", {})
            for key, entry in self._entries.items():
                if key in snap_entries:
                    se = snap_entries[key]
                    entry.value = copy.deepcopy(se["value"])
                    entry.version = se.get("version", 0)
                    entry.ttl = se.get("ttl", entry.base_ttl)
                    entry.created_at = se.get("created_at", 0)
                    entry.last_error = None
                    entry.error_count = 0
                else:
                    entry.created_at = 0
                    entry.value = _EMPTY
            self._version_counter = snapshot.get("version", 0)
        logger.info("Cache rollback applied (%d entries)", len(snap_entries))

    def clear(self):
        """Clear all cached values (keep registrations)."""
        with self._lock:
            for entry in self._entries.values():
                entry.value = _EMPTY
                entry.created_at = 0
                entry.version = 0
                entry.last_error = None
                entry.error_count = 0
        logger.debug("Cache cleared")


_cache_manager: Optional[CacheManager] = None
_lock = threading.Lock()


def get_cache() -> CacheManager:
    global _cache_manager
    if _cache_manager is None:
        with _lock:
            if _cache_manager is None:
                _cache_manager = CacheManager()
    return _cache_manager
