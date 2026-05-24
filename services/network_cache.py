import time
import threading


class NetworkCache:
    """Thread-safe TTL cache for network data: routes, interfaces, IP info.

    Data is loaded on demand (lazy) and invalidated after ttl_seconds.
    The cache is NOT auto-refreshed — the caller controls refresh()
    or the RouteChangeListener invalidates it.
    """

    def __init__(self, ttl_seconds=2.0):
        self._ttl = ttl_seconds
        self._lock = threading.Lock()
        self._routes = None
        self._routes_time = 0.0
        self._interfaces = None
        self._interfaces_time = 0.0
        self._ip_info = None
        self._ip_info_time = 0.0

    def invalidate_all(self):
        with self._lock:
            self._routes = None
            self._routes_time = 0.0
            self._interfaces = None
            self._interfaces_time = 0.0
            self._ip_info = None
            self._ip_info_time = 0.0

    def get_routes(self, fetcher):
        with self._lock:
            now = time.time()
            if self._routes is not None and (now - self._routes_time) < self._ttl:
                return self._routes
        fresh = fetcher()
        with self._lock:
            self._routes = fresh
            self._routes_time = time.time()
        return fresh

    def get_interfaces(self, fetcher):
        with self._lock:
            now = time.time()
            if self._interfaces is not None and (now - self._interfaces_time) < self._ttl:
                return self._interfaces
        fresh = fetcher()
        with self._lock:
            self._interfaces = fresh
            self._interfaces_time = time.time()
        return fresh

    def get_ip_info(self, fetcher):
        with self._lock:
            now = time.time()
            if self._ip_info is not None and (now - self._ip_info_time) < self._ttl:
                return self._ip_info
        fresh = fetcher()
        with self._lock:
            self._ip_info = fresh
            self._ip_info_time = time.time()
        return fresh
