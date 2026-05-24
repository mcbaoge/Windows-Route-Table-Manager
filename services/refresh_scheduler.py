"""Centralized refresh scheduler with debounce and merge.

Problem:
  VPN switch → NotifyRouteChange2 fires dozens of times per second.
  Both RouteChangeListener and EventTracer have independent Win32 handles,
  each firing separate debounce → double/triple refresh cycles.

Solution:
  RefreshScheduler aggregates ALL "routes may have changed" notifications
  from every source into a single dirty flag. A QTimer singleShot provides
  the debounce window. After the window closes, one unified refresh_requested
  signal fires — consumed by route table, topology, cache, etc.

Sources:
  - RouteChangeListener (IPv4 + IPv6 Win32 notifications)
  - EventTracer._poll_routes (periodic route scan)
  - RouteTableTab._on_family_changed
  - Manual refresh button

Consumers:
  - RouteTableTab: submit_serial("route-refresh", ...)
  - TopologyWidget: refresh()
  - CacheManager: invalidate_all()
"""

import logging
import threading

from PyQt5.QtCore import QObject, Qt, QTimer, pyqtSignal

logger = logging.getLogger(__name__)


class RefreshScheduler(QObject):
    """Aggregates route change notifications into a single debounced refresh.

    Thread-safe: mark_dirty() can be called from any thread.
    The debounce timer and signal emission always happen on the Qt main thread.

    Usage:
        scheduler = RefreshScheduler(debounce_ms=500)

        # Sources call this from any thread:
        scheduler.mark_dirty()

        # Consumers connect:
        scheduler.refresh_requested.connect(self._do_refresh)
    """

    refresh_requested = pyqtSignal()
    _dispatch = pyqtSignal()

    def __init__(self, parent=None, debounce_ms: int = 500):
        super().__init__(parent)
        self._debounce_ms = debounce_ms
        self._dirty = False
        self._lock = threading.Lock()

        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(debounce_ms)
        self._timer.timeout.connect(self._flush)

        self._dispatch.connect(self._on_dispatch, Qt.QueuedConnection)

    @property
    def debounce_ms(self) -> int:
        return self._debounce_ms

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def mark_dirty(self):
        """Signal that routes may have changed. Thread-safe.

        Can be called from:
        - Win32 NotifyRouteChange2 callbacks (any thread)
        - QTimer poll handlers (main thread)
        - Manual refresh button clicks (main thread)

        Each call restarts the debounce window (extend on burst).
        """
        with self._lock:
            self._dirty = True
        self._dispatch.emit()

    def _on_dispatch(self):
        """Called on main thread via queued signal. Restarts the debounce timer.

        During a VPN switch, rapid mark_dirty() calls queue multiple
        _on_dispatch invocations — each one restarts the timer, so the
        actual refresh fires 500ms after the *last* notification.
        """
        self._timer.start()

    def _flush(self):
        """Debounce window closed. Emit if dirty."""
        with self._lock:
            if not self._dirty:
                return
            self._dirty = False

        logger.debug("RefreshScheduler firing refresh_requested")
        self.refresh_requested.emit()

    def force_refresh(self):
        """Bypass debounce, fire immediately."""
        with self._lock:
            self._dirty = False
            self._timer.stop()
        logger.debug("RefreshScheduler force refresh")
        self.refresh_requested.emit()

    def cancel(self):
        """Cancel pending refresh."""
        with self._lock:
            self._dirty = False
            self._timer.stop()
