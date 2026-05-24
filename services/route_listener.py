"""Win32 NotifyRouteChange2 wrapper for IPv4 and IPv6.

Thread model:
- NotifyRouteChange2 callbacks arrive on an arbitrary Win32 worker thread.
- We emit a queued pyqtSignal to bridge to the Qt main thread.
- The main thread handler emits routes_changed, consumed by RefreshScheduler.

No debounce here — that's RefreshScheduler's job.
"""

import ctypes
import ctypes.wintypes
import logging
from ctypes import byref

from PyQt5.QtCore import QObject, pyqtSignal

from services.winapi_network import (
    NOTIFY_ROUTE_CALLBACK, _NotifyRouteChange2, _CancelMibChangeNotify2,
)

logger = logging.getLogger(__name__)

ROUTE_HANDLE = ctypes.wintypes.LPVOID

AF_INET = 2
AF_INET6 = 23


class RouteChangeListener(QObject):
    """Monitors system route changes via NotifyRouteChange2 for IPv4 and IPv6.

    Emits ``routes_changed`` on the Qt main thread whenever Win32 detects
    a route table change. No internal debounce — connect this signal to
    RefreshScheduler.mark_dirty() for centralized debounce and merge.
    """

    routes_changed = pyqtSignal()
    _route_update = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._handle_v4 = None
        self._handle_v6 = None
        self._cb_v4 = None
        self._cb_v6 = None

        self._route_update.connect(self._emit)

    def start(self):
        if self._handle_v4 is not None or self._handle_v6 is not None:
            self.stop()

        for fam, attr_handle, attr_cb in [
            (AF_INET, "_handle_v4", "_cb_v4"),
            (AF_INET6, "_handle_v6", "_cb_v6"),
        ]:
            try:
                callback = NOTIFY_ROUTE_CALLBACK(self._make_callback())
                handle = ROUTE_HANDLE()
                ret = _NotifyRouteChange2(byref(handle), callback, None, 1)
                if ret == 0:
                    setattr(self, attr_handle, handle)
                    setattr(self, attr_cb, callback)
                    logger.debug("NotifyRouteChange2 (AF=%d) started", fam)
                else:
                    logger.warning("NotifyRouteChange2 (AF=%d) failed: %d", fam, ret)
            except Exception as e:
                logger.warning("NotifyRouteChange2 (AF=%d) error: %s", fam, e)

        logger.info("RouteChangeListener started (IPv4 + IPv6)")

    def stop(self):
        for handle_attr in ["_handle_v4", "_handle_v6"]:
            h = getattr(self, handle_attr, None)
            if h is not None:
                try:
                    _CancelMibChangeNotify2(h)
                except Exception:
                    pass
                setattr(self, handle_attr, None)
        self._cb_v4 = None
        self._cb_v6 = None
        logger.info("RouteChangeListener stopped")

    def _make_callback(self):
        def _cb(caller_context, row, notification_type):
            self._route_update.emit()
            return 0
        return _cb

    def _emit(self):
        """Called on main thread via queued signal bridge."""
        self.routes_changed.emit()
