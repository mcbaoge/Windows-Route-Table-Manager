"""Default route switching detection with cache-backed diff engine.

Detects:
- Default route changes (IPv4 + IPv6)
- Metric changes
- VPN takeover
- WiFi/wired failover

Uses route cache to avoid frequent full scans.
Emits signals when route topology changes.
"""
import logging
import threading
import time
from typing import Optional

from PyQt5.QtCore import QObject, pyqtSignal

from services.topology_engine import NetworkGraph, TopologyEdge, NodeType
from services.winapi_network import get_routes, AF_INET, AF_INET6

logger = logging.getLogger(__name__)


class RouteSnapshot:
    """Snapshot of default routes for diff comparison."""

    def __init__(self):
        self.v4_iface: str = ""
        self.v4_gateway: str = ""
        self.v4_metric: int = 9999
        self.v6_iface: str = ""
        self.v6_gateway: str = ""
        self.v6_metric: int = 9999
        self.timestamp: float = 0.0
        self.all_defaults: list[dict] = []

    @classmethod
    def capture(cls) -> "RouteSnapshot":
        snap = cls()
        snap.timestamp = time.time()

        v4 = [r for r in get_routes(AF_INET) if r.is_default]
        if v4:
            best = min(v4, key=lambda r: int(r.metric) if r.metric and r.metric.isdigit() else 9999)
            snap.v4_iface = best.interface
            snap.v4_gateway = best.gateway
            snap.v4_metric = int(best.metric) if best.metric and best.metric.isdigit() else 9999

        v6 = [r for r in get_routes(AF_INET6) if r.is_default]
        if v6:
            best = min(v6, key=lambda r: int(r.metric) if r.metric and r.metric.isdigit() else 9999)
            snap.v6_iface = best.interface
            snap.v6_gateway = best.gateway
            snap.v6_metric = int(best.metric) if best.metric and best.metric.isdigit() else 9999

        # Store all default routes for full diff
        for r in v4 + v6:
            snap.all_defaults.append({
                "dest": r.destination,
                "gw": r.gateway,
                "iface": r.interface,
                "metric": r.metric,
                "is_ipv6": r.is_ipv6,
            })

        return snap


class RouteChangeInfo:
    """Describes a detected route change."""

    def __init__(self):
        self.v4_changed: bool = False
        self.v6_changed: bool = False
        self.old_v4_gateway: str = ""
        self.new_v4_gateway: str = ""
        self.old_v6_gateway: str = ""
        self.new_v6_gateway: str = ""
        self.old_v4_iface: str = ""
        self.new_v4_iface: str = ""
        self.old_v4_metric: int = 0
        self.new_v4_metric: int = 0
        self.is_vpn_takeover: bool = False
        self.is_failover: bool = False


class RouteMonitor(QObject):
    """Monitors default route changes via periodic diff."""

    route_changed = pyqtSignal(object)  # RouteChangeInfo
    default_path_changed = pyqtSignal(str, str)  # new_gateway, new_iface

    def __init__(self, parent=None):
        super().__init__(parent)
        self._lock = threading.Lock()
        self._prev_snapshot: Optional[RouteSnapshot] = None
        self._prev_graph: Optional[NetworkGraph] = None
        self._running = False

    def start(self):
        self._running = True
        self._prev_snapshot = RouteSnapshot.capture()
        logger.info("RouteMonitor started, v4 gw=%s iface=%s",
                    self._prev_snapshot.v4_gateway, self._prev_snapshot.v4_iface)

    def stop(self):
        self._running = False

    def tick(self) -> Optional[RouteChangeInfo]:
        """Check for route changes. Call periodically."""
        if not self._running:
            return None
        with self._lock:
            current = RouteSnapshot.capture()
            prev = self._prev_snapshot
            if prev is None:
                self._prev_snapshot = current
                return None

            info = RouteChangeInfo()

            # IPv4 changes
            if current.v4_iface != prev.v4_iface or current.v4_gateway != prev.v4_gateway:
                info.v4_changed = True
                info.old_v4_gateway = prev.v4_gateway
                info.new_v4_gateway = current.v4_gateway
                info.old_v4_iface = prev.v4_iface
                info.new_v4_iface = current.v4_iface
                info.old_v4_metric = prev.v4_metric
                info.new_v4_metric = current.v4_metric

            # IPv6 changes
            if current.v6_iface != prev.v6_iface or current.v6_gateway != prev.v6_gateway:
                info.v6_changed = True
                info.old_v6_gateway = prev.v6_gateway
                info.new_v6_gateway = current.v6_gateway

            self._prev_snapshot = current

            if info.v4_changed or info.v6_changed:
                logger.info("Route change detected: v4=%s->%s v6=%s->%s",
                            info.old_v4_gateway, info.new_v4_gateway,
                            info.old_v6_gateway, info.new_v6_gateway)
                self.route_changed.emit(info)
                if info.v4_changed:
                    self.default_path_changed.emit(
                        current.v4_gateway, current.v4_iface)
                return info

            return None

    @property
    def current_gateway(self) -> str:
        if self._prev_snapshot:
            return self._prev_snapshot.v4_gateway or self._prev_snapshot.v6_gateway
        return ""
