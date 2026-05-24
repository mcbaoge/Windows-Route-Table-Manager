"""Async WinAPI-based network stats engine.

Zero subprocess calls. Uses:
- GetIfEntry2         → bandwidth, speed, MTU, oper status
- IcmpSendEcho2       → latency, jitter, packet loss
- GetAdaptersAddresses → DNS servers, adapter gateways
- GetIpStatisticsEx   → packet errors
- get_default_route   → default interface

All async via TaskManager. No ping.exe, no PowerShell, no psutil.
"""

import logging
import time

from PyQt5.QtCore import QObject, QTimer, pyqtSignal

from services.task_manager import get_task_manager
from services.winapi_network import (
    get_if_entry2, get_dns_servers, IcmpPingSession, icmp_ping4,
    format_speed,
)

logger = logging.getLogger(__name__)

PING_TARGETS = ["1.1.1.1", "8.8.8.8"]
PING_SAMPLES = 3
PING_TIMEOUT_MS = 4000
PING_INTERVAL_TICKS = 5
DNS_INTERVAL_TICKS = 30


class BandwidthTracker:
    """Tracks bandwidth via GetIfEntry2 octet deltas.

    Thread-safe: tick() can be called from any thread.
    """

    def __init__(self):
        self._prev_in = 0
        self._prev_out = 0
        self._prev_time = 0.0
        self._iface_index = -1

    def set_iface(self, iface_index: int):
        self._iface_index = iface_index

    def tick(self):
        if self._iface_index < 0:
            return 0.0, 0.0
        now = time.time()
        row = get_if_entry2(self._iface_index)
        if row is None:
            return 0.0, 0.0
        curr_in = row["in_octets"]
        curr_out = row["out_octets"]
        if self._prev_time <= 0:
            self._prev_in = curr_in
            self._prev_out = curr_out
            self._prev_time = now
            return 0.0, 0.0
        elapsed = now - self._prev_time
        if elapsed <= 0:
            return 0.0, 0.0
        up = max(0, (curr_out - self._prev_out)) / elapsed
        down = max(0, (curr_in - self._prev_in)) / elapsed
        self._prev_in = curr_in
        self._prev_out = curr_out
        self._prev_time = now
        return up, down


class NetworkStatsEngine(QObject):
    """Async WinAPI-based network stats engine.

    Signals match StatusPanel's connection interface for drop-in compatibility.
    """

    latency_ready = pyqtSignal(int, int)
    bandwidth_ready = pyqtSignal(float, float)
    dns_ready = pyqtSignal(str)
    default_route_ready = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._bw = BandwidthTracker()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._tick_count = 0
        self._ping_history = {}

    def start(self):
        self._find_default_iface()
        self._do_ping()
        self._do_dns()
        self._timer.start(1000)

    def stop(self):
        self._timer.stop()

    def find_default_iface(self) -> int:
        """Find the interface index for the default IPv4 route."""
        try:
            from network.networking import get_default_route
            route = get_default_route(2)
            if route:
                idx = int(route.interface)
                self._bw.set_iface(idx)
                return idx
        except Exception as e:
            logger.warning("find_default_iface failed: %s", e)
        return -1

    def _find_default_iface(self):
        self.find_default_iface()

    def _tick(self):
        self._tick_count += 1
        self._update_bandwidth()
        if self._tick_count % PING_INTERVAL_TICKS == 0:
            self._do_ping()
        if self._tick_count % DNS_INTERVAL_TICKS == 0:
            self._do_dns()
        if self._tick_count % 5 == 0:
            self._update_iface()

    def _update_iface(self):
        self.find_default_iface()

    def _update_bandwidth(self):
        up, down = self._bw.tick()
        if up or down:
            self.bandwidth_ready.emit(up, down)

    def _do_ping(self):
        tm = get_task_manager()

        def worker():
            latencies = []
            try:
                with IcmpPingSession() as h:
                    for _ in range(PING_SAMPLES):
                        ok, rtt = icmp_ping4(h, "1.1.1.1", PING_TIMEOUT_MS)
                        if ok:
                            latencies.append(rtt)
            except Exception as e:
                logger.debug("ICMP ping 1.1.1.1 error: %s", e)

            r1 = int(sum(latencies) / len(latencies)) if latencies else -1

            latencies2 = []
            try:
                with IcmpPingSession() as h:
                    for _ in range(PING_SAMPLES):
                        ok, rtt = icmp_ping4(h, "8.8.8.8", PING_TIMEOUT_MS)
                        if ok:
                            latencies2.append(rtt)
            except Exception as e:
                logger.debug("ICMP ping 8.8.8.8 error: %s", e)

            r2 = int(sum(latencies2) / len(latencies2)) if latencies2 else -1
            self.latency_ready.emit(r1, r2)

        tm.submit(fn=worker, task_id="stats-ping", timeout=30)

    def _do_dns(self):
        tm = get_task_manager()

        def worker():
            servers = get_dns_servers()
            dns_str = ", ".join(servers) if servers else "获取失败"
            self.dns_ready.emit(dns_str)

        tm.submit(fn=worker, task_id="stats-dns", timeout=10)
