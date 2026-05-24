"""RTT / packet loss monitoring via ICMP ping.

Pings gateway, 1.1.1.1, 8.8.8.8 in a background thread pool.
Computes RTT, jitter, and loss percentage with EMA smoothing.

Thread model: PeriodicTaskMgr via TaskManager.
Emits results via pyqtSignal for thread-safe GUI updates.
"""
import logging
import time
import statistics
from typing import Optional

from PyQt5.QtCore import QObject, pyqtSignal

from services.task_manager import get_task_manager
from services.winapi_network import IcmpPingSession, icmp_ping4

logger = logging.getLogger(__name__)

PING_SAMPLES = 4
PING_TIMEOUT_MS = 3000
PING_INTERVAL_TICKS = 5  # every 5 seconds
EMA_ALPHA = 0.25


class RttMonitor(QObject):
    """Monitors RTT and packet loss to gateway and internet targets."""

    rtt_updated = pyqtSignal(str, float, float, float)  # target, rtt_ms, loss%, jitter_ms
    all_updated = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._targets = {
            "gateway": {"host": "", "rtt": 0.0, "loss": 0.0, "jitter": 0.0},
            "cloudflare": {"host": "1.1.1.1", "rtt": 0.0, "loss": 0.0, "jitter": 0.0},
            "google": {"host": "8.8.8.8", "rtt": 0.0, "loss": 0.0, "jitter": 0.0},
            "dns": {"host": "", "rtt": 0.0, "loss": 0.0, "jitter": 0.0},
        }
        self._tick_count = 0
        self._running = False

    def set_gateway(self, gw_ip: str):
        self._targets["gateway"]["host"] = gw_ip

    def set_dns(self, dns_ip: str):
        self._targets["dns"]["host"] = dns_ip

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def tick(self):
        """Call this periodically (e.g. every 1s from a timer)."""
        if not self._running:
            return
        self._tick_count += 1
        if self._tick_count % PING_INTERVAL_TICKS != 0:
            return

        tm = get_task_manager()

        for key, info in self._targets.items():
            host = info["host"]
            if not host:
                continue

            def _ping(key=key, host=host):
                latencies = []
                fails = 0
                try:
                    with IcmpPingSession() as h:
                        for _ in range(PING_SAMPLES):
                            ok, rtt = icmp_ping4(h, host, PING_TIMEOUT_MS)
                            if ok:
                                latencies.append(rtt)
                            else:
                                fails += 1
                except Exception as e:
                    logger.debug("Ping %s error: %s", host, e)
                    fails = PING_SAMPLES

                total = len(latencies) + fails
                loss_pct = (fails / total * 100) if total > 0 else 100.0
                avg_rtt = statistics.mean(latencies) if latencies else -1.0
                jitter = statistics.stdev(latencies) if len(latencies) > 1 else 0.0

                self._apply_ema(key, avg_rtt, loss_pct, jitter)
                info = self._targets[key]
                self.rtt_updated.emit(key, info["rtt"], info["loss"], info["jitter"])
                self.all_updated.emit()

            tm.submit(fn=_ping, task_id=f"rtt-{key}", timeout=10)

    def _apply_ema(self, key: str, rtt: float, loss: float, jitter: float):
        info = self._targets[key]
        if rtt >= 0:
            if info["rtt"] == 0:
                info["rtt"] = rtt
            else:
                info["rtt"] = info["rtt"] * (1 - EMA_ALPHA) + rtt * EMA_ALPHA
        if info["loss"] == 0:
            info["loss"] = loss
        else:
            info["loss"] = info["loss"] * (1 - EMA_ALPHA) + loss * EMA_ALPHA
        if info["jitter"] == 0:
            info["jitter"] = jitter
        else:
            info["jitter"] = info["jitter"] * (1 - EMA_ALPHA) + jitter * EMA_ALPHA

    def get_rtt(self, key: str = "gateway") -> float:
        return self._targets.get(key, {}).get("rtt", 0.0)

    def get_loss(self, key: str = "gateway") -> float:
        return self._targets.get(key, {}).get("loss", 0.0)

    def get_jitter(self, key: str = "gateway") -> float:
        return self._targets.get(key, {}).get("jitter", 0.0)

    def get_summary(self) -> dict:
        return dict(self._targets)
