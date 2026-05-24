"""Real-time per-interface bandwidth monitor using GetIfEntry2.

Reads MIB_IF_ROW2 octet counters per interface, computes delta-based
byte/sec rates with EMA smoothing. Zero subprocess calls.

Thread model: PeriodicTaskMgr via TaskManager (QTimer + pool).
"""
import logging
import time
from typing import Optional

from services.winapi_network import get_if_entry2 as _winapi_get_if_entry2

logger = logging.getLogger(__name__)

EMA_ALPHA = 0.3
MAX_SANE_BYTES_PER_SEC = 10 * 1024 * 1024 * 1024  # 10 GB/s — anything above is a wraparound glitch


def get_if_entry2(iface_index: int) -> Optional[dict]:
    """Get interface stats — delegates to winapi_network's proven struct."""
    return _winapi_get_if_entry2(iface_index)


class InterfaceBandwidthTracker:
    """Tracks bandwidth via GetIfEntry2 with EMA smoothing.

    Thread-safe: tick() can be called from any thread.
    """

    def __init__(self, iface_index: int = -1):
        self.iface_index = iface_index
        self._prev_in = 0
        self._prev_out = 0
        self._prev_in_pkts = 0
        self._prev_out_pkts = 0
        self._prev_time = 0.0
        self.rx_rate = 0.0
        self.tx_rate = 0.0
        self.packets_rate = 0.0
        self._initialized = False

    def tick(self) -> tuple[float, float, float]:
        """Compute rates. Returns (rx_bytes_s, tx_bytes_s, packets_s)."""
        if self.iface_index < 0:
            return 0.0, 0.0, 0.0

        row = get_if_entry2(self.iface_index)
        if row is None:
            return self.rx_rate, self.tx_rate, self.packets_rate

        now = time.time()
        curr_in = row["in_octets"]
        curr_out = row["out_octets"]
        curr_in_pkts = row.get("in_ucast_pkts", 0)
        curr_out_pkts = row.get("out_ucast_pkts", 0)

        if not self._initialized:
            self._prev_in = curr_in
            self._prev_out = curr_out
            self._prev_in_pkts = curr_in_pkts
            self._prev_out_pkts = curr_out_pkts
            self._prev_time = now
            self._initialized = True
            return 0.0, 0.0, 0.0

        elapsed = now - self._prev_time
        if elapsed <= 0:
            return self.rx_rate, self.tx_rate, self.packets_rate

        # Compute raw deltas with 64-bit wraparound guard
        in_delta = self._delta64(curr_in, self._prev_in)
        out_delta = self._delta64(curr_out, self._prev_out)
        pkt_delta = self._delta64(curr_in_pkts + curr_out_pkts,
                                   self._prev_in_pkts + self._prev_out_pkts)

        raw_rx = in_delta / elapsed
        raw_tx = out_delta / elapsed
        raw_pkts = pkt_delta / elapsed

        # Sanity clamp: if any rate exceeds MAX_SANE, assume wraparound glitch
        # and keep previous smoothed value.
        if raw_rx > MAX_SANE_BYTES_PER_SEC or raw_tx > MAX_SANE_BYTES_PER_SEC:
            logger.debug("Bandwidth spike clamped: rx=%.0f tx=%.0f B/s (iface=%d)",
                         raw_rx, raw_tx, self.iface_index)
            return self.rx_rate, self.tx_rate, self.packets_rate

        # EMA smoothing
        self.rx_rate = self.rx_rate * (1 - EMA_ALPHA) + raw_rx * EMA_ALPHA
        self.tx_rate = self.tx_rate * (1 - EMA_ALPHA) + raw_tx * EMA_ALPHA
        self.packets_rate = self.packets_rate * (1 - EMA_ALPHA) + raw_pkts * EMA_ALPHA

        self._prev_in = curr_in
        self._prev_out = curr_out
        self._prev_in_pkts = curr_in_pkts
        self._prev_out_pkts = curr_out_pkts
        self._prev_time = now

        return self.rx_rate, self.tx_rate, self.packets_rate

    @staticmethod
    def _delta64(curr: int, prev: int) -> int:
        """64-bit counter wraparound-safe difference.

        Returns 0 if the delta is negative (counter reinit/broken API).
        """
        if curr >= prev:
            return curr - prev
        # 64-bit wraparound: curr has wrapped past 2^64
        wrapped = curr + (0xFFFFFFFFFFFFFFFF - prev)
        # If wrapped result is still larger than 10 GB in bytes, it's a glitch
        if wrapped > 10 * 1024 * 1024 * 1024:
            return 0
        return wrapped


def format_bandwidth(bytes_per_sec: float) -> str:
    """Auto-scale bytes/sec to human-readable string."""
    if bytes_per_sec < 0 or bytes_per_sec > 1e15:
        return "-"
    if bytes_per_sec < 1024:
        return f"{bytes_per_sec:.1f} B/s"
    elif bytes_per_sec < 1024 * 1024:
        return f"{bytes_per_sec / 1024:.1f} KB/s"
    elif bytes_per_sec < 1024 * 1024 * 1024:
        return f"{bytes_per_sec / 1024 / 1024:.1f} MB/s"
    return f"{bytes_per_sec / 1024 / 1024 / 1024:.2f} GB/s"
