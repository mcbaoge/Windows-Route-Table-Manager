"""Traffic statistics tracker with delta-based rate calculation."""
import threading
import time
from dataclasses import dataclass, field


@dataclass
class TrafficSnapshot:
    upload_bytes: int = 0
    download_bytes: int = 0
    upload_packets: int = 0
    download_packets: int = 0
    upload_bps: float = 0.0
    download_bps: float = 0.0
    upload_pps: float = 0.0
    download_pps: float = 0.0


class TrafficTracker:
    """Thread-safe traffic stats tracker.

    Records cumulative bytes/packets and computes real-time rates
    based on delta since the last snapshot request.
    """

    def __init__(self):
        self._lock = threading.Lock()

        self._up_bytes = 0
        self._down_bytes = 0
        self._up_packets = 0
        self._down_packets = 0

        self._prev_up_bytes = 0
        self._prev_down_bytes = 0
        self._prev_up_packets = 0
        self._prev_down_packets = 0
        self._prev_time = time.time()

    def record_up(self, byte_count: int):
        with self._lock:
            self._up_bytes += byte_count
            self._up_packets += 1

    def record_down(self, byte_count: int):
        with self._lock:
            self._down_bytes += byte_count
            self._down_packets += 1

    def snapshot(self) -> TrafficSnapshot:
        """Return current cumulative stats + rate since last snapshot."""
        with self._lock:
            now = time.time()
            dt = now - self._prev_time

            up_delta = self._up_bytes - self._prev_up_bytes
            down_delta = self._down_bytes - self._prev_down_bytes
            up_pkts_delta = self._up_packets - self._prev_up_packets
            down_pkts_delta = self._down_packets - self._prev_down_packets

            up_bps = (up_delta * 8 / dt) if dt > 0 else 0.0
            down_bps = (down_delta * 8 / dt) if dt > 0 else 0.0

            self._prev_up_bytes = self._up_bytes
            self._prev_down_bytes = self._down_bytes
            self._prev_up_packets = self._up_packets
            self._prev_down_packets = self._down_packets
            self._prev_time = now

            up_pps = (up_pkts_delta / dt) if dt > 0 else 0.0
            down_pps = (down_pkts_delta / dt) if dt > 0 else 0.0

            return TrafficSnapshot(
                upload_bytes=self._up_bytes,
                download_bytes=self._down_bytes,
                upload_packets=self._up_packets,
                download_packets=self._down_packets,
                upload_bps=up_bps,
                download_bps=down_bps,
                upload_pps=up_pps,
                download_pps=down_pps,
            )