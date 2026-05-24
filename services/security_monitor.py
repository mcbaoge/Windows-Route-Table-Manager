"""Network security threat/anomaly detection.

Detects:
- ARP spoofing (via gateway MAC changes)
- DNS spoofing (via response inconsistency)
- High-risk ports (e.g., 445, 3389 external)
- Connection flood (DDoS-like behavior)
- DNS tunnel (high-frequency DNS to same domain)
- Anomalous connection bursts

Publishes security alerts to EventBus for GUI display.
"""
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from services.event_bus import get_event_bus
from services.event_types import PacketDropEvent

logger = logging.getLogger(__name__)

HIGH_RISK_PORTS = {445, 135, 139, 3389, 22, 23, 21, 1433, 3306, 5900, 5800, 8080}
PORT_THRESHOLD = 5       # connections to high-risk port within window
FLOOD_THRESHOLD = 50     # total new connections in window
BURST_WINDOW = 5.0       # seconds
DNS_TUNNEL_THRESHOLD = 20  # queries per second to same domain


@dataclass
class SecurityAlert:
    timestamp: float = 0.0
    alert_type: str = ""  # "arp_spoof", "dns_spoof", "high_risk_port", "flood", "dns_tunnel", "burst"
    severity: str = "low"  # "low", "medium", "high", "critical"
    source: str = ""
    target: str = ""
    description: str = ""
    details: dict = field(default_factory=dict)


class ConnectionWindow:
    """Sliding window tracker for connection events."""

    def __init__(self, window_sec: float = BURST_WINDOW):
        self.window_sec = window_sec
        self.entries: list[tuple[float, str, str, int]] = []  # timestamp, src, dst, port

    def add(self, src: str, dst: str, port: int):
        now = time.time()
        self.entries.append((now, src, dst, port))
        self._trim(now)

    def _trim(self, now: float):
        cutoff = now - self.window_sec
        self.entries = [(t, s, d, p) for t, s, d, p in self.entries if t >= cutoff]

    def count_by_dst(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for _, _, dst, _ in self.entries:
            counts[dst] = counts.get(dst, 0) + 1
        return counts

    def count_by_port(self, port: int) -> int:
        return sum(1 for _, _, _, p in self.entries if p == port)

    @property
    def total(self) -> int:
        return len(self.entries)


class SecurityMonitor:
    """Anomaly detection engine for network security events."""

    def __init__(self):
        self._conn_window = ConnectionWindow()
        self._dns_count: dict[str, list[float]] = defaultdict(list)  # domain -> timestamps
        self._prev_gateway_mac: Optional[str] = None
        self._dns_cache: dict[str, set[str]] = {}  # domain -> set of resolved IPs
        self._alerts: list[SecurityAlert] = []
        self._max_alerts = 100
        self._running = False

    @property
    def alerts(self) -> list[SecurityAlert]:
        return list(self._alerts)

    def start(self):
        self._running = True
        self._alerts.clear()

    def stop(self):
        self._running = False

    def record_connection(self, src_addr: str, dst_addr: str, dst_port: int, protocol: str = "TCP"):
        if not self._running:
            return
        self._conn_window.add(src_addr, dst_addr, dst_port)

        if dst_port in HIGH_RISK_PORTS:
            count = self._conn_window.count_by_port(dst_port)
            if count >= PORT_THRESHOLD:
                self._raise_alert(SecurityAlert(
                    timestamp=time.time(),
                    alert_type="high_risk_port",
                    severity="high",
                    source=src_addr,
                    target=dst_addr,
                    description=f"High-risk port {dst_port} targeted ({count} connections)",
                    details={"port": dst_port, "count": count},
                ))

        total = self._conn_window.total
        if total >= FLOOD_THRESHOLD:
            self._raise_alert(SecurityAlert(
                timestamp=time.time(),
                alert_type="flood",
                severity="critical",
                source=src_addr,
                description=f"Connection flood detected ({total} in {BURST_WINDOW}s)",
                details={"count": total, "window": BURST_WINDOW},
            ))

    def record_dns_query(self, domain: str, resolved_ip: str):
        if not self._running:
            return

        now = time.time()
        self._dns_count[domain].append(now)
        # Trim old entries
        self._dns_count[domain] = [t for t in self._dns_count[domain] if now - t < BURST_WINDOW]

        # DNS tunnel detection
        freq = len([t for t in self._dns_count[domain] if now - t < 1.0])
        if freq >= DNS_TUNNEL_THRESHOLD:
            self._raise_alert(SecurityAlert(
                timestamp=now,
                alert_type="dns_tunnel",
                severity="high",
                target=domain,
                description=f"Possible DNS tunnel: {freq} queries/sec to {domain}",
                details={"domain": domain, "freq": freq},
            ))

        # DNS spoofing detection
        if domain in self._dns_cache:
            known_ips = self._dns_cache[domain]
            if known_ips and resolved_ip not in known_ips:
                self._raise_alert(SecurityAlert(
                    timestamp=now,
                    alert_type="dns_spoof",
                    severity="critical",
                    target=domain,
                    description=f"DNS spoofing? {domain} -> {resolved_ip} (expected {known_ips})",
                    details={"domain": domain, "resolved": resolved_ip, "expected": list(known_ips)},
                ))
        else:
            self._dns_cache[domain] = set()
        self._dns_cache[domain].add(resolved_ip)

    def _raise_alert(self, alert: SecurityAlert):
        self._alerts.append(alert)
        if len(self._alerts) > self._max_alerts:
            self._alerts.pop(0)
        logger.warning("Security alert [%s] %s: %s", alert.severity, alert.alert_type, alert.description)
        try:
            get_event_bus().publish(alert)
        except Exception:
            pass

    def check_arp(self, gateway_ip: str, gateway_mac: str) -> bool:
        """Check for ARP spoofing. Returns True if suspicious."""
        if not self._running:
            return False
        if self._prev_gateway_mac is None:
            self._prev_gateway_mac = gateway_mac
            return False
        if self._prev_gateway_mac != gateway_mac:
            self._raise_alert(SecurityAlert(
                timestamp=time.time(),
                alert_type="arp_spoof",
                severity="critical",
                target=gateway_ip,
                description=f"ARP spoofing? Gateway MAC changed to {gateway_mac}",
                details={"gateway_ip": gateway_ip, "new_mac": gateway_mac, "old_mac": self._prev_gateway_mac},
            ))
            self._prev_gateway_mac = gateway_mac
            return True
        return False
