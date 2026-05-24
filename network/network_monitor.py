"""Network monitoring — UI and backend.

Refactored to use NetworkStatsEngine (pure WinAPI, no subprocess).
StatusPanel is unchanged; NetworkMonitor is a thin wrapper.
"""

import logging

from PyQt5.QtCore import QObject, pyqtSignal
from PyQt5.QtWidgets import QGroupBox, QGridLayout, QLabel

from services.network_stats_engine import NetworkStatsEngine
from services.winapi_network import format_speed

logger = logging.getLogger(__name__)


class NetworkMonitor(QObject):
    """Thin wrapper around NetworkStatsEngine for backward compatibility.

    All monitoring is done by NetworkStatsEngine via WinAPI / TaskManager.
    """

    latency_ready = pyqtSignal(int, int)
    bandwidth_ready = pyqtSignal(float, float)
    dns_ready = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._engine = NetworkStatsEngine(self)
        self._engine.latency_ready.connect(self.latency_ready)
        self._engine.bandwidth_ready.connect(self.bandwidth_ready)
        self._engine.dns_ready.connect(self.dns_ready)

    def start(self):
        self._engine.start()

    def stop(self):
        self._engine.stop()


class StatusPanel(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("网络状态", parent)
        self.setMinimumHeight(100)

        grid = QGridLayout(self)
        grid.setVerticalSpacing(3)
        grid.setHorizontalSpacing(12)

        self.status_dot = QLabel("● 检测中...")
        self.status_dot.setStyleSheet("color: #888888; font-size: 13px; font-weight: bold;")
        grid.addWidget(self.status_dot, 0, 0, 1, 6)

        grid.addWidget(QLabel("默认出口:"), 1, 0)
        self.default_exit = QLabel("-")
        grid.addWidget(self.default_exit, 1, 1)
        grid.addWidget(QLabel("公网 IP:"), 1, 2)
        self.public_ip = QLabel("-")
        grid.addWidget(self.public_ip, 1, 3)

        grid.addWidget(QLabel("延迟:"), 2, 0)
        self.latency = QLabel("-")
        grid.addWidget(self.latency, 2, 1)
        grid.addWidget(QLabel("上行:"), 2, 2)
        self.up_speed = QLabel("-")
        grid.addWidget(self.up_speed, 2, 3)
        grid.addWidget(QLabel("下行:"), 2, 4)
        self.down_speed = QLabel("-")
        grid.addWidget(self.down_speed, 2, 5)

        grid.addWidget(QLabel("网关:"), 3, 0)
        self.gateway = QLabel("-")
        grid.addWidget(self.gateway, 3, 1)
        grid.addWidget(QLabel("DNS:"), 3, 2)
        self.dns = QLabel("-")
        grid.addWidget(self.dns, 3, 3)

        grid.setColumnStretch(5, 1)

    def _set_status(self, text, color):
        self.status_dot.setText(text)
        self.status_dot.setStyleSheet(
            f"color: {color}; font-size: 13px; font-weight: bold;"
        )

    def set_online(self):
        self._set_status("● 在线", "#4CAF50")

    def set_high_latency(self):
        self._set_status("● 高延迟", "#FFC107")

    def set_offline(self):
        self._set_status("● 断网", "#F44336")

    def update_default_info(self, iface_label, gw):
        self.default_exit.setText(iface_label or "-")
        self.gateway.setText(gw or "-")

    def update_latency(self, ms1, ms2):
        if ms1 >= 0 or ms2 >= 0:
            vals = [v for v in (ms1, ms2) if v >= 0]
            avg = sum(vals) // len(vals)
            self.latency.setText(f"{avg}ms")
            if avg < 100:
                self.set_online()
            elif avg < 300:
                self.set_high_latency()
            else:
                self.set_offline()
        elif ms1 < 0 and ms2 < 0:
            self.latency.setText("超时")
            self.set_offline()
        else:
            self.latency.setText("-")

    def update_public_ip(self, ip):
        self.public_ip.setText(ip)

    def update_bandwidth(self, up_bps, down_bps):
        self.up_speed.setText(format_speed(up_bps))
        self.down_speed.setText(format_speed(down_bps))

    def update_dns(self, dns_str):
        self.dns.setText(dns_str or "-")
