import subprocess
import os
import logging
import ipaddress

from PyQt5.QtCore import QObject, QTimer, pyqtSignal
from PyQt5.QtWidgets import (
    QGroupBox, QVBoxLayout, QHBoxLayout, QLineEdit, QRadioButton,
    QCheckBox, QPushButton, QTextEdit,
)
from PyQt5.QtGui import QFont

from network.networking import get_default_route, get_interface_ipv4_info, get_interfaces
from services.winapi_network import AF_INET, AF_INET6
from services.task_manager import get_task_manager

logger = logging.getLogger(__name__)


def _startupinfo():
    si = None
    if os.name == "nt":
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return si


def _is_ipv6_target(target: str) -> bool:
    try:
        ipaddress.IPv6Address(target)
        return True
    except Exception:
        return False


class NetDiagWorkerSignals(QObject):
    """Signals for NetDiagWorker results."""
    output_line = pyqtSignal(str)
    finished = pyqtSignal()
    error = pyqtSignal(str)


def _run_diag(tool, target, source_ip, is_ipv6, signals: NetDiagWorkerSignals):
    """Run a diagnostic tool and emit results via signals.
    
    This function runs in a TaskRunnable via QThreadPool.
    """
    if tool == "ping":
        cmd = ["ping", "-n", "10"]
        if is_ipv6:
            cmd.append("-6")
            if source_ip:
                cmd.extend(["-S", source_ip])
        else:
            if source_ip:
                cmd.extend(["-S", source_ip])
        cmd.append(target)
    elif tool == "tracert":
        cmd = ["tracert", "-d"]
        if is_ipv6:
            cmd.append("-6")
        cmd.append(target)
    elif tool == "pathping":
        cmd = ["pathping", "-n", "-q", "10", "-w", "500"]
        if is_ipv6:
            cmd.append("-6")
        cmd.append(target)
    else:
        cmd = ["ping", "-n", "4", target]

    signals.output_line.emit("> " + " ".join(cmd))
    signals.output_line.emit("")
    logger.info("诊断测试启动 | tool=%s target=%s source_ip=%s", tool, target, source_ip)

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="gbk",
            startupinfo=_startupinfo(),
        )
        for raw in iter(process.stdout.readline, ''):
            line = raw.rstrip("\r\n")
            if line:
                signals.output_line.emit(line)
        process.wait()
    except FileNotFoundError:
        logger.error("诊断测试失败：命令未找到 %s", cmd[0])
        signals.error.emit(f"命令未找到: {cmd[0]}")
    except Exception as e:
        logger.error("诊断测试异常: %s", e)
        signals.error.emit(str(e))
    finally:
        logger.info("诊断测试结束 | tool=%s target=%s", tool, target)
        signals.finished.emit()


class NetDiagPanel(QGroupBox):
    def __init__(self, parent=None):
        super().__init__("网络测试", parent)

        layout = QVBoxLayout(self)
        layout.setSpacing(6)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("输入 IP 或域名，支持 IPv4 / IPv6")
        layout.addWidget(self.target_input)

        row2 = QHBoxLayout()
        self.ping_rb = QRadioButton("Ping")
        self.tracert_rb = QRadioButton("Tracert")
        self.pathping_rb = QRadioButton("Pathping")
        self.ping_rb.setChecked(True)
        row2.addWidget(self.ping_rb)
        row2.addWidget(self.tracert_rb)
        row2.addWidget(self.pathping_rb)
        row2.addStretch()
        self.v6_cb = QCheckBox("强制 IPv6")
        self.v6_cb.setToolTip("使用 -6 选项强制 IPv6 ping/tracert")
        row2.addWidget(self.v6_cb)
        self.default_exit_cb = QCheckBox("使用当前默认出口")
        row2.addWidget(self.default_exit_cb)
        layout.addLayout(row2)

        row3 = QHBoxLayout()
        self.start_btn = QPushButton("开始测试")
        self.stop_btn = QPushButton("停止")
        self.clear_btn = QPushButton("清空输出")
        self.stop_btn.setEnabled(False)
        row3.addWidget(self.start_btn)
        row3.addWidget(self.stop_btn)
        row3.addWidget(self.clear_btn)
        row3.addStretch()
        layout.addLayout(row3)

        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.output.setFont(QFont("Consolas", 10))
        self.output.setMinimumHeight(80)
        self.output.setMaximumHeight(200)
        layout.addWidget(self.output)

        self.start_btn.clicked.connect(self._start_test)
        self.stop_btn.clicked.connect(self._stop_test)
        self.clear_btn.clicked.connect(self._clear_output)

        self._current_task = None
        self._signals = None
        self._pending_scroll = False
        self._scroll_timer = QTimer(self)
        self._scroll_timer.setSingleShot(True)
        self._scroll_timer.timeout.connect(self._do_scroll)

    def _selected_tool(self):
        if self.ping_rb.isChecked():
            return "ping"
        elif self.tracert_rb.isChecked():
            return "tracert"
        return "pathping"

    def _get_source_ip(self):
        if not self.default_exit_cb.isChecked():
            return None
        is_ipv6 = self._target_is_ipv6()
        family = AF_INET6 if is_ipv6 else AF_INET
        default = get_default_route(family)
        if not default:
            default = get_default_route(AF_INET if is_ipv6 else AF_INET6)
        if not default:
            return None
        ifaces = get_interfaces()
        target_name = None
        for idx, name, _luid in ifaces:
            if idx == default.interface:
                target_name = name
                break
        if target_name:
            if is_ipv6:
                info = get_interface_ipv4_info()
                ip = info.get(target_name, {}).get("ip")
            else:
                info = get_interface_ipv4_info()
                ip = info.get(target_name, {}).get("ip")
            if ip and ip != "-":
                return ip
        return None

    def _target_is_ipv6(self):
        if self.v6_cb.isChecked():
            return True
        try:
            ipaddress.IPv6Address(self.target_input.text().strip())
            return True
        except Exception:
            return False

    def _start_test(self):
        target = self.target_input.text().strip()
        if not target:
            self.output.append("[错误] 请输入 IP 地址或域名")
            return

        tool = self._selected_tool()
        is_ipv6 = self._target_is_ipv6()
        source_ip = self._get_source_ip()

        self._signals = NetDiagWorkerSignals()
        self._signals.output_line.connect(self._on_output)
        self._signals.finished.connect(self._on_finished)
        self._signals.error.connect(self._on_error)

        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

        tm = get_task_manager()
        self._current_task = tm.submit(
            fn=_run_diag,
            args=(tool, target, source_ip, is_ipv6, self._signals),
            task_id=f"netdiag-{tool}-{target}",
            timeout=120,
        )

    def _stop_test(self):
        if self._current_task:
            self._current_task.cancel()
            self._current_task = None
        if self._signals:
            self._on_finished()
        logger.info("诊断测试手动停止")

    def _on_output(self, text):
        self.output.append(text)
        self._pending_scroll = True
        self._scroll_timer.start(30)

    def _do_scroll(self):
        if self._pending_scroll:
            sb = self.output.verticalScrollBar()
            sb.setValue(sb.maximum())
            self._pending_scroll = False

    def _on_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def _on_error(self, msg):
        self.output.append(f"[错误] {msg}")
        self._on_finished()

    def _clear_output(self):
        self.output.clear()
