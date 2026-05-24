"""Real-time packet monitor widget — display stats, per-process connections, egress selector."""

import logging

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
    QTableWidget, QTableWidgetItem, QGroupBox, QLabel,
    QHeaderView, QSplitter,
    QGridLayout, QFrame, QAbstractItemView,
    QMessageBox,
)



logger = logging.getLogger(__name__)


def _format_bytes(b: int) -> str:
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / 1024 / 1024:.1f} MB"
    return f"{b / 1024 / 1024 / 1024:.2f} GB"


def _format_bps(bps: float) -> str:
    if bps < 1000:
        return f"{bps:.0f} bps"
    elif bps < 1000000:
        return f"{bps / 1000:.1f} Kbps"
    elif bps < 1000000000:
        return f"{bps / 1000000:.1f} Mbps"
    return f"{bps / 1000000000:.2f} Gbps"


def _format_pps(pps: float) -> str:
    if pps < 1000:
        return f"{pps:.0f} pps"
    elif pps < 1000000:
        return f"{pps / 1000:.1f} Kpps"
    return f"{pps / 1000000:.2f} Mpps"


class StatCard(QFrame):
    def __init__(self, title: str, value: str = "-", parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet("""
            StatCard { background: #2d2d2d; border: 1px solid #3c3c3c;
                       border-radius: 4px; padding: 6px; }
        """)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(2)
        self._title = QLabel(title)
        self._title.setStyleSheet("color: #888; font-size: 11px;")
        self._value = QLabel(value)
        self._value.setStyleSheet("color: #fff; font-size: 18px; font-weight: bold;")
        layout.addWidget(self._title)
        layout.addWidget(self._value)

    def set_value(self, text: str):
        self._value.setText(text)


class PacketMonitorWidget(QWidget):
    def __init__(self, interceptor=None, parent=None):
        super().__init__(parent)
        self._interceptor = interceptor
        self._running = False
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._refresh_stats)
        self._process_filter = ""
        self.setup_ui()

    def set_interceptor(self, interceptor):
        self._interceptor = interceptor

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        ctrl = QHBoxLayout()
        self.start_btn = QPushButton("▶ 开始")
        self.start_btn.clicked.connect(self._toggle_capture)
        self.start_btn.setFixedWidth(90)
        ctrl.addStretch(1)
        ctrl.addWidget(self.start_btn)
        layout.addLayout(ctrl)

        cards = QGridLayout()
        cards.setSpacing(4)
        self.card_upload = StatCard("上行速率")
        self.card_download = StatCard("下行速率")
        self.card_upload_pps = StatCard("上行包率")
        self.card_download_pps = StatCard("下行包率")
        self.card_total_up = StatCard("总上行")
        self.card_total_down = StatCard("总下行")
        self.card_conns = StatCard("活跃连接")
        self.card_status = StatCard("状态", "未启动")

        positions = [
            (0, 0, self.card_upload), (0, 1, self.card_download),
            (0, 2, self.card_upload_pps), (0, 3, self.card_download_pps),
            (1, 0, self.card_total_up), (1, 1, self.card_total_down),
            (1, 2, self.card_conns), (1, 3, self.card_status),
        ]
        for row, col, card in positions:
            cards.addWidget(card, row, col)
        layout.addLayout(cards)

        splitter = QSplitter(Qt.Vertical)
        proc_group = QGroupBox("进程连接统计")
        proc_layout = QVBoxLayout(proc_group)
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("过滤进程:"))
        self.process_filter = QLineEdit()
        self.process_filter.setPlaceholderText("输入进程名过滤...")
        self.process_filter.textChanged.connect(self._on_process_filter_changed)
        filter_row.addWidget(self.process_filter, 1)
        proc_layout.addLayout(filter_row)

        self.proc_table = QTableWidget(0, 2)
        self.proc_table.setHorizontalHeaderLabels(["进程", "连接数"])
        self.proc_table.setShowGrid(False)
        self.proc_table.verticalHeader().setVisible(False)
        self.proc_table.horizontalHeader().setStretchLastSection(True)
        self.proc_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.proc_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.proc_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        proc_layout.addWidget(self.proc_table, 1)
        splitter.addWidget(proc_group)
        layout.addWidget(splitter, 1)

        self._update_status()

    def _update_status(self):
        if not self._interceptor:
            return
        self.card_status.set_value("就绪")
        self.card_status.setToolTip(f"版本: {self._interceptor.get_version()}")

    def _toggle_capture(self):
        if self._running:
            self._stop()
        else:
            self._start()

    def _start(self):
        if not self._interceptor:
            return
        if not self._interceptor.available:
            QMessageBox.warning(self, "无法启动",
                "IP Helper API 不可用。")
            return
        ok = self._interceptor.start_capture()

        if ok:
            self._running = True
            self.start_btn.setText("■ 停止")
            self.card_status.set_value("运行中")
            self.card_status.setToolTip("")
            self._timer.start()
            logger.info("监控已启动")
        else:
            err = self._interceptor.last_error or "未知错误"
            self.card_status.set_value("启动失败")
            self.card_status.setToolTip(err)
            logger.warning("启动失败: %s", err)

            if "拒绝访问" in err or "ACCESS_DENIED" in err.upper():
                QMessageBox.warning(self, "权限不足",
                    "需要管理员权限。\n\n请以管理员身份重新运行本程序。")
            else:
                QMessageBox.warning(self, "启动失败", str(err))

    def _stop(self):
        if self._interceptor:
            self._interceptor.stop_capture()
        self._running = False
        self._timer.stop()
        self.start_btn.setText("▶ 开始")
        self.card_status.set_value("已停止")
        logger.info("监控已停止")

    def _refresh_stats(self):
        if not self._interceptor or not self._running:
            return
        try:
            ss = self._interceptor.get_stats_snapshot()
            self.card_upload.set_value(_format_bps(ss.upload_bps))
            self.card_download.set_value(_format_bps(ss.download_bps))
            self.card_upload_pps.set_value(_format_pps(ss.upload_pps))
            self.card_download_pps.set_value(_format_pps(ss.download_pps))
            self.card_total_up.set_value(_format_bytes(ss.upload_bytes))
            self.card_total_down.set_value(_format_bytes(ss.download_bytes))
            self.card_conns.set_value(str(ss.active_connections))
            self._update_proc_table(ss.per_process)
        except Exception:
            logger.exception("刷新统计异常")

    def _update_proc_table(self, per_process: list):
        filt = self._process_filter.lower()
        filtered = [e for e in per_process if not filt or filt in e[0].lower()]
        self.proc_table.setRowCount(len(filtered))
        for i, entry in enumerate(filtered):
            self.proc_table.setItem(i, 0, QTableWidgetItem(entry[0]))
            conns = entry[1] if len(entry) > 1 and isinstance(entry[1], int) else 0
            self.proc_table.setItem(i, 1, QTableWidgetItem(str(conns)))

    def _on_process_filter_changed(self, text: str):
        self._process_filter = text

    def cleanup(self):
        self._stop()
