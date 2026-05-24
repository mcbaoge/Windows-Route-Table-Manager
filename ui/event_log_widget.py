"""Real-time ETW event log widget with ring buffer, batch update, and filtering."""

import logging
import time
from collections.abc import Callable

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QLabel, QComboBox, QCheckBox, QPushButton, QLineEdit,
    QAbstractItemView,
)
from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtGui import QColor, QBrush

from services.event_bus import get_event_bus, EventBus
from services.event_types import ConnectionEvent, DnsEvent, RouteEvent, InterfaceEvent, PacketDropEvent

logger = logging.getLogger(__name__)

COLUMN_HEADERS = ["时间", "类型", "详情", "PID", "进程"]

COLOR_MAP = {
    "connect":     QColor(0x4E, 0xC9, 0xB0),  # teal
    "disconnect":  QColor(0xE0, 0x6C, 0x75),  # red
    "retransmit":  QColor(0xE5, 0xC0, 0x7B),  # amber
    "drop":        QColor(0xD4, 0x6B, 0x08),   # orange
    "dns":         QColor(0x56, 0xB4, 0xE9),  # blue
    "route":       QColor(0xC8, 0xA0, 0xE0),  # purple
    "interface":   QColor(0xA0, 0xC8, 0xE0),  # light blue
    "default":     QColor(0xD4, 0xD4, 0xD4),  # gray
}


class EventLogWidget(QWidget):
    """Real-time network event display.

    Displays ETW events from EventBus in a ring-buffer-backed table.
    Supports:
      - Type filter (combo box)
      - Auto-scroll toggle
      - Process name filter
      - Clear
    """

    MAX_DISPLAY = 500

    def __init__(self, parent=None):
        super().__init__(parent)
        self._bus: EventBus = get_event_bus()
        self._display_events: list = []
        self._pending_events: list = []
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setSingleShot(True)
        self._refresh_timer.setInterval(100)
        self._refresh_timer.timeout.connect(self._batch_update)
        self._update_pending = False

        self._setup_ui()

        self._bus.batch_ready.connect(self._on_batch)
        self._bus.start()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(6)

        self._filter_combo = QComboBox()
        self._filter_combo.addItems(["全部", "连接", "DNS", "路由", "接口", "丢包"])
        self._filter_combo.currentTextChanged.connect(self._on_filter_change)
        toolbar.addWidget(QLabel("类型："))
        toolbar.addWidget(self._filter_combo)

        self._process_filter = QLineEdit()
        self._process_filter.setPlaceholderText("筛选进程...")
        self._process_filter.setMaximumWidth(150)
        self._process_filter.textChanged.connect(self._on_filter_change)
        toolbar.addWidget(self._process_filter)

        self._auto_scroll_cb = QCheckBox("自动滚动")
        self._auto_scroll_cb.setChecked(True)
        toolbar.addWidget(self._auto_scroll_cb)

        toolbar.addStretch()

        self._count_label = QLabel("0 事件")
        toolbar.addWidget(self._count_label)

        clear_btn = QPushButton("清空")
        clear_btn.clicked.connect(self._clear)
        clear_btn.setMaximumWidth(60)
        toolbar.addWidget(clear_btn)

        layout.addLayout(toolbar)

        # Table
        self._table = QTableWidget(0, len(COLUMN_HEADERS))
        self._table.setHorizontalHeaderLabels(COLUMN_HEADERS)
        self._table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table.setSelectionMode(QAbstractItemView.SingleSelection)
        self._table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.verticalHeader().setDefaultSectionSize(22)
        self._table.verticalHeader().setVisible(False)
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)

        layout.addWidget(self._table)

        # Apply dark theme
        self._table.setStyleSheet("""
            QTableWidget {
                background-color: #1E1E1E;
                alternate-background-color: #252526;
                color: #D4D4D4;
                gridline-color: #3C3C3C;
                border: 1px solid #3C3C3C;
            }
            QHeaderView::section {
                background-color: #2D2D2D;
                color: #D4D4D4;
                padding: 4px;
                border: 1px solid #3C3C3C;
            }
            QTableWidget::item {
                padding: 2px 6px;
            }
        """)

    def _on_batch(self, events: list):
        self._pending_events.extend(events)
        if not self._update_pending:
            self._update_pending = True
            self._refresh_timer.start()

    def _batch_update(self):
        self._update_pending = False
        if not self._pending_events:
            return

        events = list(self._pending_events)
        self._pending_events.clear()

        self._display_events.extend(events)
        if len(self._display_events) > self.MAX_DISPLAY:
            self._display_events = self._display_events[-self.MAX_DISPLAY:]

        self._refresh_table()
        self._count_label.setText(f"{len(self._display_events)} 事件")

    def _refresh_table(self):
        filtered = self._apply_filters(self._display_events)
        table = self._table
        table.setRowCount(0)

        row = 0
        for evt in filtered:
            table.insertRow(row)
            items = self._event_to_row(evt)
            for col, (text, color) in enumerate(items):
                item = QTableWidgetItem(text)
                if color:
                    item.setForeground(QBrush(color))
                table.setItem(row, col, item)
            row += 1

        if self._auto_scroll_cb.isChecked() and row > 0:
            table.scrollToBottom()

    def _apply_filters(self, events: list) -> list:
        filter_text = self._filter_combo.currentText()
        proc_filter = self._process_filter.text().strip().lower()

        result = events
        if filter_text == "连接":
            result = [e for e in result if isinstance(e, ConnectionEvent)]
        elif filter_text == "DNS":
            result = [e for e in result if isinstance(e, DnsEvent)]
        elif filter_text == "路由":
            result = [e for e in result if isinstance(e, (RouteEvent, InterfaceEvent))]
        elif filter_text == "接口":
            result = [e for e in result if isinstance(e, InterfaceEvent)]
        elif filter_text == "丢包":
            result = [e for e in result if isinstance(e, PacketDropEvent)]

        if proc_filter:
            result = [e for e in result if proc_filter in (getattr(e, 'process_name', '') or '').lower()]

        return result

    def _event_to_row(self, evt) -> list[tuple[str, QColor | None]]:
        ts = getattr(evt, 'timestamp', time.time())
        time_str = time.strftime("%H:%M:%S", time.localtime(ts))

        if isinstance(evt, ConnectionEvent):
            if evt.event_subtype == "connect":
                type_str = "连接"
                color = COLOR_MAP["connect"]
            elif evt.event_subtype == "disconnect":
                type_str = "断开"
                color = COLOR_MAP["disconnect"]
            else:
                type_str = "TCP"
                color = COLOR_MAP["default"]

            detail = f"{evt.local_addr}:{evt.local_port} → {evt.remote_addr}:{evt.remote_port}"

        elif isinstance(evt, DnsEvent):
            type_str = "DNS"
            color = COLOR_MAP["dns"]
            detail = f"{evt.query_type} {evt.query}"
            if evt.answers:
                detail += f" → {', '.join(evt.answers[:2])}"
            if evt.rtt_ms > 0:
                detail += f" ({evt.rtt_ms:.0f}ms)"

        elif isinstance(evt, RouteEvent):
            type_str = "路由"
            color = COLOR_MAP["route"]
            detail = f"{evt.event_subtype}: {evt.destination}/{evt.address_family}"

        elif isinstance(evt, InterfaceEvent):
            type_str = "接口"
            color = COLOR_MAP["interface"]
            detail = f"{evt.event_subtype}: {evt.interface_name}"

        elif isinstance(evt, PacketDropEvent):
            type_str = "丢包"
            color = COLOR_MAP["drop"]
            detail = f"{evt.remote_addr}:{evt.remote_port} [{evt.reason}]"

        else:
            type_str = type(evt).__name__
            color = COLOR_MAP["default"]
            detail = str(evt)[:80]

        pid = str(getattr(evt, 'pid', 0))
        proc = getattr(evt, 'process_name', '')

        return [
            (time_str, None),
            (type_str, color),
            (detail, None),
            (pid, None),
            (proc, None),
        ]

    def _on_filter_change(self):
        self._refresh_table()

    def _clear(self):
        self._display_events.clear()
        self._pending_events.clear()
        self._bus.clear()
        self._table.setRowCount(0)
        self._count_label.setText("0 事件")
