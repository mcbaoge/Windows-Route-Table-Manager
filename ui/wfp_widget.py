"""WFP Firewall management widget -- rule display, add/remove, hit counting GUI.

Displays current WFP filter rules with hit counts, supports dynamic
addition and removal of block/allow rules via the WfpManager.
"""
import logging

from PyQt5.QtCore import Qt, QTimer
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
    QTableWidget, QTableWidgetItem, QGroupBox, QLabel,
    QHeaderView, QSplitter, QFormLayout, QComboBox,
    QCheckBox, QMessageBox, QFrame, QGridLayout,
)

from services.wfp_manager import (
    WfpManager, WfpRule, get_wfp_manager,
)

logger = logging.getLogger(__name__)

TABLE_COLS = ["名称", "方向", "动作", "协议", "本地地址", "本地端口",
              "远程地址", "远程端口", "PID", "命中次数", "已启用"]


class WfpRuleDialog(QWidget):
    """Inline form for adding WFP rules."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()

    def setup_ui(self):
        layout = QFormLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.rule_name = QLineEdit()
        self.rule_name.setPlaceholderText("规则名称")
        layout.addRow("名称:", self.rule_name)

        self.layer_combo = QComboBox()
        self.layer_combo.addItem("IPv4 出站", "ALE_AUTH_CONNECT_V4")
        self.layer_combo.addItem("IPv6 出站", "ALE_AUTH_CONNECT_V6")
        layout.addRow("层:", self.layer_combo)

        self.action_combo = QComboBox()
        self.action_combo.addItem("阻止", "block")
        self.action_combo.addItem("允许", "allow")
        layout.addRow("动作:", self.action_combo)

        self.protocol_combo = QComboBox()
        self.protocol_combo.addItem("任意", "")
        self.protocol_combo.addItem("TCP", "TCP")
        self.protocol_combo.addItem("UDP", "UDP")
        self.protocol_combo.addItem("ICMP", "ICMP")
        layout.addRow("协议:", self.protocol_combo)

        self.local_addr = QLineEdit()
        self.local_addr.setPlaceholderText("留空=任意")
        layout.addRow("本地地址:", self.local_addr)

        self.local_port = QLineEdit()
        self.local_port.setPlaceholderText("0=任意")
        layout.addRow("本地端口:", self.local_port)

        self.remote_addr = QLineEdit()
        self.remote_addr.setPlaceholderText("留空=任意")
        layout.addRow("远程地址:", self.remote_addr)

        self.remote_port = QLineEdit()
        self.remote_port.setPlaceholderText("0=任意")
        layout.addRow("远程端口:", self.remote_port)

        self.pid_input = QLineEdit()
        self.pid_input.setPlaceholderText("0=任意")
        layout.addRow("PID:", self.pid_input)

        self.app_path = QLineEdit()
        self.app_path.setPlaceholderText("例如 C:\\Program.exe")
        layout.addRow("程序路径:", self.app_path)

        self.persistent_cb = QCheckBox("持久规则（重启后保留）")
        layout.addRow("", self.persistent_cb)

    def get_rule(self) -> WfpRule:
        name = self.rule_name.text().strip() or "未命名规则"
        layer = self.layer_combo.currentData()
        action = self.action_combo.currentData()
        protocol = self.protocol_combo.currentData()
        local_addr = self.local_addr.text().strip()
        local_port = int(self.local_port.text().strip() or "0")
        remote_addr = self.remote_addr.text().strip()
        remote_port = int(self.remote_port.text().strip() or "0")
        pid = int(self.pid_input.text().strip() or "0")
        app_path = self.app_path.text().strip()
        persistent = self.persistent_cb.isChecked()

        return WfpRule(
            name=name, layer=layer, action=action,
            protocol=protocol, local_addr=local_addr,
            local_port=local_port, remote_addr=remote_addr,
            remote_port=remote_port, pid=pid, app_path=app_path,
            enabled=True, persistent=persistent,
        )

    def clear(self):
        self.rule_name.clear()
        self.layer_combo.setCurrentIndex(0)
        self.action_combo.setCurrentIndex(0)
        self.protocol_combo.setCurrentIndex(0)
        self.local_addr.clear()
        self.local_port.clear()
        self.remote_addr.clear()
        self.remote_port.clear()
        self.pid_input.clear()
        self.app_path.clear()
        self.persistent_cb.setChecked(False)


class StatsCard(QFrame):
    def __init__(self, title: str, value: str = "-", parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet("""
            StatsCard { background: #2d2d2d; border: 1px solid #3c3c3c;
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


class WfpWidget(QWidget):
    """GUI widget for managing WFP firewall rules."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._wfp: WfpManager = get_wfp_manager()
        self._refresh_timer = QTimer(self)
        self._refresh_timer.setInterval(2000)
        self._refresh_timer.timeout.connect(self._refresh_table)
        self._rules: list[tuple[str, WfpRule]] = []  # (key, rule)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        # ---- Stats cards ----
        cards = QGridLayout()
        cards.setSpacing(4)
        self.card_status = StatsCard("WFP 引擎")
        self.card_rule_count = StatsCard("规则数")
        self.card_hits = StatsCard("总命中")
        self.card_recovery = StatsCard("会话恢复")
        cards.addWidget(self.card_status, 0, 0)
        cards.addWidget(self.card_rule_count, 0, 1)
        cards.addWidget(self.card_hits, 0, 2)
        cards.addWidget(self.card_recovery, 0, 3)
        layout.addLayout(cards)

        # ---- Splitter: form + table ----
        splitter = QSplitter(Qt.Horizontal)

        # Left: rule form
        form_group = QGroupBox("添加过滤规则")
        form_layout = QVBoxLayout(form_group)
        self.rule_form = WfpRuleDialog(self)
        form_layout.addWidget(self.rule_form)

        form_btns = QHBoxLayout()
        self.add_btn = QPushButton("+ 添加规则")
        self.add_btn.clicked.connect(self._on_add_rule)
        form_btns.addWidget(self.add_btn)

        self.clear_form_btn = QPushButton("清空")
        self.clear_form_btn.clicked.connect(self.rule_form.clear)
        form_btns.addWidget(self.clear_form_btn)

        self.engine_btn = QPushButton("打开引擎")
        self.engine_btn.clicked.connect(self._toggle_engine)
        form_btns.addWidget(self.engine_btn)

        form_layout.addLayout(form_btns)

        # Blacklist/Whitelist quick buttons
        quick_group = QGroupBox("快速操作")
        quick_layout = QHBoxLayout(quick_group)
        self.bl_pid_btn = QPushButton("黑名单 PID")
        self.bl_pid_btn.clicked.connect(self._quick_blacklist_pid)
        quick_layout.addWidget(self.bl_pid_btn)
        self.wl_pid_btn = QPushButton("白名单 PID")
        self.wl_pid_btn.clicked.connect(self._quick_whitelist_pid)
        quick_layout.addWidget(self.wl_pid_btn)
        self.bl_addr_btn = QPushButton("黑名单 IP")
        self.bl_addr_btn.clicked.connect(self._quick_blacklist_addr)
        quick_layout.addWidget(self.bl_addr_btn)
        self.wl_addr_btn = QPushButton("白名单 IP")
        self.wl_addr_btn.clicked.connect(self._quick_whitelist_addr)
        quick_layout.addWidget(self.wl_addr_btn)
        form_layout.addWidget(quick_group)

        splitter.addWidget(form_group)

        # Right: rule table
        table_group = QGroupBox("当前过滤规则")
        table_layout = QVBoxLayout(table_group)

        table_controls = QHBoxLayout()
        self.remove_btn = QPushButton("删除选中")
        self.remove_btn.clicked.connect(self._on_remove_selected)
        table_controls.addWidget(self.remove_btn)

        self.clear_all_btn = QPushButton("清空全部")
        self.clear_all_btn.clicked.connect(self._on_clear_all)
        table_controls.addWidget(self.clear_all_btn)

        self.reset_hits_btn = QPushButton("重置命中")
        self.reset_hits_btn.clicked.connect(self._on_reset_hits)
        table_controls.addWidget(self.reset_hits_btn)

        table_controls.addStretch(1)
        table_layout.addLayout(table_controls)

        self.table = QTableWidget(0, len(TABLE_COLS))
        self.table.setHorizontalHeaderLabels(TABLE_COLS)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.ExtendedSelection)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        table_layout.addWidget(self.table, 1)

        splitter.addWidget(table_group)
        splitter.setSizes([350, 600])
        layout.addWidget(splitter, 1)

        self._update_ui()

    # ---- Engine management ----
    def _toggle_engine(self):
        if self._wfp.get_stats().engine_open:
            self._wfp.close()
        else:
            ok = self._wfp.open()
            if ok:
                self._wfp.subscribe_net_events()
        self._update_ui()

    def start(self):
        """Initialize: open engine if possible, start refresh timer."""
        ok = self._wfp.open()
        if ok:
            self._wfp.subscribe_net_events()
        self._refresh_timer.start()
        self._update_ui()

    def stop(self):
        self._refresh_timer.stop()

    # ---- Rule management ----
    def _on_add_rule(self):
        rule = self.rule_form.get_rule()
        if not rule.name:
            QMessageBox.warning(self, "错误", "请输入规则名称")
            return

        ok = self._wfp.add_rule(rule)
        if ok:
            logger.info("WFP rule added: %s", rule.name)
            self.rule_form.clear()
            self._refresh_table()
        else:
            stats = self._wfp.get_stats()
            QMessageBox.warning(self, "添加失败",
                f"无法添加规则。\n\n{stats.last_error}\n\n"
                "请确保以管理员身份运行。")

    def _on_remove_selected(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.warning(self, "提示", "请先选择要删除的规则")
            return

        reply = QMessageBox.question(self, "确认删除",
            f"确定删除选中的 {len(selected)} 条规则?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply != QMessageBox.Yes:
            return

        for idx in reversed(selected):
            row = idx.row()
            if row < len(self._rules):
                key, _ = self._rules[row]
                self._wfp.remove_rule(key)
        self._refresh_table()

    def _on_clear_all(self):
        count = len(self._wfp.get_rules())
        if count == 0:
            return
        reply = QMessageBox.question(self, "确认清空",
            f"确定清空全部 {count} 条规则?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply != QMessageBox.Yes:
            return
        self._wfp.clear_all_rules()
        self._refresh_table()

    def _on_reset_hits(self):
        for _, rule in self._rules:
            rule.hit_count = 0
        self._refresh_table()

    def _quick_blacklist_pid(self):
        try:
            pid = int(self.rule_form.pid_input.text().strip() or "0")
        except ValueError:
            pid = 0
        if pid <= 0:
            QMessageBox.warning(self, "提示", "请先输入有效的 PID")
            return
        name = f"黑名单-PID-{pid}"
        app_path = self.rule_form.app_path.text().strip()
        proto = self.rule_form.protocol_combo.currentData()
        key = self._wfp.blacklist_process(name, pid, app_path, proto)
        if key:
            logger.info("Blacklist PID %d: %s", pid, key)
            self._refresh_table()
        else:
            QMessageBox.warning(self, "失败", "黑名单规则添加失败")

    def _quick_whitelist_pid(self):
        try:
            pid = int(self.rule_form.pid_input.text().strip() or "0")
        except ValueError:
            pid = 0
        if pid <= 0:
            QMessageBox.warning(self, "提示", "请先输入有效的 PID")
            return
        name = f"白名单-PID-{pid}"
        app_path = self.rule_form.app_path.text().strip()
        proto = self.rule_form.protocol_combo.currentData()
        key = self._wfp.whitelist_process(name, pid, app_path, proto)
        if key:
            logger.info("Whitelist PID %d: %s", pid, key)
            self._refresh_table()
        else:
            QMessageBox.warning(self, "失败", "白名单规则添加失败")

    def _quick_blacklist_addr(self):
        addr = self.rule_form.remote_addr.text().strip()
        if not addr:
            QMessageBox.warning(self, "提示", "请先输入远程地址")
            return
        name = f"黑名单-{addr}"
        port = int(self.rule_form.remote_port.text().strip() or "0")
        proto = self.rule_form.protocol_combo.currentData()
        layer = self.rule_form.layer_combo.currentData()
        key = self._wfp.blacklist_addr(name, addr, proto, port, layer)
        if key:
            logger.info("Blacklist addr %s: %s", addr, key)
            self._refresh_table()
        else:
            QMessageBox.warning(self, "失败", "黑名单规则添加失败")

    def _quick_whitelist_addr(self):
        addr = self.rule_form.remote_addr.text().strip()
        if not addr:
            QMessageBox.warning(self, "提示", "请先输入远程地址")
            return
        name = f"白名单-{addr}"
        port = int(self.rule_form.remote_port.text().strip() or "0")
        proto = self.rule_form.protocol_combo.currentData()
        layer = self.rule_form.layer_combo.currentData()
        key = self._wfp.whitelist_addr(name, addr, proto, port, layer)
        if key:
            logger.info("Whitelist addr %s: %s", addr, key)
            self._refresh_table()
        else:
            QMessageBox.warning(self, "失败", "白名单规则添加失败")

    # ---- Table refresh ----
    def _refresh_table(self):
        rules = self._wfp.get_rules()
        self._rules = [(r.filter_key_hex, r) for r in rules]

        self.table.setRowCount(len(self._rules))
        for row, (key, rule) in enumerate(self._rules):
            items = [
                QTableWidgetItem(rule.name),
                QTableWidgetItem(rule.direction),
                QTableWidgetItem(rule.action),
                QTableWidgetItem(rule.protocol or "任意"),
                QTableWidgetItem(rule.local_addr or "任意"),
                QTableWidgetItem(str(rule.local_port) if rule.local_port else "任意"),
                QTableWidgetItem(rule.remote_addr or "任意"),
                QTableWidgetItem(str(rule.remote_port) if rule.remote_port else "任意"),
                QTableWidgetItem(str(rule.pid) if rule.pid else "任意"),
                QTableWidgetItem(str(rule.hit_count)),
                QTableWidgetItem("是" if rule.enabled else "否"),
            ]
            for col, item in enumerate(items):
                self.table.setItem(row, col, item)

            tip = (
                f"名称: {rule.name}\n"
                f"层: {rule.layer}\n"
                f"动作: {rule.action}\n"
                f"协议: {rule.protocol or '任意'}\n"
                f"本地: {rule.local_addr or '*'}:{rule.local_port or '*'}\n"
                f"远程: {rule.remote_addr or '*'}:{rule.remote_port or '*'}\n"
                f"PID: {rule.pid or '任意'}\n"
                f"路径: {rule.app_path or '任意'}\n"
                f"命中: {rule.hit_count}\n"
                f"FilterId: {rule.filter_id}\n"
                f"Key: {rule.filter_key_hex}\n"
            )
            for col in range(len(TABLE_COLS)):
                item = self.table.item(row, col)
                if item:
                    item.setToolTip(tip)

        self._update_ui()

    def _update_ui(self):
        stats = self._wfp.get_stats()
        status_text = "已打开" if stats.engine_open else "已关闭"
        status_color = "#4ec9b0" if stats.engine_open else "#f14c4c"
        self.card_status.set_value(status_text)
        self.card_status._value.setStyleSheet(
            f"color: {status_color}; font-size: 18px; font-weight: bold;")
        self.card_rule_count.set_value(str(stats.filter_count))
        self.card_hits.set_value(str(stats.total_hits))
        self.card_recovery.set_value(str(stats.session_recoveries))

        self.engine_btn.setText("关闭引擎" if stats.engine_open else "打开引擎")

    def cleanup(self):
        self.stop()
        self._wfp.shutdown()
