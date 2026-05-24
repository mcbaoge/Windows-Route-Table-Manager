import json
import logging
import os
import ipaddress

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit,
    QFormLayout, QTableView, QMessageBox,
    QGroupBox, QCheckBox, QComboBox, QDialog, QFileDialog, QLabel,
    QHeaderView, QTabWidget, QAbstractItemView,
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QCoreApplication

from core import config
from core.logger import LOG_PATH
from core.utils import RouteEntry, cidr_to_mask, mask_to_cidr
from network.networking import (
    get_routes, get_interfaces, get_interface_ipv4_info,
    get_default_route, route_exists, add_route,
    delete_route, set_route_metric,
    export_routes_to_dict, import_routes_from_dict,
    AF_INET, AF_INET6, AF_UNSPEC,
)
from ui.ui_components import (
    ValidatedLineEdit, ConfirmDialog,
    set_default_route_with_ui, ImportOptionsDialog,
    LoadingDialog,
)
from network.network_monitor import StatusPanel, NetworkMonitor
from network.network_diag import NetDiagPanel
from services.route_listener import RouteChangeListener
from services.event_tracer import EventTracer
from services.etw_tracer import ETWTracer
from services.event_bus import get_event_bus
from services.cache_manager import get_cache
from services.task_manager import get_task_manager, TaskSignals
from services.refresh_scheduler import RefreshScheduler
from ui.topology_widget import TopologyWidget
from ui.event_log_widget import EventLogWidget
from ui.packet_monitor_widget import PacketMonitorWidget
from services.packet_interceptor import get_interceptor
from ui.wfp_widget import WfpWidget
from ui.route_table_model import (
    RouteTableModel, RouteFilterProxyModel,
)

logger = logging.getLogger(__name__)


class RouteTableTab(QWidget):
    """Route table management UI as a tab with IPv4 + IPv6 support.

    Thread model:
    - Route refresh uses TaskManager serial queue (no concurrent refresh)
    - Background data loading uses TaskManager pool
    - All UI updates via Signal/Slot in main thread
    """

    _data_loaded = pyqtSignal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.parent_console = parent
        self.current_row_route = None
        self.iface_info_v4 = {}
        self.iface_info_v6 = {}
        self.interfaces = []
        self._loading = False

        self.status_panel = StatusPanel(self)
        self.diag_panel = NetDiagPanel(self)

        self._monitor = NetworkMonitor(self)
        self._monitor.latency_ready.connect(self.status_panel.update_latency)
        self._monitor.bandwidth_ready.connect(self.status_panel.update_bandwidth)
        self._monitor.dns_ready.connect(self.status_panel.update_dns)

        self._route_listener = RouteChangeListener(self)

        self._route_model = RouteTableModel(self)
        self._route_proxy = RouteFilterProxyModel(self)
        self._route_proxy.setSourceModel(self._route_model)
        self._route_proxy.set_show_ipv4(True)
        self._route_proxy.set_show_ipv6(True)

        self._data_loaded.connect(self._on_data_loaded)

        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        self.default_route_box = QGroupBox("默认路由出接口（加载中...）")
        self.default_route_layout = QHBoxLayout(self.default_route_box)
        self.default_route_layout.addWidget(QLabel("正在获取网络信息..."))
        self.iface_checks = []

        self.table = QTableView()
        self.table.setModel(self._route_proxy)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.setVerticalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.table.selectionModel().selectionChanged.connect(self._on_selection_changed)

        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)

        self.table.setStyleSheet("""
            QTableView { background: #252526; alternate-background-color: #2d2d2d;
                         border: 1px solid #3c3c3c; gridline-color: #3c3c3c;
                         outline: none; }
            QTableView::item { padding: 4px 6px; color: #d4d4d4; }
            QTableView::item:selected { background: #094771; color: #fff; }
            QHeaderView::section { background: #1e1e1e; color: #969696; padding: 5px;
                                   border: none; border-bottom: 1px solid #3c3c3c;
                                   font-weight: bold; }
            QTableView::item:hover { background: #2a2d2e; }
        """)

        top_bar = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("搜索目标 / 网关 / 接口...")
        self.search_input.textChanged.connect(self._on_search_changed)
        top_bar.addWidget(self.search_input, 1)

        top_bar.addWidget(QLabel("地址族:"))
        self.family_combo = QComboBox()
        self.family_combo.addItem("IPv4", AF_INET)
        self.family_combo.addItem("IPv6", AF_INET6)
        self.family_combo.addItem("全部", AF_UNSPEC)
        self.family_combo.setCurrentIndex(2)
        self.family_combo.currentIndexChanged.connect(self._on_family_changed)
        top_bar.addWidget(self.family_combo)

        self.show_default_cb = QCheckBox("仅默认路由")
        self.show_default_cb.stateChanged.connect(self._on_default_only_changed)
        top_bar.addWidget(self.show_default_cb)

        form = QFormLayout()
        self.dest = QLineEdit()

        self.prefix_combo = QComboBox()
        for i in range(33):
            mask = cidr_to_mask(i)
            self.prefix_combo.addItem(f"{mask} ({i})", i)
        self.prefix_combo.setCurrentIndex(24)

        self.prefix_edit = ValidatedLineEdit(self.validate_prefix)
        self.prefix_edit.setText("24")

        prefix_hbox = QHBoxLayout()
        prefix_hbox.addWidget(self.prefix_edit)
        prefix_hbox.addWidget(self.prefix_combo)
        self.prefix_label = QLabel("子网掩码/CIDR:")

        self.gw_combo = QComboBox()
        self.gw_combo.addItem("0.0.0.0 (接口直连)", "0.0.0.0")

        self.gw_edit = ValidatedLineEdit(self.validate_gateway)
        self.gw_edit.setText("0.0.0.0")

        gw_hbox = QHBoxLayout()
        gw_hbox.addWidget(self.gw_edit)
        gw_hbox.addWidget(self.gw_combo)

        self.iface = QLineEdit()
        self.iface.setReadOnly(True)

        self.metric_edit = QLineEdit()
        self.metric_edit.setPlaceholderText(f"({config.METRIC_MIN}-{config.METRIC_MAX})")

        form.addRow("地址族:", self.family_combo)
        form.addRow("目标网络:", self.dest)
        form.addRow(self.prefix_label, prefix_hbox)
        form.addRow("网关:", gw_hbox)
        form.addRow("接口索引:", self.iface)
        form.addRow("Metric:", self.metric_edit)

        btns = QHBoxLayout()
        for text, handler in [
            ("刷新", self.refresh), ("添加", self.add), ("删除", self.delete),
            ("修改", self.modify), ("导出", self.export_snapshot),
            ("导入", self.import_snapshot), ("日志", self.open_log_file),
        ]:
            b = QPushButton(text)
            b.clicked.connect(handler)
            btns.addWidget(b)
        btns.addStretch(1)

        self.prefix_combo.currentIndexChanged.connect(self._on_prefix_combo_changed)
        self.gw_combo.currentIndexChanged.connect(self.on_gw_combo_changed)

        mid = QHBoxLayout()
        left_col = QVBoxLayout()
        left_col.addLayout(top_bar)
        left_col.addWidget(self.table, 1)
        mid.addLayout(left_col, 3)

        right_col = QVBoxLayout()
        right_col.addWidget(self.default_route_box)
        right_col.addLayout(form)
        right_col.addLayout(btns)
        right_col.addWidget(self.diag_panel)
        mid.addLayout(right_col, 2)

        layout.addWidget(self.status_panel)
        layout.addLayout(mid, 1)

        self._family = AF_UNSPEC

    # =================== Data loading ===================

    def start(self):
        QTimer.singleShot(0, self._lazy_init)

    def stop(self):
        self._monitor.stop()
        self._route_listener.stop()

    def _on_search_changed(self, text: str):
        self._route_proxy.set_search_text(text)
        if not text:
            self.table.clearSelection()

    def _on_default_only_changed(self, state: int):
        self._route_proxy.set_default_only(state == Qt.Checked)

    def _on_family_changed(self):
        self._family = self.family_combo.currentData()
        self._route_proxy.set_show_ipv4(
            self._family in (AF_INET, AF_UNSPEC))
        self._route_proxy.set_show_ipv6(
            self._family in (AF_INET6, AF_UNSPEC))
        self._async_refresh()

    def connect_to_refresh_scheduler(self, scheduler):
        self._route_listener.routes_changed.connect(scheduler.mark_dirty)

    def _async_refresh(self):
        """Route refresh is serialized via TaskManager to avoid concurrent refreshes."""
        tm = get_task_manager()
        tm.submit_serial(
            queue_name="route-refresh",
            fn=lambda: get_routes(self._family),
            timeout=30,
            on_finished=self._on_refreshed,
        )

    def _on_refreshed(self, routes):
        try:
            self._route_model.set_routes(routes)
            self._update_default_checks(routes)
            self._populate_status_panel(routes)
        except Exception as e:
            logger.exception("刷新表格异常: %s", e)

    def _lazy_init(self):
        self._loading = True
        tm = get_task_manager()
        task = tm.submit(fn=self._load_all_data, task_id="route-lazy-init", timeout=30)
        task.signals.finished.connect(self._data_loaded.emit)
        task.signals.error.connect(self._on_load_error)

    def _on_load_error(self, err_msg):
        self._loading = False
        logger.error("后台数据加载失败: %s", err_msg)
        self.default_route_box.setTitle("默认路由出接口（加载失败）")

    def _load_all_data(self):
        routes = get_routes(AF_UNSPEC)
        iface_info_v4 = get_interface_ipv4_info()
        iface_info_v6 = get_interface_ipv6_info() if False else {}
        interfaces = get_interfaces()
        return {"routes": routes, "iface_info_v4": iface_info_v4,
                "iface_info_v6": iface_info_v6, "interfaces": interfaces}

    def _on_data_loaded(self, data):
        self._loading = False
        self.iface_info_v4 = data["iface_info_v4"]
        self.iface_info_v6 = data.get("iface_info_v6", {})
        self.interfaces = data["interfaces"]
        routes = data["routes"]

        self._rebuild_default_route_panel(routes)
        self._populate_gw_combo(routes)

        self._route_model.set_routes(routes)
        self._populate_status_panel(routes)
        self._monitor.start()
        self._route_listener.start()

    def _rebuild_default_route_panel(self, routes):
        self.default_route_box.setTitle("默认路由出接口（IPv4 / IPv6）")
        for i in reversed(range(self.default_route_layout.count())):
            w = self.default_route_layout.itemAt(i).widget()
            if w:
                w.deleteLater()
        self.iface_checks.clear()

        for label, family in [("IPv4", AF_INET), ("IPv6", AF_INET6)]:
            def_routes = [r for r in routes if r.is_default and r.address_family == family]
            if not def_routes:
                continue
            default = min(def_routes, key=lambda x: int(x.metric))
            default_iface_indices = {r.interface for r in def_routes}

            for idx, name, _luid in self.interfaces:
                if idx not in default_iface_indices:
                    continue
                cb = QCheckBox(f"[{label}] {name} (if {idx})")
                cb.iface_idx = idx
                cb.setChecked(idx == default.interface)
                info_v4 = self.iface_info_v4.get(name, {})
                tip = f"接口: {name}\n索引: {idx}\nIP: {info_v4.get('ip', '-')}\n网关: {info_v4.get('gateway', '-')}"
                cb.setToolTip(tip)
                cb.stateChanged.connect(self.on_default_change)
                self.iface_checks.append(cb)
                self.default_route_layout.addWidget(cb)

    def _populate_gw_combo(self, routes):
        self.gw_combo.clear()
        self.gw_combo.addItem("0.0.0.0 (接口直连)", "0.0.0.0")
        seen = set()
        for idx, name, _luid in self.interfaces:
            for r in routes:
                if r.interface == idx and r.gateway and r.gateway not in ("-", "0.0.0.0", "::"):
                    key = (r.gateway, idx)
                    if key not in seen:
                        seen.add(key)
                        self.gw_combo.addItem(f"{r.gateway} → {name} (if {idx})", key)

    # =================== Validation ===================

    def validate_prefix(self):
        text = self.prefix_edit.text().strip()
        is_ipv6 = self.family_combo.currentData() == AF_INET6
        if is_ipv6:
            try:
                val = int(text)
                if 0 <= val <= 128:
                    return True
            except ValueError:
                pass
            QMessageBox.warning(self, "错误", "IPv6 前缀长度必须是 0-128")
            return False
        if text.isdigit() and 0 <= int(text) <= 32:
            cidr = int(text)
            mask = cidr_to_mask(cidr)
            self.prefix_edit.setText(str(cidr))
            idx = self.prefix_combo.findData(cidr)
            if idx != -1:
                self.prefix_combo.blockSignals(True)
                self.prefix_combo.setCurrentIndex(idx)
                self.prefix_combo.blockSignals(False)
            return True
        elif text.startswith("/") and text[1:].isdigit():
            cidr = int(text[1:])
            if 0 <= cidr <= 32:
                self.prefix_edit.setText(str(cidr))
                idx = self.prefix_combo.findData(cidr)
                if idx != -1:
                    self.prefix_combo.blockSignals(True)
                    self.prefix_combo.setCurrentIndex(idx)
                    self.prefix_combo.blockSignals(False)
                return True
        else:
            cidr = mask_to_cidr(text)
            if cidr is not None:
                self.prefix_edit.setText(str(cidr))
                idx = self.prefix_combo.findData(cidr)
                if idx != -1:
                    self.prefix_combo.blockSignals(True)
                    self.prefix_combo.setCurrentIndex(idx)
                    self.prefix_combo.blockSignals(False)
                return True
        QMessageBox.warning(self, "错误", "无效的子网掩码或前缀长度")
        return False

    def _on_prefix_combo_changed(self):
        cidr = self.prefix_combo.currentData()
        self.prefix_edit.setText(str(cidr))

    def validate_gateway(self):
        text = self.gw_edit.text().strip()
        is_ipv6 = self.family_combo.currentData() == AF_INET6
        try:
            if is_ipv6:
                ipaddress.IPv6Address(text)
            else:
                ipaddress.IPv4Address(text)
            for i in range(self.gw_combo.count()):
                data = self.gw_combo.itemData(i)
                if isinstance(data, tuple) and data[0] == text:
                    self.gw_combo.setCurrentIndex(i)
                    self.iface.setText(data[1])
                    return True
            return True
        except Exception:
            pass
        for idx, name, _luid in self.interfaces:
            if text == idx:
                default_gw = "::" if is_ipv6 else "0.0.0.0"
                gw = default_gw
                for r in get_routes(self.family_combo.currentData()):
                    if r.interface == idx and r.gateway not in ("-", "0.0.0.0", "::"):
                        gw = r.gateway
                        break
                self.gw_edit.setText(gw)
                self.iface.setText(idx)
                return True
        QMessageBox.warning(self, "错误", f"无效的{'IPv6' if is_ipv6 else 'IPv4'}网关")
        return False

    def on_gw_combo_changed(self):
        data = self.gw_combo.currentData()
        if isinstance(data, tuple):
            gw, idx = data
            self.gw_edit.setText(gw)
            self.iface.setText(idx)
        else:
            self.gw_edit.setText(data)

    # =================== Table & CRUD ===================

    def refresh(self):
        self._async_refresh()

    def _on_selection_changed(self, selected, _deselected):
        indexes = selected.indexes()
        if not indexes:
            return
        source_row = self._route_proxy.mapToSource(indexes[0]).row()
        route = self._route_model.get_route_at(source_row)
        if not route:
            return

        self.current_row_route = route

        family_af = AF_INET6 if route.is_ipv6 else AF_INET
        idx = self.family_combo.findData(family_af)
        if idx >= 0:
            self.family_combo.setCurrentIndex(idx)

        self.dest.setText(route.destination)
        if route.is_ipv6:
            self.prefix_edit.setText(str(route.prefix_length))
        else:
            self.prefix_edit.setText(route.mask)
            cidr = mask_to_cidr(route.mask)
            if cidr is not None:
                pi = self.prefix_combo.findData(cidr)
                if pi >= 0:
                    self.prefix_combo.setCurrentIndex(pi)
        self.gw_edit.setText(route.gateway)
        self.iface.setText(route.interface)
        self.metric_edit.setText(route.metric)

    def add(self):
        if not self.validate_prefix() or not self.validate_gateway():
            return
        dest = self.dest.text().strip()
        prefix_text = self.prefix_edit.text().strip()
        gw = self.gw_edit.text().strip()
        iface = self.iface.text().strip()
        metric_text = self.metric_edit.text().strip()
        family = self.family_combo.currentData()
        is_ipv6 = (family == AF_INET6)

        if not dest or not iface:
            QMessageBox.warning(self, "错误", "目标网络和接口索引不能为空")
            return

        if is_ipv6:
            try:
                prefix_val = int(prefix_text)
            except ValueError:
                QMessageBox.warning(self, "错误", "IPv6 前缀长度必须是数字")
                return
            mask_or_plen = prefix_val
        else:
            cidr = mask_to_cidr(prefix_text) if not prefix_text.isdigit() else int(prefix_text)
            if cidr is None:
                QMessageBox.warning(self, "错误", "无效的子网掩码")
                return
            mask_or_plen = cidr

        if metric_text:
            if not metric_text.isdigit() or not (config.METRIC_MIN <= int(metric_text) <= config.METRIC_MAX):
                QMessageBox.warning(self, "错误", f"Metric 必须是 {config.METRIC_MIN}-{config.METRIC_MAX}")
                return

        logger.info("UI 添加路由 | dest=%s/%s gw=%s iface=%s family=%d",
                     dest, str(mask_or_plen), gw, iface, family)

        if route_exists(dest, mask_or_plen, iface, family):
            reply = QMessageBox.question(self, "路由已存在",
                f"已存在相同的路由条目，是否覆盖？", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                return
            delete_route(dest, mask_or_plen, gw, iface, address_family=family)

        dlg = ConfirmDialog("添加路由", f"添加 {'IPv6' if is_ipv6 else 'IPv4'} 路由：\n{dest}/{mask_or_plen}")
        if dlg.exec_() != QDialog.Accepted:
            return

        result = add_route(dest, mask_or_plen, gw, iface, address_family=family)
        if result.returncode != 0:
            QMessageBox.critical(self, "添加失败", f"错误: {result.stderr}")
            return
        if metric_text:
            set_route_metric(dest, mask_or_plen, gw, iface, int(metric_text), address_family=family)
        logger.info("UI 添加路由成功 | dest=%s/%s iface=%s", dest, str(mask_or_plen), iface)
        QMessageBox.information(self, "成功", "路由添加成功")
        self.refresh()

    def delete(self):
        if QMessageBox.question(self, "确认", "确定删除该路由？") != QMessageBox.Yes:
            return
        dest = self.dest.text().strip()
        prefix_text = self.prefix_edit.text().strip()
        gw = self.gw_edit.text().strip()
        iface = self.iface.text().strip()
        family = self.family_combo.currentData()
        is_ipv6 = (family == AF_INET6)

        if is_ipv6:
            mask_or_plen = int(prefix_text) if prefix_text.isdigit() else 0
        else:
            cidr = mask_to_cidr(prefix_text) if not prefix_text.isdigit() else int(prefix_text)
            if cidr is None:
                QMessageBox.warning(self, "错误", "无效的子网掩码")
                return
            mask_or_plen = prefix_text

        logger.info("UI 删除路由 | dest=%s iface=%s family=%d", dest, iface, family)
        result = delete_route(dest, mask_or_plen, gw, iface, address_family=family)
        if result.returncode != 0:
            QMessageBox.critical(self, "删除失败", f"错误: {result.stderr}")
        else:
            QMessageBox.information(self, "成功", "路由删除成功")
            self.refresh()

    def modify(self):
        if not self.current_row_route:
            QMessageBox.warning(self, "错误", "请先在表格中选择一条要修改的路由")
            return
        old_dest = self.current_row_route.destination
        old_gw = self.current_row_route.gateway
        old_iface = self.current_row_route.interface
        old_family = self.current_row_route.address_family
        old_is_ipv6 = self.current_row_route.is_ipv6

        if QMessageBox.question(self, "确认", "修改路由将先删除旧条目再添加新条目，确定继续？") != QMessageBox.Yes:
            return

        old_mask_or_plen = str(self.current_row_route.mask) if not old_is_ipv6 else old_is_ipv6
        del_result = delete_route(old_dest, old_mask_or_plen, old_gw, old_iface, address_family=old_family)
        if del_result.returncode != 0:
            QMessageBox.critical(self, "修改失败（删除阶段）", f"错误: {del_result.stderr}")
            return

        if not self.validate_prefix() or not self.validate_gateway():
            self.refresh()
            return

        dest = self.dest.text().strip()
        prefix_text = self.prefix_edit.text().strip()
        gw = self.gw_edit.text().strip()
        iface = self.iface.text().strip()
        metric_text = self.metric_edit.text().strip()
        family = self.family_combo.currentData()
        is_ipv6 = (family == AF_INET6)

        if not dest or not iface:
            QMessageBox.warning(self, "错误", "目标网络和接口索引不能为空")
            self.refresh()
            return

        if is_ipv6:
            try:
                mask_or_plen = int(prefix_text)
            except ValueError:
                QMessageBox.warning(self, "错误", "IPv6 前缀长度必须是数字")
                self.refresh()
                return
        else:
            cidr = mask_to_cidr(prefix_text) if not prefix_text.isdigit() else int(prefix_text)
            if cidr is None:
                QMessageBox.warning(self, "错误", "无效的子网掩码")
                self.refresh()
                return
            mask_or_plen = cidr

        if metric_text:
            if not metric_text.isdigit() or not (config.METRIC_MIN <= int(metric_text) <= config.METRIC_MAX):
                QMessageBox.warning(self, "错误", f"Metric 必须是 {config.METRIC_MIN}-{config.METRIC_MAX}")
                self.refresh()
                return

        dlg = ConfirmDialog("修改路由 — 添加新条目",
            f"添加 {'IPv6' if is_ipv6 else 'IPv4'} 路由：\n{dest}/{mask_or_plen}")
        if dlg.exec_() != QDialog.Accepted:
            self.refresh()
            return

        result = add_route(dest, mask_or_plen, gw, iface, address_family=family)
        if result.returncode != 0:
            QMessageBox.critical(self, "修改失败（添加阶段）", f"错误: {result.stderr}")
            return

        if metric_text:
            set_route_metric(dest, mask_or_plen, gw, iface, int(metric_text), address_family=family)

        QMessageBox.information(self, "成功", "路由修改成功")
        self.refresh()

    def on_default_change(self):
        cb = self.sender()
        if not cb.isChecked():
            return
        for other in self.iface_checks:
            if other is cb:
                continue
            other.blockSignals(True)
            other.setChecked(False)
            other.blockSignals(False)
        for chk in self.iface_checks:
            chk.setEnabled(False)
        try:
            set_default_route_with_ui(self, cb.iface_idx)
        finally:
            self.refresh()
            for chk in self.iface_checks:
                chk.setEnabled(True)

    def _update_default_checks(self, routes):
        v4_defaults = [r for r in routes if r.is_default and not r.is_ipv6]
        v6_defaults = [r for r in routes if r.is_default and r.is_ipv6]
        v4_iface = min(v4_defaults, key=lambda x: int(x.metric)).interface if v4_defaults else None
        v6_iface = min(v6_defaults, key=lambda x: int(x.metric)).interface if v6_defaults else None
        for cb in self.iface_checks:
            cb.blockSignals(True)
            target = None
            if cb.text().startswith("[IPv4]"):
                target = v4_iface
            else:
                target = v6_iface
            cb.setChecked(cb.iface_idx == target)
            cb.blockSignals(False)

    def _populate_status_panel(self, routes=None):
        v4_default = get_default_route(AF_INET)
        v6_default = get_default_route(AF_INET6)
        if v4_default:
            iface_label = v4_default.interface
            for idx, name, _luid in self.interfaces:
                if idx == v4_default.interface:
                    iface_label = f"{name} (if {idx})"
                    break
            self.status_panel.update_default_info(f"IPv4: {iface_label}", v4_default.gateway)
        elif v6_default:
            iface_label = v6_default.interface
            for idx, name, _luid in self.interfaces:
                if idx == v6_default.interface:
                    iface_label = f"{name} (if {idx})"
                    break
            self.status_panel.update_default_info(f"IPv6: {iface_label}", v6_default.gateway)

    def open_log_file(self):
        if os.path.exists(LOG_PATH):
            os.startfile(LOG_PATH)
        else:
            QMessageBox.information(self, "日志", "暂无日志记录")

    def closeEvent(self, event):
        self.stop()
        super().closeEvent(event)

    def export_snapshot(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "导出路由配置", "route_snapshot.json", "JSON 文件 (*.json)")
        if not file_path:
            return
        data = export_routes_to_dict()
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info("导出配置成功 | 路径=%s 路由数=%d", file_path, len(data['routes']))
            QMessageBox.information(self, "成功", f"已导出 {len(data['routes'])} 条路由到：\n{file_path}")
        except Exception as e:
            logger.error("导出配置失败 | %s", e)
            QMessageBox.critical(self, "导出失败", f"写入文件失败：{e}")

    def import_snapshot(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "导入路由配置", "", "JSON 文件 (*.json)")
        if not file_path:
            return
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logger.error("导入配置读取失败 | %s", e)
            QMessageBox.critical(self, "导入失败", f"读取文件失败：{e}")
            return
        route_list = data.get("routes", [])
        logger.info("UI 导入配置 | 文件=%s 路由数=%d", file_path, len(route_list) if isinstance(route_list, list) else 0)
        if not isinstance(route_list, list) or not route_list:
            QMessageBox.warning(self, "导入失败", "JSON 文件中没有有效的路由数据")
            return
        dlg = ImportOptionsDialog(len(route_list), self)
        if dlg.exec_() != QDialog.Accepted:
            return
        mode = dlg.selected_mode()
        if mode == "restore":
            reply = QMessageBox.warning(self, "高危操作确认",
                "即将清空当前所有路由并恢复为配置文件中的路由。\n\n"
                "⚠ 这可能导致网络连接中断！\n请确保您有物理访问权限或其他管理通道。",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply != QMessageBox.Yes:
                return
        result_holder = {"result": None, "error": None}

        def _task():
            return import_routes_from_dict(data, mode)

        dlg_loading = LoadingDialog(text="正在导入路由配置，请稍候...", parent=self)
        tm = get_task_manager()
        task = tm.submit(fn=_task, task_id="route-import", timeout=120)
        task.signals.finished.connect(lambda res: _on_import_ok(res, dlg_loading, result_holder))
        task.signals.error.connect(lambda err: _on_import_err(err, dlg_loading, result_holder))

        dlg_loading.exec_()
        task.wait(timeout=30)
        self.refresh()
        if result_holder["error"] is not None:
            logger.error("UI 导入配置异常 | %s", result_holder["error"])
            QMessageBox.critical(self, "导入失败", str(result_holder["error"]))
            return
        result = result_holder["result"]
        logger.info("UI 导入配置结果 | success=%d failed=%d", result['success'], result['failed'])
        msg_lines = [f"导入完成", f"成功: {result['success']} 条", f"失败: {result['failed']} 条"]
        if result["errors"]:
            max_show = 10
            shown = result["errors"][:max_show]
            msg_lines.append("")
            msg_lines.append("错误详情:")
            msg_lines.extend(shown)
            if len(result["errors"]) > max_show:
                msg_lines.append(f"...及其他 {len(result['errors']) - max_show} 条错误")
        QMessageBox.information(self, "导入结果", "\n".join(msg_lines))


def _on_import_ok(res, dlg_loading, result_holder):
    result_holder["result"] = res
    if dlg_loading.isVisible():
        dlg_loading.accept()


def _on_import_err(err, dlg_loading, result_holder):
    result_holder["error"] = err
    if dlg_loading.isVisible():
        dlg_loading.accept()


class ShutdownOverlay(QDialog):
    """Frameless modal overlay shown during application shutdown."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.Dialog)
        self.setModal(True)
        self.setStyleSheet("background-color: rgba(0, 0, 0, 200);")
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        label = QLabel("正在退出...")
        label.setStyleSheet("""
            QLabel {
                color: white;
                font-size: 28px;
                font-weight: bold;
                padding: 30px 60px;
                background: transparent;
            }
        """)
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

    def resizeToParent(self):
        p = self.parent()
        if p:
            self.resize(p.size())
            self.move(p.mapToGlobal(p.rect().topLeft()))


class IntelligentConsole(QWidget):
    """Main intelligent network console window with tabbed interface.

    Manages TaskManager lifecycle for clean application shutdown.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"NetVista v{__import__('core').__version__}")
        self.resize(1280, 720)

        # Initialize TaskManager (singleton)
        self._task_manager = get_task_manager(self)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane { border: none; background: #1e1e1e; }
            QTabBar::tab { background: #2d2d2d; color: #ccc; padding: 8px 20px;
                           border: none; margin-right: 2px; }
            QTabBar::tab:selected { background: #3c3c3c; color: #fff; }
            QTabBar::tab:hover { background: #383838; }
        """)

        self.route_tab = RouteTableTab(self)
        self._refresh_scheduler = RefreshScheduler(self, debounce_ms=500)
        self.route_tab.connect_to_refresh_scheduler(self._refresh_scheduler)
        self._refresh_scheduler.refresh_requested.connect(self._on_refresh_needed)
        self.tabs.addTab(self.route_tab, "📋 路由表")

        self.topology_widget = TopologyWidget(self)
        self.tabs.addTab(self.topology_widget, "🌐 网络拓扑")

        self.event_log_widget = EventLogWidget(self)
        self.tabs.addTab(self.event_log_widget, "📡 事件日志")

        self.packet_monitor = PacketMonitorWidget(parent=self)
        self.tabs.addTab(self.packet_monitor, "📦 包监控")

        self.wfp_widget = WfpWidget(parent=self)
        self.tabs.addTab(self.wfp_widget, "🛡️ WFP 防火墙")

        layout.addWidget(self.tabs)

        self._event_tracer = EventTracer(self)
        self._event_tracer.network_changed.connect(self._refresh_scheduler.mark_dirty)

        self._etw_tracer = ETWTracer()

        self.route_tab.start()
        self.topology_widget.start()
        get_cache().warmup()

        interceptor = get_interceptor()
        self.packet_monitor.set_interceptor(interceptor)

        QTimer.singleShot(500, self.wfp_widget.start)

        QTimer.singleShot(1000, self._event_tracer.start)
        QTimer.singleShot(2000, self._etw_tracer.start)

    def _on_refresh_needed(self):
        """Called once per debounce window by RefreshScheduler.

        Merges route table refresh + cache invalidate + topology refresh
        into a single cycle — no duplicate work during VPN switch storms.
        """
        cache = get_cache()
        cache.invalidate_all()
        self.topology_widget.refresh()
        self.route_tab._async_refresh()

    def closeEvent(self, event):
        logger.info("Application shutting down...")
        event.ignore()

        # Show frameless modal "正在退出..." overlay — blocks parent interaction
        overlay = ShutdownOverlay(self)
        overlay.resizeToParent()
        overlay.show()
        QCoreApplication.processEvents()

        try:
            # Stop all subsystems in order
            self._refresh_scheduler.cancel()
            self._event_tracer.stop()
            self._etw_tracer.stop()
            get_event_bus().stop()
            self.packet_monitor.cleanup()
            self.topology_widget.stop()
            self.route_tab.stop()
            self.wfp_widget.cleanup()

            # Shutdown TaskManager (graceful, waits for all threads)
            self._task_manager.shutdown(timeout=5)
        finally:
            overlay.close()
            overlay.deleteLater()
            event.accept()
            super().closeEvent(event)
