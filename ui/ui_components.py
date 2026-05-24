import logging

from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QLabel, QDialog,
    QDialogButtonBox, QCheckBox, QRadioButton, QMessageBox,
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFocusEvent

from core import config
from network.networking import do_set_default_route
from services.task_manager import get_task_manager, TaskSignals

logger = logging.getLogger(__name__)


class ImportOptionsDialog(QDialog):
    def __init__(self, route_count, parent=None):
        super().__init__(parent)
        self.setWindowTitle("导入路由配置")
        self.setModal(True)
        self.setMinimumWidth(420)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"将导入 {route_count} 条路由，请选择导入模式："))

        self.skip_rb = QRadioButton("跳过重复路由（已有则跳过，其余添加）")
        self.overwrite_rb = QRadioButton("覆盖已有路由（先删除再添加）")
        self.restore_rb = QRadioButton("清空后完全恢复（先删除全部现有路由，再导入）")
        self.skip_rb.setChecked(True)

        layout.addWidget(self.skip_rb)
        layout.addWidget(self.overwrite_rb)
        layout.addWidget(self.restore_rb)

        layout.addSpacing(10)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def selected_mode(self):
        if self.skip_rb.isChecked():
            return "skip"
        elif self.overwrite_rb.isChecked():
            return "overwrite"
        return "restore"


def apply_style(app):
    app.setStyleSheet("""
    QWidget {
        background-color: #1e1e1e;
        color: #dddddd;
        font-family: "Segoe UI";
        font-size: 12px;
    }
    QTableWidget {
        background-color: #252526;
        border: none;
        selection-background-color: #094771;
    }
    QHeaderView::section {
        background-color: #2d2d30;
        border: none;
        padding: 6px;
    }
    QTableWidget::item {
        padding: 6px;
        border: none;
    }
    QLineEdit, QComboBox {
        background-color: #2b2b2b;
        border: 1px solid #3c3c3c;
        border-radius: 4px;
        padding: 4px 6px;
    }
    QPushButton {
        background-color: #2d2d30;
        border: 1px solid #3c3c3c;
        border-radius: 4px;
        padding: 6px 14px;
        min-height: 28px;
    }
    QPushButton:hover { background-color: #3e3e42; }
    """)


class LoadingDialog(QDialog):
    def __init__(self, text="正在应用配置，请稍候...", parent=None):
        super().__init__(parent)
        self.setWindowTitle("请稍候")
        self.setModal(True)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowCloseButtonHint)

        layout = QVBoxLayout(self)
        label = QLabel(text)
        label.setAlignment(Qt.AlignCenter)
        layout.addWidget(label)

        self.resize(320, 120)


def run_with_loading(parent, text, func, *args, **kwargs):
    """Run a function in TaskManager's thread pool with a loading dialog."""
    dlg = LoadingDialog(text=text, parent=parent)
    tm = get_task_manager()

    def on_finished_ok(result):
        if dlg.isVisible():
            dlg.accept()

    def on_finished_err(err_msg):
        if dlg.isVisible():
            dlg.accept()
        QMessageBox.critical(parent, "错误", f"执行操作时发生异常：{err_msg}")

    task = tm.submit(fn=func, args=args, kwargs=kwargs)
    task.signals.finished.connect(on_finished_ok)
    task.signals.error.connect(on_finished_err)

    dlg.exec_()
    return task


class ValidatedLineEdit(QLineEdit):
    def __init__(self, validator_callback, parent=None):
        super().__init__(parent)
        self.validator_callback = validator_callback

    def focusOutEvent(self, event: QFocusEvent):
        self.validator_callback()
        super().focusOutEvent(event)


class ConfirmDialog(QDialog):
    def __init__(self, title, message, parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(message))
        self.persistent_cb = QCheckBox("永久路由（重启后保留）")
        self.persistent_cb.setChecked(True)
        layout.addWidget(self.persistent_cb)
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)


def set_default_route_with_ui(parent: QWidget, iface_idx: str):
    logger.info("UI 切换默认路由 | 目标接口=%s", iface_idx)
    result_holder = {"msg": None, "error": None}

    def task():
        return do_set_default_route(iface_idx)

    dlg = LoadingDialog(text="正在切换默认路由优先级，请稍候...", parent=parent)
    task_signals = TaskSignals()
    tm = get_task_manager()

    def on_ok(msg):
        result_holder["msg"] = msg
        if dlg.isVisible():
            dlg.accept()

    def on_err(err_msg):
        result_holder["error"] = Exception(err_msg)
        if dlg.isVisible():
            dlg.accept()

    task = tm.submit(fn=task)
    task.signals.finished.connect(on_ok)
    task.signals.error.connect(on_err)

    dlg.exec_()
    task.wait(timeout=30)

    if result_holder["error"] is not None:
        QMessageBox.warning(parent, "切换默认路由失败", str(result_holder["error"]))
    elif result_holder["msg"] is not None:
        QMessageBox.information(
            parent,
            "成功",
            f"默认路由优先出口已切换到接口 {iface_idx}（metric={config.DEFAULT_METRIC_LOW}），"
            f"其他已有默认路由的接口 metric 已设为 {config.DEFAULT_METRIC_HIGH}。\n\n"
            f"详情：\n{result_holder['msg']}"
        )
