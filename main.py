import sys
import os
import ctypes
import logging
import traceback

from PyQt5.QtWidgets import QApplication

from core.logger import setup_logging
from ui.ui_components import apply_style
from ui.main_window import IntelligentConsole


logger = logging.getLogger(__name__)

if getattr(sys, 'frozen', False):
    _TRACE_FILE = os.path.join(os.path.dirname(sys.executable), "app.log")
else:
    _TRACE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.log")


def _trace(msg):
    """Write directly to a trace file, independent of the logging system."""
    try:
        with open(_TRACE_FILE, "a", encoding="utf-8") as f:
            f.write(f"{msg}\n")
    except Exception:
        pass


def _setup_qt_env():
    """Set Qt platform plugin path and DLL PATH before QApplication init.
    UAC-elevated processes lose some environment variables, causing
    QApplication to fail with 'no Qt platform plugin could be initialized'."""
    try:
        import PyQt5
        qt_dir = os.path.dirname(PyQt5.__file__)
        candidates = [
            os.path.join(qt_dir, "Qt5", "plugins"),
            os.path.join(qt_dir, "plugins"),
        ]
        for d in candidates:
            if os.path.isdir(d):
                os.environ.setdefault("QT_QPA_PLATFORM_PLUGIN_PATH", d)
                _trace(f"QT_QPA_PLATFORM_PLUGIN_PATH = {d}")
                break

        bin_dirs = [
            os.path.join(qt_dir, "Qt5", "bin"),
            os.path.join(qt_dir, "bin"),
        ]
        for bd in bin_dirs:
            if os.path.isdir(bd):
                os.environ["PATH"] = bd + os.pathsep + os.environ.get("PATH", "")
                _trace(f"Qt bin added to PATH: {bd}")
                break
    except Exception as e:
        _trace(f"_setup_qt_env error: {e}")


def _win_messagebox(title, message):
    ctypes.windll.user32.MessageBoxW(None, message, title, 0)


def ensure_admin():
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        is_admin = False

    if not is_admin:
        exe = sys.executable
        script = os.path.abspath(sys.argv[0])
        workdir = os.path.dirname(script)
        quoted_args = [f'"{a}"' if " " in a else a for a in sys.argv[1:]]
        params = " ".join([f'"{script}"'] + quoted_args)
        _trace(f"ShellExecuteW: exe={exe} params={params} workdir={workdir}")
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, workdir, 1)
        _trace(f"ShellExecuteW returned: {ret}")
        if ret <= 32:
            logger.error("请求管理员权限失败，ShellExecuteW 返回 %d", ret)
            _win_messagebox("权限不足",
                "无法获取管理员权限，程序即将退出。\n\n"
                "请右键点击程序，选择「以管理员身份运行」。")
        sys.exit(0)


if __name__ == "__main__":
    try:
        setup_logging()
        logger.info("程序启动")
        _trace("=== 程序启动 ===")
        ensure_admin()
        _trace("=== 管理员权限已获取 ===")
        logger.info("获取管理员权限成功")
        _trace("=== 设置 Qt 环境变量 ===")
        _setup_qt_env()
        _trace("=== 正在创建 QApplication ===")
        app = QApplication(sys.argv)
        _trace("=== QApplication 创建成功 ===")
        apply_style(app)
        _trace("=== 样式已应用 ===")
        win = IntelligentConsole()
        _trace("=== IntelligentConsole 创建成功 ===")
        win.show()
        _trace("=== 窗口已显示 ===")
        sys.exit(app.exec_())
    except SystemExit:
        _trace("=== SystemExit 异常 ===")
        raise
    except Exception:
        _trace("=== 未预期的异常 ===")
        tb = traceback.format_exc()
        _trace(tb)
        logger.exception("程序启动异常")
        _win_messagebox("程序启动失败",
            f"程序初始化时发生未预期的异常：\n\n{tb}\n\n"
            f"详细日志已写入 app.log，请查看。")
        sys.exit(1)
