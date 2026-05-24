"""Wintun-based virtual TUN adapter for packet capture and I/O.

Provides a virtual network adapter that works at the IP layer,
bypassing the Windows Driver Signature Enforcement (DSE) issue
that affects WinDivert on modern Windows.

Wintun driver is Microsoft-signed (used by WireGuard).
"""
import ctypes
import io
import logging
import os
import platform
import threading
import time
import zipfile
from urllib.request import urlopen

logger = logging.getLogger(__name__)

# ============================================================
# Constants
# ============================================================

WINTUN_MAX_PACKET_SIZE = 65535
WINTUN_DEFAULT_CAPACITY = 0x200000  # 2MB ring buffer
WINTUN_DOWNLOAD_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip"

# ============================================================
# ctypes Structures
# ============================================================

class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_uint8 * 8),
    ]


class NET_LUID(ctypes.Structure):
    _fields_ = [
        ("Value", ctypes.c_uint64),
    ]


# ============================================================
# Wintun DLL
# ============================================================

_wintun_dll: ctypes.WinDLL | None = None
_wintun_lock = threading.Lock()


def _get_app_dir() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _get_arch_dir() -> str:
    """Return the architecture subdirectory name."""
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64", "x64"):
        return "amd64"
    if machine in ("arm64", "aarch64"):
        return "arm64"
    if machine in ("arm",):
        return "arm"
    return "x86"


def _get_wintun_dll_path() -> str:
    app_dir = _get_app_dir()
    arch = _get_arch_dir()
    return os.path.join(app_dir, "tun", arch, "wintun.dll")


def _get_tun_dir() -> str:
    return os.path.dirname(_get_wintun_dll_path())


def _download_wintun() -> bool:
    """Download wintun.dll from official source into tun/<arch>/."""
    dest = _get_wintun_dll_path()
    tun_dir = _get_tun_dir()
    logger.info("正在下载 Wintun (wintun.dll) 到 %s ...", dest)
    try:
        os.makedirs(tun_dir, exist_ok=True)
        resp = urlopen(WINTUN_DOWNLOAD_URL, timeout=30)
        data = resp.read()
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            arch = _get_arch_dir()
            member = f"wintun/bin/{arch}/wintun.dll"
            if member not in zf.namelist():
                logger.error("Wintun 包中未找到 %s", member)
                return False
            with zf.open(member) as src, open(dest, "wb") as dst:
                dst.write(src.read())
        logger.info("Wintun 下载完成: %s", dest)
        return True
    except Exception as e:
        logger.error("Wintun 下载失败: %s", e)
        return False


def _load_wintun() -> ctypes.WinDLL | None:
    global _wintun_dll
    if _wintun_dll is not None:
        return _wintun_dll
    with _wintun_lock:
        if _wintun_dll is not None:
            return _wintun_dll

        dll_path = _get_wintun_dll_path()
        if not os.path.isfile(dll_path):
            logger.info("wintun.dll 未找到，尝试自动下载...")
            if not _download_wintun():
                logger.warning("自动下载失败，请手动从 %s 下载 wintun.dll 放入应用根目录",
                               WINTUN_DOWNLOAD_URL)
                return None

        try:
            _wintun_dll = ctypes.WinDLL(dll_path)
        except OSError as e:
            logger.error("wintun.dll 加载失败: %s", e)
            return None

        _bind_wintun_functions()
        logger.info("Wintun 已加载 (%s)", dll_path)
        return _wintun_dll


def _bind_wintun_functions():
    global _wintun_dll
    if _wintun_dll is None:
        return

    _wintun_dll.WintunCreateAdapter.restype = ctypes.c_void_p
    _wintun_dll.WintunCreateAdapter.argtypes = [
        ctypes.c_wchar_p,
        ctypes.c_wchar_p,
        ctypes.POINTER(GUID),
    ]

    _wintun_dll.WintunStartSession.restype = ctypes.c_void_p
    _wintun_dll.WintunStartSession.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

    _wintun_dll.WintunEndSession.restype = None
    _wintun_dll.WintunEndSession.argtypes = [ctypes.c_void_p]

    _wintun_dll.WintunAllocateSendPacket.restype = ctypes.c_void_p
    _wintun_dll.WintunAllocateSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_uint32]

    _wintun_dll.WintunSendPacket.restype = None
    _wintun_dll.WintunSendPacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    _wintun_dll.WintunReceivePacket.restype = ctypes.c_void_p
    _wintun_dll.WintunReceivePacket.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]

    _wintun_dll.WintunReleaseReceivePacket.restype = None
    _wintun_dll.WintunReleaseReceivePacket.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

    _wintun_dll.WintunGetAdapterLUID.restype = None
    _wintun_dll.WintunGetAdapterLUID.argtypes = [ctypes.c_void_p, ctypes.POINTER(NET_LUID)]

    _wintun_dll.WintunGetRunningDriverVersion.restype = ctypes.c_bool
    _wintun_dll.WintunGetRunningDriverVersion.argtypes = [ctypes.POINTER(ctypes.c_uint32)]

    for name in ("WintunDeleteAdapter", "WintunFreeAdapter"):
        try:
            fn = getattr(_wintun_dll, name)
            fn.restype = None
            fn.argtypes = [ctypes.c_void_p, ctypes.c_bool]
        except AttributeError:
            logger.warning("wintun.dll 不导出 %s (功能降级)", name)


# ============================================================
# WintunAdapter
# ============================================================

class WintunAdapter:
    """Manages a Wintun virtual TUN adapter for packet I/O."""

    ADAPTER_NAME = "Windows 路由管理器"
    TUNNEL_TYPE = "RouteManager"

    def __init__(self):
        self._dll = None
        self._adapter = None
        self._session = None
        self._name = None
        self._luid = NET_LUID()
        self._recv_size = ctypes.c_uint32(0)
        self._running = False

    @property
    def available(self) -> bool:
        return self._dll is not None

    @property
    def running(self) -> bool:
        return self._running

    @property
    def luid(self) -> int:
        return self._luid.Value

    def load(self) -> bool:
        self._dll = _load_wintun()
        if self._dll is None:
            return False
        ver = ctypes.c_uint32(0)
        if self._dll.WintunGetRunningDriverVersion(ctypes.byref(ver)):
            logger.info("Wintun 驱动版本: %d.%d", ver.value >> 16, ver.value & 0xFFFF)
        return True

    def create_adapter(self, name: str | None = None) -> bool:
        if self._dll is None:
            return False
        if self._adapter:
            return True

        self._name = name or self.ADAPTER_NAME
        try:
            self._adapter = ctypes.c_void_p(
                self._dll.WintunCreateAdapter(self._name, self.TUNNEL_TYPE, None)
            )
            if not self._adapter or not self._adapter.value:
                self._adapter = None
                logger.error("WintunCreateAdapter 失败")
                return False

            self._dll.WintunGetAdapterLUID(self._adapter, ctypes.byref(self._luid))
            logger.info("TUN 适配器已创建: name=%s, LUID=0x%x", self._name, self._luid.Value)
            return True
        except Exception as e:
            logger.exception("创建 TUN 适配器异常: %s", e)
            self._adapter = None
            return False

    def open_session(self, capacity: int = WINTUN_DEFAULT_CAPACITY) -> bool:
        if self._dll is None or self._adapter is None:
            return False
        if self._session:
            return True

        try:
            self._session = ctypes.c_void_p(
                self._dll.WintunStartSession(self._adapter, capacity)
            )
            if not self._session or not self._session.value:
                self._session = None
                logger.error("WintunStartSession 失败")
                return False
            self._running = True
            logger.info("TUN 会话已打开 (capacity=%d)", capacity)
            return True
        except Exception as e:
            logger.exception("打开 TUN 会话异常: %s", e)
            self._session = None
            return False

    def read_packet(self) -> tuple[bytes, int] | None:
        """Read a packet from the TUN adapter.

        Returns (packet_bytes, length) or None if no packet available.
        """
        if self._dll is None or self._session is None:
            return None
        self._recv_size.value = 0
        try:
            pkt = self._dll.WintunReceivePacket(
                self._session, ctypes.byref(self._recv_size)
            )
            if not pkt:
                return None
            size = self._recv_size.value
            if size == 0:
                return None
            data = ctypes.string_at(pkt, size)
            self._dll.WintunReleaseReceivePacket(self._session, ctypes.c_void_p(pkt))
            return data, size
        except Exception:
            return None

    def write_packet(self, data: bytes) -> bool:
        """Write a packet to the TUN adapter."""
        if self._dll is None or self._session is None:
            return False
        size = len(data)
        try:
            pkt = self._dll.WintunAllocateSendPacket(self._session, size)
            if not pkt:
                return False
            ctypes.memmove(pkt, data, size)
            self._dll.WintunSendPacket(self._session, ctypes.c_void_p(pkt))
            return True
        except Exception:
            return False

    def close_session(self):
        if self._session:
            try:
                self._dll.WintunEndSession(self._session)
            except Exception:
                pass
            self._session = None
        self._running = False

    def delete_adapter(self):
        self.close_session()
        if self._adapter:
            fn = getattr(self._dll, "WintunDeleteAdapter", None) or getattr(self._dll, "WintunFreeAdapter", None)
            if fn:
                try:
                    fn(self._adapter, True)
                    logger.info("TUN 适配器已删除")
                except Exception:
                    pass
            else:
                logger.warning("wintun.dll 无删除适配器函数，跳过清理")
            self._adapter = None

    def close(self):
        self.delete_adapter()
        self._dll = None


# ============================================================
# Module-level singleton
# ============================================================

_adapter_instance: WintunAdapter | None = None
_adapter_lock = threading.Lock()


def get_adapter() -> WintunAdapter:
    global _adapter_instance
    if _adapter_instance is None:
        with _adapter_lock:
            if _adapter_instance is None:
                _adapter_instance = WintunAdapter()
    return _adapter_instance
