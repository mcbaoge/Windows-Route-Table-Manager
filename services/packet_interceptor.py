"""Network traffic monitor — polls GetIfTable for per-interface byte/packet counters.

Monitor mode:  polls interface byte counters (no admin required).

Thread model: PeriodicTaskMgr via TaskManager (QTimer + pool).
"""
import ctypes
import ctypes.wintypes
import logging
import os
import socket
import threading
import time
from dataclasses import dataclass, field

from services.task_manager import get_task_manager

logger = logging.getLogger(__name__)

class MIB_IFROW(ctypes.Structure):
    _fields_ = [
        ("wszName", ctypes.wintypes.WCHAR * 256),
        ("dwIndex", ctypes.c_uint32),
        ("dwType", ctypes.c_uint32),
        ("dwMtu", ctypes.c_uint32),
        ("dwSpeed", ctypes.c_uint32),
        ("dwPhysAddrLen", ctypes.c_uint32),
        ("bPhysAddr", ctypes.c_uint8 * 8),
        ("dwAdminStatus", ctypes.c_uint32),
        ("dwOperStatus", ctypes.c_uint32),
        ("dwLastChange", ctypes.c_uint32),
        ("dwInOctets", ctypes.c_uint32),
        ("dwInUcastPkts", ctypes.c_uint32),
        ("dwInNUcastPkts", ctypes.c_uint32),
        ("dwInDiscards", ctypes.c_uint32),
        ("dwInErrors", ctypes.c_uint32),
        ("dwInUnknownProtos", ctypes.c_uint32),
        ("dwOutOctets", ctypes.c_uint32),
        ("dwOutUcastPkts", ctypes.c_uint32),
        ("dwOutNUcastPkts", ctypes.c_uint32),
        ("dwOutDiscards", ctypes.c_uint32),
        ("dwOutErrors", ctypes.c_uint32),
        ("dwOutQLen", ctypes.c_uint32),
        ("dwDescrLen", ctypes.c_uint32),
        ("bDescr", ctypes.c_uint8 * 256),
    ]


PMIB_IFROW = ctypes.POINTER(MIB_IFROW)


class MIB_IFTABLE(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", ctypes.c_uint32),
        ("table", MIB_IFROW * 1),
    ]


PMIB_IFTABLE = ctypes.POINTER(MIB_IFTABLE)


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.c_uint32),
        ("dwLocalAddr", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("dwRemoteAddr", ctypes.c_uint32),
        ("dwRemotePort", ctypes.c_uint32),
        ("dwOwningPid", ctypes.c_uint32),
    ]


class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", ctypes.c_uint32),
        ("table", MIB_TCPROW_OWNER_PID * 1),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("dwOwningPid", ctypes.c_uint32),
    ]


class MIB_UDPTABLE_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwNumEntries", ctypes.c_uint32),
        ("table", MIB_UDPROW_OWNER_PID * 1),
    ]


_iphlpapi = ctypes.WinDLL("iphlpapi")

_iphlpapi.GetIfTable.argtypes = [
    PMIB_IFTABLE,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.c_bool,
]
_iphlpapi.GetIfTable.restype = ctypes.c_uint32

_iphlpapi.GetExtendedTcpTable.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.c_bool,
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_uint32,
]
_iphlpapi.GetExtendedTcpTable.restype = ctypes.c_uint32

_iphlpapi.GetExtendedUdpTable.argtypes = [
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.c_bool,
    ctypes.c_uint32,
    ctypes.c_uint32,
    ctypes.c_uint32,
]
_iphlpapi.GetExtendedUdpTable.restype = ctypes.c_uint32

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
_kernel32.OpenProcess.restype = ctypes.c_void_p
_kernel32.QueryFullProcessImageNameW.argtypes = [
    ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32),
]
_kernel32.QueryFullProcessImageNameW.restype = ctypes.c_bool
_kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
_kernel32.CloseHandle.restype = ctypes.c_bool

PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
NO_ERROR = 0
ERROR_INSUFFICIENT_BUFFER = 122
AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
PID_NONE = 0xFFFFFFFF


_IFACE_BLACKLIST = [
    "vmware", "virtual", "hyper-v", "loopback", "tunnel",
    "pseudo", "bluetooth", "ppp", "适配器", "虚拟", "隧道",
    "kernel debug", "miniport", "6to4", "ip-https", "isatap",
    "teredo", "wan miniport", "wintun", "路由管理器",
]


def _clean_iface_desc(raw: bytes) -> str:
    desc = raw.split(b'\x00')[0].decode('gbk', errors='replace').strip()
    return desc


def _is_valid_iface(row) -> bool:
    desc = _clean_iface_desc(bytes(row.bDescr))
    if not desc:
        return False
    low = desc.lower()
    for b in _IFACE_BLACKLIST:
        if b in low:
            return False
    return True


@dataclass
class TrafficStatsSnapshot:
    timestamp: float = 0.0
    upload_bytes: int = 0
    download_bytes: int = 0
    upload_packets: int = 0
    download_packets: int = 0
    upload_bps: float = 0.0
    download_bps: float = 0.0
    upload_pps: float = 0.0
    download_pps: float = 0.0
    active_connections: int = 0
    per_process: list = field(default_factory=list)


_PID_CACHE: dict[int, tuple[str, float]] = {}
_PID_CACHE_LOCK = threading.Lock()
_PID_CACHE_TTL = 10.0


def _get_process_name(pid: int) -> str:
    if pid <= 0 or pid == PID_NONE:
        return "System"
    now = time.time()
    with _PID_CACHE_LOCK:
        cached = _PID_CACHE.get(pid)
        if cached and (now - cached[1]) < _PID_CACHE_TTL:
            return cached[0]
    name = f"PID:{pid}"
    h_process = None
    try:
        h_process = _kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if h_process:
            buf = ctypes.create_unicode_buffer(260)
            size = ctypes.c_uint32(260)
            if _kernel32.QueryFullProcessImageNameW(h_process, 0, buf, ctypes.byref(size)):
                name = os.path.basename(buf.value) or name
    except Exception:
        pass
    finally:
        if h_process:
            _kernel32.CloseHandle(h_process)
    with _PID_CACHE_LOCK:
        _PID_CACHE[pid] = (name, now)
    return name


class InterfaceStatsReader:
    """Polls GetIfTable for per-interface byte/packet counters."""

    def __init__(self):
        self._buf_size = ctypes.c_uint32(0)
        self._buf = None
        self._table_ptr = None
        self._valid_indices: list[int] = []
        self._row_size = ctypes.sizeof(MIB_IFROW)

    def _ensure_buf(self, needed: int):
        if self._buf is None or self._buf_size.value < needed:
            self._buf_size.value = needed + 4096
            self._buf = ctypes.create_string_buffer(self._buf_size.value)
            self._table_ptr = ctypes.cast(self._buf, PMIB_IFTABLE)

    def read_all(self) -> tuple[int, int, int, int]:
        buf_size = ctypes.c_uint32(0)
        rc = _iphlpapi.GetIfTable(None, ctypes.byref(buf_size), False)
        if rc != ERROR_INSUFFICIENT_BUFFER:
            return 0, 0, 0, 0

        self._ensure_buf(buf_size.value)
        rc = _iphlpapi.GetIfTable(self._table_ptr, ctypes.byref(self._buf_size), False)
        if rc != NO_ERROR:
            return 0, 0, 0, 0

        table = self._table_ptr.contents
        n = table.dwNumEntries
        total_up = 0
        total_down = 0
        total_up_pkts = 0
        total_down_pkts = 0
        base = ctypes.addressof(table)
        offset = ctypes.sizeof(ctypes.c_uint32)

        for i in range(n):
            addr = base + offset + i * self._row_size
            row = ctypes.cast(addr, PMIB_IFROW).contents
            if not _is_valid_iface(row):
                continue
            total_up += row.dwOutOctets
            total_down += row.dwInOctets
            total_up_pkts += row.dwOutUcastPkts
            total_down_pkts += row.dwInUcastPkts

        return total_up, total_down, total_up_pkts, total_down_pkts


class ProcessScanner:
    """Scans TCP/UDP tables to count connections per process."""

    def __init__(self):
        self._lock = threading.Lock()
        self._buf_tcp = ctypes.create_string_buffer(65536)
        self._buf_udp = ctypes.create_string_buffer(65536)
        self._tcp_size = ctypes.c_uint32(65536)
        self._udp_size = ctypes.c_uint32(65536)
        self._row_size_udp = ctypes.sizeof(MIB_UDPROW_OWNER_PID)
        self._row_size_tcp = ctypes.sizeof(MIB_TCPROW_OWNER_PID)

    def scan(self) -> tuple[list, int]:
        tcp_pids = self._scan_tcp()
        udp_pids = self._scan_udp()
        with self._lock:
            proc_conns: dict[str, int] = {}
            total = 0
            for pid in tcp_pids:
                name = _get_process_name(pid)
                proc_conns[name] = proc_conns.get(name, 0) + 1
                total += 1
            for pid in udp_pids:
                name = _get_process_name(pid)
                proc_conns[name] = proc_conns.get(name, 0) + 1
                total += 1

            pp_list = sorted(
                [(name, count) for name, count in proc_conns.items()],
                key=lambda x: x[1], reverse=True,
            )
        return pp_list, total

    def _scan_tcp(self) -> list[int]:
        try:
            size = ctypes.c_uint32(0)
            _iphlpapi.GetExtendedTcpTable(None, ctypes.byref(size), False, AF_INET,
                                          TCP_TABLE_OWNER_PID_ALL, 0)
            if size.value > self._tcp_size.value:
                self._tcp_size.value = size.value + 4096
                self._buf_tcp = ctypes.create_string_buffer(self._tcp_size.value)
            rc = _iphlpapi.GetExtendedTcpTable(self._buf_tcp, ctypes.byref(self._tcp_size),
                                               False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
            if rc != NO_ERROR:
                return []
            n = ctypes.cast(self._buf_tcp, ctypes.POINTER(ctypes.c_uint32))[0]
            pids = []
            for i in range(n):
                offset = 4 + i * self._row_size_tcp
                row = ctypes.cast(ctypes.byref(self._buf_tcp, offset),
                                  ctypes.POINTER(MIB_TCPROW_OWNER_PID)).contents
                pids.append(row.dwOwningPid)
            return pids
        except Exception:
            return []

    def _scan_udp(self) -> list[int]:
        try:
            size = ctypes.c_uint32(0)
            _iphlpapi.GetExtendedUdpTable(None, ctypes.byref(size), False, AF_INET,
                                          UDP_TABLE_OWNER_PID, 0)
            if size.value > self._udp_size.value:
                self._udp_size.value = size.value + 4096
                self._buf_udp = ctypes.create_string_buffer(self._udp_size.value)
            rc = _iphlpapi.GetExtendedUdpTable(self._buf_udp, ctypes.byref(self._udp_size),
                                               False, AF_INET, UDP_TABLE_OWNER_PID, 0)
            if rc != NO_ERROR:
                return []
            n = ctypes.cast(self._buf_udp, ctypes.POINTER(ctypes.c_uint32))[0]
            pids = []
            for i in range(n):
                offset = 4 + i * self._row_size_udp
                row = ctypes.cast(ctypes.byref(self._buf_udp, offset),
                                  ctypes.POINTER(MIB_UDPROW_OWNER_PID)).contents
                pids.append(row.dwOwningPid)
            return pids
        except Exception:
            return []


class PacketInterceptor:
    """Monitors network interface byte/packet counters via GetIfTable.

    Uses PeriodicTaskMgr (QTimer + pool) instead of a dedicated thread.
    """

    def __init__(self):
        self._running = False
        self._mode = "idle"
        self._stop_event = threading.Event()
        self._stats_lock = threading.Lock()
        self._iface_reader = InterfaceStatsReader()
        self._proc_scanner = ProcessScanner()
        self._periodic = None

        self._up_bytes = 0
        self._down_bytes = 0
        self._up_packets = 0
        self._down_packets = 0
        self._up_bps = 0.0
        self._down_bps = 0.0
        self._up_pps = 0.0
        self._down_pps = 0.0
        self._pp_list: list = []
        self._active_conns = 0

        self._last_up = 0
        self._last_down = 0
        self._last_up_pkts = 0
        self._last_down_pkts = 0
        self._last_sample = time.time()
        self._last_error = ""

    @property
    def available(self) -> bool:
        return _iphlpapi is not None

    @property
    def running(self) -> bool:
        return self._running

    @property
    def mode(self) -> str:
        return self._mode

    @property
    def last_error(self) -> str:
        return self._last_error

    def start_capture(self) -> bool:
        if self._running:
            return True
        if not self.available:
            self._last_error = "iphlpapi.dll 不可用"
            return False

        self._stop_event.clear()
        self._running = True
        self._mode = "monitor"
        self._last_sample = time.time()

        self._up_bytes, self._down_bytes, self._up_packets, self._down_packets = \
            self._iface_reader.read_all()
        self._last_up = self._up_bytes
        self._last_down = self._down_bytes
        self._last_up_pkts = self._up_packets
        self._last_down_pkts = self._down_packets

        tm = get_task_manager()
        self._periodic = tm.schedule_periodic(
            interval_ms=1000,
            fn=self._poll,
            task_id="packet-interceptor",
        )
        logger.info("监控模式已启动 (PeriodicTaskMgr)")
        return True

    def stop_capture(self):
        self._running = False
        self._stop_event.set()
        if self._periodic:
            self._periodic.stop()
            self._periodic = None
        self._mode = "idle"
        logger.info("监控模式已停止")

    def _poll(self):
        if not self._running:
            return
        try:
            self._do_poll()
        except Exception:
            logger.exception("轮询异常")

    def _do_poll(self):
        now = time.time()
        up, down, up_pkts, down_pkts = self._iface_reader.read_all()
        dt = now - self._last_sample

        with self._stats_lock:
            du = up - self._last_up
            dd = down - self._last_down
            dpu = up_pkts - self._last_up_pkts
            dpd = down_pkts - self._last_down_pkts

            if dt > 0.01:
                du = (du + 0x100000000) % 0x100000000
                dd = (dd + 0x100000000) % 0x100000000
                dpu = (dpu + 0x100000000) % 0x100000000
                dpd = (dpd + 0x100000000) % 0x100000000
                self._up_bps = (du * 8) / dt
                self._down_bps = (dd * 8) / dt
                self._up_pps = dpu / dt
                self._down_pps = dpd / dt

            self._up_bytes = up
            self._down_bytes = down
            self._up_packets = up_pkts
            self._down_packets = down_pkts
            self._last_up = up
            self._last_down = down
            self._last_up_pkts = up_pkts
            self._last_down_pkts = down_pkts

        self._last_sample = now

    def get_stats_snapshot(self) -> TrafficStatsSnapshot:
        with self._stats_lock:
            pp_list, active = self._proc_scanner.scan()
            per_proc = [(name, count) for name, count in pp_list]
            return TrafficStatsSnapshot(
                timestamp=time.time(),
                upload_bytes=self._up_bytes, download_bytes=self._down_bytes,
                upload_packets=self._up_packets, download_packets=self._down_packets,
                upload_bps=self._up_bps, download_bps=self._down_bps,
                upload_pps=self._up_pps, download_pps=self._down_pps,
                active_connections=active,
                per_process=per_proc,
            )

    def get_version(self) -> str:
        return "IPHLPAPI"

    def diagnose(self) -> str:
        return "监控模式 (接口统计轮询)"


_instance: PacketInterceptor | None = None
_instance_lock = threading.Lock()


def get_interceptor() -> PacketInterceptor:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = PacketInterceptor()
    return _instance
