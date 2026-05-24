"""Process-to-network connection mapping.

Maps:
  process (chrome.exe) → TCP/UDP connection → remote IP → interface → gateway

Uses GetExtendedTcpTable / GetExtendedUdpTable for connection enumeration
and OpenProcess/QueryFullProcessImageNameW for process name resolution.

Thread model: PeriodicTaskMgr via TaskManager.
"""
import ctypes
import ctypes.wintypes
import logging
import os
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from services.task_manager import get_task_manager

logger = logging.getLogger(__name__)

NO_ERROR = 0
ERROR_INSUFFICIENT_BUFFER = 122
AF_INET = 2
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
PID_NONE = 0xFFFFFFFF
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

_iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

_kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_bool, ctypes.c_uint32]
_kernel32.OpenProcess.restype = ctypes.c_void_p
_kernel32.QueryFullProcessImageNameW.argtypes = [
    ctypes.c_void_p, ctypes.c_uint32, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint32),
]
_kernel32.QueryFullProcessImageNameW.restype = ctypes.c_bool
_kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
_kernel32.CloseHandle.restype = ctypes.c_bool


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.c_uint32),
        ("dwLocalAddr", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("dwRemoteAddr", ctypes.c_uint32),
        ("dwRemotePort", ctypes.c_uint32),
        ("dwOwningPid", ctypes.c_uint32),
    ]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("dwOwningPid", ctypes.c_uint32),
    ]


# PID → process name cache
_pid_cache: dict[int, tuple[str, float]] = {}
_pid_cache_lock = threading.Lock()
_PID_CACHE_TTL = 10.0


def get_process_name(pid: int) -> str:
    if pid <= 0 or pid == PID_NONE:
        return "System"
    now = time.time()
    with _pid_cache_lock:
        cached = _pid_cache.get(pid)
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
    with _pid_cache_lock:
        _pid_cache[pid] = (name, now)
    return name


@dataclass
class ProcessConnection:
    process_name: str = ""
    pid: int = 0
    protocol: str = "TCP"
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    remote_host: str = ""
    state: str = ""


@dataclass
class ProcessNetworkInfo:
    process_name: str = ""
    pid: int = 0
    path: str = ""
    connection_count: int = 0
    unique_remotes: int = 0
    connections: list[ProcessConnection] = field(default_factory=list)
    bandwidth_estimate: float = 0.0


class ProcessMonitor:
    """Scans TCP/UDP tables to build process→network mapping."""

    def __init__(self):
        self._lock = threading.Lock()
        self._proc_map: dict[str, ProcessNetworkInfo] = {}
        self._buf_tcp = ctypes.create_string_buffer(65536)
        self._buf_udp = ctypes.create_string_buffer(65536)
        self._tcp_size = ctypes.c_uint32(65536)
        self._udp_size = ctypes.c_uint32(65536)
        self._row_size_tcp = ctypes.sizeof(MIB_TCPROW_OWNER_PID)
        self._row_size_udp = ctypes.sizeof(MIB_UDPROW_OWNER_PID)
        self._running = False

    @property
    def process_map(self) -> dict[str, ProcessNetworkInfo]:
        with self._lock:
            return dict(self._proc_map)

    def start(self):
        self._running = True

    def stop(self):
        self._running = False

    def scan(self) -> dict[str, ProcessNetworkInfo]:
        """Scan all TCP/UDP connections and build process map."""
        if not self._running:
            return {}
        tcp_conns = self._scan_tcp()
        udp_conns = self._scan_udp()

        proc_map: dict[str, ProcessNetworkInfo] = {}

        def _add(conn: ProcessConnection):
            key = f"{conn.process_name}|{conn.pid}"
            if key not in proc_map:
                proc_map[key] = ProcessNetworkInfo(
                    process_name=conn.process_name,
                    pid=conn.pid,
                )
            info = proc_map[key]
            info.connections.append(conn)
            info.connection_count = len(info.connections)
            info.unique_remotes = len(set(c.remote_addr for c in info.connections
                                          if c.remote_addr and c.remote_addr != "0.0.0.0"))

        for c in tcp_conns:
            _add(c)
        for c in udp_conns:
            _add(c)

        with self._lock:
            self._proc_map = proc_map

        return proc_map

    def _scan_tcp(self) -> list[ProcessConnection]:
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
            n = struct.unpack_from("I", self._buf_tcp, 0)[0]
            conns = []
            for i in range(n):
                offset = 4 + i * self._row_size_tcp
                row = ctypes.cast(
                    ctypes.byref(self._buf_tcp, offset),
                    ctypes.POINTER(MIB_TCPROW_OWNER_PID),
                ).contents

                la = socket.inet_ntoa(struct.pack("I", row.dwLocalAddr))
                ra = socket.inet_ntoa(struct.pack("I", row.dwRemoteAddr))
                lp = socket.ntohs(row.dwLocalPort)
                rp = socket.ntohs(row.dwRemotePort)
                pid = row.dwOwningPid

                state_map = {
                    1: "CLOSED", 2: "LISTEN", 3: "SYN_SENT", 4: "SYN_RCVD",
                    5: "ESTAB", 6: "FIN_WAIT1", 7: "FIN_WAIT2", 8: "CLOSE_WAIT",
                    9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
                }
                state = state_map.get(row.dwState, "UNKNOWN")

                if ra.startswith("127.") or ra == "0.0.0.0" or ra == "0.0.0.0":
                    continue

                proc_name = get_process_name(pid)
                conns.append(ProcessConnection(
                    process_name=proc_name, pid=pid, protocol="TCP",
                    local_addr=la, local_port=lp,
                    remote_addr=ra, remote_port=rp,
                    state=state,
                ))
            return conns
        except Exception as e:
            logger.debug("TCP scan error: %s", e)
            return []

    def _scan_udp(self) -> list[ProcessConnection]:
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
            n = struct.unpack_from("I", self._buf_udp, 0)[0]
            conns = []
            for i in range(n):
                offset = 4 + i * self._row_size_udp
                row = ctypes.cast(
                    ctypes.byref(self._buf_udp, offset),
                    ctypes.POINTER(MIB_UDPROW_OWNER_PID),
                ).contents
                la = socket.inet_ntoa(struct.pack("I", row.dwLocalAddr))
                lp = socket.ntohs(row.dwLocalPort)
                pid = row.dwOwningPid
                proc_name = get_process_name(pid)
                conns.append(ProcessConnection(
                    process_name=proc_name, pid=pid, protocol="UDP",
                    local_addr=la, local_port=lp,
                    remote_addr="0.0.0.0", remote_port=0,
                    state="LISTEN",
                ))
            return conns
        except Exception as e:
            logger.debug("UDP scan error: %s", e)
            return []
