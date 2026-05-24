"""Event tracer — network event monitoring and diagnostics.

Monitors:
  - TCP connections via GetExtendedTcpTable polling (ConnectionEvent)
  - Route changes via NotifyRouteChange2 (RouteEvent)
  - Interface/address changes via NotifyIpInterfaceChange /
    NotifyUnicastIpAddressChange (InterfaceEvent)
  - DNS events via ETWTracer (managed separately in main_window.py)

Publishes all typed events to EventBus for GUI display.
"""

import logging
import ctypes
import ctypes.wintypes
from ctypes import byref, POINTER, wintypes
import socket
import struct
import threading
import time

from PyQt5.QtCore import QObject, QTimer, pyqtSignal

from services.event_bus import get_event_bus
from services.event_types import ConnectionEvent, RouteEvent, InterfaceEvent, PacketDropEvent

logger = logging.getLogger(__name__)

# TCP table constants
TCP_TABLE_OWNER_PID_ALL = 5
AF_INET = 2
MIB_TCP_STATE_ESTAB = 5
MIB_TCP_STATE_LISTEN = 2
TCP_ROW_SIZE = 24  # 6 ULONGs

# Polling intervals
TCP_POLL_MS = 3000
MAX_EVENTS_PER_CYCLE = 20

# Callback signature for IPHLPAPI notifications
NOTIFY_CALLBACK = ctypes.WINFUNCTYPE(
    wintypes.DWORD,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.BYTE,
)

# ---------------------------------------------------------------------------
# PID → process name cache (shared; same approach as etw_tracer.py)
# ---------------------------------------------------------------------------

_pid_cache: dict[int, tuple[str, float]] = {}
_pid_cache_lock = threading.Lock()
_PID_CACHE_TTL = 5.0


def _pid_to_name(pid: int) -> str:
    if pid <= 0:
        return "System"
    now = time.time()
    with _pid_cache_lock:
        if pid in _pid_cache:
            name, cached_at = _pid_cache[pid]
            if now - cached_at < _PID_CACHE_TTL:
                return name
    try:
        import psutil
        proc = psutil.Process(pid)
        name = proc.name()
    except Exception:
        name = f"pid:{pid}"
    with _pid_cache_lock:
        _pid_cache[pid] = (name, now)
    return name


# ---------------------------------------------------------------------------
# TCP connection snapshot via GetExtendedTcpTable
# ---------------------------------------------------------------------------

def _snapshot_tcp_connections() -> list[tuple]:
    """Return list of (local_addr, local_port, remote_addr, remote_port, pid)
    for all ESTABLISHED IPv4 TCP connections, skipping loopback."""
    try:
        iphlp = ctypes.WinDLL("iphlpapi", use_last_error=True)
        get_table = iphlp.GetExtendedTcpTable
        get_table.argtypes = [
            ctypes.c_void_p,
            POINTER(wintypes.ULONG),
            wintypes.BOOL,
            wintypes.ULONG,
            wintypes.ULONG,
            wintypes.ULONG,
        ]
        get_table.restype = wintypes.ULONG

        buf_size = wintypes.ULONG(0)
        ret = get_table(None, byref(buf_size), False, AF_INET,
                        TCP_TABLE_OWNER_PID_ALL, 0)
        if ret != 122 and ret != 0:
            return []

        buf = ctypes.create_string_buffer(buf_size.value)
        ret = get_table(buf, byref(buf_size), False, AF_INET,
                        TCP_TABLE_OWNER_PID_ALL, 0)
        if ret != 0:
            return []

        count = struct.unpack_from("I", buf, 0)[0]
        conns = []
        off = 4

        for _ in range(count):
            if off + TCP_ROW_SIZE > len(buf.raw):
                break
            state, la, lp, ra, rp, pid = struct.unpack_from(
                "IIIIII", buf, off)
            off += TCP_ROW_SIZE

            if state != MIB_TCP_STATE_ESTAB:
                continue

            la_str = socket.inet_ntoa(struct.pack("I", la))
            ra_str = socket.inet_ntoa(struct.pack("I", ra))

            # Skip loopback
            if ra_str.startswith("127.") or ra_str == "0.0.0.0":
                continue

            lp_port = socket.ntohs(lp)
            rp_port = socket.ntohs(rp)

            conns.append((la_str, lp_port, ra_str, rp_port, pid))

        return conns
    except Exception as e:
        logger.debug("TCP snapshot error: %s", e)
        return []


# ---------------------------------------------------------------------------
# EventTracer
# ---------------------------------------------------------------------------

class EventTracer(QObject):
    """Monitors network changes via Win32 notification APIs + polling.

    Emits:
        routes_changed — when any route entry changes
        interfaces_changed — when any interface changes
        addresses_changed — when unicast IP addresses change
        network_changed — any of the above

    Also pushes typed ConnectionEvent / RouteEvent / InterfaceEvent
    to EventBus for the event log widget.
    """

    routes_changed = pyqtSignal()
    interfaces_changed = pyqtSignal()
    addresses_changed = pyqtSignal()
    network_changed = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

        # Notification handles / callbacks
        self._handle_route: wintypes.LPVOID | None = None
        self._handle_route6: wintypes.LPVOID | None = None
        self._handle_iface: wintypes.LPVOID | None = None
        self._handle_iface6: wintypes.LPVOID | None = None
        self._handle_addr: wintypes.LPVOID | None = None
        self._handle_addr6: wintypes.LPVOID | None = None
        self._cb_route: ctypes.CFUNCTYPE | None = None
        self._cb_route6: ctypes.CFUNCTYPE | None = None
        self._cb_iface: ctypes.CFUNCTYPE | None = None
        self._cb_iface6: ctypes.CFUNCTYPE | None = None
        self._cb_addr: ctypes.CFUNCTYPE | None = None
        self._cb_addr6: ctypes.CFUNCTYPE | None = None

        # Debounce for notification callbacks
        self._debounce_timer = QTimer(self)
        self._debounce_timer.setSingleShot(True)
        self._debounce_timer.setInterval(500)
        self._debounce_timer.timeout.connect(self._emit_network_changed)
        self._pending: set[str] = set()

        # TCP connection monitor
        self._tcp_timer = QTimer(self)
        self._tcp_timer.setInterval(TCP_POLL_MS)
        self._tcp_timer.timeout.connect(self._poll_tcp)
        self._prev_tcp: set[tuple] = set()
        self._tcp_ready = False

        # Route change detection via periodic snapshots
        self._route_scan_timer = QTimer(self)
        self._route_scan_timer.setInterval(5000)
        self._route_scan_timer.timeout.connect(self._poll_routes)
        self._prev_routes: list[dict] = []
        self._route_scan_ready = False

        # Interface polling — initial snapshot + change detection
        self._iface_timer = QTimer(self)
        self._iface_timer.setInterval(7000)
        self._iface_timer.timeout.connect(self._poll_interfaces)
        self._prev_ifaces: dict[str, str] = {}
        self._iface_ready = False

        # Packet discard monitoring via interface counters
        self._drop_timer = QTimer(self)
        self._drop_timer.setInterval(10000)
        self._drop_timer.timeout.connect(self._poll_drops)
        self._prev_discards: dict[int, dict] = {}
        self._drop_ready = False

        self._bus = get_event_bus()

    # ==================================================================
    # Lifecycle
    # ==================================================================

    def start(self):
        self._start_route_listener()
        self._start_interface_listener()
        self._start_address_listener()
        self._tcp_timer.start()
        self._route_scan_timer.start()
        self._iface_timer.start()
        self._drop_timer.start()
        logger.info("EventTracer started")

    def stop(self):
        for attr in ["_handle_route", "_handle_route6",
                      "_handle_iface", "_handle_iface6",
                      "_handle_addr", "_handle_addr6"]:
            h = getattr(self, attr, None)
            if h is not None:
                self._cancel(h)
                setattr(self, attr, None)
        self._cb_route = self._cb_route6 = None
        self._cb_iface = self._cb_iface6 = None
        self._cb_addr = self._cb_addr6 = None
        self._tcp_timer.stop()
        self._route_scan_timer.stop()
        self._iface_timer.stop()
        self._drop_timer.stop()
        logger.info("EventTracer stopped")

    # ==================================================================
    # Win32 notification callback helpers
    # ==================================================================

    def _cancel(self, handle):
        try:
            cancel = self._iphlpapi.CancelMibChangeNotify2
            cancel.argtypes = [wintypes.LPVOID]
            cancel.restype = wintypes.ULONG
            cancel(handle)
        except Exception as e:
            logger.warning("CancelMibChangeNotify2 error: %s", e)

    def _make_callback(self, event_name: str):
        """Create a C-callable callback that flags + publishes to EventBus."""

        def _cb(ctx, row, notify_type):
            self._flag(event_name)
            ts = time.time()
            if event_name == "routes":
                self._bus.publish(RouteEvent(
                    timestamp=ts,
                    event_subtype="route_changed",
                    address_family="IPv4/IPv6",
                ))
            elif event_name in ("interfaces", "addresses"):
                self._bus.publish(InterfaceEvent(
                    timestamp=ts,
                    event_subtype="changed",
                    interface_name="",
                    interface_index=0,
                    address_family="IPv4/IPv6",
                ))
            return 0

        return _cb

    def _flag(self, event: str):
        self._pending.add(event)
        self._debounce_timer.start()

    def _emit_network_changed(self):
        if "routes" in self._pending:
            self.routes_changed.emit()
        if "interfaces" in self._pending or "addresses" in self._pending:
            self.interfaces_changed.emit()
        if "addresses" in self._pending:
            self.addresses_changed.emit()
        self.network_changed.emit()
        self._pending.clear()

    # ==================================================================
    # Win32 notification registrations
    # ==================================================================

    def _start_route_listener(self):
        for fam, attr_h, attr_cb in [
            (AF_INET, "_handle_route", "_cb_route"),
            (23, "_handle_route6", "_cb_route6"),
        ]:
            try:
                func = self._iphlpapi.NotifyRouteChange2
                func.argtypes = [
                    POINTER(wintypes.LPVOID),
                    NOTIFY_CALLBACK,
                    wintypes.LPVOID,
                    wintypes.BYTE,
                ]
                func.restype = wintypes.ULONG
                cb = NOTIFY_CALLBACK(self._make_callback("routes"))
                handle = wintypes.LPVOID()
                ret = func(byref(handle), cb, None, 1)
                if ret == 0:
                    setattr(self, attr_h, handle)
                    setattr(self, attr_cb, cb)
                else:
                    logger.warning("NotifyRouteChange2 (AF=%d): %d", fam, ret)
            except Exception as e:
                logger.warning("NotifyRouteChange2 (AF=%d) error: %s", fam, e)

    def _start_interface_listener(self):
        for fam, attr_h, attr_cb in [
            (AF_INET, "_handle_iface", "_cb_iface"),
            (23, "_handle_iface6", "_cb_iface6"),
        ]:
            try:
                func = self._iphlpapi.NotifyIpInterfaceChange
                func.argtypes = [
                    wintypes.USHORT,
                    NOTIFY_CALLBACK,
                    wintypes.LPVOID,
                    wintypes.BYTE,
                ]
                func.restype = wintypes.ULONG
                cb = NOTIFY_CALLBACK(self._make_callback("interfaces"))
                handle = wintypes.LPVOID()
                ret = func(fam, cb, None, 1)
                if ret == 0:
                    setattr(self, attr_h, handle)
                    setattr(self, attr_cb, cb)
                else:
                    logger.warning("NotifyIpInterfaceChange (AF=%d): %d", fam, ret)
            except Exception as e:
                logger.warning("NotifyIpInterfaceChange (AF=%d) error: %s", fam, e)

    def _start_address_listener(self):
        for fam, attr_h, attr_cb in [
            (AF_INET, "_handle_addr", "_cb_addr"),
            (23, "_handle_addr6", "_cb_addr6"),
        ]:
            try:
                func = self._iphlpapi.NotifyUnicastIpAddressChange
                func.argtypes = [
                    wintypes.USHORT,
                    NOTIFY_CALLBACK,
                    wintypes.LPVOID,
                    wintypes.BYTE,
                ]
                func.restype = wintypes.ULONG
                cb = NOTIFY_CALLBACK(self._make_callback("addresses"))
                handle = wintypes.LPVOID()
                ret = func(fam, cb, None, 1)
                if ret == 0:
                    setattr(self, attr_h, handle)
                    setattr(self, attr_cb, cb)
                else:
                    logger.warning("NotifyUnicastIpAddressChange (AF=%d): %d", fam, ret)
            except Exception as e:
                logger.warning("NotifyUnicastIpAddressChange (AF=%d) error: %s", fam, e)

    # ==================================================================
    # TCP connection polling → ConnectionEvent
    # ==================================================================

    def _poll_tcp(self):
        current = _snapshot_tcp_connections()
        current_set = set(current)

        if not self._tcp_ready:
            self._prev_tcp = current_set
            self._tcp_ready = True
            return

        new_conns = current_set - self._prev_tcp
        self._prev_tcp = current_set

        count = 0
        for conn in sorted(new_conns, key=lambda x: x[4]):  # sort by pid
            if count >= MAX_EVENTS_PER_CYCLE:
                break
            la, lp, ra, rp, pid = conn
            proc = _pid_to_name(pid)
            self._bus.publish(ConnectionEvent(
                timestamp=time.time(),
                event_subtype="connect",
                local_addr=la,
                local_port=lp,
                remote_addr=ra,
                remote_port=rp,
                pid=pid,
                process_name=proc,
            ))
            count += 1

        if count:
            logger.debug("TCP connections detected: %d", count)

    # ==================================================================
    # Route snapshot polling → detailed RouteEvent
    # ==================================================================

    def _poll_routes(self):
        """Poll route table and publish detailed RouteEvent for changes."""
        try:
            from network.networking import get_routes
            routes4 = get_routes(AF_INET)
            routes6 = get_routes(23)
            routes = routes4 + routes6
            snap = [
                {"dest": r.destination, "mask": str(getattr(r, 'prefix_length', r.mask)),
                 "gw": r.gateway, "iface": r.interface, "metric": r.metric,
                 "af": "IPv6" if getattr(r, 'is_ipv6', False) else "IPv4"}
                for r in routes
            ]

            ts = time.time()

            if not self._route_scan_ready:
                # Publish initial snapshot
                self._prev_routes = snap
                self._route_scan_ready = True
                logger.info("Route snapshot initialised (%d routes)", len(snap))
                for r in snap[:100]:  # cap initial burst
                    self._bus.publish(RouteEvent(
                        timestamp=ts,
                        event_subtype="route_added",
                        destination=r["dest"] + "/" + r["mask"],
                        gateway=r["gw"],
                        interface=r["iface"],
                        metric=int(r["metric"]),
                        address_family=r["af"],
                    ))
                return

            # Change detection: key by (dest, mask, af)
            prev_map = {(r["dest"], r["mask"], r["af"]): r for r in self._prev_routes}
            curr_map = {(r["dest"], r["mask"], r["af"]): r for r in snap}

            # New routes
            for key, cur in curr_map.items():
                if key not in prev_map:
                    self._bus.publish(RouteEvent(
                        timestamp=ts, event_subtype="route_added",
                        destination=cur["dest"] + "/" + cur["mask"],
                        gateway=cur["gw"], interface=cur["iface"],
                        metric=int(cur["metric"]), address_family=cur["af"],
                    ))

            # Removed routes
            for key, prev in prev_map.items():
                if key not in curr_map:
                    self._bus.publish(RouteEvent(
                        timestamp=ts, event_subtype="route_removed",
                        destination=prev["dest"] + "/" + prev["mask"],
                        gateway=prev["gw"], interface=prev["iface"],
                        metric=int(prev["metric"]), address_family=prev["af"],
                    ))

            # Changed (metric/gateway)
            for key, cur in curr_map.items():
                prev = prev_map.get(key)
                if prev and (prev["metric"] != cur["metric"]
                             or prev["gw"] != cur["gw"]):
                    self._bus.publish(RouteEvent(
                        timestamp=ts, event_subtype="route_changed",
                        destination=cur["dest"] + "/" + cur["mask"],
                        gateway=cur["gw"], interface=cur["iface"],
                        metric=int(cur["metric"]), address_family=cur["af"],
                    ))

            self._prev_routes = snap

        except Exception as e:
            logger.debug("Route poll error: %s", e)

    # ==================================================================
    # Interface polling → InterfaceEvent
    # ==================================================================

    def _poll_interfaces(self):
        """Poll interface list and publish InterfaceEvent for changes."""
        try:
            from network.networking import get_interfaces
            iface_list = get_interfaces()  # [(index, name, luid)]
            snap = {idx: name for idx, name, luid in iface_list}
            ts = time.time()

            if not self._iface_ready:
                self._prev_ifaces = snap
                self._iface_ready = True
                logger.info("Interface snapshot initialised (%d interfaces)", len(snap))
                for idx, name in snap.items():
                    self._bus.publish(InterfaceEvent(
                        timestamp=ts, event_subtype="up",
                        interface_name=name, interface_index=int(idx),
                        address_family="IPv4/IPv6",
                    ))
                return

            # New interfaces
            for idx, name in snap.items():
                if idx not in self._prev_ifaces:
                    self._bus.publish(InterfaceEvent(
                        timestamp=ts, event_subtype="up",
                        interface_name=name, interface_index=int(idx),
                        address_family="IPv4/IPv6",
                    ))

            # Removed interfaces
            for idx, name in self._prev_ifaces.items():
                if idx not in snap:
                    self._bus.publish(InterfaceEvent(
                        timestamp=ts, event_subtype="down",
                        interface_name=name, interface_index=int(idx),
                        address_family="IPv4/IPv6",
                    ))

            self._prev_ifaces = snap
        except Exception as e:
            logger.debug("Interface poll error: %s", e)

    # ==================================================================
    # Packet discard monitoring → PacketDropEvent
    # ==================================================================

    def _poll_drops(self):
        """Monitor interface discard/error counters and publish PacketDropEvent."""
        current = _snapshot_discards()

        if not self._drop_ready:
            self._prev_discards = current
            self._drop_ready = True
            return

        ts = time.time()
        count = 0

        for idx, cur in current.items():
            prev = self._prev_discards.get(idx)
            if not prev:
                continue

            reasons = []
            in_d = cur["in_discards"] - prev["in_discards"]
            out_d = cur["out_discards"] - prev["out_discards"]
            in_e = cur["in_errors"] - prev["in_errors"]
            out_e = cur["out_errors"] - prev["out_errors"]

            if in_d > 0:
                reasons.append(f"入丢弃+{in_d}")
            if out_d > 0:
                reasons.append(f"出丢弃+{out_d}")
            if in_e > 0:
                reasons.append(f"入错误+{in_e}")
            if out_e > 0:
                reasons.append(f"出错误+{out_e}")
            if not reasons:
                continue

            self._bus.publish(PacketDropEvent(
                timestamp=ts,
                reason="; ".join(reasons),
                local_addr=cur["name"] or f"iface:{idx}",
                pid=0,
                process_name="",
            ))
            count += 1
            if count >= MAX_EVENTS_PER_CYCLE:
                break

        self._prev_discards = current


# ---------------------------------------------------------------------------
# Interface discard/error counter snapshot via GetIfTable
# ---------------------------------------------------------------------------

def _snapshot_discards() -> dict[int, dict]:
    """Get per-interface discard/error counters via GetIfTable.

    Returns dict: interface_index → {name, in_discards, in_errors,
                                      out_discards, out_errors}
    """
    try:
        iphlp = ctypes.WinDLL("iphlpapi", use_last_error=True)
        get_table = iphlp.GetIfTable
        get_table.argtypes = [
            ctypes.c_void_p,
            POINTER(wintypes.ULONG),
            wintypes.BOOL,
        ]
        get_table.restype = wintypes.ULONG

        MIB_IFROW_SIZE = 860
        buf_size = wintypes.ULONG(0)
        ret = get_table(None, byref(buf_size), False)
        if ret != 122:  # ERROR_INSUFFICIENT_BUFFER
            return {}

        buf = ctypes.create_string_buffer(buf_size.value)
        ret = get_table(buf, byref(buf_size), False)
        if ret != 0:
            return {}

        count = struct.unpack_from("I", buf, 0)[0]
        result: dict[int, dict] = {}

        for i in range(count):
            off = 4 + i * MIB_IFROW_SIZE
            if off + MIB_IFROW_SIZE > len(buf.raw):
                break
            row = buf.raw[off:off + MIB_IFROW_SIZE]

            idx = struct.unpack_from("I", row, 512)[0]
            name_raw = row[:512].decode("utf-16-le", errors="replace").split("\x00")[0]
            in_disc = struct.unpack_from("I", row, 568)[0]
            in_err = struct.unpack_from("I", row, 572)[0]
            out_disc = struct.unpack_from("I", row, 592)[0]
            out_err = struct.unpack_from("I", row, 596)[0]

            result[idx] = {
                "name": name_raw,
                "in_discards": in_disc,
                "in_errors": in_err,
                "out_discards": out_disc,
                "out_errors": out_err,
            }

        return result
    except Exception as e:
        logger.debug("Discard snapshot error: %s", e)
        return {}
