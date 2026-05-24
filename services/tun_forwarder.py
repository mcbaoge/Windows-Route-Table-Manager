"""Wintun route/capture controller.

Wintun is a layer-3 userspace adapter. It can receive packets that Windows
routes into the virtual NIC and it can inject packets back into Windows, but it
does not forward arbitrary IP packets to a physical NIC by itself.

This module keeps the reliable parts:
- create/open the Wintun adapter,
- steer the default IPv4 route into the adapter,
- keep physical egress reachability exceptions out of the TUN loop,
- count captured packets without creating per-flow sockets.

Thread model: DedicatedTask via TaskManager for TUN capture loop.
"""

from __future__ import annotations

import logging
import socket
import subprocess
import threading
import time
import ctypes
import ctypes.wintypes
from dataclasses import dataclass
from typing import Optional

from services.traffic_stats import TrafficTracker
from services.winapi_network import (
    add_route,
    delete_route,
    get_interface_ipv4_info,
    get_interfaces,
    get_physical_interfaces,
)
from services.wintun_adapter import get_adapter
from services.task_manager import get_task_manager

logger = logging.getLogger(__name__)

TUN_IP = "10.89.0.2"
TUN_GW = "10.89.0.1"
TUN_MASK = "255.255.255.252"
TUN_METRIC = 10
EGRESS_METRIC = 1

_iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)


class _NET_LUID(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_uint64)]


_iphlpapi.ConvertInterfaceLuidToIndex.argtypes = [
    ctypes.POINTER(_NET_LUID),
    ctypes.POINTER(ctypes.wintypes.ULONG),
]
_iphlpapi.ConvertInterfaceLuidToIndex.restype = ctypes.wintypes.ULONG


@dataclass(frozen=True)
class _RouteSpec:
    dest: str
    mask: str
    gw: str
    iface: str


class TUNForwarder:
    """Route all IPv4 traffic into Wintun and collect packet statistics.

    TUN capture runs as a DedicatedTask via TaskManager.
    """

    def __init__(self):
        self._tun = get_adapter()
        self._running = False
        self._stop_event = threading.Event()
        self._dedicated_task = None
        self._egress_idx: int | None = None
        self._egress_gw = "0.0.0.0"
        self._tun_iface_idx: int | None = None
        self._saved_routes: list[_RouteSpec] = []
        self._tracker = TrafficTracker()
        self._last_error = ""

    @property
    def available(self) -> bool:
        if not self._tun.available:
            self._tun.load()
        return self._tun.available

    @property
    def running(self) -> bool:
        return self._running

    @property
    def tracker(self) -> TrafficTracker:
        return self._tracker

    @property
    def last_error(self) -> str:
        return self._last_error

    def setup_adapter(self) -> bool:
        self._last_error = ""
        if not self._tun.load():
            self._last_error = "Wintun DLL load failed"
            logger.error(self._last_error)
            return False
        if not self._tun.create_adapter():
            self._last_error = "TUN adapter creation failed"
            logger.error(self._last_error)
            return False
        if not self._tun.open_session():
            self._last_error = "TUN session open failed"
            logger.error(self._last_error)
            return False
        logger.info("TUN adapter ready LUID=0x%x", self._tun.luid)
        return True

    def _get_tun_iface_idx(self) -> Optional[int]:
        idx = ctypes.wintypes.ULONG(0)
        luid = _NET_LUID(self._tun.luid)
        if _iphlpapi.ConvertInterfaceLuidToIndex(ctypes.byref(luid), ctypes.byref(idx)) == 0:
            return int(idx.value)

        tun_luid = f"0x{self._tun.luid:016X}".lower()
        for idx_str, desc, luid_str in get_interfaces():
            text = (desc or "").lower()
            luid = (luid_str or "").lower()
            if luid == tun_luid or "route manager" in text or "routemanager" in text:
                return int(idx_str)
            if "windows" in text and "route" in text:
                return int(idx_str)
        return None

    def _get_tun_iface_name(self, iface_idx: int) -> str:
        for idx_str, desc, _ in get_interfaces():
            if int(idx_str) == iface_idx:
                return desc
        return str(iface_idx)

    def _set_tun_ip(self, iface_idx: int) -> bool:
        names = [str(iface_idx)]
        iface_name = self._get_tun_iface_name(iface_idx)
        if iface_name not in names:
            names.append(iface_name)

        for name in names:
            cmd = [
                "netsh",
                "interface",
                "ip",
                "set",
                "address",
                f"name={name}",
                "static",
                TUN_IP,
                TUN_MASK,
                TUN_GW,
            ]
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                    timeout=10,
                )
            except Exception as exc:
                logger.warning("netsh set address failed for %s: %s", name, exc)
                continue
            if result.returncode == 0:
                logger.info("TUN IPv4 address set on %s: %s/%s gw=%s", name, TUN_IP, TUN_MASK, TUN_GW)
                return True
            logger.warning("netsh set address failed for %s: %s", name, result.stderr.strip())

        self._last_error = "Failed to set TUN IPv4 address"
        return False

    def _find_egress_info(self, egress_idx: int) -> tuple[bool, str, str, str]:
        info_by_name = get_interface_ipv4_info()
        for idx_str, name, _, _ in get_physical_interfaces():
            if int(idx_str) != egress_idx:
                continue
            info = info_by_name.get(name, {})
            ip = info.get("ip", "")
            mask = info.get("mask", "255.255.255.0")
            gw = info.get("gateway", "0.0.0.0")
            return True, ip, mask, gw
        return False, "", "", ""

    def start_forwarding(self, egress_idx: int) -> bool:
        if self._running:
            return True

        self._last_error = ""
        self._egress_idx = egress_idx
        ok, _ip, _mask, gw = self._find_egress_info(egress_idx)
        if not ok:
            self._last_error = f"Physical egress interface not found: {egress_idx}"
            logger.error(self._last_error)
            return False
        self._egress_gw = gw if gw and gw not in ("-", "0.0.0.0") else "0.0.0.0"

        if not self.setup_adapter():
            return False

        tun_idx = self._get_tun_iface_idx()
        if tun_idx is None:
            self._last_error = "TUN interface index not found"
            logger.error(self._last_error)
            return False
        self._tun_iface_idx = tun_idx

        self._set_tun_ip(tun_idx)
        self._add_routes(tun_idx)

        self._running = True
        self._stop_event.clear()

        tm = get_task_manager()
        self._dedicated_task = tm.start_dedicated(
            poll_fn=self._capture_once,
            task_id="tun-capture",
        )
        logger.info(
            "TUN route capture started (DedicatedTask, tun_if=%d, egress_if=%d, egress_gw=%s)",
            tun_idx, egress_idx, self._egress_gw,
        )
        return True

    def _remember_route(self, dest: str, mask: str, gw: str, iface: str):
        self._saved_routes.append(_RouteSpec(dest, mask, gw, iface))

    def _add_route(self, dest: str, mask: str, gw: str, iface: str, metric: int) -> bool:
        ok, err = add_route(dest, mask, gw, iface, metric=metric)
        if ok:
            self._remember_route(dest, mask, gw, iface)
            return True
        logger.warning("Failed to add route %s/%s via %s if=%s: %s", dest, mask, gw, iface, err)
        return False

    def _add_routes(self, tun_iface_idx: int):
        self._saved_routes.clear()

        if self._egress_idx is None:
            return
        egress_iface = str(self._egress_idx)
        ok, egress_ip, egress_mask, egress_gw = self._find_egress_info(self._egress_idx)
        if ok and egress_ip and egress_ip != "0.0.0.0":
            self._add_route(egress_ip, egress_mask, "0.0.0.0", egress_iface, EGRESS_METRIC)
            logger.info("Added physical subnet exception %s/%s -> if %s", egress_ip, egress_mask, egress_iface)

        if egress_gw and egress_gw not in ("-", "0.0.0.0"):
            self._add_route(egress_gw, "255.255.255.255", "0.0.0.0", egress_iface, EGRESS_METRIC)
            logger.info("Added egress gateway exception %s/32 -> if %s", egress_gw, egress_iface)

        self._add_route("0.0.0.0", "0.0.0.0", TUN_GW, str(tun_iface_idx), TUN_METRIC)
        logger.info("Added default IPv4 route 0.0.0.0/0 -> TUN if %s", tun_iface_idx)

    def _remove_routes(self):
        for route in reversed(self._saved_routes):
            try:
                delete_route(route.dest, route.mask, route.gw, route.iface)
            except Exception as exc:
                logger.debug("Failed to remove route %s: %s", route, exc)
        self._saved_routes.clear()

    def _capture_once(self):
        """Called by DedicatedTask in a loop. Blocks on TUN read."""
        if self._stop_event.is_set():
            return
        try:
            result = self._tun.read_packet()
            if result is None:
                time.sleep(0.001)
                return
            data, length = result
            self._handle_packet(data, length)
        except Exception:
            if not self._stop_event.is_set():
                logger.exception("TUN capture loop error")

    def _handle_packet(self, data: bytes, length: int):
        if length < 20:
            return
        version = data[0] >> 4
        if version != 4:
            return

        self._tracker.record_up(length)
        protocol = data[9]
        src = socket.inet_ntoa(data[12:16])
        dst = socket.inet_ntoa(data[16:20])
        logger.debug("Captured IPv4 packet proto=%d %s -> %s bytes=%d", protocol, src, dst, length)

    def stop(self):
        self._running = False
        self._stop_event.set()
        if self._dedicated_task:
            self._dedicated_task.stop(timeout=3.0)
            self._dedicated_task = None
        self._remove_routes()
        self._tun.close_session()
        self._tun.delete_adapter()
        logger.info("TUN route capture stopped")
