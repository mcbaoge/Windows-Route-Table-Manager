import ctypes
import ctypes.wintypes
from ctypes import (
    wintypes, Structure, Union, POINTER, byref, cast,
    create_string_buffer,
)
from typing import Optional

from core.utils import RouteEntry

# ----------- constants -----------
AF_INET = 2
AF_INET6 = 23
AF_UNSPEC = 0
NO_ERROR = 0
ERROR_BUFFER_OVERFLOW = 111
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_NOT_FOUND = 1168

# ----------- v1 structs: MIB_IPFORWARDROW (56 bytes) -----------
class MIB_IPFORWARDROW(Structure):
    _fields_ = [
        ("dwForwardDest", wintypes.DWORD),
        ("dwForwardMask", wintypes.DWORD),
        ("dwForwardPolicy", wintypes.DWORD),
        ("dwForwardNextHop", wintypes.DWORD),
        ("dwForwardIfIndex", wintypes.DWORD),
        ("dwForwardType", wintypes.DWORD),
        ("dwForwardProto", wintypes.DWORD),
        ("dwForwardAge", wintypes.DWORD),
        ("dwForwardNextHopAS", wintypes.DWORD),
        ("dwForwardMetric1", wintypes.DWORD),
        ("dwForwardMetric2", wintypes.DWORD),
        ("dwForwardMetric3", wintypes.DWORD),
        ("dwForwardMetric4", wintypes.DWORD),
        ("dwForwardMetric5", wintypes.DWORD),
    ]

PMIB_IPFORWARDROW = POINTER(MIB_IPFORWARDROW)


class MIB_IPFORWARDTABLE(Structure):
    _fields_ = [
        ("dwNumEntries", wintypes.DWORD),
        ("table", MIB_IPFORWARDROW * 1),
    ]

PMIB_IPFORWARDTABLE = POINTER(MIB_IPFORWARDTABLE)


# ----------- v1 structs: MIB_IFROW -----------
MAX_INTERFACE_NAME_LEN = 256
MAXLEN_PHYSADDR = 8
MAXLEN_IFDESCR = 256


class MIB_IFROW(Structure):
    _fields_ = [
        ("wszName", wintypes.WCHAR * MAX_INTERFACE_NAME_LEN),
        ("dwIndex", wintypes.DWORD),
        ("dwType", wintypes.DWORD),
        ("dwMtu", wintypes.DWORD),
        ("dwSpeed", wintypes.DWORD),
        ("dwPhysAddrLen", wintypes.DWORD),
        ("bPhysAddr", wintypes.BYTE * MAXLEN_PHYSADDR),
        ("dwAdminStatus", wintypes.DWORD),
        ("dwOperStatus", wintypes.DWORD),
        ("dwLastChange", wintypes.DWORD),
        ("dwInOctets", wintypes.DWORD),
        ("dwInUcastPkts", wintypes.DWORD),
        ("dwInNUcastPkts", wintypes.DWORD),
        ("dwInDiscards", wintypes.DWORD),
        ("dwInErrors", wintypes.DWORD),
        ("dwInUnknownProtos", wintypes.DWORD),
        ("dwOutOctets", wintypes.DWORD),
        ("dwOutUcastPkts", wintypes.DWORD),
        ("dwOutNUcastPkts", wintypes.DWORD),
        ("dwOutDiscards", wintypes.DWORD),
        ("dwOutErrors", wintypes.DWORD),
        ("dwOutQLen", wintypes.DWORD),
        ("dwDescrLen", wintypes.DWORD),
        ("bDescr", wintypes.BYTE * MAXLEN_IFDESCR),
    ]

PMIB_IFROW = POINTER(MIB_IFROW)


class MIB_IFTABLE(Structure):
    _fields_ = [
        ("dwNumEntries", wintypes.DWORD),
        ("table", MIB_IFROW * 1),
    ]

PMIB_IFTABLE = POINTER(MIB_IFTABLE)


# ----------- v1 struct: MIB_IPADDRROW -----------
class MIB_IPADDRROW(Structure):
    _fields_ = [
        ("dwAddr", wintypes.ULONG),
        ("dwIndex", wintypes.ULONG),
        ("dwMask", wintypes.ULONG),
        ("dwBCastAddr", wintypes.ULONG),
        ("dwReasmSize", wintypes.ULONG),
        ("unused1", wintypes.USHORT),
        ("wType", wintypes.USHORT),
    ]

PMIB_IPADDRROW = POINTER(MIB_IPADDRROW)


class MIB_IPADDRTABLE(Structure):
    _fields_ = [
        ("dwNumEntries", wintypes.ULONG),
        ("table", MIB_IPADDRROW * 1),
    ]

PMIB_IPADDRTABLE = POINTER(MIB_IPADDRTABLE)


# ----------- v2 structs: for GetIpForwardTable2 / CRUD -----------
class IN_ADDR(Structure):
    _fields_ = [("S_addr", wintypes.ULONG)]


class SOCKADDR_IN(Structure):
    _fields_ = [
        ("sin_family", wintypes.USHORT),
        ("sin_port", wintypes.USHORT),
        ("sin_addr", IN_ADDR),
        ("sin_zero", wintypes.CHAR * 8),
    ]


class SOCKADDR_IN6(Structure):
    _fields_ = [
        ("sin6_family", wintypes.USHORT),
        ("sin6_port", wintypes.USHORT),
        ("sin6_flowinfo", wintypes.ULONG),
        ("sin6_addr", wintypes.BYTE * 16),
        ("sin6_scope_id", wintypes.ULONG),
    ]


class SOCKADDR_INET(Union):
    _fields_ = [
        ("Ipv4", SOCKADDR_IN),
        ("Ipv6", SOCKADDR_IN6),
        ("si_family", wintypes.USHORT),
    ]


class IP_ADDRESS_PREFIX(Structure):
    _fields_ = [
        ("Prefix", SOCKADDR_INET),
        ("PrefixLength", ctypes.c_uint8),
        ("Padding", ctypes.c_uint8 * 3),
    ]


class MIB_IPFORWARD_ROW2(Structure):
    _fields_ = [
        ("DestinationPrefix", IP_ADDRESS_PREFIX),
        ("NextHop", SOCKADDR_INET),
        ("InterfaceIndex", wintypes.ULONG),
        ("InterfaceLuid", wintypes.ULONG * 2),
        ("PreferredLifetime", wintypes.ULONG),
        ("ValidLifetime", wintypes.ULONG),
        ("Metric", wintypes.ULONG),
        ("Protocol", wintypes.ULONG),
        ("Loopback", wintypes.BYTE),
        ("AutoconfigureAddress", wintypes.BYTE),
        ("Publish", wintypes.BYTE),
        ("Immortal", wintypes.BYTE),
        ("Age", wintypes.ULONG),
        ("Origin", wintypes.ULONG),
    ]


PMIB_IPFORWARD_ROW2 = POINTER(MIB_IPFORWARD_ROW2)


class MIB_IPFORWARD_TABLE2(Structure):
    _fields_ = [("NumEntries", wintypes.ULONG)]


PMIB_IPFORWARD_TABLE2 = POINTER(MIB_IPFORWARD_TABLE2)


# ----------- NET_LUID struct & conversion -----------

class NET_LUID(Union):
    _fields_ = [
        ("Value", ctypes.c_uint64),
        ("Reserved", wintypes.ULONG),
        ("NetLuidIndex", wintypes.ULONG),
    ]


PNET_LUID = POINTER(NET_LUID)


# ----------- load iphlpapi.dll -----------
_iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)

_GetIpForwardTable = _iphlpapi.GetIpForwardTable
_GetIpForwardTable.argtypes = [PMIB_IPFORWARDTABLE, POINTER(wintypes.ULONG), wintypes.BOOL]
_GetIpForwardTable.restype = wintypes.ULONG

_GetIfTable = _iphlpapi.GetIfTable
_GetIfTable.argtypes = [PMIB_IFTABLE, POINTER(wintypes.ULONG), wintypes.BOOL]
_GetIfTable.restype = wintypes.ULONG

_GetIpAddrTable = _iphlpapi.GetIpAddrTable
_GetIpAddrTable.argtypes = [PMIB_IPADDRTABLE, POINTER(wintypes.ULONG), wintypes.BOOL]
_GetIpAddrTable.restype = wintypes.ULONG

_GetIpForwardTable2 = _iphlpapi.GetIpForwardTable2
_GetIpForwardTable2.argtypes = [wintypes.USHORT, POINTER(PMIB_IPFORWARD_TABLE2)]
_GetIpForwardTable2.restype = wintypes.ULONG

_FreeMibTable = _iphlpapi.FreeMibTable
_FreeMibTable.argtypes = [wintypes.LPVOID]
_FreeMibTable.restype = None

_CreateIpForwardEntry2 = _iphlpapi.CreateIpForwardEntry2
_CreateIpForwardEntry2.argtypes = [PMIB_IPFORWARD_ROW2]
_CreateIpForwardEntry2.restype = wintypes.ULONG

_DeleteIpForwardEntry2 = _iphlpapi.DeleteIpForwardEntry2
_DeleteIpForwardEntry2.argtypes = [PMIB_IPFORWARD_ROW2]
_DeleteIpForwardEntry2.restype = wintypes.ULONG

_SetIpForwardEntry2 = _iphlpapi.SetIpForwardEntry2
_SetIpForwardEntry2.argtypes = [PMIB_IPFORWARD_ROW2]
_SetIpForwardEntry2.restype = wintypes.ULONG

NOTIFY_ROUTE_CALLBACK = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID, wintypes.BYTE)
_NotifyRouteChange2 = _iphlpapi.NotifyRouteChange2
_NotifyRouteChange2.argtypes = [wintypes.LPVOID, NOTIFY_ROUTE_CALLBACK, wintypes.LPVOID, wintypes.BYTE]
_NotifyRouteChange2.restype = wintypes.ULONG

_CancelMibChangeNotify2 = _iphlpapi.CancelMibChangeNotify2
_CancelMibChangeNotify2.argtypes = [wintypes.LPVOID]
_CancelMibChangeNotify2.restype = wintypes.ULONG

_ConvertInterfaceIndexToLuid = _iphlpapi.ConvertInterfaceIndexToLuid
_ConvertInterfaceIndexToLuid.argtypes = [wintypes.ULONG, PNET_LUID]
_ConvertInterfaceIndexToLuid.restype = wintypes.ULONG

_ConvertInterfaceLuidToIndex = _iphlpapi.ConvertInterfaceLuidToIndex
_ConvertInterfaceLuidToIndex.argtypes = [PNET_LUID, POINTER(wintypes.ULONG)]
_ConvertInterfaceLuidToIndex.restype = wintypes.ULONG


# ----------- utility helpers -----------

def _ip_to_str(addr_ulong):
    if addr_ulong == 0:
        return "0.0.0.0"
    import socket
    host = socket.ntohl(addr_ulong)
    return ".".join(str((host >> (8 * i)) & 0xFF) for i in range(3, -1, -1))


def _str_to_ip(ip_str: str) -> int:
    import socket
    parts = ip_str.split(".")
    if len(parts) != 4:
        return 0
    host_order = sum(int(p) << (8 * i) for i, p in enumerate(parts))
    return socket.htonl(host_order)


def _sockaddr_inet_to_ip(sa: SOCKADDR_INET) -> str:
    family = sa.si_family
    if family == AF_INET:
        raw = sa.Ipv4.sin_addr.S_addr
        if raw == 0:
            return "0.0.0.0"
        import socket
        host = socket.ntohl(raw)
        return ".".join(str((host >> (24 - 8 * i)) & 0xFF) for i in range(4))
    elif family == AF_INET6:
        raw_bytes = bytes(sa.Ipv6.sin6_addr)
        if all(b == 0 for b in raw_bytes):
            return "::"
        import socket
        return socket.inet_ntop(socket.AF_INET6, raw_bytes)
    return ""


def _clean_iface_desc(raw_desc: str) -> str:
    import re
    desc = raw_desc.strip()
    desc = re.sub(r'\s*-(?:WFP|Npcap|QoS|Native|NDIS|Ras|Ppp|Miniport).*', '', desc, count=1).strip()
    return desc


def _luid_to_str(luid: NET_LUID) -> str:
    """Convert NET_LUID to hex string like '0x17000000000000'."""
    return f"0x{luid.Value:016X}"


def _str_to_luid(hex_str: str) -> NET_LUID:
    """Convert hex string like '0x17000000000000' to NET_LUID."""
    val = int(hex_str, 16) if hex_str.startswith("0x") else int(hex_str)
    luid = NET_LUID()
    luid.Value = val
    return luid


def _index_to_luid(iface_index: int) -> str:
    """Convert InterfaceIndex to NET_LUID hex string. Returns '' on failure."""
    luid = NET_LUID()
    ret = _ConvertInterfaceIndexToLuid(iface_index, byref(luid))
    if ret != NO_ERROR:
        return ""
    return _luid_to_str(luid)


def _luid_from_row_luid_field(luid_array) -> str:
    """Convert a ULONG[2] InterfaceLuid field from MIB_IPFORWARD_ROW2 to hex string."""
    val = (luid_array[0] & 0xFFFFFFFF) | ((luid_array[1] & 0xFFFFFFFF) << 32)
    return f"0x{val:016X}"


def _build_sockaddr_inet(ip_str: str) -> SOCKADDR_INET:
    import socket
    import ipaddress
    sa = SOCKADDR_INET()
    try:
        ipaddress.IPv4Address(ip_str)
        sa.Ipv4.sin_family = AF_INET
        sa.Ipv4.sin_port = 0
        sa.Ipv4.sin_addr.S_addr = _str_to_ip(ip_str)
    except Exception:
        try:
            ipaddress.IPv6Address(ip_str)
            sa.Ipv6.sin6_family = AF_INET6
            sa.Ipv6.sin6_port = 0
            sa.Ipv6.sin6_flowinfo = 0
            raw = socket.inet_pton(socket.AF_INET6, ip_str)
            for i in range(16):
                sa.Ipv6.sin6_addr[i] = raw[i]
            sa.Ipv6.sin6_scope_id = 0
        except Exception:
            sa.Ipv4.sin_family = AF_INET
            sa.Ipv4.sin_port = 0
            sa.Ipv4.sin_addr.S_addr = 0
    return sa


# ----------- public route reading API -----------

ROW2_SIZE = ctypes.sizeof(MIB_IPFORWARD_ROW2)


def _read_v4_table_v1() -> list[RouteEntry]:
    """Read IPv4 routes using GetIpForwardTable (v1, clean/proven)."""
    import socket

    buf_size = wintypes.ULONG(0)
    ret = _GetIpForwardTable(None, byref(buf_size), False)
    if ret != ERROR_INSUFFICIENT_BUFFER:
        return []

    buf = create_string_buffer(buf_size.value)
    p_table = cast(buf, PMIB_IPFORWARDTABLE)
    ret = _GetIpForwardTable(p_table, byref(buf_size), False)
    if ret != NO_ERROR:
        return []

    table = p_table.contents
    count = table.dwNumEntries
    entries = []
    base = ctypes.addressof(p_table.contents)
    row_size = ctypes.sizeof(MIB_IPFORWARDROW)
    table_offset = ctypes.sizeof(wintypes.DWORD)

    for i in range(count):
        addr = base + table_offset + i * row_size
        row = cast(addr, PMIB_IPFORWARDROW).contents

        dest_raw = socket.ntohl(row.dwForwardDest)
        mask_raw = socket.ntohl(row.dwForwardMask)
        gw_raw = socket.ntohl(row.dwForwardNextHop)

        dest = ".".join(str((dest_raw >> (24 - 8 * j)) & 0xFF) for j in range(4))
        mask = ".".join(str((mask_raw >> (24 - 8 * j)) & 0xFF) for j in range(4))
        gw = ".".join(str((gw_raw >> (24 - 8 * j)) & 0xFF) for j in range(4))

        iface_idx = row.dwForwardIfIndex
        metric = row.dwForwardMetric1

        plen = 0 if mask_raw == 0 else bin(mask_raw).count("1")
        is_default = (dest_raw == 0)

        luid_str = _index_to_luid(iface_idx)
        entries.append(RouteEntry(
            destination=dest,
            mask=mask,
            gateway=gw,
            interface=str(iface_idx),
            metric=str(metric),
            prefix_length=plen,
            is_default=is_default,
            interface_name="",
            address_family=AF_INET,
            is_ipv6=False,
            interface_luid=luid_str,
        ))

    return entries


def _read_v6_table_v2() -> list[RouteEntry]:
    """Read IPv6 routes using GetIpForwardTable2 (v2, only option for IPv6)."""
    import socket

    entries: list[RouteEntry] = []

    p_table = PMIB_IPFORWARD_TABLE2()
    ret = _GetIpForwardTable2(AF_INET6, byref(p_table))
    if ret != NO_ERROR:
        return entries

    try:
        table = p_table.contents
        count = table.NumEntries
        base = ctypes.addressof(table)

        for i in range(count):
            addr = base + 4 + i * ROW2_SIZE
            row = cast(addr, PMIB_IPFORWARD_ROW2).contents

            # Forced IPv6: parse directly from sin6_addr bytes
            raw_addr = bytes(row.DestinationPrefix.Prefix.Ipv6.sin6_addr)
            if all(b == 0 for b in raw_addr):
                dest = "::"
            else:
                dest = socket.inet_ntop(socket.AF_INET6, raw_addr)

            plen = row.DestinationPrefix.PrefixLength
            iface_idx = row.InterfaceIndex
            metric = row.Metric

            # Next hop
            nh_raw = bytes(row.NextHop.Ipv6.sin6_addr)
            if all(b == 0 for b in nh_raw):
                nh = "::"
            else:
                nh = socket.inet_ntop(socket.AF_INET6, nh_raw)

            is_default = (plen == 0) and (dest == "::")

            luid_str = _luid_from_row_luid_field(row.InterfaceLuid)

            entries.append(RouteEntry(
                destination=dest,
                mask="",
                gateway=nh,
                interface=str(iface_idx),
                metric=str(metric),
                prefix_length=plen,
                is_default=is_default,
                interface_name="",
                address_family=AF_INET6,
                is_ipv6=True,
                interface_luid=luid_str,
            ))

    finally:
        _FreeMibTable(p_table)

    return entries


def get_routes(address_family: int = AF_UNSPEC):
    """Get routes.

    - IPv4: uses GetIpForwardTable (v1, clean).
    - IPv6: uses GetIpForwardTable2 (v2, forced IPv6 parsing).
    - AF_UNSPEC: returns both.

    Args:
        address_family: AF_INET=2, AF_INET6=23, or AF_UNSPEC=0 (both).

    Returns list of RouteEntry.
    """
    result: list[RouteEntry] = []

    if address_family in (AF_INET, AF_UNSPEC):
        result.extend(_read_v4_table_v1())

    if address_family in (AF_INET6, AF_UNSPEC):
        result.extend(_read_v6_table_v2())

    return result


# Interface type constants (from Ifdef.h)
IF_TYPE_ETHERNET_CSMACD = 6
IF_TYPE_IEEE80211 = 71


def get_physical_interfaces():
    """Returns only real physical interfaces (Ethernet / Wi-Fi).

    Returns list of (index_str, name_str, luid_str, type_int).
    Filters by dwType: only IF_TYPE_ETHERNET_CSMACD and IF_TYPE_IEEE80211,
    and excludes known virtual adapters via description blacklist.
    """
    buf_size = wintypes.ULONG(0)
    ret = _GetIfTable(None, byref(buf_size), False)
    if ret != ERROR_INSUFFICIENT_BUFFER:
        return []
    buf = create_string_buffer(buf_size.value)
    p_table = cast(buf, PMIB_IFTABLE)
    ret = _GetIfTable(p_table, byref(buf_size), False)
    if ret != NO_ERROR:
        return []

    table = p_table.contents
    count = table.dwNumEntries
    res = []
    base = ctypes.addressof(p_table.contents)
    row_size = ctypes.sizeof(MIB_IFROW)
    table_offset = ctypes.sizeof(wintypes.DWORD)
    physical_types = {IF_TYPE_ETHERNET_CSMACD, IF_TYPE_IEEE80211}
    blacklist = ["tap", "virtual", "vmware", "wan miniport", "bluetooth",
                 "wifi direct", "kernel debug", "ms isatap", "teredo", "6to4",
                 "ip-https", "loopback", "pseudo", "npcap", "qos packet scheduler",
                 "wfp native mac layer", "wfp 802.3 mac layer", "native wifi filter",
                 "microsoft wi-fi direct virtual adapter", "remote ndis based internet sharing device",
                 "microsoft kernel debug network adapter"]

    for i in range(count):
        addr = base + table_offset + i * row_size
        row = cast(addr, PMIB_IFROW).contents
        if row.dwType not in physical_types:
            continue
        raw = bytes(row.bDescr).split(b'\x00')[0]
        desc = raw.decode('gbk', errors='replace').strip()
        if not desc:
            continue
        desc_lower = desc.lower()
        if any(b in desc_lower for b in blacklist):
            continue
        luid_str = _index_to_luid(row.dwIndex)
        res.append((str(row.dwIndex), desc, luid_str, row.dwType))

    return res


def get_interfaces():
    """Get physical interface list using GetIfTable (v1).

    Returns list of (index_str, name_str, luid_str).
    """
    buf_size = wintypes.ULONG(0)
    ret = _GetIfTable(None, byref(buf_size), False)
    if ret != ERROR_INSUFFICIENT_BUFFER:
        return []

    buf = create_string_buffer(buf_size.value)
    p_table = cast(buf, PMIB_IFTABLE)
    ret = _GetIfTable(p_table, byref(buf_size), False)
    if ret != NO_ERROR:
        return []

    table = p_table.contents
    count = table.dwNumEntries
    res = []
    base = ctypes.addressof(p_table.contents)
    row_size = ctypes.sizeof(MIB_IFROW)
    table_offset = ctypes.sizeof(wintypes.DWORD)

    blacklist = ["vmware", "virtual", "hyper-v", "loopback", "tunnel",
                 "pseudo", "bluetooth", "ppp", "适配器", "虚拟", "隧道",
                 "kernel debug", "miniport", "6to4", "ip-https", "isatap",
                 "teredo", "wan miniport"]

    for i in range(count):
        addr = base + table_offset + i * row_size
        row = cast(addr, PMIB_IFROW).contents
        idx = row.dwIndex
        raw = bytes(row.bDescr).split(b'\x00')[0]
        desc = raw.decode('gbk', errors='replace')
        desc = _clean_iface_desc(desc)
        if not desc:
            continue
        combined = desc.lower()
        # Allow our Wintun adapter (by adapter name or tunnel type) even if it contains 'tunnel'
        if "windows 路由管理器" in combined or "routemanager" in combined:
            pass  # Don't blacklist
        elif any(b in combined for b in blacklist):
            continue
        luid_str = _index_to_luid(idx)
        res.append((str(idx), desc, luid_str))

    return res


def get_interface_ipv4_info():
    """Get IPv4 IP/mask/gateway per interface.

    Returns dict: {iface_name: {"ip": str, "mask": str, "gateway": str}}
    """
    ip_info = {}

    buf_size = wintypes.ULONG(0)
    ret = _GetIpAddrTable(None, byref(buf_size), False)
    if ret != ERROR_INSUFFICIENT_BUFFER:
        return ip_info

    buf = create_string_buffer(buf_size.value)
    p_table = cast(buf, PMIB_IPADDRTABLE)
    ret = _GetIpAddrTable(p_table, byref(buf_size), False)
    if ret != NO_ERROR:
        return ip_info

    table = p_table.contents
    addr_info = {}
    base = ctypes.addressof(p_table.contents)
    row_size = ctypes.sizeof(MIB_IPADDRROW)
    table_offset = ctypes.sizeof(wintypes.ULONG)
    for i in range(table.dwNumEntries):
        addr = base + table_offset + i * row_size
        row = cast(addr, PMIB_IPADDRROW).contents
        idx = str(row.dwIndex)
        if idx not in addr_info:
            addr_info[idx] = {"ip": _ip_to_str(row.dwAddr), "mask": _ip_to_str(row.dwMask)}

    name_by_idx = {}
    luid_by_idx = {}
    if_buf_size = wintypes.ULONG(0)
    ret2 = _GetIfTable(None, byref(if_buf_size), False)
    if ret2 == ERROR_INSUFFICIENT_BUFFER:
        if_buf = create_string_buffer(if_buf_size.value)
        p_if = cast(if_buf, PMIB_IFTABLE)
        ret2 = _GetIfTable(p_if, byref(if_buf_size), False)
        if ret2 == NO_ERROR:
            if_table = p_if.contents
            base_if = ctypes.addressof(p_if.contents)
            row_size_if = ctypes.sizeof(MIB_IFROW)
            for i in range(if_table.dwNumEntries):
                addr = base_if + ctypes.sizeof(wintypes.DWORD) + i * row_size_if
                row = cast(addr, PMIB_IFROW).contents
                idx_val = row.dwIndex
                idx_str = str(idx_val)
                raw = bytes(row.bDescr).split(b'\x00')[0]
                desc = raw.decode('gbk', errors='replace')
                desc = _clean_iface_desc(desc)
                name_by_idx[idx_str] = desc
                luid_by_idx[idx_str] = _index_to_luid(idx_val)

    all_routes_v4 = _read_v4_table_v1()
    # Build set of all local interface IPs
    local_ips: set[str] = set()
    for info in addr_info.values():
        ip = info["ip"]
        if ip and ip != "0.0.0.0":
            local_ips.add(ip)

    gw_by_idx: dict[str, str] = {}
    for r in all_routes_v4:
        # Only use default routes for gateway detection
        if not r.is_default:
            continue
        if r.gateway and r.gateway not in ("0.0.0.0", "On-link", "") and r.gateway not in local_ips:
            gw_by_idx[r.interface] = r.gateway

    for idx_str, info in addr_info.items():
        name = name_by_idx.get(idx_str, "")
        if not name:
            continue
        gw = gw_by_idx.get(idx_str, "-")
        ip_info[name] = {
            "ip": info["ip"],
            "mask": info["mask"],
            "gateway": gw,
        }

    return ip_info


def get_interface_ipv6_info():
    """Get IPv6 address list per interface.

    Returns dict: {iface_name: {"ipv6_addresses": list[str], "ipv6_gateway": str}}
    """
    ifaces = get_interfaces()
    v6_routes = _read_v6_table_v2()

    addr_by_idx: dict[str, set[str]] = {}
    gw_by_idx: dict[str, str] = {}

    for r in v6_routes:
        idx = r.interface
        if idx not in addr_by_idx:
            addr_by_idx[idx] = set()
        if r.destination and r.destination != "::":
            if r.prefix_length not in (0, 128):
                addr_by_idx[idx].add(r.destination)
        if r.is_default and r.gateway and r.gateway != "::":
            gw_by_idx[idx] = r.gateway

    info: dict[str, dict] = {}
    for idx_str, name, luid_str in ifaces:
        ips = list(addr_by_idx.get(idx_str, []))
        gw = gw_by_idx.get(idx_str, "-")
        info[name] = {
            "ipv6_addresses": ips,
            "ipv6_gateway": gw,
        }

    return info


# ----------- default route -----------

def get_default_route(address_family: int = AF_INET):
    """Find the default route with lowest metric.

    Args:
        address_family: AF_INET=2 (default), AF_INET6=23, or AF_UNSPEC.

    Returns RouteEntry or None.
    """
    candidates = [r for r in get_routes(address_family) if r.is_default]
    if not candidates:
        return None
    return min(candidates, key=lambda r: int(r.metric) if r.metric and r.metric.isdigit() else 9999)


# ----------- CRUD (v2, supports both AF_INET and AF_INET6) -----------

def add_route(dest, mask_or_plen, gw, iface_idx_str, metric=0, address_family=AF_INET):
    """Add a route using CreateIpForwardEntry2."""
    is_ipv6 = (address_family == AF_INET6)

    if is_ipv6:
        plen = int(mask_or_plen) if isinstance(mask_or_plen, (int, str)) else 64
    else:
        from core.utils import mask_to_cidr
        plen = mask_to_cidr(mask_or_plen)
        if plen is None:
            return False, "无效的子网掩码"

    row = MIB_IPFORWARD_ROW2()
    row.DestinationPrefix.Prefix = _build_sockaddr_inet(dest)
    row.DestinationPrefix.PrefixLength = plen
    nh_str = gw if gw and gw not in ("0.0.0.0", "::") else ("::" if is_ipv6 else "0.0.0.0")
    row.NextHop = _build_sockaddr_inet(nh_str)
    iface_idx = int(iface_idx_str)
    row.InterfaceIndex = iface_idx
    # Set LUID from Index for robustness
    luid_str = _index_to_luid(iface_idx)
    if luid_str:
        luid = _str_to_luid(luid_str)
        row.InterfaceLuid[0] = luid.Value & 0xFFFFFFFF
        row.InterfaceLuid[1] = (luid.Value >> 32) & 0xFFFFFFFF
    row.Metric = metric if metric > 0 else 256
    row.Protocol = 3
    row.Loopback = 0
    row.AutoconfigureAddress = 0
    row.Publish = 0
    row.Immortal = 1
    row.Age = 0
    row.Origin = 0
    row.PreferredLifetime = 0xFFFFFFFF
    row.ValidLifetime = 0xFFFFFFFF

    ret = _CreateIpForwardEntry2(byref(row))
    if ret != NO_ERROR:
        return False, f"CreateIpForwardEntry2 失败: {ret}"
    return True, ""


def delete_route(dest, mask_or_plen, gw, iface_idx_str, address_family=AF_INET):
    """Delete a route using DeleteIpForwardEntry2."""
    is_ipv6 = (address_family == AF_INET6)

    if is_ipv6:
        plen = int(mask_or_plen) if isinstance(mask_or_plen, (int, str)) else 0
    else:
        from core.utils import mask_to_cidr
        plen = mask_to_cidr(mask_or_plen)
        if plen is None:
            return False, "无效的子网掩码"

    row = MIB_IPFORWARD_ROW2()
    row.DestinationPrefix.Prefix = _build_sockaddr_inet(dest)
    row.DestinationPrefix.PrefixLength = plen
    nh_str = gw if gw and gw not in ("0.0.0.0", "::") else ("::" if is_ipv6 else "0.0.0.0")
    row.NextHop = _build_sockaddr_inet(nh_str)
    iface_idx = int(iface_idx_str)
    row.InterfaceIndex = iface_idx
    luid_str = _index_to_luid(iface_idx)
    if luid_str:
        luid = _str_to_luid(luid_str)
        row.InterfaceLuid[0] = luid.Value & 0xFFFFFFFF
        row.InterfaceLuid[1] = (luid.Value >> 32) & 0xFFFFFFFF

    ret = _DeleteIpForwardEntry2(byref(row))
    if ret != NO_ERROR:
        return False, f"DeleteIpForwardEntry2 失败: {ret}"
    return True, ""


def set_route_metric(dest, mask_or_plen, gw, iface_idx_str, new_metric, address_family=AF_INET):
    """Modify route metric using SetIpForwardEntry2."""
    is_ipv6 = (address_family == AF_INET6)

    if is_ipv6:
        plen = int(mask_or_plen) if isinstance(mask_or_plen, (int, str)) else 0
    else:
        from core.utils import mask_to_cidr
        plen = mask_to_cidr(mask_or_plen)
        if plen is None:
            return False, "无效的子网掩码"

    row = MIB_IPFORWARD_ROW2()
    row.DestinationPrefix.Prefix = _build_sockaddr_inet(dest)
    row.DestinationPrefix.PrefixLength = plen
    nh_str = gw if gw and gw not in ("0.0.0.0", "::") else ("::" if is_ipv6 else "0.0.0.0")
    row.NextHop = _build_sockaddr_inet(nh_str)
    iface_idx = int(iface_idx_str)
    row.InterfaceIndex = iface_idx
    luid_str = _index_to_luid(iface_idx)
    if luid_str:
        luid = _str_to_luid(luid_str)
        row.InterfaceLuid[0] = luid.Value & 0xFFFFFFFF
        row.InterfaceLuid[1] = (luid.Value >> 32) & 0xFFFFFFFF
    row.Metric = new_metric
    row.Protocol = 3

    ret = _SetIpForwardEntry2(byref(row))
    if ret != NO_ERROR:
        return False, f"SetIpForwardEntry2 失败: {ret}"
    return True, ""


# ----------- MIB_IF_ROW2 for GetIfEntry2 (bandwidth, speed, MTU, oper status) -----------

class MIB_IF_ROW2(Structure):
    _pack_ = 1
    _fields_ = [
        ("InterfaceLuid", ctypes.c_uint64),
        ("InterfaceIndex", wintypes.ULONG),
        ("InterfaceGuid", wintypes.BYTE * 16),
        ("Alias", wintypes.WCHAR * 257),
        ("Description", wintypes.WCHAR * 257),
        ("PhysicalAddressLength", wintypes.ULONG),
        ("PhysicalAddress", wintypes.BYTE * 32),
        ("PermanentPhysicalAddress", wintypes.BYTE * 32),
        ("Mtu", wintypes.ULONG),
        ("Type", wintypes.ULONG),
        ("TunnelType", wintypes.ULONG),
        ("MediaType", wintypes.ULONG),
        ("PhysicalMediumType", wintypes.ULONG),
        ("AccessType", wintypes.ULONG),
        ("DirectionType", wintypes.ULONG),
        ("OperStatus", wintypes.ULONG),
        ("AdminStatus", wintypes.ULONG),
        ("MediaConnectState", wintypes.ULONG),
        ("NetworkGuid", wintypes.BYTE * 16),
        ("ConnectionType", wintypes.ULONG),
        ("TransmitLinkSpeed", ctypes.c_uint64),
        ("ReceiveLinkSpeed", ctypes.c_uint64),
        ("InOctets", ctypes.c_uint64),
        ("InUcastPkts", ctypes.c_uint64),
        ("InNUcastPkts", ctypes.c_uint64),
        ("InDiscards", ctypes.c_uint64),
        ("InErrors", ctypes.c_uint64),
        ("InUnknownProtos", ctypes.c_uint64),
        ("InUcastOctets", ctypes.c_uint64),
        ("InMulticastOctets", ctypes.c_uint64),
        ("InBroadcastOctets", ctypes.c_uint64),
        ("OutOctets", ctypes.c_uint64),
        ("OutUcastPkts", ctypes.c_uint64),
        ("OutNUcastPkts", ctypes.c_uint64),
        ("OutDiscards", ctypes.c_uint64),
        ("OutErrors", ctypes.c_uint64),
        ("OutUnknownProtos", ctypes.c_uint64),
        ("OutUcastOctets", ctypes.c_uint64),
        ("OutMulticastOctets", ctypes.c_uint64),
        ("OutBroadcastOctets", ctypes.c_uint64),
        ("OutQLen", ctypes.c_uint64),
    ]


PMIB_IF_ROW2 = POINTER(MIB_IF_ROW2)

_GetIfEntry2 = _iphlpapi.GetIfEntry2
_GetIfEntry2.argtypes = [PMIB_IF_ROW2]
_GetIfEntry2.restype = wintypes.ULONG


def get_if_entry2(iface_index: int):
    """Get interface stats using GetIfEntry2.
    
    Returns dict with speed, mtu, oper_status, bytes, errors
    or None on failure.
    """
    row = MIB_IF_ROW2()
    row.InterfaceIndex = iface_index
    ret = _GetIfEntry2(byref(row))
    if ret != NO_ERROR:
        return None
    return {
        "mtu": row.Mtu,
        "speed": row.TransmitLinkSpeed,
        "oper_status": row.OperStatus,
        "in_octets": row.InOctets,
        "out_octets": row.OutOctets,
        "in_errors": row.InErrors,
        "out_errors": row.OutErrors,
        "out_discards": row.OutDiscards,
        "in_discards": row.InDiscards,
    }


# ----------- MIB_IPSTATS for GetIpStatisticsEx -----------

class MIB_IPSTATS(Structure):
    _fields_ = [
        ("dwForwarding", wintypes.DWORD),
        ("dwDefaultTTL", wintypes.DWORD),
        ("dwInReceives", wintypes.DWORD),
        ("dwInHdrErrors", wintypes.DWORD),
        ("dwInAddrErrors", wintypes.DWORD),
        ("dwForwDatagrams", wintypes.DWORD),
        ("dwInUnknownProtos", wintypes.DWORD),
        ("dwInDiscards", wintypes.DWORD),
        ("dwInDelivers", wintypes.DWORD),
        ("dwOutRequests", wintypes.DWORD),
        ("dwRoutingDiscards", wintypes.DWORD),
        ("dwOutDiscards", wintypes.DWORD),
        ("dwOutNoRoutes", wintypes.DWORD),
        ("dwReasmTimeout", wintypes.DWORD),
        ("dwReasmReqds", wintypes.DWORD),
        ("dwReasmOks", wintypes.DWORD),
        ("dwReasmFails", wintypes.DWORD),
        ("dwFragOks", wintypes.DWORD),
        ("dwFragFails", wintypes.DWORD),
        ("dwFragCreates", wintypes.DWORD),
        ("dwInTruncatedPkts", wintypes.DWORD),
        ("dwOutTruncatedPkts", wintypes.DWORD),
    ]


PMIB_IPSTATS = POINTER(MIB_IPSTATS)

_GetIpStatisticsEx = _iphlpapi.GetIpStatisticsEx
_GetIpStatisticsEx.argtypes = [PMIB_IPSTATS, wintypes.DWORD]
_GetIpStatisticsEx.restype = wintypes.ULONG


def get_ip_statistics_ex(address_family: int = AF_INET):
    """Get IP statistics for the given address family.
    
    Returns dict with packet stats and errors, or None on failure.
    """
    stats = MIB_IPSTATS()
    ret = _GetIpStatisticsEx(byref(stats), address_family)
    if ret != NO_ERROR:
        return None
    return {
        "in_receives": stats.dwInReceives,
        "in_header_errors": stats.dwInHdrErrors,
        "in_address_errors": stats.dwInAddrErrors,
        "forw_datagrams": stats.dwForwDatagrams,
        "in_unknown_protos": stats.dwInUnknownProtos,
        "in_discards": stats.dwInDiscards,
        "in_delivers": stats.dwInDelivers,
        "out_requests": stats.dwOutRequests,
        "routing_discards": stats.dwRoutingDiscards,
        "out_discards": stats.dwOutDiscards,
        "out_no_routes": stats.dwOutNoRoutes,
        "reasm_fails": stats.dwReasmFails,
        "frag_fails": stats.dwFragFails,
        "in_truncated": stats.dwInTruncatedPkts,
    }


# ----------- GetAdaptersAddresses for DNS, gateway, IPs -----------

MAX_ADAPTER_ADDRESS_LENGTH = 8
GAA_FLAG_INCLUDE_PREFIX = 0x0010
GAA_FLAG_SKIP_UNICAST = 0x0001
GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
GAA_FLAG_INCLUDE_GATEWAYS = 0x0080


class SOCKET_ADDRESS(Structure):
    _fields_ = [
        ("lpSockaddr", wintypes.LPVOID),
        ("iSockaddrLength", wintypes.INT),
    ]


class _IP_ADAPTER_DNS_SERVER_ADDRESS(Structure):
    pass


_IP_ADAPTER_DNS_SERVER_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG),
    ("Reserved", wintypes.DWORD),
    ("Next", POINTER(_IP_ADAPTER_DNS_SERVER_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
]


class _IP_ADAPTER_GATEWAY_ADDRESS(Structure):
    pass


_IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG),
    ("Reserved", wintypes.DWORD),
    ("Next", POINTER(_IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
]


class _IP_ADAPTER_UNICAST_ADDRESS(Structure):
    pass


_IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", wintypes.ULONG),
    ("Reserved", wintypes.DWORD),
    ("Next", POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
]


class _IP_ADAPTER_ADDRESSES(Structure):
    pass


_IP_ADAPTER_ADDRESSES._fields_ = [
    ("Alignment", ctypes.c_uint64),
    ("Next", POINTER(_IP_ADAPTER_ADDRESSES)),
    ("AdapterName", wintypes.LPVOID),
    ("FirstUnicastAddress", POINTER(_IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", wintypes.LPVOID),
    ("FirstMulticastAddress", wintypes.LPVOID),
    ("FirstDnsServerAddress", POINTER(_IP_ADAPTER_DNS_SERVER_ADDRESS)),
    ("DnsSuffix", wintypes.LPVOID),
    ("Description", wintypes.LPVOID),
    ("FriendlyName", wintypes.LPVOID),
    ("PhysicalAddress", wintypes.BYTE * MAX_ADAPTER_ADDRESS_LENGTH),
    ("PhysicalAddressLength", wintypes.DWORD),
    ("Flags", wintypes.DWORD),
    ("Mtu", wintypes.DWORD),
    ("IfType", wintypes.DWORD),
    ("OperStatus", wintypes.DWORD),
    ("Ipv6IfIndex", wintypes.DWORD),
    ("ZoneIndices", wintypes.DWORD * 16),
    ("FirstGatewayAddress", POINTER(_IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Ipv4Metric", wintypes.ULONG),
    ("Ipv6Metric", wintypes.ULONG),
    ("Luid", ctypes.c_uint64),
    ("Dhcpv4Server", SOCKET_ADDRESS),
    ("CompartmentId", wintypes.DWORD),
    ("NetworkGuid", wintypes.BYTE * 16),
    ("InterfaceGuid", wintypes.BYTE * 16),
]


PIP_ADAPTER_ADDRESSES = POINTER(_IP_ADAPTER_ADDRESSES)

_GetAdaptersAddresses = _iphlpapi.GetAdaptersAddresses
_GetAdaptersAddresses.argtypes = [
    wintypes.ULONG,
    wintypes.ULONG,
    wintypes.LPVOID,
    PIP_ADAPTER_ADDRESSES,
    POINTER(wintypes.ULONG),
]
_GetAdaptersAddresses.restype = wintypes.ULONG


def _sockaddr_to_ip(sockaddr_ptr, addr_len):
    """Extract IP string from a sockaddr pointer."""
    if not sockaddr_ptr:
        return None
    try:
        if isinstance(sockaddr_ptr, ctypes.c_void_p):
            addr = sockaddr_ptr.value
        else:
            addr = sockaddr_ptr
        if not addr:
            return None
        family = ctypes.c_ushort.from_address(addr).value
        if family == AF_INET:
            addr_bytes = (ctypes.c_ubyte * 4).from_address(addr + 4)
            return ".".join(str(b) for b in addr_bytes)
        elif family == AF_INET6:
            addr_bytes = (ctypes.c_ubyte * 16).from_address(addr + 8)
            return ":".join(f"{addr_bytes[i] << 8 | addr_bytes[i+1]:04x}" for i in range(0, 16, 2))
    except Exception:
        pass
    return None


def get_adapters_addresses(flags: int = GAA_FLAG_INCLUDE_GATEWAYS):
    """Get adapter info via GetAdaptersAddresses.
    
    Returns list of dicts with keys:
        - friendly_name, description, if_type, oper_status, mtu
        - ips: list of IP strings
        - dns_servers: list of DNS server IP strings
        - gateways: list of gateway IP strings
    Returns empty list on failure.
    """
    bufsize = wintypes.ULONG(15000)
    buf = ctypes.create_string_buffer(bufsize.value)
    family = AF_UNSPEC
    ret = _GetAdaptersAddresses(family, flags, None, cast(buf, PIP_ADAPTER_ADDRESSES), byref(bufsize))

    if ret == ERROR_BUFFER_OVERFLOW:
        buf = ctypes.create_string_buffer(bufsize.value)
        ret = _GetAdaptersAddresses(family, flags, None, cast(buf, PIP_ADAPTER_ADDRESSES), byref(bufsize))

    if ret != NO_ERROR:
        return []

    result = []
    addr = cast(buf, PIP_ADAPTER_ADDRESSES)
    while addr:
        a = addr.contents
        friendly_name = ""
        if a.FriendlyName:
            try:
                friendly_name = ctypes.c_wchar_p(a.FriendlyName).value or ""
            except Exception:
                pass

        description = ""
        if a.Description:
            try:
                description = ctypes.c_wchar_p(a.Description).value or ""
            except Exception:
                pass

        ips = []
        ua = a.FirstUnicastAddress
        while ua:
            ip = _sockaddr_to_ip(ua.contents.Address.lpSockaddr, ua.contents.Address.iSockaddrLength)
            if ip:
                ips.append(ip)
            ua = ua.contents.Next

        dns_servers = []
        dns = a.FirstDnsServerAddress
        while dns:
            ip = _sockaddr_to_ip(dns.contents.Address.lpSockaddr, dns.contents.Address.iSockaddrLength)
            if ip:
                dns_servers.append(ip)
            dns = dns.contents.Next

        gateways = []
        gw = a.FirstGatewayAddress
        while gw:
            ip = _sockaddr_to_ip(gw.contents.Address.lpSockaddr, gw.contents.Address.iSockaddrLength)
            if ip:
                gateways.append(ip)
            gw = gw.contents.Next

        result.append({
            "friendly_name": friendly_name,
            "description": description,
            "if_type": a.IfType,
            "oper_status": a.OperStatus,
            "mtu": a.Mtu,
            "ips": ips,
            "dns_servers": dns_servers,
            "gateways": gateways,
            "ipv4_metric": a.Ipv4Metric,
            "ipv6_metric": a.Ipv6Metric,
        })

        addr = a.Next

    return result


def get_dns_servers():
    """Get list of DNS server IPs from all adapters."""
    adapters = get_adapters_addresses(flags=0)
    seen = set()
    servers = []
    for a in adapters:
        for dns in a["dns_servers"]:
            if dns not in seen:
                seen.add(dns)
                servers.append(dns)
    return servers


def get_adapter_gateways():
    """Get dict of if_index -> list[gateway_ip] from adapter info.

    We approximate if_index using the adapter's IPv4 metric.
    The actual if_index would require calling GetAdaptersAddresses with
    the adapter name to index conversion, which GetAdapterIndex does.
    Instead, we cross-reference with the friendly name in get_interfaces().
    """
    adapters = get_adapters_addresses()
    gateways = {}
    for a in adapters:
        for ip in a["gateways"]:
            key = a["friendly_name"]
            if key not in gateways:
                gateways[key] = []
            if ip not in gateways[key]:
                gateways[key].append(ip)
    return gateways


# ----------- ICMP ping via IcmpSendEcho2 -----------

class IP_OPTION_INFORMATION(Structure):
    _fields_ = [
        ("Ttl", wintypes.BYTE),
        ("Tos", wintypes.BYTE),
        ("Flags", wintypes.BYTE),
        ("OptionsSize", wintypes.BYTE),
        ("OptionsData", wintypes.LPVOID),
    ]


class ICMP_ECHO_REPLY(Structure):
    _fields_ = [
        ("Address", wintypes.ULONG),
        ("Status", wintypes.ULONG),
        ("RoundTripTime", wintypes.ULONG),
        ("DataSize", wintypes.USHORT),
        ("Reserved", wintypes.USHORT),
        ("Data", wintypes.LPVOID),
        ("Options", IP_OPTION_INFORMATION),
    ]


class ICMPV6_ECHO_REPLY(Structure):
    _fields_ = [
        ("Address", wintypes.BYTE * 16),
        ("Status", wintypes.ULONG),
        ("RoundTripTime", wintypes.ULONG),
        ("DataSize", wintypes.USHORT),
        ("Reserved", wintypes.USHORT),
        ("Data", wintypes.LPVOID),
        ("Options", IP_OPTION_INFORMATION),
    ]


IP_STATUS_BASE = 11000
IP_SUCCESS = 0
IP_DEST_NET_UNREACHABLE = IP_STATUS_BASE + 1
IP_DEST_HOST_UNREACHABLE = IP_STATUS_BASE + 2
IP_DEST_PROT_UNREACHABLE = IP_STATUS_BASE + 3
IP_REQ_TIMED_OUT = IP_STATUS_BASE + 10
IP_BUF_TOO_SMALL = IP_STATUS_BASE + 12
IP_GENERAL_FAILURE = IP_STATUS_BASE + 50

_icmp = ctypes.WinDLL("icmp", use_last_error=True)

_IcmpCreateFile = _icmp.IcmpCreateFile
_IcmpCreateFile.argtypes = []
_IcmpCreateFile.restype = wintypes.HANDLE

_IcmpSendEcho = _icmp.IcmpSendEcho
_IcmpSendEcho.argtypes = [
    wintypes.HANDLE,
    wintypes.ULONG,
    wintypes.LPVOID,
    wintypes.USHORT,
    wintypes.LPVOID,
    wintypes.LPVOID,
    wintypes.DWORD,
    wintypes.DWORD,
]
_IcmpSendEcho.restype = wintypes.DWORD

_IcmpCloseHandle = _icmp.IcmpCloseHandle
_IcmpCloseHandle.argtypes = [wintypes.HANDLE]
_IcmpCloseHandle.restype = wintypes.BOOL


def _ip_str_to_ulong(ip_str: str) -> int:
    """Convert dotted IPv4 string to ULONG (network byte order)."""
    import socket
    import struct
    try:
        return struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except Exception:
        return 0


INVALID_HANDLE_VALUE = wintypes.HANDLE(-1).value


class IcmpPingSession:
    """Context manager for ICMP ping sessions (IPv4).

    Usage:
        with IcmpPingSession() as h:
            rtt = icmp_ping4(h, "8.8.8.8", 3000)
    """

    def __init__(self):
        self.handle = None

    def __enter__(self):
        self.handle = _IcmpCreateFile()
        if self.handle == INVALID_HANDLE_VALUE or self.handle is None:
            raise RuntimeError("IcmpCreateFile failed")
        return self.handle

    def __exit__(self, *args):
        if self.handle and self.handle != INVALID_HANDLE_VALUE:
            _IcmpCloseHandle(self.handle)
        self.handle = None


def icmp_ping4(icmp_handle, target_ip: str, timeout_ms: int = 3000):
    """Send a single ICMP echo request (IPv4) using IcmpSendEcho.

    Args:
        icmp_handle: Handle from IcmpCreateFile
        target_ip: Dotted IPv4 string
        timeout_ms: Timeout in milliseconds

    Returns:
        (True, rtt_ms) on success
        (False, error_msg) on failure/timeout
    """
    dest = _ip_str_to_ulong(target_ip)

    reply_size = ctypes.sizeof(ICMP_ECHO_REPLY) + 64
    reply_buf = ctypes.create_string_buffer(reply_size)
    send_data = ctypes.create_string_buffer(b"Ping", 4)

    ret = _IcmpSendEcho(
        icmp_handle,
        dest,
        send_data,
        4,
        None,
        reply_buf,
        reply_size,
        timeout_ms,
    )

    if ret == 0:
        return False, "timeout"

    reply = ctypes.cast(reply_buf, POINTER(ICMP_ECHO_REPLY)).contents
    if reply.Status == IP_SUCCESS:
        return True, int(reply.RoundTripTime)
    elif reply.Status == IP_REQ_TIMED_OUT:
        return False, "timeout"
    else:
        return False, f"status={reply.Status}"


def format_speed(bps: float) -> str:
    """Format bps to human-readable string."""
    if bps < 0:
        return "-"
    if bps < 1024:
        return f"{bps:.0f} B/s"
    elif bps < 1024 * 1024:
        return f"{bps / 1024:.1f} KB/s"
    elif bps < 1024 * 1024 * 1024:
        return f"{bps / 1024 / 1024:.1f} MB/s"
    return f"{bps / 1024 / 1024 / 1024:.2f} GB/s"
