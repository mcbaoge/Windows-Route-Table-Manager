"""Network topology engine — discovers the machine's network graph.

Uses WinAPI (GetAdaptersAddresses when available, GetIfTable+route table as fallback)
to build a live graph of:

    [本机] ── [网卡] ── [网关/下一跳] ── [Internet / VPN]

Supports IPv4 + IPv6 dual-stack.
"""
import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional
from enum import IntEnum, auto

from core.utils import RouteEntry
from services.winapi_network import (
    get_routes, get_interfaces, get_interface_ipv4_info, get_interface_ipv6_info,
    _ip_to_str, _str_to_ip,
    AF_INET, AF_INET6, AF_UNSPEC,
)

logger = logging.getLogger(__name__)

# EMA smoothing constant
EMA_ALPHA = 0.3

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class NodeType(IntEnum):
    LOCAL_MACHINE = 0
    ETHERNET = 1
    WIFI = 2
    VPN = 3
    VIRTUAL = 4
    GATEWAY = 5
    INTERNET = 6
    LOOPBACK = 7
    OTHER = 8


class LinkStatus(IntEnum):
    UNKNOWN = 0
    UP = 1
    DOWN = 2
    DEGRADED = 3


@dataclass
class InterfaceInfo:
    idx: str
    name: str
    display_name: str
    iftype: int          # MIB_IFROW.dwType
    oper_status: int     # 1=UP 2=DOWN etc.
    speed: int
    mtu: int
    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    gateways: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    is_default: bool = False
    metric: int = 0
    rtt_ms: float = 0.0
    rx_bytes: int = 0
    tx_bytes: int = 0
    # Real-time bandwidth (bytes/sec, EMA smoothed)
    rx_rate: float = 0.0
    tx_rate: float = 0.0
    rx_packets: int = 0
    tx_packets: int = 0
    packets_rate: float = 0.0
    # RTT / loss
    loss_percent: float = 0.0
    jitter_ms: float = 0.0


@dataclass
class TopologyNode:
    """A node in the network topology graph."""
    id: str
    label: str
    node_type: NodeType
    ip_addresses: list[str] = field(default_factory=list)
    gateway: str = ""
    iface_idx: str = ""
    iface_luid: str = ""
    metric: int = 0
    rtt_ms: float = 0.0
    status: LinkStatus = LinkStatus.UNKNOWN
    is_default: bool = False
    is_vpn: bool = False
    children: list = field(default_factory=list)
    # Real-time bandwidth
    rx_rate: float = 0.0
    tx_rate: float = 0.0
    packets_rate: float = 0.0
    # RTT / loss
    loss_percent: float = 0.0
    jitter_ms: float = 0.0
    # Security
    security_alerts: list = field(default_factory=list)
    # Position
    x: float = 0.0
    y: float = 0.0
    vx: float = 0.0
    vy: float = 0.0


@dataclass
class TopologyEdge:
    """A directed edge (connection) between two topology nodes."""
    source_id: str
    target_id: str
    label: str = ""
    metric: int = 0
    rtt_ms: float = 0.0
    status: LinkStatus = LinkStatus.UNKNOWN
    is_default: bool = False
    # Real-time bandwidth (bytes/sec)
    rx_rate: float = 0.0
    tx_rate: float = 0.0
    packets_rate: float = 0.0
    loss_percent: float = 0.0
    jitter_ms: float = 0.0
    # Traffic flow direction for animation
    has_traffic: bool = False
    traffic_direction: str = ""  # "tx", "rx", "both"
    # Security
    security_alerts: list = field(default_factory=list)
    # Transition state
    is_new: bool = False
    is_fading: bool = False
    fade_alpha: float = 1.0


@dataclass
class NetworkGraph:
    """Complete network topology graph."""
    nodes: dict[str, TopologyNode] = field(default_factory=dict)
    edges: list[TopologyEdge] = field(default_factory=list)
    default_iface_idx: str = ""
    default_gateway: str = ""
    # Version for cache/diff tracking
    version: int = 0
    # Timestamp
    timestamp: float = 0.0


@dataclass
class GraphDiff:
    """Incremental difference between two graph snapshots."""
    added_nodes: dict[str, TopologyNode] = field(default_factory=dict)
    removed_nodes: list[str] = field(default_factory=list)
    changed_nodes: dict[str, TopologyNode] = field(default_factory=dict)
    added_edges: list[TopologyEdge] = field(default_factory=list)
    removed_edges: list[tuple[str, str]] = field(default_factory=list)
    changed_edges: list[TopologyEdge] = field(default_factory=list)
    # Positions for new nodes
    new_positions: dict[str, tuple[float, float]] = field(default_factory=dict)


def diff_graph(old: NetworkGraph, new: NetworkGraph) -> GraphDiff:
    """Compute incremental diff between two graph snapshots."""
    diff = GraphDiff()

    old_node_ids = set(old.nodes.keys())
    new_node_ids = set(new.nodes.keys())

    # Added nodes
    for nid in new_node_ids - old_node_ids:
        diff.added_nodes[nid] = new.nodes[nid]

    # Removed nodes
    for nid in old_node_ids - new_node_ids:
        diff.removed_nodes.append(nid)

    # Changed nodes (same id, different data)
    for nid in new_node_ids & old_node_ids:
        old_node = old.nodes[nid]
        new_node = new.nodes[nid]
        if (old_node.status != new_node.status or
                old_node.is_default != new_node.is_default or
                old_node.rtt_ms != new_node.rtt_ms or
                old_node.rx_rate != new_node.rx_rate or
                old_node.tx_rate != new_node.tx_rate or
                old_node.loss_percent != new_node.loss_percent):
            diff.changed_nodes[nid] = new_node

    # Edge diff
    old_edges = {(e.source_id, e.target_id) for e in old.edges}
    new_edges = {(e.source_id, e.target_id) for e in new.edges}

    old_edge_map = {(e.source_id, e.target_id): e for e in old.edges}
    new_edge_map = {(e.source_id, e.target_id): e for e in new.edges}

    for key in new_edges - old_edges:
        diff.added_edges.append(new_edge_map[key])

    for key in old_edges - new_edges:
        diff.removed_edges.append(key)

    for key in new_edges & old_edges:
        oe = old_edge_map[key]
        ne = new_edge_map[key]
        if (oe.status != ne.status or oe.is_default != ne.is_default or
                oe.rtt_ms != ne.rtt_ms or oe.rx_rate != ne.rx_rate or
                oe.tx_rate != ne.tx_rate or oe.loss_percent != ne.loss_percent):
            diff.changed_edges.append(ne)

    return diff


# ---------------------------------------------------------------------------
# Topology engine
# ---------------------------------------------------------------------------

def _detect_iface_category(name: str, iftype: int) -> NodeType:
    """Categorize an interface based on its name and type."""
    lower = name.lower()
    # Check TAP/VPN/tunnel first (these keywords may appear in other names)
    if "tap" in lower or "openvpn" in lower or "vpn" in lower:
        return NodeType.VPN
    iftype_map = {
        6: NodeType.LOOPBACK,
        23: NodeType.ETHERNET,
        71: NodeType.WIFI,
        131: NodeType.VPN,
        144: NodeType.VIRTUAL,
        53: NodeType.OTHER,
        243: NodeType.VPN,
        28: NodeType.ETHERNET,
    }
    if iftype in iftype_map:
        base = iftype_map[iftype]
        if base == NodeType.ETHERNET:
            if "wireless" in lower or "wlan" in lower:
                return NodeType.WIFI
            if "vmware" in lower or "virtual" in lower:
                return NodeType.VIRTUAL
        return base
    if "loopback" in lower:
        return NodeType.LOOPBACK
    if "vmware" in lower or "hyper" in lower or "virtual" in lower:
        return NodeType.VIRTUAL
    if "wireless" in lower or "wlan" in lower or "wi-fi" in lower:
        return NodeType.WIFI
    if "tunnel" in lower or "teredo" in lower or "6to4" in lower:
        return NodeType.VPN
    if "eth" in lower or "e" == name.strip().lower():
        return NodeType.ETHERNET
    return NodeType.OTHER


def _get_dns_servers() -> dict[str, list[str]]:
    """Read DNS servers from registry per interface GUID."""
    import winreg
    dns_map: dict[str, list[str]] = {}
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        )
        try:
            i = 0
            while True:
                guid = winreg.EnumKey(key, i)
                i += 1
                try:
                    sub = winreg.OpenKey(key, guid)
                    try:
                        servers = winreg.QueryValueEx(sub, "DhcpNameServer")[0]
                        if servers:
                            dns_map[guid] = [s.strip() for s in servers.split(",")]
                    except FileNotFoundError:
                        pass
                    try:
                        servers = winreg.QueryValueEx(sub, "NameServer")[0]
                        if servers:
                            existing = dns_map.get(guid, [])
                            dns_map[guid] = existing + [s.strip() for s in servers.split(",")]
                    except FileNotFoundError:
                        pass
                    winreg.CloseKey(sub)
                except OSError:
                    pass
        except OSError:
            pass
        winreg.CloseKey(key)
    except OSError as e:
        logger.warning("读取 DNS 注册表失败: %s", e)
    return dns_map


def build_topology() -> NetworkGraph:
    """Build the full network topology graph from live WinAPI data.

    Supports IPv4 + IPv6 dual-stack.

    Returns:
        NetworkGraph with nodes, edges, default route info.
    """
    graph = NetworkGraph()

    # 1. Get all data sources
    routes = get_routes(AF_UNSPEC)
    ifaces_raw = get_interfaces()       # list[(idx, name, luid_str)]
    iface_info_v4 = get_interface_ipv4_info()  # dict[name -> {ip, mask, gateway}]
    iface_info_v6 = get_interface_ipv6_info()  # dict[name -> {ipv6_addresses, ipv6_gateway}]

    # 2. Build interface details
    iface_details = _get_interface_details()

    # 3. Find default route (IPv4 preferred, fallback to IPv6)
    v4_default = [r for r in routes if r.is_default and not r.is_ipv6]
    v6_default = [r for r in routes if r.is_default and r.is_ipv6]
    if v4_default:
        best = min(v4_default, key=lambda r: int(r.metric) if r.metric.isdigit() else 9999)
        graph.default_iface_idx = best.interface
        graph.default_gateway = best.gateway
    elif v6_default:
        best = min(v6_default, key=lambda r: int(r.metric) if r.metric.isdigit() else 9999)
        graph.default_iface_idx = best.interface
        graph.default_gateway = best.gateway

    # 4. Build local machine node
    local_node = TopologyNode(
        id="localhost",
        label="本机",
        node_type=NodeType.LOCAL_MACHINE,
        status=LinkStatus.UP,
    )
    graph.nodes["localhost"] = local_node

    # 5. Deduplicate interfaces by name (keep first / best status)
    seen_names: set[str] = set()
    deduped_ifaces: list[tuple[str, str, str]] = []
    for idx_str, name, luid_str in ifaces_raw:
        if name and name not in seen_names:
            seen_names.add(name)
            deduped_ifaces.append((idx_str, name, luid_str))

    # 6. Build per-interface nodes + edges
    dns_map = _get_dns_servers()

    for idx_str, name, luid_str in deduped_ifaces:
        detail = iface_details.get(idx_str, {})
        cat = _detect_iface_category(name, detail.get("type", 1))
        oper = detail.get("oper_status", 1)
        speed = detail.get("speed", 0)
        mtu = detail.get("mtu", 1500)

        # Gather IPs (IPv4 + IPv6)
        ips = []
        info_v4 = iface_info_v4.get(name, {})
        if info_v4.get("ip") and info_v4["ip"] != "0.0.0.0":
            ips.append(info_v4["ip"])
        info_v6 = iface_info_v6.get(name, {})
        for v6ip in info_v6.get("ipv6_addresses", []):
            if v6ip not in ips:
                ips.append(v6ip)

        # Gather gateways — filter out self-IPs (on-link next-hop)
        gws = []
        gw = info_v4.get("gateway", "")
        if gw and gw not in ("-", "0.0.0.0") and gw not in ips:
            gws.append(gw)
        gw6 = info_v6.get("ipv6_gateway", "")
        if gw6 and gw6 not in ("-", "::") and gw6 not in ips:
            gws.append(gw6)

        # Check if this is the default route interface
        is_default = (idx_str == graph.default_iface_idx)

        # Find metric from routes on this interface
        iface_routes = [r for r in routes if r.interface == idx_str and r.is_default]
        metric = int(iface_routes[0].metric) if iface_routes else 0

        # Check VPN
        is_vpn = cat == NodeType.VPN

        # Status
        status = LinkStatus.UP if oper == 1 else LinkStatus.DOWN
        if status == LinkStatus.UP and not ips:
            status = LinkStatus.DEGRADED

        node_id = f"iface_{idx_str}"
        node_label = name
        if len(node_label) > 30:
            node_label = node_label[:27] + "..."

        iface_node = TopologyNode(
            id=node_id,
            label=node_label,
            node_type=cat,
            ip_addresses=ips,
            gateway=gw,
            iface_idx=idx_str,
            iface_luid=luid_str,
            metric=metric,
            status=status,
            is_default=is_default,
            is_vpn=is_vpn,
        )
        graph.nodes[node_id] = iface_node

        # Edge: localhost → interface
        graph.edges.append(TopologyEdge(
            source_id="localhost",
            target_id=node_id,
            label=f"if {idx_str}",
            metric=metric,
            status=status,
            is_default=is_default,
        ))

        # 6. Gateway nodes for each interface
        for gw_ip in gws:
            gw_id = f"gw_{gw_ip.replace('.', '_').replace(':', '_')}"
            if gw_id not in graph.nodes:
                gw_node = TopologyNode(
                    id=gw_id,
                    label=gw_ip,
                    node_type=NodeType.GATEWAY,
                    gateway=gw_ip,
                    status=LinkStatus.UP,
                    is_default=is_default,
                )
                graph.nodes[gw_id] = gw_node

            graph.edges.append(TopologyEdge(
                source_id=node_id,
                target_id=gw_id,
                label=f"metric={metric}" if metric else "",
                metric=metric,
                status=status,
                is_default=is_default,
            ))

            # 7. Internet node (connected to default gateway — IPv4 or IPv6)
            if is_default and (gw_ip == graph.default_gateway or (graph.default_gateway == "" and gw_ip != "")):
                internet_id = "internet"
                if internet_id not in graph.nodes:
                    graph.nodes[internet_id] = TopologyNode(
                        id=internet_id,
                        label="Internet",
                        node_type=NodeType.INTERNET,
                        status=LinkStatus.UNKNOWN,
                    )
                graph.edges.append(TopologyEdge(
                    source_id=gw_id,
                    target_id=internet_id,
                    label="默认出口" if is_default else "",
                    metric=metric,
                    is_default=True,
                    status=LinkStatus.UP,
                ))

    return graph


def _get_interface_details() -> dict[str, dict]:
    """Read full MIB_IFROW details (type, oper_status, speed, mtu) via raw WinAPI.

    Returns dict: {idx_str: {"type":int, "oper_status":int, "speed":int, "mtu":int}}
    """
    import ctypes
    from ctypes import wintypes, POINTER, byref, create_string_buffer

    iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    GetIfTable = iphlpapi.GetIfTable
    GetIfTable.argtypes = [ctypes.c_void_p, POINTER(wintypes.ULONG), wintypes.BOOL]
    GetIfTable.restype = wintypes.ULONG

    NO_ERROR = 0
    ERROR_INSUFFICIENT_BUFFER = 122
    result = {}

    buf_size = wintypes.ULONG(0)
    ret = GetIfTable(None, byref(buf_size), False)
    if ret != ERROR_INSUFFICIENT_BUFFER:
        return result

    buf = create_string_buffer(buf_size.value)
    ret = GetIfTable(buf, byref(buf_size), False)
    if ret != NO_ERROR:
        return result

    raw = buf.raw
    num = struct.unpack_from('I', raw, 0)[0]

    # MIB_IFROW offset layout on x64:
    # 0:     wszName[256] = 512 bytes
    # 512:   dwIndex
    # 516:   dwType
    # 520:   dwMtu
    # 524:   dwSpeed
    # 528:   dwPhysAddrLen
    # 532:   bPhysAddr[8]
    # 540:   dwAdminStatus
    # 544:   dwOperStatus
    # ... more fields follow

    row_size = 4 + 512 + 4 + 4 + 4 + 4 + 4 + 8 + 4 + 4 + 20 * 4 + 256
    # num(4) + wszName(512) + dwIndex(4) + dwType(4) + dwMtu(4) + dwSpeed(4)
    # + dwPhysAddrLen(4) + bPhysAddr(8) + dwAdminStatus(4) + dwOperStatus(4)
    # + 20 more DWORDs + bDescr(256)
    row_size = 4 + 512 + 92 + 256  # approximate ~864

    # Find row_sise by probing: each row is MIB_IFROW.
    # We can compute the row size from buffer_size vs num_entries.
    row_size_guess = (len(raw) - 4) // max(num, 1)
    # MIB_IFROW should be ~868 bytes on x64. Use whichever is larger.
    row_size = max(row_size_guess, 800)

    for i in range(num):
        base = 4 + i * row_size
        if base + 548 > len(raw):
            break
        idx = struct.unpack_from('I', raw, base + 512)[0]
        iftype = struct.unpack_from('I', raw, base + 516)[0]
        mtu = struct.unpack_from('I', raw, base + 520)[0]
        speed = struct.unpack_from('I', raw, base + 524)[0]
        oper = struct.unpack_from('I', raw, base + 544)[0]
        result[str(idx)] = {
            "type": iftype,
            "oper_status": oper,
            "speed": speed,
            "mtu": mtu,
        }

    return result


# ---------------------------------------------------------------------------
# Auto-layout
# ---------------------------------------------------------------------------

def auto_layout(graph: NetworkGraph, canvas_w: float, canvas_h: float):
    """Position nodes in a hierarchical tree layout.

    Layout:
        [本机 (localhost)]     → left
        [网卡 (iface_*)]      → middle-left
        [网关 (gw_*)]         → middle-right
        [Internet]            → right
    """
    positions: dict[str, tuple[float, float]] = {}

    level_width = canvas_w * 0.85
    level_height = canvas_h * 0.80
    x_start = canvas_w * 0.05
    y_start = canvas_h * 0.10

    # Level 0: localhost
    positions["localhost"] = (x_start, canvas_h / 2)

    # Level 1: interfaces
    iface_nodes = [nid for nid, n in graph.nodes.items() if nid.startswith("iface_")]
    iface_nodes.sort()
    if iface_nodes:
        spacing = level_height / max(len(iface_nodes), 1)
        for i, nid in enumerate(iface_nodes):
            x = x_start + level_width * 0.30
            y = y_start + i * spacing
            positions[nid] = (x, y)

    # Level 2: gateways
    gw_nodes = [nid for nid, n in graph.nodes.items() if nid.startswith("gw_")]
    gw_nodes.sort()
    if gw_nodes:
        spacing = level_height / max(len(gw_nodes), 1)
        for i, nid in enumerate(gw_nodes):
            x = x_start + level_width * 0.60
            y = y_start + i * spacing
            positions[nid] = (x, y)

    # Level 3: internet
    if "internet" in graph.nodes:
        positions["internet"] = (x_start + level_width * 0.90, canvas_h / 2)

    return positions
