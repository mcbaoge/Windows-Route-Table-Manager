from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ConnectionEvent:
    timestamp: float = 0.0
    event_subtype: str = ""     # "connect" | "disconnect" | "retransmit" | "drop"
    protocol: str = "TCP"
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    pid: int = 0
    process_name: str = ""
    status: str = ""             # "success" | "reset" | "timeout"
    stack_size: int = 0
    mss: int = 0


@dataclass
class DnsEvent:
    timestamp: float = 0.0
    query: str = ""
    query_type: str = "A"
    answers: list[str] = field(default_factory=list)
    rtt_ms: float = 0.0
    pid: int = 0
    process_name: str = ""
    status: str = ""             # "success" | "timeout" | "error" | "cached"
    server_ip: str = ""


@dataclass
class RouteEvent:
    timestamp: float = 0.0
    event_subtype: str = ""      # "route_added" | "route_removed" | "route_changed"
    destination: str = ""
    gateway: str = ""
    interface: str = ""
    metric: int = 0
    address_family: str = "IPv4"  # "IPv4" | "IPv6"
    pid: int = 0
    process_name: str = ""


@dataclass
class InterfaceEvent:
    timestamp: float = 0.0
    event_subtype: str = ""      # "up" | "down" | "address_added" | "address_removed"
    interface_name: str = ""
    interface_index: int = 0
    ip_address: str = ""
    address_family: str = "IPv4"


@dataclass
class PacketDropEvent:
    timestamp: float = 0.0
    protocol: str = "TCP"
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    reason: str = ""
    pid: int = 0
    process_name: str = ""


@dataclass
class PacketEvent:
    timestamp: float = 0.0
    protocol: str = ""
    src_addr: str = ""
    dst_addr: str = ""
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    direction: str = ""  # "outbound" | "inbound"
    pid: int = 0
    process_name: str = ""
    iface_index: int = 0
    is_ipv6: bool = False


@dataclass
class TrafficStatsEvent:
    timestamp: float = 0.0
    upload_bps: float = 0.0
    download_bps: float = 0.0
    upload_pps: float = 0.0
    download_pps: float = 0.0
    total_upload_bytes: int = 0
    total_download_bytes: int = 0
    total_packets: int = 0
    active_connections: int = 0
    per_process: list = field(default_factory=list)
