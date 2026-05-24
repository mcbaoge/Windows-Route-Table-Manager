import subprocess
import os
import ipaddress
import logging
from dataclasses import dataclass

from core.config import NETSH_ENCODING

logger = logging.getLogger(__name__)


@dataclass
class RouteEntry:
    destination: str = ""
    mask: str = ""
    gateway: str = ""
    interface: str = ""
    metric: str = ""
    prefix_length: int = 0
    is_default: bool = False
    interface_name: str = ""
    address_family: int = 2  # AF_INET=2, AF_INET6=23
    is_ipv6: bool = False
    interface_luid: str = ""     # NET_LUID as hex string, e.g. "0x17000000000000"
    luid_index: int = 0          # NetLuidIndex extracted from NET_LUID


def make_error_result(stderr_msg):
    class _R:
        returncode = 1
        stdout = ""
        stderr = stderr_msg
    return _R()


def run(cmd):
    logger.debug("RUN | %s", " ".join(cmd))

    startupinfo = None
    creationflags = 0
    if os.name == "nt":
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        creationflags |= subprocess.CREATE_NO_WINDOW

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding=NETSH_ENCODING,
        startupinfo=startupinfo,
        creationflags=creationflags,
    )

    if result.returncode != 0:
        logger.warning("RUN failed (code=%d)\nSTDOUT: %s\nSTDERR: %s",
                       result.returncode, result.stdout.strip(), result.stderr.strip())
    return result


def cidr_to_mask(cidr: int) -> str:
    if cidr < 0 or cidr > 32:
        return "0.0.0.0"
    mask = (0xffffffff << (32 - cidr)) & 0xffffffff
    return ".".join(str((mask >> (i * 8)) & 0xff) for i in [3, 2, 1, 0])


def mask_to_cidr(mask: str) -> int | None:
    try:
        expected = int(ipaddress.IPv4Address(mask))
        bits = bin(expected).count('1')
        contiguous = (0xffffffff << (32 - bits)) & 0xffffffff
        if contiguous == expected:
            return bits
    except Exception:
        pass
    return None


def is_valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return True
    except Exception:
        return False


def is_valid_ipv6(s: str) -> bool:
    try:
        ipaddress.IPv6Address(s)
        return True
    except Exception:
        return False


def compress_ipv6(addr: str) -> str:
    """Compress an IPv6 address to its shortest representation."""
    try:
        return str(ipaddress.IPv6Address(addr))
    except Exception:
        return addr
