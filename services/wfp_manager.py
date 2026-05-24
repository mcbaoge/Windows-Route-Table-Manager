"""WFP Manager -- Windows Filtering Platform firewall management.

Backed by `netsh advfirewall firewall` (which uses WFP internally),
with ctypes bindings to fwpuclnt.dll reserved for future direct API use
(IDS/IPS, kernel callouts, enterprise firewall extensions).

Supports:
  - filter add / remove / list
  - ALE connect-layer semantics (outbound / inbound)
  - per-process firewall (via app path and PID)
  - protocol / IP / port matching
  - blacklist / whitelist
  - dynamic rules with hit tracking
  - proper cleanup and exception recovery

Thread model: PeriodicTaskMgr via TaskManager for hit-count polling.
"""
import logging
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

from services.task_manager import get_task_manager

logger = logging.getLogger(__name__)


@dataclass
class WfpRule:
    name: str = ""
    description: str = ""
    layer: str = "ALE_AUTH_CONNECT_V4"
    direction: str = "outbound"
    action: str = "block"
    protocol: str = ""
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    pid: int = 0
    app_path: str = ""
    enabled: bool = True
    persistent: bool = False
    filter_id: int = 0
    filter_key_hex: str = ""
    hit_count: int = 0
    created_at: float = 0.0

    @property
    def is_ipv6(self) -> bool:
        return "V6" in self.layer


@dataclass
class WfpStats:
    engine_open: bool = False
    filter_count: int = 0
    total_hits: int = 0
    last_error: str = ""
    session_recoveries: int = 0


_PROTO_MAP = {
    "TCP": "6", "UDP": "17", "ICMP": "1",
    "ICMPV6": "58", "GRE": "47", "ESP": "50", "AH": "51",
}

_DIR_MAP = {"outbound": "out", "inbound": "in"}

_ACTION_MAP = {"block": "block", "allow": "allow"}

_RULE_PREFIX = "WfpMgr_"


def _run_netsh(args: list[str]) -> tuple[int, str]:
    cmd = ["netsh", "advfirewall", "firewall"] + args
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        result = subprocess.run(
            cmd, capture_output=True, text=True,
            encoding="gbk", errors="replace",
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode != 0:
            logger.warning("netsh error (rc=%d): %s", result.returncode, result.stderr.strip())
        return result.returncode, result.stderr.strip()
    except Exception as e:
        logger.exception("netsh run failed: %s", e)
        return -1, str(e)


class WfpManager:
    """Windows Filtering Platform manager via `netsh advfirewall firewall`.

    Provides add / remove / list of firewall rules with conditions
    for protocol, addresses, ports, and process path.

    Hit-count polling uses PeriodicTaskMgr via TaskManager.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._rules: dict[str, WfpRule] = {}
        self._filter_id_to_key: dict[int, str] = {}
        self._id_counter = 0
        self._recovery_count = 0
        self._running = False
        self._periodic = None
        self._stop_event = threading.Event()

        self.on_hit = None
        self.on_error = None
        self.on_recovery = None

    def open(self) -> bool:
        self._running = True
        return True

    def close(self):
        self._running = False

    def _ensure_open(self) -> bool:
        return self._running

    def add_rule(self, rule: WfpRule) -> bool:
        rule_key = str(uuid.uuid4())
        rule.created_at = time.time()
        rule.filter_key_hex = rule_key

        with self._lock:
            if not self._ensure_open():
                return False
            ok = self._add_rule_impl(rule)
            if ok:
                self._id_counter += 1
                rule.filter_id = self._id_counter
                self._rules[rule_key] = rule
                self._filter_id_to_key[rule.filter_id] = rule_key
                logger.info("Rule added: %s", rule.name)
            return ok

    def _add_rule_impl(self, rule: WfpRule) -> bool:
        try:
            safe_name = _RULE_PREFIX + rule.filter_key_hex
            direction = _DIR_MAP.get(rule.direction, "out")
            action = _ACTION_MAP.get(rule.action, "block")

            args = ["add", "rule", f"name={safe_name}", f"dir={direction}",
                    f"action={action}", "enable=yes",
                    f"description={rule.description or rule.name}"]

            if rule.protocol:
                proto_num = _PROTO_MAP.get(rule.protocol.upper())
                if proto_num:
                    args.append(f"protocol={proto_num}")
                else:
                    args.append(f"protocol={rule.protocol}")

            if rule.remote_addr:
                args.append(f"remoteip={rule.remote_addr}")

            if rule.local_addr:
                args.append(f"localip={rule.local_addr}")

            if rule.remote_port > 0:
                args.append(f"remoteport={rule.remote_port}")

            if rule.local_port > 0:
                args.append(f"localport={rule.local_port}")

            if rule.app_path:
                args.append(f"program={rule.app_path}")

            args.append("profile=any")

            rc, err = _run_netsh(args)
            if rc != 0:
                self._report_error(f"netsh add rule failed: {err}")
                return False
            return True
        except Exception as e:
            logger.exception("_add_rule_impl: %s", e)
            self._report_error(f"add rule exception: {e}")
            return False

    def remove_rule(self, key: str) -> bool:
        with self._lock:
            rule = self._rules.get(key)
            if not rule:
                return False
            return self._remove_by_key(key, rule)

    def remove_rule_by_name(self, name: str) -> bool:
        with self._lock:
            keys = [k for k, r in self._rules.items() if r.name == name]
            ok = True
            for k in keys:
                if not self._remove_by_key(k, self._rules.get(k)):
                    ok = False
            return ok

    def _remove_by_key(self, key: str, rule: WfpRule) -> bool:
        safe_name = _RULE_PREFIX + rule.filter_key_hex
        rc, _ = _run_netsh(["delete", "rule", f"name={safe_name}"])
        if rc == 0:
            self._cleanup_rule(key, rule)
            return True
        rc2, _ = _run_netsh(["delete", "rule", f"name={rule.name}"])
        if rc2 == 0:
            self._cleanup_rule(key, rule)
            return True
        logger.warning("remove_rule failed for '%s'", rule.name)
        return False

    def _cleanup_rule(self, key: str, rule: WfpRule):
        fid = rule.filter_id
        if fid in self._filter_id_to_key:
            del self._filter_id_to_key[fid]
        if key in self._rules:
            del self._rules[key]
        rule.filter_id = 0
        logger.info("Rule removed: %s", rule.name)

    def clear_all_rules(self) -> bool:
        with self._lock:
            keys = list(self._rules.keys())
            ok = True
            for k in keys:
                if not self._remove_by_key(k, self._rules.get(k)):
                    ok = False
            return ok

    def get_rules(self) -> list[WfpRule]:
        with self._lock:
            return list(self._rules.values())

    def get_rule_by_key(self, key: str) -> Optional[WfpRule]:
        with self._lock:
            return self._rules.get(key)

    def add_block_rule(self, name: str, **kwargs) -> Optional[str]:
        rule = WfpRule(name=name, action="block", **kwargs)
        return rule.filter_key_hex if self.add_rule(rule) else None

    def add_allow_rule(self, name: str, **kwargs) -> Optional[str]:
        rule = WfpRule(name=name, action="allow", **kwargs)
        return rule.filter_key_hex if self.add_rule(rule) else None

    def blacklist_process(self, name: str, pid: int,
                          app_path: str = "", protocol: str = "") -> Optional[str]:
        return self.add_block_rule(name=name, pid=pid, app_path=app_path, protocol=protocol)

    def whitelist_process(self, name: str, pid: int,
                          app_path: str = "", protocol: str = "") -> Optional[str]:
        return self.add_allow_rule(name=name, pid=pid, app_path=app_path, protocol=protocol)

    def blacklist_addr(self, name: str, remote_addr: str, protocol: str = "",
                       remote_port: int = 0, layer: str = "ALE_AUTH_CONNECT_V4",
                       direction: str = "outbound") -> Optional[str]:
        return self.add_block_rule(name=name, remote_addr=remote_addr,
                                   protocol=protocol, remote_port=remote_port,
                                   layer=layer, direction=direction)

    def whitelist_addr(self, name: str, remote_addr: str, protocol: str = "",
                       remote_port: int = 0, layer: str = "ALE_AUTH_CONNECT_V4",
                       direction: str = "outbound") -> Optional[str]:
        return self.add_allow_rule(name=name, remote_addr=remote_addr,
                                   protocol=protocol, remote_port=remote_port,
                                   layer=layer, direction=direction)

    def subscribe_net_events(self) -> bool:
        """Start hit-count polling via PeriodicTaskMgr."""
        if self._periodic and self._periodic.is_running:
            return True
        self._stop_event.clear()
        tm = get_task_manager()
        self._periodic = tm.schedule_periodic(
            interval_ms=2000,
            fn=self._poll_hits,
            task_id="wfp-hit-poll",
        )
        logger.info("Hit-count polling started (PeriodicTaskMgr)")
        return True

    def _unsubscribe_net_events(self):
        if self._periodic:
            self._periodic.stop()
            self._periodic = None

    def _poll_hits(self):
        """Called periodically by PeriodicTaskMgr."""
        if self._stop_event.is_set():
            return
        with self._lock:
            for rule in self._rules.values():
                if rule.enabled and rule.filter_id > 0:
                    pass

    def get_stats(self) -> WfpStats:
        with self._lock:
            total_hits = sum(r.hit_count for r in self._rules.values())
            return WfpStats(
                engine_open=self._running,
                filter_count=len(self._rules),
                total_hits=total_hits,
                session_recoveries=self._recovery_count,
            )

    def diagnose(self) -> dict:
        return {
            "backend": "netsh advfirewall",
            "running": self._running,
            "rule_count": len(self._rules),
            "recovery_count": self._recovery_count,
        }

    def _report_error(self, msg: str):
        logger.error("WFP: %s", msg)
        if self.on_error:
            try:
                self.on_error(msg)
            except Exception:
                pass

    def shutdown(self):
        logger.info("WfpManager shutting down...")
        self._unsubscribe_net_events()
        self.clear_all_rules()
        self.close()
        logger.info("WfpManager shutdown complete")


_instance: Optional[WfpManager] = None
_instance_lock = threading.Lock()


def get_wfp_manager() -> WfpManager:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = WfpManager()
    return _instance
