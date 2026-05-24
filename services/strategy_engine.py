"""Strategy engine — policy-based routing framework.

Allows defining routing policies (e.g., "VPN traffic by destination",
"load balance across interfaces", "failover").

Current implementation is a framework placeholder.
"""
import logging
from dataclasses import dataclass, field
from typing import Optional

from core.utils import RouteEntry

logger = logging.getLogger(__name__)


@dataclass
class RoutingPolicy:
    """A single routing policy rule."""
    name: str
    priority: int = 100
    match_dest: str = ""        # destination prefix (e.g. "10.0.0.0/8")
    match_iface: str = ""       # interface index to match
    match_gateway: str = ""     # gateway to match
    action: str = "route"       # "route", "block", "redirect"
    target_iface: str = ""      # route via this interface
    target_gateway: str = ""    # route via this gateway
    target_metric: int = 0      # metric on target route
    enabled: bool = True


class StrategyEngine:
    """Evaluate and apply routing policies."""

    def __init__(self):
        self.policies: list[RoutingPolicy] = []

    def add_policy(self, policy: RoutingPolicy):
        self.policies.append(policy)
        self.policies.sort(key=lambda p: p.priority)
        logger.info("策略已添加: %s", policy.name)

    def remove_policy(self, name: str):
        self.policies = [p for p in self.policies if p.name != name]
        logger.info("策略已移除: %s", name)

    def evaluate(self, routes: list[RouteEntry]) -> list[RouteEntry]:
        """Apply policies to a route list. Returns modified route list.

        For now, this is a pass-through (framework placeholder).
        Future: integrate with WinDivert / WFP for real traffic steering.
        """
        if not self.policies:
            return routes
        # TODO: implement route modification based on policies
        logger.debug("策略引擎评估 %d 条路由, %d 个策略", len(routes), len(self.policies))
        return routes

    def activate_policy(self, name: str) -> bool:
        """Activate a specific policy (apply routes). Returns success."""
        for p in self.policies:
            if p.name == name and p.enabled:
                logger.info("激活策略: %s", name)
                # TODO: implement actual route changes via winapi_network
                return True
        return False
