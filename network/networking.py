"""Network data access layer — all reads go through CacheManager.

GUI code MUST use this module, never services.winapi_network directly.
This ensures:
- Cache hits avoid redundant WinAPI calls
- Cache invalidation is respected
- Cache stats are accurate
"""

import json
import logging

from core import config
from core.utils import RouteEntry, mask_to_cidr
from services.cache_manager import get_cache
from services.winapi_network import (
    get_routes as _win_get_routes,
    get_interfaces as _win_get_interfaces,
    get_interface_ipv4_info as _win_get_iface_info_v4,
    get_interface_ipv6_info as _win_get_iface_info_v6,
    add_route as _win_add_route,
    delete_route as _win_delete_route,
    set_route_metric as _win_set_metric,
    get_default_route as _win_get_default,
    AF_INET,
    AF_INET6,
    AF_UNSPEC,
)

logger = logging.getLogger(__name__)


# ======================== Cached reads ========================

def get_routes(address_family=AF_UNSPEC) -> list:
    """Read routes from CacheManager. Filters by address_family."""
    cache = get_cache()
    routes = cache.get("routes")
    if routes is None:
        return []
    if address_family == AF_UNSPEC:
        return routes
    return [r for r in routes if r.address_family == address_family]


def get_interfaces():
    """Read interfaces from CacheManager."""
    cache = get_cache()
    return cache.get("interfaces") or []


def get_interface_ipv4_info():
    """Read IPv4 interface info from CacheManager."""
    cache = get_cache()
    return cache.get("iface_ipv4_info") or {}


def get_interface_ipv6_info():
    """Read IPv6 interface info from CacheManager (uncached, rare)."""
    return _win_get_iface_info_v6()


def get_default_route(address_family=AF_INET):
    """Get lowest-metric default route from cached routes (no extra WinAPI)."""
    routes = get_routes(address_family)
    default_routes = [r for r in routes if r.is_default]
    if not default_routes:
        return None
    return min(default_routes, key=lambda x: int(x.metric))


def route_exists(dest, mask_or_plen, iface, address_family=AF_INET):
    """Check route existence from cached routes."""
    for r in get_routes(address_family):
        if r.destination == dest and r.interface == iface:
            if address_family == AF_INET6:
                if r.prefix_length == int(mask_or_plen):
                    return True
            elif r.mask == mask_or_plen:
                return True
    return False


# ======================== Write operations ========================
# These modify system state, then invalidate cache.

def add_route(dest, mask_or_plen, gw, iface, address_family=AF_INET, persistent=False):
    ok, err = _win_add_route(dest, mask_or_plen, gw, iface, address_family=address_family)
    if ok:
        logger.info("添加路由成功 | dest=%s iface=%s gw=%s family=%d", dest, iface, gw, address_family)
        get_cache().invalidate("routes")
        return _result_ok()
    logger.error("添加路由失败 | dest=%s iface=%s gw=%s reason=%s", dest, iface, gw, err)
    return _result_err(err)


def delete_route(dest, mask_or_plen, gw, iface, address_family=AF_INET):
    ok, err = _win_delete_route(dest, mask_or_plen, gw, iface, address_family=address_family)
    if ok:
        logger.info("删除路由成功 | dest=%s iface=%s", dest, iface)
        get_cache().invalidate("routes")
        return _result_ok()
    logger.error("删除路由失败 | dest=%s iface=%s reason=%s", dest, iface, err)
    return _result_err(err)


def set_route_metric(dest, mask_or_plen, gw, iface, metric, address_family=AF_INET):
    if not (config.METRIC_MIN <= metric <= config.METRIC_MAX):
        return _result_err(f"Metric 必须在 {config.METRIC_MIN}-{config.METRIC_MAX} 之间")

    ok, err = _win_set_metric(dest, mask_or_plen, gw, iface, metric, address_family=address_family)
    if ok:
        logger.info("设置 metric 成功 | dest=%s iface=%s metric=%d", dest, iface, metric)
        get_cache().invalidate("routes")
        return _result_ok()
    logger.error("设置 metric 失败 | dest=%s iface=%s reason=%s", dest, iface, err)
    return _result_err(err)


# ======================== Bulk operations ========================

def export_routes_to_dict():
    routes = get_routes(AF_UNSPEC)
    logger.info("导出配置 | 共 %d 条路由", len(routes))
    return {
        "version": 2,
        "routes": [
            {
                "destination": r.destination,
                "mask": r.mask,
                "gateway": r.gateway,
                "interface": r.interface,
                "metric": int(r.metric) if r.metric and r.metric.isdigit() else 256,
                "prefix_length": r.prefix_length,
                "address_family": r.address_family,
                "is_ipv6": r.is_ipv6,
            }
            for r in routes
        ],
    }


def import_routes_from_dict(data, mode="skip"):
    route_list = data.get("routes", [])
    if not isinstance(route_list, list):
        return {"success": 0, "failed": 1, "errors": ["无效的 JSON 格式：routes 应为数组"]}

    results = {"success": 0, "failed": 0, "errors": []}
    logger.info("导入配置 | mode=%s 路由数=%d", mode, len(route_list))

    if mode == "restore":
        current = _win_get_routes(AF_UNSPEC)
        logger.info("导入配置 | 清空现有 %d 条路由", len(current))
        for r in current:
            _win_delete_route(r.destination, r.mask if not r.is_ipv6 else r.prefix_length,
                              r.gateway, r.interface, address_family=r.address_family)

    for i, rd in enumerate(route_list):
        dest = rd.get("destination", "")
        gw = rd.get("gateway", "0.0.0.0")
        iface = rd.get("interface", "")
        metric = rd.get("metric", 256)
        address_family = rd.get("address_family", AF_INET)
        is_ipv6 = rd.get("is_ipv6", False) or (address_family == AF_INET6)

        if not dest or not iface:
            results["failed"] += 1
            results["errors"].append(f"第 {i+1} 条路由: 缺少必要字段")
            continue

        if is_ipv6:
            plen = rd.get("prefix_length", 64)
            mask_or_plen = plen
        else:
            mask_or_plen = rd.get("mask", "255.255.255.0")
            if mask_to_cidr(mask_or_plen) is None:
                results["failed"] += 1
                results["errors"].append(f"第 {i+1} 条路由 ({dest}/{mask_or_plen}): 无效的子网掩码")
                continue

        if mode == "skip":
            if route_exists(dest, mask_or_plen, iface, address_family):
                continue
        elif mode == "overwrite":
            if route_exists(dest, mask_or_plen, iface, address_family):
                _win_delete_route(dest, mask_or_plen, gw, iface, address_family=address_family)

        ok, err = _win_add_route(dest, mask_or_plen, gw, iface, address_family=address_family)
        if not ok:
            results["failed"] += 1
            results["errors"].append(f"第 {i+1} 条路由 ({dest}): {err}")
            continue

        if isinstance(metric, int) and config.METRIC_MIN <= metric <= config.METRIC_MAX:
            _win_set_metric(dest, mask_or_plen, gw, iface, metric, address_family=address_family)

        results["success"] += 1

    get_cache().invalidate("routes")
    logger.info("导入配置结果 | success=%d failed=%d errors=%d",
                results["success"], results["failed"], len(results["errors"]))
    return results


def do_set_default_route(iface_idx_str: str, address_family=AF_INET):
    """Switch default route priority to a specific interface."""
    current_defaults = [r for r in get_routes(address_family) if r.is_default]
    if not current_defaults:
        label = "IPv4" if address_family == AF_INET else "IPv6"
        raise RuntimeError(f"当前路由表中没有{label}默认路由，无法切换优先级。")

    logger.info("切换默认路由 | 目标接口=%s 当前默认路由数=%d", iface_idx_str, len(current_defaults))
    details = []
    success = True

    for route in current_defaults:
        if route.gateway == "On-link":
            details.append(f"接口 {route.interface} 的默认路由为 On-link，跳过修改。")
            continue

        if route.interface == iface_idx_str:
            new_metric = config.DEFAULT_METRIC_LOW
        else:
            new_metric = config.DEFAULT_METRIC_HIGH

        if route.is_ipv6:
            mask_or_plen = route.prefix_length
        else:
            mask_or_plen = route.mask

        ok, err = _win_set_metric(
            route.destination, mask_or_plen, route.gateway, route.interface,
            new_metric, address_family=route.address_family,
        )
        if ok:
            details.append(
                f"接口 {route.interface} (网关 {route.gateway}) metric 已设为 {new_metric}"
            )
        else:
            success = False
            details.append(
                f"修改接口 {route.interface} (网关 {route.gateway}) metric 失败: {err}"
            )

    get_cache().invalidate("routes")

    if not success:
        raise RuntimeError("部分接口修改失败：\n" + "\n".join(details))

    return "\n".join(details)


def _result_ok():
    class _R:
        returncode = 0
        stdout = ""
        stderr = ""
    return _R()


def _result_err(msg):
    class _R:
        returncode = 1
        stdout = ""
        stderr = msg
    return _R()
