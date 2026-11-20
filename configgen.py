"""Kernel-agnostic-ish config generation for proxy-harvest.

The rest of the program no longer has to know the exact mihomo YAML shape:
`build_config()` owns ports, groups, rules, DNS and credential stripping. A
future sing-box backend can add a sibling builder instead of editing the
harvest/probe code.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

DEFAULT_NAMESERVERS = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]


def clean_proxy(p: Dict[str, Any]) -> Dict[str, Any]:
    """Strip proxy-harvest metadata; keep only kernel fields."""
    return {k: v for k, v in p.items()
            if not k.startswith("_") and k not in ("source", "source_id", "source_url")}


def default_dns_config(servers: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    if isinstance(servers, str):
        names = [servers]
    else:
        names = list(servers or DEFAULT_NAMESERVERS)
    return {
        "enable": True,
        "ipv6": False,
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "nameserver": names,
        "proxy-server-nameserver": names,
    }


def build_config(proxies: List[Dict[str, Any]], port: int, api_port: int,
                 rules: Optional[List[str]] = None, with_groups: bool = False,
                 secret: Optional[str] = None, insecure: bool = False,
                 dns: Optional[Dict[str, Any]] = None,
                 proto_groups: Optional[Dict[str, List[str]]] = None,
                 ) -> Dict[str, Any]:
    proxies = [clean_proxy(p) for p in proxies
               if isinstance(p, dict) and isinstance(p.get("name"), str)
               and p.get("name")]
    if not insecure:
        proxies = [{k: v for k, v in p.items() if k != "skip-cert-verify"}
                   for p in proxies]
    names = [p["name"] for p in proxies]
    groups = [
        {"name": "AUTO", "type": "url-test", "url": "http://cp.cloudflare.com",
         "interval": 300, "tolerance": 100, "proxies": names},
        {"name": "PROXY", "type": "select", "proxies": ["AUTO"] + names},
    ]
    if with_groups:
        for g, types in (proto_groups or {}).items():
            if g == "all":
                continue
            gn = [p["name"] for p in proxies if p["type"] in types]
            if gn:
                groups.append({"name": f"G_{g}", "type": "select",
                               "proxies": ["AUTO"] + gn})
    if not isinstance(rules, (list, tuple)) or not all(isinstance(r, str) for r in rules):
        rules = ["MATCH,PROXY"]
    rules = list(rules) or ["MATCH,PROXY"]
    cfg: Dict[str, Any] = {
        "mixed-port": port,
        "external-controller": f"127.0.0.1:{api_port}",
        "secret": secret if secret is not None else "",
        "allow-lan": False, "mode": "rule", "log-level": "warning",
        "proxies": proxies,
        "proxy-groups": groups,
        "rules": rules or ["MATCH,PROXY"],
    }
    if dns:
        cfg["dns"] = dns
    return cfg


def build_sources_config(proxies: List[Dict[str, Any]],
                         rules: Optional[List[str]] = None,
                         insecure: bool = False,
                         dns: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return build_config(proxies, 2180, 9180, rules, insecure=insecure, dns=dns)
