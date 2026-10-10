"""Compile imported Mihomo YAML into a local, app-specific proxy listener.

This compiler is data-only. It never fetches imported URLs, executes imported
commands, or changes system proxy, DNS, routes, firewall, or adapter settings.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

import yaml


MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_YAML_OBJECTS = 100_000
APP_GROUP = "RuleProxySelected"
APP_LISTENER = "RuleProxyApp"
_UNSUPPORTED_SEMANTICS = frozenset({"script", "sub-rules", "tunnels"})
_SPECIAL_TYPES = frozenset({"direct", "dns", "reject", "reject-drop", "pass", "compatible"})
# Supported real outbound proxy protocols. Special Mihomo policy outbounds are
# deliberately not selectable in the app's generated group.
_REAL_PROXY_TYPES = frozenset(
    {
        "anytls",
        "http",
        "hysteria",
        "hysteria2",
        "mieru",
        "shadowtls",
        "snell",
        "socks5",
        "ssh",
        "ss",
        "ssr",
        "trojan",
        "tuic",
        "vless",
        "vmess",
        "wireguard",
    }
)
_SAFE_GROUP_TYPES = frozenset({"select", "url-test", "fallback", "load-balance"})
_BUILTIN_NAMES = frozenset(
    {
        "DIRECT",
        "REJECT",
        "REJECT-DROP",
        "PASS",
        "PASS-RULE",
        "COMPATIBLE",
        "GLOBAL",
    }
)
_GROUP_KEYS = frozenset(
    {
        "name",
        "type",
        "proxies",
        "url",
        "interval",
        "lazy",
        "tolerance",
        "strategy",
        "disable-udp",
        "expected-status",
        "hidden",
        "icon",
        "filter",
        "exclude-filter",
        "exclude-type",
        "include-all",
        "include-all-proxies",
        "default-selected",
        "max-failed-times",
        "timeout",
        "interface-name",  # stripped below
        "routing-mark",  # stripped below
    }
)
_DANGEROUS_PROXY_KEYS = frozenset(
    {
        "dialer-proxy",
        "interface-name",
        "routing-mark",
        "socket",
        "socket-path",
        "exec",
        "command",
        "script",
        # Shadowsocks plugins are external local executables selected by the
        # imported config, so this app-only importer does not allow them.
        "plugin",
        "plugin-opts",
        "client-cert-file",
        "client-key-file",
        "certificate-file",
        "private-key-file",
        "certificate",
        "private-key",
        "client-cert",
        "client-key",
        "ca-file",
        "file",
    }
)


@dataclass(frozen=True)
class CompiledConfig:
    text: str
    config: dict[str, Any]
    nodes: list[dict[str, str]]
    primary_group: str
    selected_node: str
    warnings: list[str]


def _as_map(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be a mapping with string keys")
    return value


def _safe_yaml_tree(value: Any) -> None:
    """Reject recursive aliases and pathological object graphs after safe_load."""
    active: set[int] = set()
    visited: set[int] = set()
    count = 0

    def walk(item: Any, depth: int) -> None:
        nonlocal count
        count += 1
        if count > MAX_YAML_OBJECTS:
            raise ValueError("YAML contains too many values")
        if depth > 100:
            raise ValueError("YAML nesting is too deep")
        if not isinstance(item, (dict, list, tuple)):
            return
        ident = id(item)
        if ident in active:
            raise ValueError("recursive YAML aliases are not supported")
        if ident in visited:
            return
        active.add(ident)
        if isinstance(item, dict):
            for key, child in item.items():
                walk(key, depth + 1)
                walk(child, depth + 1)
        else:
            for child in item:
                walk(child, depth + 1)
        active.remove(ident)
        visited.add(ident)

    walk(value, 0)


def _port(value: int, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1024 < value < 65536:
        raise ValueError(f"{label} must be an integer from 1025 through 65535")
    return value


def _valid_name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 200 or "\0" in value:
        raise ValueError(f"{label} must be a non-empty string of at most 200 characters")
    return value


def _contains_dangerous_proxy_key(value: Any, location: str = "proxy") -> str | None:
    if isinstance(value, dict):
        for key, child in value.items():
            if isinstance(key, str) and key.lower() in _DANGEROUS_PROXY_KEYS:
                return f"{location}.{key}"
            if isinstance(key, str) and key.lower() == "path":
                parent = location.lower()
                allowed_transport = (".ws-opts", ".grpc-opts", ".h2-opts", ".http-opts", ".xhttp-opts")
                if not parent.endswith(allowed_transport):
                    return f"{location}.{key}"
            found = _contains_dangerous_proxy_key(child, f"{location}.{key}")
            if found:
                return found
    elif isinstance(value, list):
        for index, child in enumerate(value):
            found = _contains_dangerous_proxy_key(child, f"{location}[{index}]")
            if found:
                return found
    return None


def _validate_proxy_server(server: Any, label: str) -> str:
    if not isinstance(server, str) or not server or len(server) > 253:
        raise ValueError(f"{label} must have a valid public server hostname or IP")
    if any(char in server for char in "\x00\r\n/\\@ "):
        raise ValueError(f"{label} server must be a hostname or IP, not a URL or local path")
    try:
        address = ipaddress.ip_address(server)
    except ValueError:
        host = server.rstrip(".").lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".home.arpa")):
            raise ValueError(f"{label} cannot use a local-only server hostname")
        if "." not in host:
            raise ValueError(f"{label} server must be a public hostname or IP, not a local name")
        if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part) for part in host.split(".")):
            raise ValueError(f"{label} server must be a valid hostname or IP")
    else:
        if not address.is_global:
            raise ValueError(f"{label} cannot use a private, reserved, or local server IP")
    return server


def _compile_proxy(raw_proxy: Any, index: int) -> tuple[dict[str, Any], bool]:
    item = dict(_as_map(raw_proxy, f"proxy at index {index}"))
    name = _valid_name(item.get("name"), f"proxy at index {index} name")
    if name.upper() in _BUILTIN_NAMES:
        raise ValueError(f"proxy name {name!r} conflicts with a Mihomo built-in outbound/group")
    kind = item.get("type")
    if not isinstance(kind, str):
        raise ValueError(f"proxy {name!r} needs a supported type")
    kind = kind.lower()
    item["type"] = kind
    if kind in _SPECIAL_TYPES:
        # Keep only semantic placeholders so imported rules/groups referring to
        # them remain valid; these entries never appear in the app selector.
        return {"name": name, "type": kind}, False
    if kind not in _REAL_PROXY_TYPES:
        raise ValueError(f"proxy {name!r} uses unsupported type {kind!r}")
    dangerous_key = _contains_dangerous_proxy_key(item, f"proxy {name!r}")
    if dangerous_key:
        raise ValueError(f"proxy {name!r} uses unsupported local/chain setting {dangerous_key}")
    _validate_proxy_server(item.get("server"), f"proxy {name!r}")
    port = item.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"proxy {name!r} port must be an integer from 1 through 65535")
    if kind == "vless":
        uuid = item.get("uuid")
        if not isinstance(uuid, str) or not uuid.strip() or len(uuid) > 200 or "\0" in uuid:
            raise ValueError(f"VLESS proxy {name!r} needs a valid UUID")
    return item, True


def _compile_groups(value: Any, proxy_names: set[str]) -> tuple[list[dict[str, Any]], set[str]]:
    if value is None:
        value = []
    if not isinstance(value, list):
        raise ValueError("proxy-groups must be a list")
    groups: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, raw_group in enumerate(value):
        raw = _as_map(raw_group, f"proxy group at index {index}")
        name = _valid_name(raw.get("name"), f"proxy group at index {index} name")
        if name.upper() in _BUILTIN_NAMES:
            raise ValueError(f"proxy group name {name!r} conflicts with a Mihomo built-in outbound/group")
        if name == APP_GROUP:
            raise ValueError(f"proxy group name {APP_GROUP!r} is reserved for the protected app selector")
        if name in names or name in proxy_names:
            raise ValueError(f"proxy group name {name!r} conflicts with another proxy/group")
        kind = raw.get("type")
        if not isinstance(kind, str) or kind not in _SAFE_GROUP_TYPES:
            raise ValueError(f"proxy group {name!r} has unsupported type; relay and custom groups are unavailable")
        if "use" in raw:
            raise ValueError(f"proxy group {name!r} uses providers, which this version does not import")
        if "interface-name" in raw or "routing-mark" in raw:
            # Remove local network binding controls rather than copying them.
            pass
        group = {key: raw[key] for key in raw if key in _GROUP_KEYS - {"interface-name", "routing-mark"}}
        refs = group.get("proxies", [])
        if refs is None:
            refs = []
        if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
            raise ValueError(f"proxy group {name!r} proxies must be a list of names")
        group["proxies"] = list(refs)
        groups.append(group)
        names.add(name)
    return groups, names


def _compile_dns(warnings: list[str]) -> dict[str, Any]:
    # Destination lookups go through an explicit DoH resolver over the
    # dedicated selector. Only proxy-server-name bootstrap uses system DNS.
    # This config is internal to Mihomo; it never changes OS adapter DNS.
    warnings.append(
        "Destination DNS uses DoH through the selected proxy. If a proxy server is a hostname, "
        "only that server's bootstrap lookup uses the app's system resolver; no adapter DNS is changed."
    )
    return {
        "enable": True,
        "ipv6": True,
        "enhanced-mode": "redir-host",
        "respect-rules": False,
        "use-hosts": False,
        "use-system-hosts": False,
        "default-nameserver": ["1.1.1.1"],
        "nameserver": [f"https://1.1.1.1/dns-query#{APP_GROUP}"],
        "proxy-server-nameserver": ["system"],
    }


def _validate_rule_set_usage(rules: list[str]) -> None:
    if any(re.match(r"\s*RULE-SET\s*,", rule, re.IGNORECASE) for rule in rules):
        raise ValueError("RULE-SET rules need rule-providers, which this version does not import")
    if any(re.match(r"\s*SUB-RULE\s*,|\s*SCRIPT\s*,", rule, re.IGNORECASE) for rule in rules):
        raise ValueError("This config uses unsupported SCRIPT or SUB-RULE rule semantics")


def compile_config(
    source: str,
    *,
    mixed_port: int = 10809,
    controller_port: int = 19097,
    secret: str,
    selected_node: str | None = None,
) -> CompiledConfig:
    """Compile an imported config for one explicitly proxied app listener."""
    mixed_port = _port(mixed_port, "mixed_port")
    controller_port = _port(controller_port, "controller_port")
    if mixed_port == controller_port:
        raise ValueError("mixed_port must differ from controller_port")
    if not isinstance(secret, str) or not secret.strip() or len(secret) > 512 or "\0" in secret:
        raise ValueError("secret must be a non-empty string of at most 512 characters")
    if not isinstance(source, str):
        raise ValueError("YAML source must be text")
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("YAML source exceeds the 2 MiB import limit")
    try:
        imported = yaml.safe_load(source)
    except (yaml.YAMLError, RecursionError, UnicodeError) as exc:
        raise ValueError("YAML could not be parsed safely") from exc
    if not isinstance(imported, dict):
        raise ValueError("YAML document must contain a top-level mapping")
    try:
        _safe_yaml_tree(imported)
    except RecursionError as exc:
        raise ValueError("YAML nesting is too deep") from exc
    imported = _as_map(imported, "YAML document")

    unsupported = sorted(_UNSUPPORTED_SEMANTICS.intersection(imported))
    if unsupported:
        raise ValueError("This config uses unsupported local/script semantics: " + ", ".join(unsupported))
    if imported.get("listeners"):
        # The user's source may contain TUN/redirect/TProxy listeners. They
        # are deliberately discarded; only the generated loopback mixed
        # listener is emitted below.
        warnings = ["Imported listeners were discarded; only the generated loopback app listener is enabled."]
    else:
        warnings = []
    for provider_key in ("proxy-providers", "rule-providers"):
        if imported.get(provider_key):
            raise ValueError(f"{provider_key} are not supported by this version")

    known_top = {
        "proxies",
        "proxy-groups",
        "rules",
        "dns",
        "proxy-providers",
        "rule-providers",
        "tun",
        "listeners",
        *_UNSUPPORTED_SEMANTICS,
    }
    dropped = sorted(set(imported) - known_top)
    if dropped:
        warnings.append("Ignored imported Mihomo settings outside the app-only safe subset: " + ", ".join(dropped))
    if "dns" in imported:
        warnings.append("Imported DNS settings were replaced by the app-only selected-proxy DoH configuration.")

    raw_proxies = imported.get("proxies", [])
    if not isinstance(raw_proxies, list):
        raise ValueError("proxies must be a list")
    proxies: list[dict[str, Any]] = []
    selectable: list[dict[str, str]] = []
    proxy_names: set[str] = set()
    for index, raw_proxy in enumerate(raw_proxies):
        proxy, is_real = _compile_proxy(raw_proxy, index)
        name = proxy["name"]
        if name in proxy_names:
            raise ValueError(f"duplicate proxy name {name!r}")
        if name == APP_GROUP:
            raise ValueError(f"proxy name {APP_GROUP!r} is reserved for the protected app selector")
        proxy_names.add(name)
        proxies.append(proxy)
        if is_real:
            selectable.append({"name": name, "type": proxy["type"]})
    if not selectable:
        raise ValueError("import must contain at least one supported real proxy node; DIRECT/DNS/special exits cannot be selected")

    groups, group_names = _compile_groups(imported.get("proxy-groups"), proxy_names)
    if APP_LISTENER in proxy_names or APP_LISTENER in group_names:
        raise ValueError(f"{APP_LISTENER!r} is reserved for the generated local listener")
    if selected_node is None:
        selected_node = selectable[0]["name"]
    if not isinstance(selected_node, str) or selected_node not in {node["name"] for node in selectable}:
        raise ValueError("selected_node must name one of the imported supported real proxy nodes")

    # Verify static group references while allowing the documented built-in
    # policy outbounds used by ordinary imported rules.
    allowed_refs = proxy_names | group_names | {
        "DIRECT",
        "REJECT",
        "REJECT-DROP",
        "PASS",
        "COMPATIBLE",
    }
    for group in groups:
        missing = [ref for ref in group.get("proxies", []) if ref not in allowed_refs]
        if missing:
            raise ValueError(f"proxy group {group['name']!r} references an unavailable proxy or group")

    rules = imported.get("rules", [])
    if not isinstance(rules, list) or any(not isinstance(rule, str) or not rule.strip() for rule in rules):
        raise ValueError("rules must be a list of non-empty rule strings")
    _validate_rule_set_usage(rules)

    app_group = {
        "name": APP_GROUP,
        "type": "select",
        "proxies": [selected_node, *[node["name"] for node in selectable if node["name"] != selected_node]],
        "default-selected": selected_node,
    }
    # This listener's explicit proxy field bypasses imported rule actions.
    # Its group contains only real proxy leaves, never DIRECT/DNS/group names.
    listener = {
        "name": APP_LISTENER,
        "type": "mixed",
        "listen": "127.0.0.1",
        "port": mixed_port,
        "udp": False,
        "proxy": APP_GROUP,
    }
    config: dict[str, Any] = {
        "mixed-port": 0,
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "external-controller": f"127.0.0.1:{controller_port}",
        "secret": secret,
        "tun": {"enable": False},
        "listeners": [listener],
        "dns": _compile_dns(warnings),
        "proxies": proxies,
        "proxy-groups": [*groups, app_group],
        "rules": list(rules),
    }
    text = yaml.safe_dump(config, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return CompiledConfig(
        text=text,
        config=config,
        nodes=selectable,
        primary_group=APP_GROUP,
        selected_node=selected_node,
        warnings=warnings,
    )
