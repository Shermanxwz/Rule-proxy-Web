"""Compile imported Mihomo YAML into a local, app-specific proxy listener.

This compiler is data-only. It never fetches imported URLs, executes imported
commands, or changes system proxy, DNS, routes, firewall, or adapter settings.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Any

import yaml


MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_YAML_OBJECTS = 100_000
APP_GROUP = "RuleProxySelected"
APP_LISTENER = "RuleProxyApp"
CAPTURE_MODES = frozenset({"applications", "global"})
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
_RULE_PAYLOAD_COUNTS = {
    "DOMAIN": 1,
    "DOMAIN-SUFFIX": 1,
    "DOMAIN-KEYWORD": 1,
    "DOMAIN-WILDCARD": 1,
    "DOMAIN-REGEX": 1,
    "GEOSITE": 1,
    "IP-CIDR": 1,
    "IP-CIDR6": 1,
    "IP-SUFFIX": 1,
    "IP-ASN": 1,
    "GEOIP": 1,
    "SRC-GEOIP": 1,
    "SRC-IP-ASN": 1,
    "SRC-IP-CIDR": 1,
    "SRC-IP-SUFFIX": 1,
    "DST-PORT": 1,
    "SRC-PORT": 1,
    "IN-PORT": 1,
    "IN-TYPE": 1,
    "IN-USER": 1,
    "IN-NAME": 1,
    "REMATCH-NAME": 1,
    "NETWORK": 1,
    "DSCP": 1,
    "AND": 1,
    "OR": 1,
    "NOT": 1,
    "MATCH": 0,
}
_TARGET_IP_RULES = frozenset({"IP-CIDR", "IP-CIDR6", "IP-SUFFIX", "IP-ASN", "GEOIP"})
_IDENTITY_RULES = frozenset(
    {
        "UID",
        "PROCESS-PATH",
        "PROCESS-PATH-WILDCARD",
        "PROCESS-PATH-REGEX",
        "PROCESS-NAME",
        "PROCESS-NAME-WILDCARD",
        "PROCESS-NAME-REGEX",
    }
)
_RULE_OPTIONS = frozenset({"no-resolve", "src"})
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
        raise ValueError(f"{label}必须是键为字符串的映射。")
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
            raise ValueError("YAML 包含的值过多。")
        if depth > 100:
            raise ValueError("YAML 嵌套层级过深。")
        if not isinstance(item, (dict, list, tuple)):
            return
        ident = id(item)
        if ident in active:
            raise ValueError("不支持递归引用的 YAML 别名。")
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
        raise ValueError(f"{label}的名称不能为空，且不超过 200 个字符。")
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
        raise ValueError(f"{label}缺少有效的服务器地址（公网域名或 IP）。")
    if any(char in server for char in "\x00\r\n/\\@ "):
        raise ValueError(f"{label}的服务器必须是域名或 IP，不能是网址或本地路径。")
    try:
        address = ipaddress.ip_address(server)
    except ValueError:
        host = server.rstrip(".").lower()
        if host in {"localhost", "localhost.localdomain"} or host.endswith((".localhost", ".local", ".home.arpa")):
            raise ValueError(f"{label}不能使用仅在本机或局域网可用的服务器名称。")
        if "." not in host:
            raise ValueError(f"{label}的服务器必须是公网域名或 IP，不能是本地名称。")
        if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part) for part in host.split(".")):
            raise ValueError(f"{label}的服务器地址无效。")
    else:
        if not address.is_global:
            raise ValueError(f"{label}不能使用私有、保留或本地的服务器 IP。")
    return server


def _compile_proxy(raw_proxy: Any, index: int) -> tuple[dict[str, Any], bool]:
    item = dict(_as_map(raw_proxy, f"第 {index + 1} 个代理节点"))
    name = _valid_name(item.get("name"), f"第 {index + 1} 个代理节点")
    if name.upper() in _BUILTIN_NAMES:
        raise ValueError(f"代理节点名称“{name}”与 Mihomo 内置出口或代理组同名。")
    kind = item.get("type")
    if not isinstance(kind, str):
        raise ValueError(f"代理节点“{name}”缺少受支持的类型。")
    kind = kind.lower()
    item["type"] = kind
    if kind in _SPECIAL_TYPES:
        # Keep only semantic placeholders so imported rules/groups referring to
        # them remain valid; these entries never appear in the app selector.
        return {"name": name, "type": kind}, False
    if kind not in _REAL_PROXY_TYPES:
        raise ValueError(f"代理节点“{name}”的类型 {kind} 不受支持。")
    dangerous_key = _contains_dangerous_proxy_key(item, "")
    if dangerous_key:
        raise ValueError(f"代理节点“{name}”使用了不支持的本地或链式设置：{dangerous_key.lstrip('.')}。")
    _validate_proxy_server(item.get("server"), f"代理节点“{name}”")
    port = item.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"代理节点“{name}”的端口必须是 1 到 65535 之间的整数。")
    if kind == "vless":
        uuid = item.get("uuid")
        if not isinstance(uuid, str) or not uuid.strip() or len(uuid) > 200 or "\0" in uuid:
            raise ValueError(f"VLESS 代理节点“{name}”缺少有效的 UUID。")
    return item, True


def _compile_groups(value: Any, proxy_names: set[str]) -> tuple[list[dict[str, Any]], set[str]]:
    if value is None:
        value = []
    if not isinstance(value, list):
        raise ValueError("proxy-groups 必须是列表。")
    groups: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, raw_group in enumerate(value):
        raw = _as_map(raw_group, f"第 {index + 1} 个代理组")
        name = _valid_name(raw.get("name"), f"第 {index + 1} 个代理组")
        if name.upper() in _BUILTIN_NAMES:
            raise ValueError(f"代理组名称“{name}”与 Mihomo 内置出口或代理组同名。")
        if name == APP_GROUP:
            raise ValueError(f"代理组名称“{APP_GROUP}”保留给受保护应用的节点选择器。")
        if name in names or name in proxy_names:
            raise ValueError(f"代理组名称“{name}”与其他代理节点或代理组重名。")
        kind = raw.get("type")
        if not isinstance(kind, str) or kind not in _SAFE_GROUP_TYPES:
            raise ValueError(f"代理组“{name}”的类型不受支持；不支持 relay 和自定义代理组。")
        if "use" in raw:
            raise ValueError(f"代理组“{name}”使用了 providers，此版本不导入。")
        if "interface-name" in raw or "routing-mark" in raw:
            # Remove local network binding controls rather than copying them.
            pass
        group = {key: raw[key] for key in raw if key in _GROUP_KEYS - {"interface-name", "routing-mark"}}
        refs = group.get("proxies", [])
        if refs is None:
            refs = []
        if not isinstance(refs, list) or any(not isinstance(ref, str) for ref in refs):
            raise ValueError(f"代理组“{name}”的 proxies 必须是名称列表。")
        group["proxies"] = list(refs)
        groups.append(group)
        names.add(name)
    return groups, names


def _compile_dns(warnings: list[str], *, capture_mode: str = "applications") -> dict[str, Any]:
    # Destination lookups go through an explicit DoH resolver over the
    # dedicated selector. Only proxy-server-name bootstrap uses system DNS.
    # This config is internal to Mihomo; it never changes OS adapter DNS.
    if capture_mode == "global":
        warnings.append("全局模式接管 DNS；目标解析经所选节点走 DoH。代理服务器域名的初始解析由核心直接使用固定 DoH，是承载连接所需的例外。")
    else:
        warnings.append(
            "目标地址的 DNS 查询经所选节点走 DoH。若代理服务器是域名，只有解析该服务器地址时使用系统 DNS；"
            "不会更改网卡 DNS。"
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
        "proxy-server-nameserver": (["https://1.1.1.1/dns-query#DIRECT"]
                                    if capture_mode == "global" else ["system"]),
    }


def _validate_rule_set_usage(rules: list[str]) -> None:
    if any(re.match(r"\s*RULE-SET\s*,", rule, re.IGNORECASE) for rule in rules):
        raise ValueError("RULE-SET 规则需要 rule-providers，此版本不导入。")
    if any(re.match(r"\s*SUB-RULE\s*,|\s*SCRIPT\s*,", rule, re.IGNORECASE) for rule in rules):
        raise ValueError("此配置使用了不支持的 SCRIPT 或 SUB-RULE 规则。")


def _split_rule_fields(rule: str, index: int) -> list[str]:
    """Split ordinary rules, keeping commas inside logical-rule parentheses."""
    first = rule.split(",", 1)[0].strip().upper()
    if first not in {"AND", "OR", "NOT"}:
        return [part.strip() for part in rule.split(",")]

    fields: list[str] = []
    start = 0
    depth = 0
    for position, char in enumerate(rule):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth < 0:
                raise ValueError(f"第 {index + 1} 条规则的括号不匹配。")
        elif char == "," and depth == 0:
            fields.append(rule[start:position].strip())
            start = position + 1
    if depth != 0:
        raise ValueError(f"第 {index + 1} 条规则的括号不匹配。")
    fields.append(rule[start:].strip())
    return fields


def _compile_rules(value: Any) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(rule, str) or not rule.strip() for rule in value):
        raise ValueError("rules 必须是由非空规则字符串组成的列表。")
    _validate_rule_set_usage(value)
    compiled: list[str] = []
    has_match = False
    for index, raw_rule in enumerate(value):
        fields = _split_rule_fields(raw_rule.strip(), index)
        if not fields or not fields[0]:
            raise ValueError(f"第 {index + 1} 条规则缺少规则类型。")
        kind = fields[0].upper()
        if kind in _IDENTITY_RULES:
            raise ValueError(
                f"第 {index + 1} 条规则使用了 {kind}；经过本地中继后无法识别原始应用，不支持按进程或 UID 分流。"
            )
        if kind not in _RULE_PAYLOAD_COUNTS:
            raise ValueError(f"第 {index + 1} 条规则的类型 {fields[0]} 不受支持。")
        fields[0] = kind
        payload_count = _RULE_PAYLOAD_COUNTS[kind]
        action_index = 1 + payload_count
        if len(fields) <= action_index or any(not field for field in fields):
            raise ValueError(f"第 {index + 1} 条规则的条件或动作不完整。")
        action = fields[action_index]
        options = fields[action_index + 1 :]
        if any(option.lower() not in _RULE_OPTIONS for option in options):
            raise ValueError(f"第 {index + 1} 条规则带有不支持或含义不明确的结尾选项。")
        if len({option.lower() for option in options}) != len(options):
            raise ValueError(f"第 {index + 1} 条规则重复了结尾选项。")
        if options and kind not in _TARGET_IP_RULES:
            raise ValueError(f"第 {index + 1} 条规则在 {kind} 上使用了仅适用于 IP 规则的选项。")
        if kind in {"AND", "OR", "NOT"}:
            expression = fields[1]
            if not expression.startswith("(") or not expression.endswith(")"):
                raise ValueError(f"第 {index + 1} 条规则的逻辑表达式无效。")
            if re.search(r"\(\s*(?:UID|PROCESS-[A-Z-]+)\s*,", expression, re.IGNORECASE):
                raise ValueError(
                    f"第 {index + 1} 条规则嵌套了进程或 UID 条件；经过本地中继后无法识别原始应用。"
                )
        if action.upper() in {"REJECT", "REJECT-DROP"}:
            fields[action_index] = action.upper()
        else:
            fields[action_index] = APP_GROUP
        compiled.append(",".join(fields))
        has_match = has_match or kind == "MATCH"
    if not has_match:
        compiled.append(f"MATCH,{APP_GROUP}")
    return compiled


def compile_config(
    source: str,
    *,
    mixed_port: int = 10809,
    controller_port: int = 19097,
    secret: str,
    selected_node: str | None = None,
    allow_udp: bool = False,
    capture_mode: str = "applications",
) -> CompiledConfig:
    """Compile an imported config for one explicitly proxied app listener."""
    mixed_port = _port(mixed_port, "mixed_port")
    if not isinstance(allow_udp, bool):
        raise ValueError("allow_udp must be a boolean")
    if not isinstance(capture_mode, str) or capture_mode not in CAPTURE_MODES:
        raise ValueError("接管模式必须是 applications 或 global。")
    controller_port = _port(controller_port, "controller_port")
    if mixed_port == controller_port:
        raise ValueError("mixed_port must differ from controller_port")
    if not isinstance(secret, str) or not secret.strip() or len(secret) > 512 or "\0" in secret:
        raise ValueError("secret must be a non-empty string of at most 512 characters")
    if not isinstance(source, str):
        raise ValueError("YAML source must be text")
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError("YAML 超过 2 MiB 的导入上限。")
    try:
        imported = yaml.safe_load(source)
    except (yaml.YAMLError, RecursionError, UnicodeError) as exc:
        raise ValueError("无法安全解析这个 YAML。") from exc
    if not isinstance(imported, dict):
        raise ValueError("YAML 顶层必须是映射。")
    try:
        _safe_yaml_tree(imported)
    except RecursionError as exc:
        raise ValueError("YAML 嵌套层级过深。") from exc
    imported = _as_map(imported, "YAML 顶层")

    unsupported = sorted(_UNSUPPORTED_SEMANTICS.intersection(imported))
    if unsupported:
        raise ValueError("此配置使用了不支持的本地或脚本功能：" + "、".join(unsupported) + "。")
    if imported.get("listeners"):
        # The user's source may contain TUN/redirect/TProxy listeners. They
        # are deliberately discarded; only the generated loopback mixed
        # listener is emitted below.
        warnings = ["导入的监听器已丢弃；接管入口由当前模式生成。"]
    else:
        warnings = []
    for provider_key in ("proxy-providers", "rule-providers"):
        if imported.get(provider_key):
            raise ValueError(f"此版本不支持 {provider_key}。")

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
        warnings.append("以下 Mihomo 设置不在应用专用的安全范围内，已忽略：" + "、".join(dropped) + "。")
    if "dns" in imported:
        warnings.append("导入的 DNS 设置已替换为经所选节点的 DoH 配置。")

    raw_proxies = imported.get("proxies", [])
    if not isinstance(raw_proxies, list):
        raise ValueError("proxies 必须是列表。")
    proxies: list[dict[str, Any]] = []
    selectable: list[dict[str, str]] = []
    proxy_names: set[str] = set()
    for index, raw_proxy in enumerate(raw_proxies):
        proxy, is_real = _compile_proxy(raw_proxy, index)
        name = proxy["name"]
        if name in proxy_names:
            raise ValueError(f"代理节点名称“{name}”重复。")
        if name == APP_GROUP:
            raise ValueError(f"代理节点名称“{APP_GROUP}”保留给受保护应用的节点选择器。")
        proxy_names.add(name)
        proxies.append(proxy)
        if is_real:
            selectable.append({"name": name, "type": proxy["type"]})
    if not selectable:
        raise ValueError("配置中至少需要一个受支持的真实代理节点；DIRECT、DNS 等特殊出口不能选择。")

    groups, group_names = _compile_groups(imported.get("proxy-groups"), proxy_names)
    if APP_LISTENER in proxy_names or APP_LISTENER in group_names:
        raise ValueError(f"名称“{APP_LISTENER}”保留给生成的本机入口。")
    if selected_node is None:
        selected_node = selectable[0]["name"]
    if not isinstance(selected_node, str) or selected_node not in {node["name"] for node in selectable}:
        raise ValueError("所选节点必须是配置中受支持的真实代理节点。")

    # Verify static group references while allowing the documented built-in
    # policy outbounds used by ordinary imported rules.
    allowed_refs = proxy_names | group_names | {
        "DIRECT",
        "REJECT",
        "REJECT-DROP",
        "PASS",
        "PASS-RULE",
        "COMPATIBLE",
        "GLOBAL",
    }
    for group in groups:
        missing = [ref for ref in group.get("proxies", []) if ref not in allowed_refs]
        if missing:
            raise ValueError(f"代理组“{group['name']}”引用了不存在的代理节点或代理组。")

    rules = _compile_rules(imported.get("rules", []))

    app_group = {
        "name": APP_GROUP,
        "type": "select",
        "proxies": [selected_node, *[node["name"] for node in selectable if node["name"] != selected_node]],
        "default-selected": selected_node,
    }
    # The generated selector contains only real proxy leaves. Every imported
    # forwarding action has been rewritten to this selector; reject actions
    # remain reject actions.
    listener = {
        "name": APP_LISTENER,
        "type": "mixed",
        "listen": "127.0.0.1",
        "port": mixed_port,
        "udp": allow_udp or capture_mode == "global",
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
        "dns": _compile_dns(warnings, capture_mode=capture_mode),
        "proxies": proxies,
        "proxy-groups": [*groups, app_group],
        "rules": list(rules),
    }
    if capture_mode == "global":
        config["ipv6"] = True
        config["tun"] = {
            "enable": True,
            "device": "RuleProxyTun",
            "stack": "mips",
            "auto-route": True,
            "strict-route": True,
            "auto-detect-interface": True,
            "dns-hijack": ["any:53", "tcp://any:53"],
            "inet4-address": ["198.18.0.1/30"],
            "inet6-address": ["fdfe:dcba:8879::1/126"],
            "mtu": 1500,
        }
        warnings.append("全局接管覆盖整台设备，由独立权限组件管理 TUN；停止后恢复本工具拥有的网络设置。")
    text = yaml.safe_dump(config, allow_unicode=True, sort_keys=False, default_flow_style=False)
    return CompiledConfig(
        text=text,
        config=config,
        nodes=selectable,
        primary_group=APP_GROUP,
        selected_node=selected_node,
        warnings=warnings,
    )
