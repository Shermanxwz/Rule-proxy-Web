"""Data-only ProxyBridge profile builder for the Windows/WFP feasibility gate.

This module never starts ProxyBridge or an application. A ProxyBridge PROXY rule
is not a security boundary: its engine can return DIRECT when process lookup or
proxy configuration fails. The panel must keep using its existing strict MXC
runtime until a separately enforced and *live tested* WFP design exists.
"""

from __future__ import annotations

from pathlib import PureWindowsPath
from typing import Any, Sequence


MAX_RULES = 256  # ProxyBridge v4.1.1 CLI limit; two rules per executable.


def _port(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1025 <= value <= 65535:
        raise ValueError("Mihomo listener port must be an integer from 1025 through 65535")
    return value


def _process_name(executable: str) -> str:
    if not isinstance(executable, str) or not executable or "\0" in executable:
        raise ValueError("an absolute Windows executable path is required")
    path = PureWindowsPath(executable)
    if not path.is_absolute() or len(path.drive) != 2 or path.drive[1] != ":" or path.suffix.lower() != ".exe":
        raise ValueError("an absolute Windows .exe path is required")
    name = path.name
    if any(char in name for char in "*?;") or len(name.encode("utf-8")) >= 256:
        raise ValueError("ProxyBridge cannot safely represent this executable name")
    if name.casefold() in {"proxybridge.exe", "proxybridge_cli.exe", "mihomo.exe"}:
        raise ValueError("a proxy or core executable cannot be a protected target")
    return name


def candidate_profile(executables: Sequence[str], mihomo_port: int) -> dict[str, Any]:
    """Compile explicit TCP proxy / UDP block rules for a *candidate* experiment.

    ProxyBridge matches by basename, not a unique launched process or its
    descendant tree. The caller has to discover every child executable. This
    function is deliberately not wired to the panel's launch path.
    """
    port = _port(mihomo_port)
    if not isinstance(executables, (list, tuple)) or not 1 <= len(executables) <= MAX_RULES // 2:
        raise ValueError("provide 1 through 128 explicit executable paths")
    names = [_process_name(value) for value in executables]
    if len({name.casefold() for name in names}) != len(names):
        raise ValueError("duplicate process basenames cannot be isolated independently")

    rules: list[dict[str, Any]] = []
    for name in names:
        for protocol, action in (("TCP", "PROXY"), ("UDP", "BLOCK")):
            rules.append({
                "ProcessName": name,
                "TargetHosts": "*",
                "TargetPorts": "*",
                "TargetDomains": "*",
                "Protocol": protocol,
                "Action": action,
                "IsEnabled": True,
                "ProxyConfigId": 1,
            })
    return {
        "Version": "1.0",
        # Keep the local Mihomo endpoint reachable. This is not permission for
        # applications to reach arbitrary host loopback services.
        "LocalhostViaProxy": False,
        "IsTrafficLoggingEnabled": True,
        "ProxyConfigs": [{
            "Id": 1,
            "Type": "socks5",
            "Host": "127.0.0.1",
            "Port": str(port),
            "Username": "",
            "Password": "",
            "SendDomainToProxy": True,
        }],
        "ProxyRules": rules,
    }


def candidate_status() -> dict[str, Any]:
    """The admission gate stays closed until a real, independent WFP guard exists."""
    return {
        "supported": False,
        "backend": None,
        "detail": (
            "ProxyBridge/WFP 候选后端未启用：尚无针对隔离进程及全部子进程的独立 WFP 强制规则，"
            "也没有 Windows 实机透明转发和异常后持续阻断的证据。当前仍使用 MXC。"
        ),
    }
