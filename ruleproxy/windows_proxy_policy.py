"""Pure, bounded policy for the Windows application-routing backend."""
from __future__ import annotations

import hashlib
import json
import ntpath
from pathlib import PureWindowsPath
import re

SCHEMA_VERSION = 1
SERVICE_NAME = "RuleProxyControl"
ENGINE_SERVICE_NAME = "ProxiFyreService"
MAX_MESSAGE = 256 * 1024
MAX_PATHS = 128
SID_RE = re.compile(r"S-1-5-21-(?:\d+-){3}\d+\Z")
HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
SENSITIVE_NAMES = frozenset({"svchost.exe", "services.exe", "lsass.exe", "winlogon.exe",
    "csrss.exe", "smss.exe", "wininit.exe", "spoolsv.exe", "registry", "system"})
LIMITATIONS = [
    "规则按程序路径匹配，同一路径的其他实例也可能被接管；已有连接需要重启应用后重新建立。",
    "ProxiFyre 使用路径包含匹配，包含所填完整路径文本的相似路径也可能命中。",
    "异名子进程需要显式添加其程序路径，不保证自动继承。",
    "UDP 53 与系统 DNS 不保证经过代理；当前不提供 DNS 防泄漏隔离。",
    "IPv6 运行尚需本机验证，IPv6 分片可能直连。",
    "代理引擎停止或故障后可能恢复直连；Windows 模式不提供严格隔离。",
]


class ProxyError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def pipe_name(owner_sid: str) -> str:
    if not isinstance(owner_sid, str) or not SID_RE.fullmatch(owner_sid):
        raise ProxyError("invalid_deployment", "安装用户 SID 无效。")
    return "RuleProxyControl-v1-" + hashlib.sha256(owner_sid.encode("ascii")).hexdigest()[:16]


def normalize_paths(paths, *, root=r"C:\Program Files\RuleProxy-Web",
                    proxifyre_root=r"C:\Program Files\ProxiFyre", windows_root=r"C:\Windows") -> list[str]:
    if not isinstance(paths, list) or not 1 <= len(paths) <= MAX_PATHS:
        raise ProxyError("invalid_policy", "请选择 1 至 128 个明确的程序路径。")
    result, seen = [], set()
    protected = [ntpath.normcase(ntpath.normpath(str(value))).rstrip("\\")
                 for value in (root, proxifyre_root)]
    system = ntpath.normcase(ntpath.normpath(str(windows_root))).rstrip("\\")
    allowed_curl = system + r"\system32\curl.exe"
    for value in paths:
        if (not isinstance(value, str) or not value or len(value) > 4096 or "\0" in value
                or any(char in value for char in "*?\r\n")):
            raise ProxyError("invalid_policy", "程序路径无效，不能使用通配符。")
        path = PureWindowsPath(value)
        if (not path.is_absolute() or path.drive.startswith("\\") or path.suffix.lower() != ".exe"
                or ".." in path.parts or any(":" in part for part in path.parts[1:])):
            raise ProxyError("invalid_policy", "请选择本地磁盘中的绝对 exe 路径。")
        canonical = ntpath.normpath(value)
        key = ntpath.normcase(canonical)
        if (any(key == base or key.startswith(base + "\\") for base in protected)
                or path.name.lower() in SENSITIVE_NAMES
                or (key.startswith(system + "\\") and key != allowed_curl)):
            raise ProxyError("invalid_policy", "不能接管代理组件或系统服务程序。")
        if key not in seen:
            seen.add(key)
            result.append(canonical)
    return result


def build_policy(paths, proxy_port, **directories) -> dict:
    if type(proxy_port) is not int or not 1025 <= proxy_port <= 65535:
        raise ProxyError("invalid_policy", "本机 SOCKS 端口必须在 1025 至 65535 之间。")
    selected = normalize_paths(paths, **directories)
    return {"logLevel": "Info", "bypassLan": False, "excludes": [], "proxies": [{
        "appNames": selected, "socks5ProxyEndpoint": "127.0.0.1:" + str(proxy_port),
        "socks5Transport": "TCP", "supportedProtocols": ["TCP", "UDP"],
        "supportedAddressFamilies": ["IPv4", "IPv6"]}]}


def decode_request(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_MESSAGE:
        raise ProxyError("invalid_request", "请求大小无效。")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ProxyError("invalid_request", "请求含有重复字段。")
            value[key] = item
        return value
    try:
        request = json.loads(raw.decode("utf-8"), object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProxyError("invalid_request", "请求不是有效的 JSON。") from exc
    if not isinstance(request, dict):
        raise ProxyError("invalid_request", "请求必须是对象。")
    common = {"schema_version", "request_id", "op", "client_pid"}
    operation = request.get("op")
    expected = common | ({"paths", "proxy_port", "mihomo_pid", "generation"} if operation == "apply" else set())
    if (operation not in {"status", "apply", "stop"} or set(request) != expected
            or type(request.get("schema_version")) is not int or request.get("schema_version") != 1
            or not isinstance(request.get("request_id"), str)
            or not re.fullmatch(r"[0-9a-f]{32}", request["request_id"])
            or type(request.get("client_pid")) is not int or not 1 <= request["client_pid"] <= 0xFFFFFFFF):
        raise ProxyError("invalid_request", "请求协议或字段无效。")
    if operation == "apply":
        for name in ("generation", "mihomo_pid"):
            if type(request[name]) is not int or not 1 <= request[name] <= 0xFFFFFFFF:
                raise ProxyError("invalid_request", "配置代次或核心进程无效。")
    return request
