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
# A UTF-8 YAML source has its own 2 MiB bound. JSON escaping can at most
# double otherwise valid YAML text; leave a fixed allowance for the envelope.
MAX_GLOBAL_SOURCE = 2 * 1024 * 1024
MAX_MESSAGE = 2 * MAX_GLOBAL_SOURCE + 64 * 1024
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
GLOBAL_LIMITATIONS = [
    "全局模式会接管整台设备；应用仍以面板当前账户权限运行。",
    "TUN strict-route 本身不等同于核心或服务故障后的独立防直连保护。",
    "保护状态以独立 guard 的实际状态和原生测试为准，不能据启动成功宣称零泄漏。",
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


def validate_global_request(request: dict) -> None:
    """Validate data only; the broker compiles it again before privileged use."""
    source, secret = request.get("source"), request.get("secret")
    try:
        source_size = len(source.encode("utf-8")) if isinstance(source, str) else 0
    except UnicodeError as exc:
        raise ProxyError("invalid_request", "全局 YAML 必须是有效的 UTF-8 文本。") from exc
    if (not isinstance(source, str) or not source or "\0" in source
            or source_size > MAX_GLOBAL_SOURCE):
        raise ProxyError("invalid_request", "全局 YAML 必须是至多 2 MiB 的文本。")
    if (not isinstance(secret, str) or not secret.strip() or len(secret) > 512
            or "\0" in secret):
        raise ProxyError("invalid_request", "核心控制密钥无效。")
    for key in ("mixed_port", "controller_port"):
        if type(request.get(key)) is not int or not 1025 <= request[key] <= 65535:
            raise ProxyError("invalid_request", "全局核心本地端口无效。")
    if request["mixed_port"] == request["controller_port"]:
        raise ProxyError("invalid_request", "核心监听端口不能重复。")
    node = request.get("selected_node")
    if node is not None and (not isinstance(node, str) or not node or len(node) > 4096 or "\0" in node):
        raise ProxyError("invalid_request", "所选节点无效。")
    if type(request.get("require_strict", False)) is not bool:
        raise ProxyError("invalid_request", "严格保护选项无效。")


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
    if not isinstance(operation, str):
        raise ProxyError("invalid_request", "请求操作无效。")
    extra = {"apply": {"paths", "proxy_port", "mihomo_pid", "generation"},
             "global_start": {"source", "secret", "mixed_port", "controller_port", "selected_node", "require_strict"},
             "global_select_node": {"selected_node"},
             "container_allow": {"container", "proxy_port"}, "container_revoke": {"container"}}
    expected = common | extra.get(operation, set())
    if (operation not in {"status", "apply", "stop", "global_status", "global_start", "global_stop", "global_select_node",
                          "container_allow", "container_revoke"}
            or set(request) != expected
            or type(request.get("schema_version")) is not int or request.get("schema_version") != 1
            or not isinstance(request.get("request_id"), str)
            or not re.fullmatch(r"[0-9a-f]{32}", request["request_id"])
            or type(request.get("client_pid")) is not int or not 1 <= request["client_pid"] <= 0xFFFFFFFF):
        raise ProxyError("invalid_request", "请求协议或字段无效。")
    if operation == "apply":
        for name in ("generation", "mihomo_pid"):
            if type(request[name]) is not int or not 1 <= request[name] <= 0xFFFFFFFF:
                raise ProxyError("invalid_request", "配置代次或核心进程无效。")
    if operation == "global_start":
        validate_global_request(request)
    if operation == "global_select_node":
        node = request["selected_node"]
        if not isinstance(node, str) or not node or len(node) > 4096 or "\0" in node:
            raise ProxyError("invalid_request", "所选节点无效。")
    if operation in {"container_allow", "container_revoke"}:
        if not isinstance(request["container"], str) or not re.fullmatch(r"RuleProxy\.[0-9a-f]{20}", request["container"]):
            raise ProxyError("invalid_request", "AppContainer 名称无效。")
        if operation == "container_allow" and (type(request["proxy_port"]) is not int
                                               or not 1025 <= request["proxy_port"] <= 65535):
            raise ProxyError("invalid_request", "代理端口无效。")
    return request
