"""Installed LocalSystem broker. It controls one fixed engine, never applications.

SCM entry: protected python.exe -I -S this-file --service. All Windows APIs are
loaded lazily so the policy and lifecycle logic can be tested on other hosts.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import http.client
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import socket
import secrets
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse

if __name__ == "__main__":
    sys.dont_write_bytecode = True

if __package__:
    from . import windows_proxy_policy as policy
else:
    _spec = importlib.util.spec_from_file_location("ruleproxy_windows_policy", Path(__file__).with_name("windows_proxy_policy.py"))
    policy = importlib.util.module_from_spec(_spec)
    _spec.loader.exec_module(policy)

ProxyError = policy.ProxyError
_LOG_LOCK = threading.Lock()
_LOG_LIMIT = 256 * 1024
# The pinned core otherwise removes our configured TUN IPv6 address when the
# host has no pre-existing global/ULA IPv6 interface. Apply only to the two
# service-owned global-core children; never change the service/desktop env.
# https://github.com/MetaCubeX/mihomo/blob/v1.19.32/config/utils.go#L191-L209
# https://github.com/MetaCubeX/mihomo/blob/v1.19.32/config/config.go#L1587-L1591
_GLOBAL_CORE_ENV = {"SKIP_SYSTEM_IPV6_CHECK": "true"}


def _log_service_error(context, error):
    """Write bounded diagnostics to the installer-protected fixed location.

    Traceback frames and numeric/curated error codes identify the failing API.
    Exception messages, source text, locals and request/configuration values
    are deliberately excluded, including from chained exceptions.
    """
    try:
        directory = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RuleProxy-Web"
        destination = directory / "service.log"
        with _LOG_LOCK:
            protected_path(directory)
            if destination.exists():
                protected_path(destination)
            chain, current = [], error
            while current is not None and len(chain) < 4:
                item = {"type": type(current).__name__[:80],
                        "traceback": [{"file": Path(frame.filename).name, "line": frame.lineno,
                                       "function": frame.name} for frame in traceback.extract_tb(current.__traceback__)[-20:]]}
                for key in ("errno", "winerror"):
                    value = getattr(current, key, None)
                    if isinstance(value, int):
                        item[key] = value
                if isinstance(current, ProxyError):
                    item["code"] = current.code
                chain.append(item)
                current = current.__cause__ or (None if current.__suppress_context__ else current.__context__)
            record = {"time_utc": datetime.now(timezone.utc).isoformat(), "context": context,
                      "exceptions": chain}
            encoded = (json.dumps(record, ensure_ascii=True) + "\n").encode("ascii")
            mode = "wb" if destination.exists() and destination.stat().st_size + len(encoded) > _LOG_LIMIT else "ab"
            with destination.open(mode) as output:
                output.write(encoded)
            return True
    except Exception:
        # SCM must still receive the original failure if the protected log is
        # unavailable; never fall back to a user-controlled destination.
        return False


def _windows():
    if os.name != "nt":
        raise ProxyError("setup_required", "请在 Windows 上运行安装或修复。")


def _dll(name):
    return ctypes.WinDLL(name, use_last_error=True)


def _sid_text(pointer):
    advapi, kernel = _dll("advapi32"), _dll("kernel32")
    advapi.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    kernel.LocalFree.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.restype = wintypes.HANDLE
    text = wintypes.LPWSTR()
    if not advapi.ConvertSidToStringSidW(pointer, ctypes.byref(text)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return text.value
    finally:
        kernel.LocalFree(ctypes.cast(text, wintypes.HANDLE))


def _token_sid(token):
    advapi = _dll("advapi32")
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    needed = wintypes.DWORD()
    advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
    if not 1 <= needed.value <= 65536:
        raise ProxyError("access_denied", "无法核对控制进程身份。")
    value = ctypes.create_string_buffer(needed.value)
    if not advapi.GetTokenInformation(token, 1, value, needed, ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    return _sid_text(ctypes.cast(value, ctypes.POINTER(wintypes.LPVOID))[0])


def protected_path(path: Path, *, private=False):
    """Require a trusted owner and no non-admin write grant on this object."""
    _windows()
    if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
        raise ProxyError("unsafe_installation", "安装路径不能是重解析点。")
    advapi, kernel = _dll("advapi32"), _dll("kernel32")
    advapi.GetNamedSecurityInfoW.argtypes = [wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID), wintypes.LPVOID, ctypes.POINTER(wintypes.LPVOID),
        wintypes.LPVOID, ctypes.POINTER(wintypes.LPVOID)]
    advapi.GetAce.argtypes = [wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID)]
    kernel.LocalFree.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.restype = wintypes.HANDLE
    owner, dacl, descriptor = wintypes.LPVOID(), wintypes.LPVOID(), wintypes.LPVOID()
    error = advapi.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None,
                                        ctypes.byref(dacl), None, ctypes.byref(descriptor))
    if error:
        raise ProxyError("unsafe_installation", "无法核对安装目录权限：" + str(error))
    trusted = {"S-1-5-18", "S-1-5-32-544", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}
    try:
        if _sid_text(owner) not in trusted or not dacl.value:
            raise ProxyError("unsafe_installation", "安装文件必须由系统或管理员组拥有。")
        # ACL header: revision, sbz1, size, ace-count, sbz2.
        count = ctypes.c_ushort.from_address(dacl.value + 4).value
        for index in range(count):
            ace = wintypes.LPVOID()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise ctypes.WinError(ctypes.get_last_error())
            kind = ctypes.c_ubyte.from_address(ace.value).value
            flags = ctypes.c_ubyte.from_address(ace.value + 1).value
            if flags & 8:  # INHERIT_ONLY does not grant rights on this object.
                continue
            if kind == 1:  # A deny ACE cannot grant write authority.
                continue
            if kind != 0:
                raise ProxyError("unsafe_installation", "安装文件包含不支持的访问许可。")
            mask = ctypes.c_uint32.from_address(ace.value + 4).value
            trustee = _sid_text(ace.value + 8)
            if mask & 0x500D0156 and trustee not in trusted:
                raise ProxyError("unsafe_installation", "普通用户不能改写管理员运行组件。")
            if private and mask & 0x90000001 and trustee not in trusted:
                raise ProxyError("unsafe_installation", "全局核心状态与控制密钥不能授予普通用户读取权限，请修复安装。")
    finally:
        kernel.LocalFree(descriptor)


def _file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_selected_paths(paths):
    for value in paths:
        target = Path(value)
        if not target.is_file():
            raise ProxyError("invalid_policy", "所选程序不存在。")
        for part in (target, *target.parents):
            if part.is_symlink() or getattr(part.lstat(), "st_file_attributes", 0) & 0x400:
                raise ProxyError("invalid_policy", "所选程序路径不能包含重解析点。")


def load_deployment(root: Path, *, secure=True) -> dict:
    root = Path(root).absolute()
    expected = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "RuleProxy-Web"
    if os.path.normcase(str(root)) != os.path.normcase(str(expected.absolute())):
        raise ProxyError("setup_required", "Windows 后端需要安装，请运行 Setup-Windows.cmd。")
    path = root / "deployment.json"
    if not path.is_file() or path.stat().st_size > 4 * 1024**2:
        raise ProxyError("setup_required", "Windows 后端尚未安装，请运行 Setup-Windows.cmd。")
    if secure:
        for item in (root.parent, root, path):
            protected_path(item)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, UnicodeError) as exc:
        raise ProxyError("invalid_deployment", "Windows 安装记录损坏，请修复安装。") from exc
    if (not isinstance(value, dict) or value.get("schema_version") != 1
            or value.get("service_name") != policy.SERVICE_NAME
            or value.get("pipe_name") != policy.pipe_name(value.get("owner_sid"))
            or os.path.normcase(value.get("root", "")) != os.path.normcase(str(root))):
        raise ProxyError("invalid_deployment", "Windows 安装记录身份无效。")
    engine_root = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "ProxiFyre"
    if os.path.normcase(value.get("proxifyre_root", "")) != os.path.normcase(str(engine_root)):
        raise ProxyError("invalid_deployment", "ProxiFyre 安装位置无效。")
    required = {"python/python.exe", "ruleproxy/windows_proxy_service.py", "ruleproxy/windows_proxy_policy.py"}
    if "global_backend_version" in value:
        expected_state = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RuleProxy-Web/global"
        if (type(value["global_backend_version"]) is not int or value["global_backend_version"] != 1
                or not isinstance(value.get("global_state_dir"), str)
                or os.path.normcase(value.get("global_state_dir", "")) != os.path.normcase(str(expected_state))):
            raise ProxyError("invalid_deployment", "全局后端安装记录无效，请修复安装。")
        required |= {"bin/windows-amd64/mihomo.exe", "ruleproxy/config.py", "ruleproxy/windows_app_process.py",
                     "ruleproxy/windows_global_runtime.py", "ruleproxy/windows_global_guard.py",
                     "ruleproxy/windows_global_dns.py", "ruleproxy/windows_global_qualification.py"}
    if "namespace_backend_version" in value:
        expected_state = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RuleProxy-Web/compartments"
        if (type(value["namespace_backend_version"]) is not int or value["namespace_backend_version"] != 1
                or not isinstance(value.get("namespace_state_dir"), str)
                or os.path.normcase(value["namespace_state_dir"]) != os.path.normcase(str(expected_state))):
            raise ProxyError("invalid_deployment", "网络隔间安装记录无效，请修复安装。")
        required |= {"ruleproxy/windows_compartment.py", "ruleproxy/windows_app_process.py"}
    if not required.issubset(value.get("files", {})):
        raise ProxyError("invalid_deployment", "Windows 安装清单缺少控制组件。")
    engine_required = {"ProxiFyre.exe", "socksify.dll", "ProxiFyre.Configuration.dll", "Topshelf.dll", "NLog.dll", "NLog.config"}
    if not engine_required.issubset(value.get("proxifyre_files", {})):
        raise ProxyError("invalid_deployment", "Windows 安装清单缺少代理组件。")
    for base, entries in ((root, value["files"]), (engine_root, value["proxifyre_files"])):
        if not isinstance(entries, dict) or not 1 <= len(entries) <= 4096:
            raise ProxyError("invalid_deployment", "Windows 安装文件清单无效。")
        if secure:
            protected_path(base)
        checked = set()
        for name, digest in entries.items():
            relative = PurePosixPath(name)
            if (not isinstance(name, str) or relative.is_absolute() or ".." in relative.parts
                    or "\\" in name or ":" in name or not relative.parts
                    or not isinstance(digest, str) or not policy.HASH_RE.fullmatch(digest)):
                raise ProxyError("invalid_deployment", "Windows 安装文件路径无效。")
            file = base.joinpath(*relative.parts)
            if secure:
                for item in (*file.parents, file):
                    if item == base or base in item.parents:
                        if item not in checked:
                            protected_path(item)
                            checked.add(item)
            if not file.is_file() or _file_hash(file) != digest:
                raise ProxyError("installation_changed", "Windows 运行组件已改变，请修复安装。")
    return value


class ServiceControl:
    def __init__(self):
        _windows()
        self.api = _dll("advapi32")
        self.api.OpenSCManagerW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
        self.api.OpenSCManagerW.restype = wintypes.HANDLE
        self.api.OpenServiceW.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR, wintypes.DWORD]
        self.api.OpenServiceW.restype = wintypes.HANDLE
        self.api.CloseServiceHandle.argtypes = [wintypes.HANDLE]
        self.api.QueryServiceStatusEx.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        self.api.QueryServiceConfigW.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD,
            ctypes.POINTER(wintypes.DWORD)]
        self.api.ControlService.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID]
        self.api.StartServiceW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID]
        for name in ("CloseServiceHandle", "QueryServiceStatusEx", "QueryServiceConfigW",
                     "ControlService", "StartServiceW"):
            getattr(self.api, name).restype = wintypes.BOOL

    def _open(self, name, rights):
        scm = self.api.OpenSCManagerW(None, None, 1)
        if not scm:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            service = self.api.OpenServiceW(scm, name, rights)
            if not service:
                raise ctypes.WinError(ctypes.get_last_error())
            return service
        finally:
            self.api.CloseServiceHandle(scm)

    def status(self, name=policy.ENGINE_SERVICE_NAME):
        service = self._open(name, 4)
        try:
            data = (wintypes.DWORD * 9)()
            needed = wintypes.DWORD()
            if not self.api.QueryServiceStatusEx(service, 0, data, ctypes.sizeof(data), ctypes.byref(needed)):
                raise ctypes.WinError(ctypes.get_last_error())
            return {"state": data[1], "pid": data[7], "win32_exit_code": data[3]}
        finally:
            self.api.CloseServiceHandle(service)

    def verify(self, metadata):
        class Config(ctypes.Structure):
            _fields_ = [("type", wintypes.DWORD), ("start", wintypes.DWORD), ("error", wintypes.DWORD),
                ("binary", wintypes.LPWSTR), ("group", wintypes.LPWSTR), ("tag", wintypes.DWORD),
                ("dependencies", wintypes.LPWSTR), ("account", wintypes.LPWSTR), ("display", wintypes.LPWSTR)]
        root, engine = Path(metadata["root"]), Path(metadata["proxifyre_root"])
        expected = {policy.SERVICE_NAME: [str(root / "python/python.exe"), "-I", "-S",
            str(root / "ruleproxy/windows_proxy_service.py"), "--service"],
            policy.ENGINE_SERVICE_NAME: [str(engine / "ProxiFyre.exe")]}
        shell, kernel = _dll("shell32"), _dll("kernel32")
        shell.CommandLineToArgvW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
        shell.CommandLineToArgvW.restype = ctypes.POINTER(wintypes.LPWSTR)
        kernel.LocalFree.argtypes = [wintypes.HANDLE]
        kernel.LocalFree.restype = wintypes.HANDLE
        for name, command in expected.items():
            service = self._open(name, 1)
            try:
                # QueryServiceConfigW accepts at most 8 KiB, including the
                # fixed structure and all strings (larger cbBufSize is invalid).
                buffer, needed = ctypes.create_string_buffer(8192), wintypes.DWORD()
                if not self.api.QueryServiceConfigW(service, buffer, len(buffer), ctypes.byref(needed)):
                    raise ctypes.WinError(ctypes.get_last_error())
                config = ctypes.cast(buffer, ctypes.POINTER(Config)).contents
                count = ctypes.c_int()
                args = shell.CommandLineToArgvW(config.binary, ctypes.byref(count))
                if not args:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    actual = [args[index] for index in range(count.value)]
                finally:
                    kernel.LocalFree(args)
                # Topshelf's registered service may include its fixed run verb.
                if name == policy.ENGINE_SERVICE_NAME and actual[1:] == ["run"]:
                    actual = actual[:1]
                if ([os.path.normcase(item) for item in actual] != [os.path.normcase(item) for item in command]
                        or (config.account or "").lower() not in {"localsystem", "nt authority\\system"}
                        or config.type != 0x10):
                    raise ProxyError("unsafe_service", "Windows 服务注册与固定组件不一致，请修复安装。")
            finally:
                self.api.CloseServiceHandle(service)

    def set_running(self, running, timeout=18):
        desired = 4 if running else 1
        service = self._open(policy.ENGINE_SERVICE_NAME, 4 | (16 if running else 32))
        deadline = time.monotonic() + timeout
        try:
            state = self.status()["state"]
            if state == desired:
                return self.status()
            if running:
                if not self.api.StartServiceW(service, 0, None) and ctypes.get_last_error() != 1056:
                    raise ctypes.WinError(ctypes.get_last_error())
            else:
                data = (wintypes.DWORD * 7)()
                if not self.api.ControlService(service, 1, data) and ctypes.get_last_error() != 1062:
                    raise ctypes.WinError(ctypes.get_last_error())
            while time.monotonic() < deadline:
                status = self.status()
                if status["state"] == desired:
                    return status
                if running and status["state"] == 1:
                    raise ProxyError("backend_start_failed", "ProxiFyre 服务启动后退出。")
                time.sleep(.1)
            raise ProxyError("backend_timeout", "等待 ProxiFyre 服务状态超时。")
        finally:
            self.api.CloseServiceHandle(service)


class ProcessLease:
    def __init__(self, pid, expected_sid):
        self.kernel, advapi = _dll("kernel32"), _dll("advapi32")
        self.kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel.OpenProcess.restype = wintypes.HANDLE
        self.kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        self.handle = self.kernel.OpenProcess(0x100000 | 0x1000, False, pid)
        self.pid = pid
        if not self.handle:
            raise ProxyError("invalid_process", "无法核对面板或 Mihomo 进程。")
        token = wintypes.HANDLE()
        advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
        try:
            if not advapi.OpenProcessToken(self.handle, 8, ctypes.byref(token)) or _token_sid(token) != expected_sid:
                raise ProxyError("access_denied", "面板和 Mihomo 必须由安装用户运行。")
        except BaseException:
            self.close()
            raise
        finally:
            if token.value:
                self.kernel.CloseHandle(token)

    def alive(self):
        return bool(self.handle) and self.kernel.WaitForSingleObject(self.handle, 0) == 258

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None

    def image_path(self):
        self.kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD,
            wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        buffer = ctypes.create_unicode_buffer(32768)
        size = wintypes.DWORD(len(buffer))
        if not self.kernel.QueryFullProcessImageNameW(self.handle, 0, buffer, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer.value


def _tcp_connections(family):
    """Bounded native ownership/management snapshot; no subprocess parsing."""
    class Row4(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint32) for name in
                    ("state", "local", "local_port", "remote", "remote_port", "pid")]
    class Row6(ctypes.Structure):
        _fields_ = [("local", ctypes.c_ubyte * 16), ("local_scope", ctypes.c_uint32),
                    ("local_port", ctypes.c_uint32), ("remote", ctypes.c_ubyte * 16),
                    ("remote_scope", ctypes.c_uint32), ("remote_port", ctypes.c_uint32),
                    ("state", ctypes.c_uint32), ("pid", ctypes.c_uint32)]
    row_type = Row4 if family == socket.AF_INET else Row6
    api = _dll("iphlpapi")
    api.GetExtendedTcpTable.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.DWORD),
                                       wintypes.BOOL, wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    api.GetExtendedTcpTable.restype = wintypes.DWORD
    size = wintypes.DWORD()
    error = api.GetExtendedTcpTable(None, ctypes.byref(size), False, family, 5, 0)
    if error not in (0, 122) or not 4 <= size.value <= 8 * 1024 * 1024:
        raise ProxyError("network_state_unavailable", "无法安全核对当前网络连接。")
    for _ in range(3):
        data = ctypes.create_string_buffer(size.value)
        error = api.GetExtendedTcpTable(data, ctypes.byref(size), False, family, 5, 0)
        if error == 122 and 4 <= size.value <= 8 * 1024 * 1024:
            continue
        if error:
            raise ProxyError("network_state_unavailable", "无法安全核对当前网络连接。")
        count = ctypes.c_uint32.from_buffer(data).value
        if count > 65536 or 4 + count * ctypes.sizeof(row_type) > len(data):
            raise ProxyError("network_state_unavailable", "网络连接快照无效。")
        rows = []
        for index in range(count):
            row = row_type.from_buffer_copy(data, 4 + index * ctypes.sizeof(row_type))
            def address(value):
                raw = int(value).to_bytes(4, "little") if family == socket.AF_INET else bytes(value)
                return socket.inet_ntop(family, raw)
            rows.append({"state": row.state, "pid": row.pid, "local": address(row.local),
                         "remote": address(row.remote), "local_port": socket.ntohs(row.local_port & 0xffff),
                         "remote_port": socket.ntohs(row.remote_port & 0xffff)})
        return rows
    raise ProxyError("network_state_unavailable", "网络连接变化过快，请稍后重试。")


def _management_exceptions():
    """Preserve only remote endpoints of already established RDP sessions."""
    import ipaddress
    import winreg
    port = 3389
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp") as key:
            port = winreg.QueryValueEx(key, "PortNumber")[0]
    except FileNotFoundError:
        pass
    if type(port) is not int or not 1 <= port <= 65535:
        raise ProxyError("network_state_unavailable", "无法核对远程桌面管理端口。")
    owners = {4}  # Some RDP kernel transports report System as the owner.
    try:
        terminal = ServiceControl().status("TermService")
        if terminal["state"] == 4 and terminal["pid"] > 0:
            owners.add(terminal["pid"])
    except OSError as exc:
        if getattr(exc, "winerror", None) != 1060:  # RDP host not installed.
            raise
    result = []
    for family in (socket.AF_INET, socket.AF_INET6):
        for row in _tcp_connections(family):
            if row["state"] != 5 or row["local_port"] != port or row["pid"] not in owners:
                continue
            remote = ipaddress.ip_address(row["remote"])
            if remote.is_loopback or remote.is_unspecified:
                continue
            if getattr(remote, "ipv4_mapped", None):
                remote = remote.ipv4_mapped
            route = str(remote) + ("/32" if remote.version == 4 else "/128")
            if not any(item["route"] == route for item in result):
                if len(result) >= 128:
                    raise ProxyError("network_state_unavailable", "远程管理连接过多，无法生成有界的安全例外。")
                result.append({"remote": str(remote), "route": route, "protocol": "TCP", "local_port": port,
                               "reason": "启动时已建立的远程桌面管理连接"})
    return result


class UnavailableGlobalGuard:
    """Honest intermediate capability until a verified independent guard exists."""
    def status(self):
        return {"supported": False, "active": False, "persistent": False, "strict_isolation": False,
                "detail": "未安装经过验证的独立故障阻断层；TUN 路由本身不能保证核心故障后不直连。"}

    def apply(self, _core_path, _tun):
        return self.status()

    normal_stop = status
    crash_keep = status


class UnavailableGlobalDNS:
    def status(self, *, refresh=False):
        return {"supported": False, "active": None, "effective": False, "persistent": None,
                "native_qualified": False, "state": "setup_required",
                "detail": "全局 DNS 组件尚未安装，请运行 Setup-Windows.cmd 修复安装。"}

    def apply(self):
        raise ProxyError("setup_required", self.status()["detail"])

    normal_stop = apply
    crash_keep = status


class GlobalCore:
    """One fixed installed Mihomo process, owned by the SYSTEM control service.

    The installer owns every executable/import and the private state directory.
    A killed broker closes the non-inheritable Job handle and kills the core;
    persistent traffic protection belongs to the separate guard, not that Job.
    """
    def __init__(self, metadata, *, guard=None, dns=None, compiler=None, launcher=None,
                 validator=None, health=None, management=None, state_directory=None):
        self.metadata = metadata
        self.root = Path(metadata["root"])
        self.directory = (Path(state_directory) if state_directory is not None else
                          Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "RuleProxy-Web/global")
        self.executable = self.root / "bin/windows-amd64/mihomo.exe"
        self.process = None
        self.fingerprint = None
        self.error = None
        self.management_exceptions = []
        # A caller who knows an elevated Mihomo's full controller secret can
        # use /configs to bypass the compiler and reload arbitrary YAML. Never
        # give desktop users that secret: expose only bounded broker verbs.
        self._controller_secret = secrets.token_urlsafe(48)
        self._controller_port = None
        self._allowed_nodes = set()
        self._primary_group = None
        self.selected_node = None
        self._compiler, self._launcher = compiler, launcher
        self._validator, self._health = validator, health
        self._management = management or _management_exceptions
        if guard is not None:
            self.guard = guard
        elif "ruleproxy/windows_global_guard.py" in metadata.get("files", {}):
            from ruleproxy.windows_global_guard import Guard
            self.guard = Guard(metadata)
        else:
            self.guard = UnavailableGlobalGuard()
        if dns is not None:
            self.dns = dns
        elif "ruleproxy/windows_global_dns.py" in metadata.get("files", {}):
            from ruleproxy.windows_global_dns import DnsLease
            self.dns = DnsLease(metadata)
        else:
            self.dns = UnavailableGlobalDNS()

    def _available(self):
        required = {"bin/windows-amd64/mihomo.exe", "ruleproxy/config.py",
                    "ruleproxy/windows_global_runtime.py", "ruleproxy/windows_app_process.py",
                    "ruleproxy/windows_global_dns.py", "ruleproxy/windows_global_qualification.py"}
        if self.metadata.get("global_backend_version") != 1 or not required.issubset(self.metadata.get("files", {})):
            raise ProxyError("setup_required", "控制服务尚未安装全局后端，请运行 Setup-Windows.cmd 修复安装。")
        for path in (self.directory.parent, self.directory):
            if not path.is_dir():
                raise ProxyError("setup_required", "全局运行目录尚未安装，请修复安装。")
            protected_path(path, private=True)

    @staticmethod
    def _guard_ready(value, *, strict=False, tun_ready=False):
        required = ("supported", "active", "persistent")
        if strict:
            required += ("strict_isolation", "native_qualified")
        if tun_ready:
            required += ("tun_ready",)
        return all(value.get(name) is True for name in required)

    @staticmethod
    def _preguard_ready(value, *, strict=False):
        # Before launching the core there cannot yet be a verified TUN. Require
        # the qualified persistent pre-guard, then full strict readback later.
        return (GlobalCore._guard_ready(value)
                and (not strict or value.get("native_qualified") is True))

    @staticmethod
    def _dns_ready(value, *, strict=False):
        required = ("supported", "active", "persistent", "effective", "fresh")
        if strict:
            required += ("native_qualified",)
        return (all(value.get(name) is True for name in required)
                and value.get("state") == "candidate_active")

    def status(self, *, dns_state=None, guard_state=None):
        try:
            self._available()
            available, detail = True, "Windows 全局 TUN 后端已安装。"
        except ProxyError as exc:
            available, detail = False, str(exc)
        running = self.is_running()
        guard = self.guard.status() if guard_state is None else guard_state
        dns = self.dns.status() if dns_state is None else dns_state
        strict = (running and self._guard_ready(guard, strict=True, tun_ready=True)
                  and self._dns_ready(dns, strict=True))
        protection = ("persistent_guard" if strict else "persistent_guard_unqualified"
                      if guard.get("active") is True and guard.get("persistent") is True else "routing_only")
        if not guard.get("supported"):
            detail += " 独立故障阻断层不可用，不能确认故障后防直连。"
        component_supported = available and dns.get("component_available", dns.get("supported")) is True
        policy_ready = dns.get("fresh") is True and dns.get("supported") is True and dns.get("state") in {"idle", "candidate_active"}
        dns_conflict = dns.get("state") in {"conflict", "not_effective"}
        if not policy_ready:
            detail += " " + dns.get("detail", "无法核对全局 DNS 策略。")
        return {"global_schema_version": 1, "mode": "global", "backend": "Mihomo TUN",
                "supported": component_supported and not dns_conflict, "component_supported": component_supported,
                "policy_ready": policy_ready, "setup_required": not available,
                "state": "setup_required" if not available else ("running" if running else
                         ("failed" if self.error else "idle")),
                "running": running, "pid": self.process.pid if running else None,
                "strict_isolation": strict, "protection": protection,
                "guard": guard, "dns": dns, "detail": detail, "error": self.error,
                "selected_node": self.selected_node,
                "management_exceptions": list(self.management_exceptions),
                "limitations": list(policy.GLOBAL_LIMITATIONS)}

    def is_running(self):
        """Process ownership only; watchdogs never wait on a DNS subprocess."""
        return self.process is not None and self.process.poll() is None

    def _write(self, text):
        destination, temporary = self.directory / "config.yaml", self.directory / "config.ruleproxy.tmp"
        for path in (destination, temporary):
            if path.exists() or path.is_symlink():
                protected_path(path, private=True)
        with temporary.open("wb") as output:
            output.write(text.encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, destination)
        protected_path(destination, private=True)
        return destination

    def _owned_controller(self, port, secret, process, method, path, data=None):
        """Authenticate this established TCP peer *before* disclosing a token.

        Checking a LISTEN socket before connecting is racy: a dead core's port
        could be acquired by an ordinary user's process. The connected socket
        and server-side tuple are stable while its original peer stays alive.
        """
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=.5)
        try:
            connection.connect()
            local = connection.sock.getsockname()
            owned = any(row["state"] == 5 and row["pid"] == process.pid and
                        row["local_port"] == port and row["remote_port"] == local[1] and
                        row["local"] == "127.0.0.1" and row["remote"] == local[0]
                        for row in _tcp_connections(socket.AF_INET))
            if not owned or process.poll() is not None:
                raise ProxyError("invalid_controller_owner", "核心控制连接不属于持有的固定进程，未发送控制密钥。")
            body = json.dumps(data).encode("utf-8") if data is not None else None
            connection.request(method, path, body=body,
                headers={"Authorization": "Bearer " + secret, "Content-Type": "application/json"})
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                raise ProxyError("controller_failed", "全局核心控制请求失败。")
            raw = response.read(65537)
            if len(raw) > 65536:
                raise ProxyError("invalid_controller_response", "核心控制响应过大。")
            return json.loads(raw.decode("utf-8")) if raw else None
        finally:
            connection.close()

    def _controller_ready(self, port, secret, process):
        value = self._owned_controller(port, secret, process, "GET", "/version")
        return isinstance(value, dict) and isinstance(value.get("version"), str)

    def _halt(self):
        process = self.process
        if process is not None:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
            self.process = None

    def _keep_after_start_failure(self):
        self.error = {"code": "global_start_failed", "message": "全局核心未能确认有效运行；已保留独立保护状态。"}
        try:
            self._halt()
        finally:
            # Failed cleanup never authorizes withdrawing either protection.
            try:
                self.dns.crash_keep()
            finally:
                self.guard.crash_keep()

    def _confirmed_running(self, *, strict):
        dns = self.dns.status(refresh=True)
        guard = self.guard.status()
        if not self._guard_ready(guard, strict=strict, tun_ready=True):
            raise ProxyError("strict_guard_unavailable" if strict else "global_guard_not_effective",
                             "启动后的独立保护或 TUN 接口未确认，保留独立保护。")
        if not self._dns_ready(dns, strict=strict):
            raise ProxyError("strict_dns_unavailable" if strict else "global_dns_not_effective",
                             "启动后的 DNS 有效策略未确认，保留独立保护。")
        result = self.status(dns_state=dns, guard_state=guard)
        if result["running"] is not True:
            raise ProxyError("global_start_failed", "全局核心已退出，保留独立保护。")
        return result

    def stop(self, *, normal=True):
        # Confirm process cleanup before touching either retired protection.
        self._halt()
        self.fingerprint = None
        self._controller_port, self._primary_group = None, None
        self._allowed_nodes = set()
        if normal:
            # TUN is retired. A broken/slow NRPT service must not leave our
            # independent whole-machine block in place indefinitely. Each
            # component still enforces its exact owned-resource checks.
            errors = []
            try:
                result = self.guard.normal_stop()
                if result.get("supported") is not True or result.get("active") is not False:
                    raise ValueError("自有 WFP 规则撤销未能确认。")
            except Exception as exc:
                errors.append("WFP: " + str(exc))
            try:
                dns = self.dns.normal_stop()
                if dns.get("supported") is not True or dns.get("active") is not False:
                    raise ValueError("自有 DNS 规则撤销未能确认。")
            except Exception as exc:
                errors.append("DNS: " + str(exc))
            if errors:
                self.error = {"code": "global_restore_incomplete", "message": "；".join(errors)}
                raise ProxyError("global_restore_incomplete", "旧版网络规则恢复尚未完成，请重试：" + self.error["message"])
        else:
            dns = self.dns.crash_keep()
            result = self.guard.crash_keep()
        if normal:
            self.error = None
        return {**self.status(dns_state=dns), "stopped": True, "guard": result, "dns": dns}

    def select_node(self, name):
        if self.process is None or self.process.poll() is not None:
            raise ProxyError("global_not_running", "全局核心尚未运行。")
        if not isinstance(name, str) or name not in self._allowed_nodes:
            raise ProxyError("invalid_node", "只能切换到已安全编译的代理节点。")
        path = "/proxies/" + urllib.parse.quote(self._primary_group, safe="")
        self._owned_controller(self._controller_port, self._controller_secret, self.process,
                               "PUT", path, {"name": name})
        self.selected_node = name
        return self.status()

    def start(self, request):
        policy.validate_global_request(request)
        self._available()
        strict = request.get("require_strict") is True
        if strict:
            # Revalidate the protected attestation/binaries for every strict
            # start, including the unchanged-running shortcut. Test doubles
            # and unavailable components need no receipt reader.
            for component in (self.guard, self.dns):
                refresh = getattr(component, "refresh_qualification", None)
                if refresh is not None:
                    refresh()
            capability = self.guard.status()
            if not (capability.get("supported") is True and capability.get("native_qualified") is True):
                raise ProxyError("strict_guard_unavailable", "独立故障阻断层尚未通过原生资格验证，不能启动严格全局模式。")
        # Parse/query the fixed DNS control program without changing policy
        # before installing a persistent pre-guard. A missing/broken DNSClient
        # must not lock networking before it can even inspect its own lease.
        dns_capability = self.dns.status(refresh=True)
        if (dns_capability.get("supported") is not True
                or dns_capability.get("fresh") is not True
                or dns_capability.get("state") not in {"idle", "candidate_active"}):
            raise ProxyError("global_dns_conflict", "已有 DNS 策略冲突或无法核对有效 NRPT，未启动全局接管。")
        if strict and dns_capability.get("native_qualified") is not True:
            raise ProxyError("strict_dns_unavailable", "全局 DNS 尚未通过原生资格验证，不能启动严格全局模式。")
        if self.process is None or self.process.poll() is not None:
            self._controller_secret = secrets.token_urlsafe(48)
        compiler = self._compiler
        if compiler is None:
            from ruleproxy.config import compile_config
            compiler = compile_config
        try:
            compiled = compiler(request["source"], secret=self._controller_secret, mixed_port=request["mixed_port"],
                                controller_port=request["controller_port"], selected_node=request["selected_node"],
                                capture_mode="global", allow_udp=True)
        except (ValueError, TypeError, RecursionError) as exc:
            raise ProxyError("invalid_config", "全局配置未通过安全编译，请在面板检查 YAML 与所选节点。") from exc
        fingerprint = hashlib.sha256(compiled.text.encode("utf-8")).hexdigest()
        if self.process is not None and self.process.poll() is None:
            if self.fingerprint == fingerprint:
                try:
                    return {**self._confirmed_running(strict=strict), "unchanged": True}
                except BaseException:
                    self._keep_after_start_failure()
                    raise
            raise ProxyError("already_running", "全局核心已运行，请先停止后再更改配置。")
        reservations = []
        try:
            for port in (request["mixed_port"], request["controller_port"]):
                reserved = socket.socket()
                reservations.append(reserved)
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    reserved.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                reserved.bind(("127.0.0.1", port))
        except OSError as exc:
            raise ProxyError("port_in_use", "全局核心本地监听端口已被占用，未修改路由。") from exc
        finally:
            for reserved in reservations:
                reserved.close()
        protected_path(self.executable)
        if _file_hash(self.executable) != self.metadata["files"]["bin/windows-amd64/mihomo.exe"]:
            raise ProxyError("installation_changed", "固定 Mihomo 核心已改变，请修复安装。")
        # Protect existing management before auto-route alters the default path.
        exceptions = self._management()
        tun = compiled.config["tun"]
        if (tun.get("inet4-address") != ["198.18.0.1/30"]
                or tun.get("inet6-address") != ["fdfe:dcba:8879::1/126"]):
            raise ProxyError("invalid_config", "全局 TUN 地址与固定 DNS peer 不匹配，未启动网络接管。")
        if exceptions:
            tun["route-exclude-address"] = [item["route"] for item in exceptions]
        import yaml
        text = yaml.safe_dump(compiled.config, allow_unicode=True, sort_keys=False)
        configuration = self._write(text)
        command = [str(self.executable), "-d", str(self.directory), "-f", str(configuration)]
        child_env = dict(os.environ)
        child_env.update(_GLOBAL_CORE_ENV)
        validation = self._validator or subprocess.run
        checked = validation([command[0], "-t", *command[1:]], stdin=subprocess.DEVNULL,
                             stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT, timeout=12,
                             cwd=str(self.root), env=child_env,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if checked.returncode:
            raise ProxyError("invalid_config", "固定 Mihomo 未通过全局配置校验，未启动 TUN。")
        self.management_exceptions = exceptions
        try:
            protection = self.guard.apply(self.executable, tun)
            if not self._preguard_ready(protection, strict=strict):
                raise ProxyError("strict_guard_unavailable" if strict else "global_guard_not_effective",
                                 "独立故障阻断层未进入有效状态，未启动全局核心。")
            dns = self.dns.apply()
            if not self._dns_ready(dns, strict=strict):
                raise ProxyError("strict_dns_unavailable" if strict else "global_dns_not_effective",
                                 "全局 DNS 未确认生效，未启动全局核心。")
            launcher = self._launcher
            if launcher is None:
                from ruleproxy.windows_app_process import launch
                launcher = launch
            self.process = launcher(command, child_env, str(self.root))
            deadline = time.monotonic() + 8
            health = self._health or self._controller_ready
            while time.monotonic() < deadline and self.process.poll() is None:
                try:
                    if health(request["controller_port"], self._controller_secret, self.process):
                        # First apply may deliberately install a fail-closed
                        # pre-guard before the TUN interface has a real LUID.
                        # Reapply atomically after the core creates the device.
                        ready = self.guard.apply(self.executable, tun)
                        # The controller can answer before mihomo creates the TUN
                        # (hub.ApplyConfig starts it before executor.ApplyConfig does;
                        # https://github.com/MetaCubeX/mihomo/blob/v1.19.32/hub/hub.go).
                        # Before tun_ready only the qualified persistent pre-guard is
                        # required; _confirmed_running checks strict isolation once it is.
                        if not self._preguard_ready(ready, strict=strict):
                            raise ProxyError("strict_guard_unavailable" if strict else "global_guard_not_effective",
                                             "TUN 启动后的独立保护未确认，保留独立保护。")
                        if ready.get("tun_ready") is True:
                            confirmed = self._confirmed_running(strict=strict)
                            self.fingerprint, self.error = fingerprint, None
                            self._controller_port = request["controller_port"]
                            self._allowed_nodes = {node["name"] for node in compiled.nodes}
                            self._primary_group = compiled.primary_group
                            self.selected_node = compiled.selected_node
                            return {**confirmed, "error": None, "selected_node": self.selected_node}
                except (OSError, ValueError):
                    pass
                time.sleep(.1)
            raise ProxyError("global_start_failed", "全局核心未能建立自身控制监听，请停止或修复后重试。")
        except BaseException:
            self._keep_after_start_failure()
            raise


class Broker:
    def __init__(self, metadata, control=None, lease_factory=None, global_factory=None, container_factory=None,
                 namespace_factory=None):
        self.metadata = metadata
        self.control = control or ServiceControl()
        self.lease_factory = lease_factory or ProcessLease
        self.lock = threading.RLock()
        self.panel = self.core = None
        self.generation = 0
        self.paths = []
        self.port = None
        self.error = None
        self.global_factory = global_factory or GlobalCore
        self.global_core = None
        self.global_panel = None
        self.container_factory = container_factory
        self.container_gate = None
        self.containers = set()
        self.namespace_factory = namespace_factory
        self.namespace_gate = None
        self.namespaces = set()

    def _containers(self):
        if self.container_gate is None:
            if self.container_factory is None:
                from ruleproxy.windows_appcontainer import ContainerGate
                self.container_factory = ContainerGate
            self.container_gate = self.container_factory(self.metadata)
        return self.container_gate

    def recover_containers(self):
        """Before accepting clients, revoke gates left by an earlier service."""
        result = self._containers().purge()
        if not isinstance(result, dict) or result.get('active') is not False:
            raise ProxyError('cleanup_incomplete', 'AppContainer 遗留规则恢复未能确认。')
        self.containers.clear()
        return result

    def _purge_containers(self):
        if self.container_gate is not None:
            result = self.container_gate.purge()
            if not isinstance(result, dict) or result.get('active') is not False:
                raise ProxyError('cleanup_incomplete', 'AppContainer 清理未能确认。')
        self.containers.clear()

    def _namespaces(self):
        if self.namespace_gate is None:
            if self.namespace_factory is None:
                from ruleproxy.windows_compartment import NamespaceGate
                self.namespace_factory = NamespaceGate
            self.namespace_gate = self.namespace_factory(self.metadata)
        return self.namespace_gate

    def recover_namespaces(self):
        """Before accepting clients, seal compartments left by an earlier service."""
        result = self._namespaces().purge()
        if not isinstance(result, dict) or result.get('active') is not False:
            raise ProxyError('cleanup_incomplete', '网络隔间遗留状态恢复未能确认。')
        self.namespaces.clear()
        return result

    def _purge_namespaces(self):
        if self.namespace_gate is not None:
            result = self.namespace_gate.purge()
            if not isinstance(result, dict) or result.get('active') is not False:
                raise ProxyError('cleanup_incomplete', '网络隔间清理未能确认。')
        self.namespaces.clear()

    def _global(self):
        if self.global_core is None:
            self.global_core = self.global_factory(self.metadata)
        return self.global_core

    def _global_active(self):
        if self.global_core is None:
            return False
        status = self.global_core.status()
        return (status["running"] or status.get("guard", {}).get("active") is True
                or status.get("dns", {}).get("active") is True)

    def snapshot(self):
        engine_running = self.control.status()["state"] == 4
        namespace_ready = self.panel is not None and not self.paths
        state = ("running" if self.panel else "external_conflict") if engine_running else (
            "running" if namespace_ready else
            "failed" if self.panel or self.error else "idle")
        global_active = self._global_active()
        if global_active:
            state = "global_conflict"
        return {"backend": "ProxiFyre", "mode": "application_proxy", "strict_isolation": False,
            "state": state, "running": (engine_running or namespace_ready) and self.panel is not None,
            "engine_running": engine_running, "generation": self.generation,
            "owner_pid": self.panel.pid if self.panel else None, "path_count": len(self.paths),
            "proxy_port": self.port, "limitations": list(policy.LIMITATIONS), "error": self.error,
            "global_active": global_active, "container_count": len(self.containers),
            "namespace_count": len(self.namespaces),
            "namespace_ready": namespace_ready,
            "cleanup_pending": self.error is not None and self.error.get('code') == 'cleanup_incomplete'}

    def _clear(self):
        for process in (self.panel, self.core):
            if process:
                process.close()
        self.panel = self.core = None
        self.paths, self.port = [], None

    def stop(self):
        self._purge_containers()
        self._purge_namespaces()
        result = self.control.set_running(False)
        self._clear()
        self.error = None
        return {"stopped": result["state"] == 1, "generation": self.generation}

    def check_lease(self):
        with self.lock:
            if self.panel and (not self.panel.alive() or not self.core.alive()):
                try:
                    self.stop()
                except Exception as exc:
                    if not self.error:
                        _log_service_error("lease_cleanup", exc)
                    self.error = {"code": "cleanup_incomplete", "message": str(exc)[:500]}
            if self.global_panel and (not self.global_panel.alive() or not self._global().is_running()):
                try:
                    self._global().error = {"code": "global_owner_or_core_exited",
                        "message": "全局核心或面板已退出；保留独立保护，显式停止后恢复。"}
                    self._global().stop(normal=False)
                    self.global_panel.close()
                    self.global_panel = None
                except Exception as exc:
                    if not self.error:
                        _log_service_error("global_lease_cleanup", exc)
                    self.error = {"code": "cleanup_incomplete", "message": "全局清理未能确认，保留保护状态。"}

    def shutdown(self):
        """An SCM/broker exit is not the user's explicit network restore."""
        with self.lock:
            if self.panel is not None:
                self.stop()
            else:
                self._purge_containers()
                self._purge_namespaces()
            if self.global_core is not None:
                self.global_core.stop(normal=False)
            if self.global_panel is not None:
                self.global_panel.close()
                self.global_panel = None

    def _global_handle(self, request, caller_pid, caller_sid):
        operation = request["op"]
        if operation == "global_status":
            result = self._global().status()
            if self.control.status()["state"] == 4 and self.panel is None:
                result.update(supported=False, state="external_conflict",
                              detail="ProxiFyre 已由其他程序启动，请先停止该程序的代理。")
            return result
        if ((self.panel and self.panel.pid != caller_pid)
                or (self.global_panel and self.global_panel.pid != caller_pid)):
            raise ProxyError("instance_conflict", "另一面板正在管理 Windows 代理。")
        if operation == "global_stop":
            result = self._global().stop(normal=True)
            if self.global_panel:
                self.global_panel.close()
                self.global_panel = None
            return result
        if operation == "global_select_node":
            return self._global().select_node(request["selected_node"])
        # Global mode is now the user's own system proxy. The TUN start was
        # removed; this service only releases what older versions installed.
        raise ProxyError("global_tun_removed", "全局 TUN 已移除，请更新面板；全局模式改用系统代理。")

    def handle(self, request, caller_pid, caller_sid):
        with self.lock:
            if caller_sid != self.metadata["owner_sid"] or request["client_pid"] != caller_pid:
                raise ProxyError("access_denied", "控制请求身份不匹配。")
            self.check_lease()
            # A container gate belongs to the same held panel/core lease as the
            # path policy. An arbitrary same-user pipe client cannot choose a
            # different port or silently replace another panel's gates.
            if request["op"] == "container_allow":
                if (self.panel is None or self.core is None or self.panel.pid != caller_pid
                        or not self.panel.alive() or not self.core.alive()
                        or request['proxy_port'] != self.port):
                    raise ProxyError('instance_conflict', 'AppContainer 必须使用当前面板持有的核心和代理端口。')
                name = request['container']
                # Retain intent even if allow fails after committing persistent
                # filters; explicit stop/dead-owner cleanup must still recover.
                self.containers.add(name)
                result = self._containers().allow(name, request["proxy_port"])
                if not isinstance(result, dict) or result.get('active') is not True:
                    raise ProxyError('appcontainer_failed', 'AppContainer 授权未能确认。')
                return result
            if request["op"] == "container_revoke":
                if self.panel is not None and self.panel.pid != caller_pid:
                    raise ProxyError('instance_conflict', '另一面板正在管理 Windows 代理。')
                result = self._containers().revoke(request["container"])
                if not isinstance(result, dict) or result.get('active') is not False:
                    raise ProxyError('cleanup_incomplete', 'AppContainer 撤销未能确认。')
                self.containers.discard(request['container'])
                return result
            # A compartment gate is bound to the panel's own Job handle and the
            # held core/port, exactly like the path policy and the container gate.
            if request["op"] == "namespace_allow":
                if (self.panel is None or self.core is None or self.panel.pid != caller_pid
                        or not self.panel.alive() or not self.core.alive()
                        or request['proxy_port'] != self.port):
                    raise ProxyError('instance_conflict', '网络隔间必须使用当前面板持有的核心和代理端口。')
                name = request['container']
                # Retain intent even if the bind fails midway; explicit stop and
                # dead-owner cleanup must still seal the compartment afterwards.
                self.namespaces.add(name)
                result = self._namespaces().allow(name, request["proxy_port"], caller_pid, request["job_handle"])
                if not isinstance(result, dict) or result.get('active') is not True:
                    raise ProxyError('namespace_failed', '网络隔间授权未能确认。')
                return result
            if request["op"] == "namespace_revoke":
                if self.panel is not None and self.panel.pid != caller_pid:
                    raise ProxyError('instance_conflict', '另一面板正在管理 Windows 代理。')
                result = self._namespaces().revoke(request["container"])
                if not isinstance(result, dict) or result.get('active') is not False:
                    raise ProxyError('cleanup_incomplete', '网络隔间撤销未能确认。')
                self.namespaces.discard(request['container'])
                return result
            if request["op"] in {"global_status", "global_start", "global_stop", "global_select_node"}:
                return self._global_handle(request, caller_pid, caller_sid)
            if request["op"] == "status":
                return self.snapshot()
            if self.panel and self.panel.pid != caller_pid:
                raise ProxyError("instance_conflict", "另一面板正在管理 Windows 代理。")
            if request["op"] == "stop":
                if self.panel is None:
                    self._purge_containers()
                    self._purge_namespaces()
                    return {"stopped": True, "not_owned": True, "generation": self.generation}
                return self.stop()
            if self._global_active():
                raise ProxyError("mode_conflict", "全局接管或故障保护仍在生效，请先显式停止全局模式。")
            if request["generation"] != self.generation + 1:
                raise ProxyError("generation_conflict", "配置状态已改变，请刷新后重试。")
            if request["op"] == "namespace_prepare":
                return self._prepare_namespace_core(request, caller_pid, caller_sid)
            compiled = policy.build_policy(request["paths"], request["proxy_port"],
                root=self.metadata["root"], proxifyre_root=self.metadata["proxifyre_root"],
                windows_root=os.environ.get("SystemRoot", r"C:\Windows"))
            verify_selected_paths(compiled["proxies"][0]["appNames"])
            if (self.panel is not None and self.core.pid == request["mihomo_pid"]
                    and self.port == request["proxy_port"] and self.control.status()["state"] == 4
                    and {os.path.normcase(path) for path in self.paths} == {
                        os.path.normcase(path) for path in compiled["proxies"][0]["appNames"]}):
                return {**self.snapshot(), "unchanged": True}
            panel = self.lease_factory(caller_pid, caller_sid)
            core = None
            try:
                core = self.lease_factory(request["mihomo_pid"], caller_sid)
                expected_core = Path(self.metadata["root"]) / "bin/windows-amd64/mihomo.exe"
                if os.path.normcase(core.image_path()) != os.path.normcase(str(expected_core)):
                    raise ProxyError("invalid_process", "必须使用安装包内的 Mihomo 核心。")
                if self.containers and (self.port != request['proxy_port']
                        or self.core is None or self.core.pid != request['mihomo_pid']):
                    self._purge_containers()
                if self.namespaces and (self.port != request['proxy_port']
                        or self.core is None or self.core.pid != request['mihomo_pid']):
                    self._purge_namespaces()
                self.control.verify(self.metadata)
                config = Path(self.metadata["proxifyre_root"]) / "app-config.json"
                old = config.read_bytes() if config.is_file() else None
                was_running = self.control.status()["state"] == 4
                if was_running and self.panel is None:
                    raise ProxyError("external_instance_conflict", "ProxiFyre 已由其他程序启动，不能接管。")
                self.control.set_running(False)
                try:
                    temporary = config.with_suffix(".ruleproxy.tmp")
                    if temporary.is_symlink() or config.is_symlink():
                        raise ProxyError("unsafe_installation", "代理配置不能是链接。")
                    with temporary.open("wb") as output:
                        output.write((json.dumps(compiled, ensure_ascii=True, indent=2) + "\n").encode("ascii"))
                        output.flush()
                        os.fsync(output.fileno())
                    os.replace(temporary, config)
                    self.control.set_running(True)
                except BaseException:
                    self.control.set_running(False)
                    if old is None:
                        config.unlink(missing_ok=True)
                    else:
                        config.write_bytes(old)
                    if was_running:
                        self.control.set_running(True)
                    raise
                self._clear()
                self.panel, self.core = panel, core
                panel = core = None
                self.generation = request["generation"]
                self.paths, self.port = compiled["proxies"][0]["appNames"], request["proxy_port"]
                self.error = None
                return self.snapshot()
            finally:
                for process in (panel, core):
                    if process:
                        process.close()

    def _prepare_namespace_core(self, request, caller_pid, caller_sid):
        """Bind an authenticated core lease without applying any path proxy rule."""
        if (self.panel is not None and not self.paths and self.core.pid == request["mihomo_pid"]
                and self.port == request["proxy_port"]):
            self.generation = request["generation"]
            return {**self.snapshot(), "unchanged": True}
        panel = self.lease_factory(caller_pid, caller_sid)
        core = None
        try:
            core = self.lease_factory(request["mihomo_pid"], caller_sid)
            expected = Path(self.metadata["root"]) / "bin/windows-amd64/mihomo.exe"
            if os.path.normcase(core.image_path()) != os.path.normcase(str(expected)):
                raise ProxyError("invalid_process", "必须使用安装包内的 Mihomo 核心。")
            state = self.control.status()["state"]
            if state == 4 and self.panel is None:
                raise ProxyError("external_instance_conflict", "ProxiFyre 已由其他程序启动，不能接管。")
            changed = self.port != request["proxy_port"] or self.core is None or self.core.pid != request["mihomo_pid"]
            if changed:
                self._purge_containers()
                self._purge_namespaces()
            # A transition from compatibility mode releases only our own path
            # engine. Namespace-only operation never starts the engine.
            if self.panel is not None and state == 4:
                self.control.set_running(False)
            self._clear()
            self.panel, self.core = panel, core
            panel = core = None
            self.port, self.paths = request["proxy_port"], []
            self.generation = request["generation"]
            self.error = None
            return self.snapshot()
        finally:
            for process in (panel, core):
                if process:
                    process.close()


class Overlapped(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
        ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD), ("hEvent", wintypes.HANDLE)]


class PipeAPI:
    def __init__(self):
        self.kernel, self.advapi = _dll("kernel32"), _dll("advapi32")
        signatures = {
            "CreateEventW": ([wintypes.LPVOID, wintypes.BOOL, wintypes.BOOL, wintypes.LPCWSTR], wintypes.HANDLE),
            "CloseHandle": ([wintypes.HANDLE], wintypes.BOOL),
            "WaitForSingleObject": ([wintypes.HANDLE, wintypes.DWORD], wintypes.DWORD),
            "CancelIoEx": ([wintypes.HANDLE, ctypes.POINTER(Overlapped)], wintypes.BOOL),
            "GetOverlappedResult": ([wintypes.HANDLE, ctypes.POINTER(Overlapped), ctypes.POINTER(wintypes.DWORD), wintypes.BOOL], wintypes.BOOL),
            "ReadFile": ([wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(Overlapped)], wintypes.BOOL),
            "WriteFile": ([wintypes.HANDLE, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(Overlapped)], wintypes.BOOL),
            "ConnectNamedPipe": ([wintypes.HANDLE, ctypes.POINTER(Overlapped)], wintypes.BOOL),
            "GetNamedPipeClientProcessId": ([wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)], wintypes.BOOL),
            "DisconnectNamedPipe": ([wintypes.HANDLE], wintypes.BOOL),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.kernel, name)
            function.argtypes, function.restype = args, result

    def operation(self, handle, operation, *, buffer=None, timeout=8, stop=None):
        event = self.kernel.CreateEventW(None, True, False, None)
        if not event:
            raise ctypes.WinError(ctypes.get_last_error())
        overlapped, count = Overlapped(hEvent=event), wintypes.DWORD()
        try:
            if operation == "connect":
                ok = self.kernel.ConnectNamedPipe(handle, ctypes.byref(overlapped))
            else:
                function = self.kernel.ReadFile if operation == "read" else self.kernel.WriteFile
                ok = function(handle, buffer, len(buffer), ctypes.byref(count), ctypes.byref(overlapped))
            if not ok:
                error = ctypes.get_last_error()
                if operation == "connect" and error == 535:
                    return 0
                if error != 997:
                    raise ctypes.WinError(error)
                deadline = time.monotonic() + timeout
                while self.kernel.WaitForSingleObject(event, 200) != 0:
                    if time.monotonic() >= deadline or (stop is not None and stop.is_set()):
                        self.kernel.CancelIoEx(handle, ctypes.byref(overlapped))
                        self.kernel.GetOverlappedResult(handle, ctypes.byref(overlapped), ctypes.byref(count), True)
                        raise ProxyError("request_timeout", "控制管道请求超时。")
                if not self.kernel.GetOverlappedResult(handle, ctypes.byref(overlapped), ctypes.byref(count), False):
                    raise ctypes.WinError(ctypes.get_last_error())
            return count.value
        finally:
            self.kernel.CloseHandle(event)

    def caller(self, handle):
        self.advapi.ImpersonateNamedPipeClient.argtypes = [wintypes.HANDLE]
        self.advapi.OpenThreadToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL,
                                               ctypes.POINTER(wintypes.HANDLE)]
        self.kernel.GetCurrentThread.restype = wintypes.HANDLE
        pid = wintypes.ULONG()
        if not self.kernel.GetNamedPipeClientProcessId(handle, ctypes.byref(pid)):
            raise ctypes.WinError(ctypes.get_last_error())
        token = wintypes.HANDLE()
        if not self.advapi.ImpersonateNamedPipeClient(handle):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self.advapi.OpenThreadToken(self.kernel.GetCurrentThread(), 8, True, ctypes.byref(token)):
                raise ctypes.WinError(ctypes.get_last_error())
            return pid.value, _token_sid(token)
        finally:
            if token.value:
                self.kernel.CloseHandle(token)
            if not self.advapi.RevertToSelf():
                os._exit(1)  # Never perform privileged work while impersonating.


def serve(broker, stopping):
    api = PipeAPI()
    class Security(ctypes.Structure):
        _fields_ = [("length", wintypes.DWORD), ("descriptor", wintypes.LPVOID), ("inherit", wintypes.BOOL)]
    api.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [wintypes.LPCWSTR,
        wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID), wintypes.LPVOID]
    api.kernel.CreateNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(Security)]
    api.kernel.CreateNamedPipeW.restype = wintypes.HANDLE
    api.kernel.LocalFree.argtypes = [wintypes.HANDLE]
    api.kernel.LocalFree.restype = wintypes.HANDLE
    descriptor = wintypes.LPVOID()
    sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;" + broker.metadata["owner_sid"] + ")"
    if not api.advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    attributes = Security(ctypes.sizeof(Security), descriptor, False)
    name = "\\\\.\\pipe\\" + broker.metadata["pipe_name"]
    watchdog_errors = []
    def monitor():
        while not stopping.wait(.5):
            try:
                broker.check_lease()
            except Exception as exc:
                _log_service_error("watchdog", exc)
                watchdog_errors.append(exc)
                stopping.set()
    watcher = threading.Thread(target=monitor, daemon=True)
    watcher.start()
    handle = None
    try:
        # Keep the FIRST_PIPE_INSTANCE handle for the service lifetime. A
        # disconnected client's old handle may outlive its ACK; recreating the
        # named pipe then would fail FIRST_PIPE_INSTANCE with access denied.
        handle = api.kernel.CreateNamedPipeW(name, 3 | 0x40000000 | 0x80000,
            4 | 2 | 8, 1, policy.MAX_MESSAGE, policy.MAX_MESSAGE, 0, ctypes.byref(attributes))
        if handle == ctypes.c_void_p(-1).value:
            error = ctypes.get_last_error()
            handle = None
            raise ctypes.WinError(error)
        while not stopping.is_set():
            try:
                request = {}
                try:
                    api.operation(handle, "connect", timeout=3600, stop=stopping)
                    data = ctypes.create_string_buffer(policy.MAX_MESSAGE + 1)
                    count = api.operation(handle, "read", buffer=data, stop=stopping)
                    request = policy.decode_request(data.raw[:count])
                    pid, sid = api.caller(handle)
                    result = broker.handle(request, pid, sid)
                    response = {"schema_version": 1, "request_id": request["request_id"], "ok": True, "result": result}
                except Exception as exc:
                    response = {"schema_version": 1, "request_id": locals().get("request", {}).get("request_id"),
                        "ok": False, "code": getattr(exc, "code", "backend_error"), "message": str(exc)[:1500]}
                if not stopping.is_set():
                    raw = json.dumps(response, ensure_ascii=True).encode("ascii")
                    api.operation(handle, "write", buffer=ctypes.create_string_buffer(raw, len(raw)), stop=stopping)
                    acknowledgement = ctypes.create_string_buffer(1)
                    api.operation(handle, "read", buffer=acknowledgement, timeout=2, stop=stopping)
            except (OSError, ProxyError):
                pass
            finally:
                api.kernel.DisconnectNamedPipe(handle)
    finally:
        stopping.set()
        watcher.join(timeout=2)
        try:
            with broker.lock:
                if hasattr(broker, "shutdown"):
                    broker.shutdown()
                elif broker.panel is not None:
                    broker.stop()
        finally:
            if handle is not None:
                api.kernel.CloseHandle(handle)
            api.kernel.LocalFree(descriptor)
    if watchdog_errors:
        raise RuntimeError("Service watchdog failed") from watchdog_errors[0]


def service_main():
    _windows()
    root = Path(__file__).resolve().parent.parent
    stopping = threading.Event()
    advapi = _dll("advapi32")
    handler_type = ctypes.WINFUNCTYPE(wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID)
    main_type = ctypes.WINFUNCTYPE(None, wintypes.DWORD, ctypes.POINTER(wintypes.LPWSTR))
    class Status(ctypes.Structure):
        _fields_ = [(name, wintypes.DWORD) for name in ("type", "state", "accepted", "exit", "specific", "checkpoint", "hint")]
    class Entry(ctypes.Structure):
        _fields_ = [("name", wintypes.LPWSTR), ("main", main_type)]
    advapi.RegisterServiceCtrlHandlerExW.argtypes = [wintypes.LPCWSTR, handler_type, wintypes.LPVOID]
    advapi.RegisterServiceCtrlHandlerExW.restype = wintypes.HANDLE
    advapi.SetServiceStatus.argtypes = [wintypes.HANDLE, ctypes.POINTER(Status)]
    advapi.StartServiceCtrlDispatcherW.argtypes = [ctypes.POINTER(Entry)]
    status_handle = None
    def report(state, exit_code=0):
        if status_handle:
            status = Status(0x10, state, 1 | 4 if state == 4 else 0, exit_code, 0,
                            1 if state in (2, 3) else 0, 20000 if state in (2, 3) else 0)
            advapi.SetServiceStatus(status_handle, ctypes.byref(status))
    @handler_type
    def handler(control, _event, _data, _context):
        if control in (1, 5):
            report(3)
            stopping.set()
        return 0
    @main_type
    def main(_argc, _argv):
        nonlocal status_handle
        status_handle = advapi.RegisterServiceCtrlHandlerExW(policy.SERVICE_NAME, handler, None)
        if not status_handle:
            _log_service_error("service_register", ctypes.WinError(ctypes.get_last_error()))
            return
        report(2)
        try:
            metadata = load_deployment(root)
            control = ServiceControl()
            control.verify(metadata)
            broker = Broker(metadata, control)
            broker.recover_containers()
            broker.recover_namespaces()
            report(4)
            serve(broker, stopping)
            report(1)
        except Exception as exc:
            _log_service_error("service_main", exc)
            report(1, 1064)
    entries = (Entry * 2)(Entry(policy.SERVICE_NAME, main), Entry(None, main_type()))
    if not advapi.StartServiceCtrlDispatcherW(entries):
        error = ctypes.WinError(ctypes.get_last_error())
        _log_service_error("service_dispatcher", error)
        raise error


if __name__ == "__main__":
    if sys.argv[1:] != ["--service"]:
        raise SystemExit("Use the installed RuleProxyControl service.")
    service_main()
