"""Installed LocalSystem broker. It controls one fixed engine, never applications.

SCM entry: protected python.exe -I -S this-file --service. All Windows APIs are
loaded lazily so the policy and lifecycle logic can be tested on other hosts.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import threading
import time
import traceback

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


def protected_path(path: Path):
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
            if mask & 0x500D0156 and _sid_text(ace.value + 8) not in trusted:
                raise ProxyError("unsafe_installation", "普通用户不能改写管理员运行组件。")
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


class Broker:
    def __init__(self, metadata, control=None, lease_factory=None):
        self.metadata = metadata
        self.control = control or ServiceControl()
        self.lease_factory = lease_factory or ProcessLease
        self.lock = threading.RLock()
        self.panel = self.core = None
        self.generation = 0
        self.paths = []
        self.port = None
        self.error = None

    def snapshot(self):
        engine_running = self.control.status()["state"] == 4
        state = ("running" if self.panel else "external_conflict") if engine_running else (
            "failed" if self.panel or self.error else "idle")
        return {"backend": "ProxiFyre", "mode": "application_proxy", "strict_isolation": False,
            "state": state, "running": engine_running and self.panel is not None,
            "engine_running": engine_running, "generation": self.generation,
            "owner_pid": self.panel.pid if self.panel else None, "path_count": len(self.paths),
            "proxy_port": self.port, "limitations": list(policy.LIMITATIONS), "error": self.error}

    def _clear(self):
        for process in (self.panel, self.core):
            if process:
                process.close()
        self.panel = self.core = None
        self.paths, self.port = [], None

    def stop(self):
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

    def handle(self, request, caller_pid, caller_sid):
        with self.lock:
            if caller_sid != self.metadata["owner_sid"] or request["client_pid"] != caller_pid:
                raise ProxyError("access_denied", "控制请求身份不匹配。")
            self.check_lease()
            if request["op"] == "status":
                return self.snapshot()
            if self.panel and self.panel.pid != caller_pid:
                raise ProxyError("instance_conflict", "另一面板正在管理 Windows 代理。")
            if request["op"] == "stop":
                if self.panel is None:
                    return {"stopped": True, "not_owned": True, "generation": self.generation}
                return self.stop()
            if request["generation"] != self.generation + 1:
                raise ProxyError("generation_conflict", "配置状态已改变，请刷新后重试。")
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
                if broker.panel is not None:
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
