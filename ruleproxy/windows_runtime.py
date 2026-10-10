"""Strict MXC 1.0.0 Model 3 integration for Windows proxy launches.

The selected application runs under an explicit deny-all BaseContainer policy.
This module never installs firewall rules or downloads runtime dependencies;
the caller supplies the MXC executable path.
"""

from __future__ import annotations

import json
import os
import re
import socket
import shutil
import subprocess
import sys
import tempfile
import time
import threading
import ctypes
from ctypes import wintypes
from pathlib import Path, PureWindowsPath
from typing import Any, Mapping, Sequence


CONTRACT_VERSION = "1.0.0"
MIN_PROCESS_BUILD = 26100  # Windows 11 24H2; exact support is confirmed by MXC --probe.
PROBE_TIMEOUT_SECONDS = 20
_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_ENV_KEY_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class UnsupportedRuntimeError(RuntimeError):
    """Raised when strict MXC ProcessContainer support cannot be proven."""


class SafeStopError(RuntimeError):
    """Raised when stopping could not be completed without killing MXC itself."""


class _ProcessEntry32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class _FileTime(ctypes.Structure):
    _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]


def _raw_handle(handle: Any) -> int:
    value = getattr(handle, "value", None)
    return int(value if value is not None else handle)


class _WinProcessApi:
    """Small Toolhelp/process-handle API surface used by safe wrapper stop."""

    TH32CS_SNAPPROCESS = 0x00000002
    PROCESS_TERMINATE = 0x0001
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    SYNCHRONIZE = 0x00100000
    PROCESS_ACCESS = PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE
    WAIT_OBJECT_0 = 0
    WAIT_TIMEOUT = 258
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    def __init__(self) -> None:
        if os.name != "nt":
            raise SafeStopError("safe MXC stop is available only on Windows")
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k = self.kernel32
        k.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        k.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        k.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
        k.Process32FirstW.restype = wintypes.BOOL
        k.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(_ProcessEntry32W)]
        k.Process32NextW.restype = wintypes.BOOL
        k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        k.OpenProcess.restype = wintypes.HANDLE
        k.GetProcessTimes.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),
            ctypes.POINTER(_FileTime),
        ]
        k.GetProcessTimes.restype = wintypes.BOOL
        k.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
        k.TerminateProcess.restype = wintypes.BOOL
        k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k.WaitForSingleObject.restype = wintypes.DWORD
        k.CloseHandle.argtypes = [wintypes.HANDLE]
        k.CloseHandle.restype = wintypes.BOOL

    def _creation_time(self, handle: int) -> int:
        created, exited, kernel, user = _FileTime(), _FileTime(), _FileTime(), _FileTime()
        if not self.kernel32.GetProcessTimes(
            handle,
            ctypes.byref(created),
            ctypes.byref(exited),
            ctypes.byref(kernel),
            ctypes.byref(user),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        return (int(created.dwHighDateTime) << 32) | int(created.dwLowDateTime)

    def process_creation_time(self, handle: int) -> int:
        return self._creation_time(handle)

    def process_alive(self, handle: int) -> bool:
        result = self.kernel32.WaitForSingleObject(handle, 0)
        if result == self.WAIT_TIMEOUT:
            return True
        if result == self.WAIT_OBJECT_0:
            return False
        raise ctypes.WinError(ctypes.get_last_error())

    def _snapshot_parent_ids(self) -> dict[int, int]:
        snapshot = self.kernel32.CreateToolhelp32Snapshot(self.TH32CS_SNAPPROCESS, 0)
        if snapshot == self.INVALID_HANDLE_VALUE:
            raise ctypes.WinError(ctypes.get_last_error())
        parents: dict[int, int] = {}
        try:
            entry = _ProcessEntry32W()
            entry.dwSize = ctypes.sizeof(entry)
            ok = self.kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            if not ok:
                raise ctypes.WinError(ctypes.get_last_error())
            while ok:
                parents[int(entry.th32ProcessID)] = int(entry.th32ParentProcessID)
                ok = self.kernel32.Process32NextW(snapshot, ctypes.byref(entry))
            error = ctypes.get_last_error()
            if error not in (0, 18):  # ERROR_NO_MORE_FILES
                raise ctypes.WinError(error)
            return parents
        finally:
            self.kernel32.CloseHandle(snapshot)

    def direct_children(self, parent_pid: int, parent_created: int) -> list[tuple[int, int]]:
        # A process ID from one Toolhelp snapshot is not sufficient: the child
        # can exit and its PID can be reused before OpenProcess. Re-enumerate
        # after opening candidate handles, then reopen and compare creation
        # times so the held terminate handle is for the currently listed child.
        first = self._snapshot_parent_ids()
        candidates: dict[int, tuple[int, int]] = {}
        verified: list[tuple[int, int]] = []
        keep_verified = False
        try:
            for pid, reported_parent in first.items():
                if pid == parent_pid or reported_parent != parent_pid:
                    continue
                handle = self.kernel32.OpenProcess(self.PROCESS_ACCESS, False, pid)
                if not handle:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    created = self._creation_time(handle)
                    if created >= parent_created:
                        candidates[pid] = (created, _raw_handle(handle))
                        handle = None
                finally:
                    if handle:
                        self.kernel32.CloseHandle(handle)

            second = self._snapshot_parent_ids()
            for pid, (created, old_handle) in list(candidates.items()):
                if second.get(pid) != parent_pid:
                    continue
                current_handle = self.kernel32.OpenProcess(self.PROCESS_ACCESS, False, pid)
                if not current_handle:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    if self._creation_time(current_handle) != created:
                        # PID changed identity between the two snapshots.
                        # Leave everything untouched; caller may re-enumerate.
                        return []
                    self.kernel32.CloseHandle(old_handle)
                    candidates.pop(pid)
                    verified.append((pid, _raw_handle(current_handle)))
                    current_handle = None
                finally:
                    if current_handle:
                        self.kernel32.CloseHandle(current_handle)
            keep_verified = True
            return verified
        finally:
            for _, handle in candidates.values():
                self.kernel32.CloseHandle(handle)
            if not keep_verified:
                for _, handle in verified:
                    self.kernel32.CloseHandle(handle)

    def terminate(self, handle: int) -> None:
        if not self.kernel32.TerminateProcess(handle, 1):
            error = ctypes.get_last_error()
            # It may have exited naturally after enumeration; accept only if
            # this same held process handle is already signaled.
            if self.kernel32.WaitForSingleObject(handle, 0) != self.WAIT_OBJECT_0:
                raise ctypes.WinError(error)

    def wait(self, handle: int, timeout_ms: int) -> bool:
        result = self.kernel32.WaitForSingleObject(handle, timeout_ms)
        if result == self.WAIT_OBJECT_0:
            return True
        if result == self.WAIT_TIMEOUT:
            return False
        raise ctypes.WinError(ctypes.get_last_error())

    def close(self, handle: int) -> None:
        self.kernel32.CloseHandle(handle)


def _validate_proxy_port(proxy_port: int) -> int:
    if isinstance(proxy_port, bool) or not isinstance(proxy_port, int) or not 1 <= proxy_port <= 65535:
        raise ValueError("proxy_port must be an integer from 1 through 65535")
    return proxy_port


def _validate_command(command: Sequence[str]) -> list[str]:
    if not isinstance(command, (list, tuple)) or not command:
        raise ValueError("command must be a non-empty list of strings")
    result: list[str] = []
    total = 0
    if len(command) > 128:
        raise ValueError("command exceeds the 128 argument limit")
    for arg in command:
        if not isinstance(arg, str) or not arg or "\0" in arg:
            raise ValueError("command arguments must be non-empty strings without NUL characters")
        total += len(arg)
        result.append(arg)
    if total > 16384:
        raise ValueError("command exceeds the 16384 character limit")
    return result


def _validate_env(env: Mapping[str, str] | None, proxy_port: int) -> dict[str, str]:
    if env is None:
        env = {}
    if not isinstance(env, Mapping):
        raise ValueError("env must be a mapping of names to string values")
    result: dict[str, str] = {}
    for key, value in env.items():
        if not isinstance(key, str) or not _ENV_KEY_RE.fullmatch(key):
            raise ValueError(f"invalid environment variable name: {key!r}")
        if not isinstance(value, str) or "\0" in value:
            raise ValueError(f"invalid environment value for {key}")
        result[key] = value

    # The contained application points at the guest helper's local listener.
    endpoint = f"http://127.0.0.1:{proxy_port}"
    result.update(
        {
            "HTTP_PROXY": endpoint,
            "HTTPS_PROXY": endpoint,
            "ALL_PROXY": endpoint,
            "http_proxy": endpoint,
            "https_proxy": endpoint,
            "all_proxy": endpoint,
            "NO_PROXY": "",
            "no_proxy": "",
        }
    )
    return result


def _safe_app_id(profile: Path) -> str:
    app_id = Path(profile).name
    if not _ID_RE.fullmatch(app_id) or app_id in {".", ".."}:
        raise ValueError("profile directory must end in a safe saved application id")
    return app_id


def _exe_parent(executable: str) -> str:
    """Return the executable's containing directory in host path syntax.

    PureWindowsPath keeps Windows paths testable on non-Windows hosts, while
    the real Windows process uses Path.resolve() for a canonical ACL path.
    """
    if os.name == "nt":
        return str(Path(executable).expanduser().resolve().parent)
    windows_path = PureWindowsPath(executable)
    if windows_path.drive or "\\" in executable:
        return str(windows_path.parent)
    return str(Path(executable).expanduser().resolve().parent)


def _profile_environment(env: Mapping[str, str], profile: Path) -> dict[str, str]:
    """Keep inherited variables, but relocate app-writable Windows locations.

    Environment names are case-insensitive on Windows. Canonicalizing them
    avoids duplicate TEMP/temp entries where one might otherwise win.
    """
    by_upper: dict[str, tuple[str, str]] = {}
    for key, value in env.items():
        by_upper[key.upper()] = (key.upper(), value)

    local = profile / "localappdata"
    roaming = profile / "appdata"
    temp = profile / "temp"
    home = profile / "home"
    for directory in (local, roaming, temp, home):
        directory.mkdir(parents=True, exist_ok=True)

    replacements = {
        "APPDATA": str(roaming),
        "LOCALAPPDATA": str(local),
        "TEMP": str(temp),
        "TMP": str(temp),
        "USERPROFILE": str(home),
        "HOME": str(home),
    }
    for key, value in replacements.items():
        by_upper[key] = (key, value)

    # HOMEDRIVE/HOMEPATH are still consulted by some Win32 applications even
    # when USERPROFILE is present. Keep them on the same isolated profile.
    drive, tail = os.path.splitdrive(str(home))
    if not drive and os.name != "nt":
        windows_home = PureWindowsPath(str(home))
        drive, tail = windows_home.drive, str(windows_home)[len(windows_home.drive):]
    if drive:
        by_upper["HOMEDRIVE"] = ("HOMEDRIVE", drive)
        by_upper["HOMEPATH"] = ("HOMEPATH", tail or "\\")

    return {key: value for key, value in by_upper.values()}


def build_policy(
    command: Sequence[str],
    env: Mapping[str, str] | None,
    profile: Path,
    guest_listener_port: int,
    *,
    python_executable: str | Path | None = None,
    guest_helper: str | Path | None = None,
    runtime_config: str | Path | None = None,
) -> dict[str, Any]:
    """Build an explicit Model 3 deny-all policy around the trusted guest helper."""
    command = _validate_command(command)
    guest_listener_port = _validate_proxy_port(guest_listener_port)
    environment = _validate_env(env, guest_listener_port)
    profile = Path(profile).expanduser().resolve()
    app_id = _safe_app_id(profile)
    profile.mkdir(parents=True, exist_ok=True)
    environment = _profile_environment(environment, profile)
    python_executable = Path(python_executable or sys.executable).expanduser().resolve()
    guest_helper = Path(guest_helper or Path(__file__).with_name("windows_guest.py")).resolve()
    runtime_config = Path(runtime_config or profile / ".ruleproxy-runtime.json").resolve()
    app_executable_dir = _exe_parent(command[0])
    python_base = Path(getattr(sys, "base_prefix", python_executable.parent)).resolve()
    read_only = {
        str(python_executable.parent),
        str(python_base),
        str(guest_helper.parent),
        str(Path(app_executable_dir)),
    }
    try:
        runtime_config.parent.relative_to(profile)
    except ValueError:
        read_only.add(str(runtime_config.parent))
    helper_command = [
        str(python_executable),
        "-I",
        "-S",
        str(guest_helper),
        "--config",
        str(runtime_config),
    ]
    command_line = subprocess.list2cmdline(helper_command)
    return {
        "$schema": "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.1.0.0.json",
        "version": CONTRACT_VERSION,
        "containment": "processcontainer",
        "containerId": f"ruleproxy-{app_id}",
        "process": {
            "commandLine": command_line,
            "cwd": str(profile),
            "env": [f"{key}={value}" for key, value in sorted(environment.items())],
            "inheritDefaultEnv": True,
        },
        "filesystem": {
            "readonlyPaths": sorted(read_only),
            "readwritePaths": [str(profile)],
        },
        # MXC 1.0.0 defaults visible UI to disabled. Opt into visible windows
        # while retaining the ProcessContainer's default handle isolation.
        "ui": {"disable": False},
        "processContainer": {"ui": {"isolation": "container"}},
        "network": {
            "egress": {"default": "deny"},
            "ingress": {"default": "deny", "hostLoopback": "deny"},
        },
    }


def _write_policy(policy: Mapping[str, Any], directory: Path) -> Path:
    path = directory / "mxc-policy.json"
    path.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def _check_windows_version(
    platform_name: str | None = None,
    version: tuple[int, int] | None = None,
) -> None:
    """Reject Windows 10 and pre-24H2 Windows 11 before invoking MXC."""
    platform_name = sys.platform if platform_name is None else platform_name
    if platform_name != "win32":
        raise UnsupportedRuntimeError("strict MXC ProcessContainer launch is Windows-only")
    if version is None:
        try:
            current = sys.getwindowsversion()
            version = (int(current.major), int(current.build))
        except (AttributeError, OSError, ValueError) as exc:
            raise UnsupportedRuntimeError("could not determine the Windows version") from exc
    major, build = version
    if major != 10 or build < MIN_PROCESS_BUILD:
        raise UnsupportedRuntimeError(
            "strict proxy mode requires Windows 11 24H2 (build 26100) or newer; Windows 10 and older Windows 11 releases are unsupported"
        )


def _probe_request(
    runtime_path: str | Path,
    policy: Mapping[str, Any],
    *,
    runner: Any | None = None,
    platform_name: str | None = None,
    version: tuple[int, int] | None = None,
) -> dict[str, Any]:
    _check_windows_version(platform_name, version)
    if runner is None:
        runner = subprocess.run
    runtime = Path(runtime_path).expanduser()
    if not runtime.is_file():
        raise UnsupportedRuntimeError("configured MXC runtime executable does not exist")
    with tempfile.TemporaryDirectory(prefix="ruleproxy-mxc-probe-") as temp:
        config_path = _write_policy(policy, Path(temp))
        try:
            result = runner(
                [str(runtime), "--probe", "--config", str(config_path)],
                capture_output=True,
                text=True,
                timeout=PROBE_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise UnsupportedRuntimeError(f"MXC support probe failed: {exc}") from exc
    if result.returncode != 0:
        raise UnsupportedRuntimeError(
            f"MXC support probe exited with status {result.returncode}: {result.stderr.strip()}"
        )
    try:
        output = json.loads(result.stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise UnsupportedRuntimeError("MXC support probe returned invalid JSON") from exc
    if not isinstance(output, dict) or not isinstance(output.get("probes"), dict):
        raise UnsupportedRuntimeError("MXC support probe returned an incomplete response")
    if output.get("error") is not None:
        raise UnsupportedRuntimeError(f"MXC rejected the strict request: {output['error']}")
    if output.get("tier") != "base-container":
        raise UnsupportedRuntimeError(
            f"MXC selected {output.get('tier')!r}; strict proxy mode requires base-container"
        )
    if output["probes"].get("baseContainerApiPresent") is not True:
        raise UnsupportedRuntimeError("MXC did not confirm the BaseContainer API set")
    if output.get("needsDaclAugmentation") is not False:
        raise UnsupportedRuntimeError("MXC probe did not confirm an unaugmented BaseContainer request")
    return output


def probe(
    runtime_path: str,
    proxy_port: int = 10809,
) -> dict[str, Any]:
    """Probe Model 3 BaseContainer availability; this does not run socket checks."""
    limitations = [
        "当前结果表示系统具备隔离能力；实际阻断还需在启动时检查。",
        "仅面板启动的实例受保护；启动检查失败就拒绝启动。",
        "应用使用独立配置，代理通道吞吐可能低于普通代理。",
    ]
    try:
        _validate_proxy_port(proxy_port)
        with tempfile.TemporaryDirectory(prefix="ruleproxy-probe-profile-") as temp:
            profile = Path(temp) / "probe"
            profile.mkdir()
            policy = build_policy(
                [r"C:\Windows\System32\whoami.exe"],
                {},
                profile,
                49152,
            )
            output = _probe_request(runtime_path, policy)
        warnings = output.get("warnings") or []
        return {
            "supported": True,
            "backend": output.get("tier"),
            "detail": "系统支持全拒绝网络隔离。应用启动前会检查代理通道及实际阻断。",
            "limitations": limitations + list(warnings),
        }
    except (ValueError, UnsupportedRuntimeError) as exc:
        return {
            "supported": False,
            "backend": None,
            "detail": "此设备当前不能启用严格隔离。 " + str(exc),
            "limitations": limitations,
        }


def launch(
    command: list[str],
    env: dict[str, str],
    profile: Path,
    proxy_port: int,
    runtime_path: str,
    *,
    guest_listener_port: int | None = None,
) -> tuple[subprocess.Popen, Any]:
    """Launch the trusted guest helper, gate the app on deny-all self-checks."""
    host_proxy_port = _validate_proxy_port(proxy_port)
    guest_listener_port = guest_listener_port or choose_guest_port(host_proxy_port)
    guest_listener_port = _validate_proxy_port(guest_listener_port)
    if guest_listener_port == host_proxy_port:
        raise ValueError("guest listener and host proxy ports must differ")
    command = _validate_command(command)
    env = _validate_env(env, guest_listener_port)
    profile = Path(profile).expanduser().resolve()
    _safe_app_id(profile)
    _require_guest_endpoint(command, env, profile, guest_listener_port)
    runtime = Path(runtime_path).expanduser().resolve(strict=True)
    helper = Path(__file__).with_name("windows_guest.py").resolve(strict=True)
    python_executable = Path(sys.executable).expanduser().resolve(strict=True)
    profile.mkdir(parents=True, exist_ok=True)

    try:
        from .file_bridge import FileProxyBridge
    except ImportError as exc:
        raise UnsupportedRuntimeError("the strict Windows file bridge is unavailable") from exc

    bridge_dir = profile / ".ruleproxy-bridge"
    bridge_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    run_dir = tempfile.TemporaryDirectory(prefix="ruleproxy-mxc-run-")
    fixture = _HostLoopbackFixture()
    bridge = None
    process = None
    resources = _WindowsRuntimeResources(run_dir, fixture, bridge)
    try:
        policy = build_policy(
            command,
            env,
            profile,
            guest_listener_port,
            python_executable=python_executable,
            guest_helper=helper,
            runtime_config=Path(run_dir.name) / "guest-config.json",
        )
        _probe_request(runtime, policy)
        bridge = FileProxyBridge(host_proxy_port, bridge_dir)
        resources.bridge = bridge
        fixture.start()
        app_environment = _profile_environment(env, profile)
        guest_config = {
            "command": command,
            "env": app_environment,
            "profile": str(profile),
            "listener_port": guest_listener_port,
            "bridge_directory": str(bridge.directory),
            "bridge_nonce": bridge.nonce,
            "host_fixture_port": fixture.port,
        }
        config_path = Path(run_dir.name) / "guest-config.json"
        config_path.write_text(json.dumps(guest_config, ensure_ascii=False), encoding="utf-8")
        runtime_config = _profile_environment(os.environ.copy(), profile)
        process = subprocess.Popen(
            [str(runtime), "--config", str(_write_policy(policy, Path(run_dir.name)))],
            env=runtime_config,
            shell=False,
        )
        resources.process = process

        if not bridge.wait_ready(25):
            raise UnsupportedRuntimeError(
                getattr(bridge, "last_error", None) or "contained guest self-check did not become ready"
            )
        if _host_can_reach_guest(guest_listener_port):
            bridge.reject("host-to-guest loopback check was reachable")
            raise UnsupportedRuntimeError("host unexpectedly reached the contained guest listener")
        if fixture.accepted.is_set():
            bridge.reject("guest reached a non-proxy host loopback fixture")
            raise UnsupportedRuntimeError("contained guest unexpectedly reached a host loopback listener")
        bridge.approve()
        if not _wait_for_status(bridge.directory, bridge.nonce, "APP_STARTED", process, 20):
            raise UnsupportedRuntimeError("contained helper did not confirm application startup")
        resources.detail = (
            "已在 MXC BaseContainer 全拒绝策略中通过代理桥、直连阻断和回环隔离自检。应用与隔离助手共享此应用的配置目录；应用未支持的代理流量会连接失败。"
        )
        return process, resources
    except BaseException as exc:
        if bridge is not None:
            try:
                bridge.reject(str(exc)[:512])
            except Exception:
                pass
        if process is None:
            resources.close()
        else:
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                # Keep the wrapper and resources alive so MXC can complete its
                # normal PSEC teardown; never kill the runtime wrapper here.
                resources.failed_process = process
                resources.detail = str(exc)
                exc.process = process
                exc.resource = resources
                raise
            resources.close()
        raise


def choose_guest_port(host_proxy_port: int) -> int:
    """Return a free, ephemeral loopback port distinct from the host proxy."""
    host_proxy_port = _validate_proxy_port(host_proxy_port)
    for _ in range(16):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.bind(("127.0.0.1", 0))
            port = int(sock.getsockname()[1])
        finally:
            sock.close()
        if port != host_proxy_port:
            return port
    raise UnsupportedRuntimeError("could not select a guest listener port")


def _require_guest_endpoint(command: Sequence[str], env: Mapping[str, str], profile: Path, port: int) -> None:
    endpoint = f"http://127.0.0.1:{port}"
    if not any(value == endpoint for key, value in env.items() if key.upper() in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"}):
        raise ValueError("prepared proxy environment does not point to the guest listener")
    if any(arg.startswith("--proxy-server=") and arg != f"--proxy-server={endpoint}" for arg in command):
        raise ValueError("prepared Chromium proxy endpoint does not match the guest listener")
    if any(arg == f"--proxy-server={endpoint}" for arg in command):
        return
    user_js = Path(profile) / "user.js"
    if user_js.is_file():
        content = user_js.read_text(encoding="utf-8")
        if f'network.proxy.socks_port", {port});' in content:
            return
    if any(key.upper() in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"} and value == endpoint for key, value in env.items()):
        return
    raise ValueError("prepared app has no proxy adapter targeting the guest listener")


class _HostLoopbackFixture:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(4)
        self.sock.settimeout(0.1)
        self.port = int(self.sock.getsockname()[1])
        self.accepted = threading.Event()
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        def accept_loop() -> None:
            while not self.stop_event.is_set():
                try:
                    connection, _ = self.sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                self.accepted.set()
                connection.close()

        self.thread = threading.Thread(target=accept_loop, name="RuleProxyLoopbackFixture", daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.stop_event.set()
        try:
            self.sock.close()
        except OSError:
            pass
        if self.thread:
            self.thread.join(timeout=1)


def _host_can_reach_guest(port: int) -> bool:
    try:
        connection = socket.create_connection(("127.0.0.1", port), timeout=0.5)
    except OSError:
        return False
    connection.close()
    return True


def _wait_for_status(directory: Path, nonce: str, state: str, process: Any, timeout: float) -> bool:
    status = Path(directory) / "guest-status.json"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return False
        try:
            with status.open("rb") as stream:
                raw = stream.read(1025)
            if len(raw) > 1024:
                return False
            value = json.loads(raw.decode("ascii"))
            if value.get("nonce") == nonce and value.get("state") == state:
                return True
            if value.get("nonce") == nonce and value.get("state") == "FAILED":
                return False
        except (OSError, json.JSONDecodeError, AttributeError):
            pass
        time.sleep(0.05)
    return False


class _WindowsRuntimeResources:
    def __init__(self, run_dir: tempfile.TemporaryDirectory[str], fixture: _HostLoopbackFixture, bridge: Any = None) -> None:
        self.run_dir = run_dir
        self.fixture = fixture
        self.bridge = bridge
        self.process = None
        self.failed_process = None
        self.detail = ""
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        if self.process is not None and self.process.poll() is None:
            raise SafeStopError("cannot release runtime resources while MXC wrapper is still running")
        bridge_dir = Path(self.bridge.directory) if self.bridge is not None else None
        error: Exception | None = None
        try:
            if self.bridge is not None:
                self.bridge.close()
        except Exception as exc:
            error = exc
        if error is not None:
            # Keep the bridge and its directory available for a later retry.
            # The temporary policy/config and host fixture are independent and
            # can be released even if bridge teardown itself failed.
            self.fixture.close()
            self.run_dir.cleanup()
            raise error
        if bridge_dir is not None:
            shutil.rmtree(bridge_dir, ignore_errors=True)
        self.fixture.close()
        self.run_dir.cleanup()
        self._closed = True


def _stop_with_api(
    process: Any,
    api: Any,
    *,
    timeout: float,
    poll_interval: float,
) -> None:
    """Stop the direct MXC workload and let its wrapper perform teardown."""
    if process.poll() is not None:
        process.wait(timeout=0)
        return
    wrapper_handle = getattr(process, "_handle", None)
    if wrapper_handle is None:
        raise SafeStopError("MXC wrapper has no verifiable Windows process handle")
    try:
        wrapper_created = api.process_creation_time(_raw_handle(wrapper_handle))
    except Exception as exc:
        raise SafeStopError(f"could not verify MXC wrapper creation time: {exc}") from exc

    deadline = time.monotonic() + timeout
    while True:
        if process.poll() is not None:
            process.wait(timeout=0)
            return
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SafeStopError(
                "no safely verifiable direct workload child appeared before timeout; "
                "MXC wrapper was left running"
            )
        try:
            children = api.direct_children(int(process.pid), wrapper_created)
        except Exception as exc:
            raise SafeStopError(
                f"could not safely enumerate MXC workload child processes; wrapper was left running: {exc}"
            ) from exc

        if process.poll() is not None or not api.process_alive(_raw_handle(wrapper_handle)):
            for _, handle in children:
                api.close(handle)
            process.wait(timeout=0)
            return

        if len(children) > 1:
            for _, handle in children:
                api.close(handle)
            raise SafeStopError(
                "multiple verified direct children make the MXC workload ambiguous; wrapper was left running"
            )
        if not children:
            time.sleep(min(poll_interval, remaining))
            continue

        _, child_handle = children[0]
        try:
            api.terminate(child_handle)
            remaining = max(0.0, deadline - time.monotonic())
            if not api.wait(child_handle, int(remaining * 1000)):
                raise SafeStopError(
                    "MXC workload child did not exit after termination; wrapper was left running"
                )
        except SafeStopError:
            raise
        except Exception as exc:
            raise SafeStopError(
                f"could not terminate or wait for verified MXC workload child; wrapper was left running: {exc}"
            ) from exc
        finally:
            api.close(child_handle)

        remaining = max(0.0, deadline - time.monotonic())
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            raise SafeStopError(
                "MXC wrapper did not complete its normal teardown after workload exit; "
                "wrapper was left running"
            ) from exc
        return


def stop(process: subprocess.Popen, timeout: float = 15.0) -> None:
    """Stop an MXC-owned workload while leaving cleanup to MXC itself.

    MXC v1.0.0 launches the BaseContainer workload with `CreateProcessW` from
    the runtime process. This terminates only that verified direct child, then
    waits for MXC's normal wait path to kill any job descendants and close the
    Process Security Environment. This function never terminates the runtime
    wrapper. If enumeration, identity checks, or normal teardown fail, it
    raises `SafeStopError` and leaves the wrapper available for manual recovery.
    """
    if sys.platform != "win32" or os.name != "nt":
        raise SafeStopError("safe MXC stop is available only on Windows")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("timeout must be a positive number of seconds")
    try:
        _stop_with_api(process, _WinProcessApi(), timeout=float(timeout), poll_interval=0.05)
    except SafeStopError:
        raise
    except Exception as exc:
        raise SafeStopError(f"safe MXC stop failed; wrapper was left running: {exc}") from exc
