"""MXC ProcessContainer integration with a single kernel-scoped proxy endpoint.

The selected application runs in a BaseContainer with direct egress denied.
Only the configured loopback proxy is permitted by the PSEC proxy policy.
This module never installs firewall rules or downloads runtime dependencies;
the caller supplies the MXC executable path.
"""

from __future__ import annotations

import json
import os
import re
import socket
import shutil
import secrets
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

    # The application and kernel policy use the same host proxy endpoint.
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
    proxy_port: int,
    *,
    python_executable: str | Path | None = None,
    guest_helper: str | Path | None = None,
    runtime_config: str | Path | None = None,
) -> dict[str, Any]:
    """Build the PSEC proxy policy around the trusted startup gate.

    Host loopback allow is required by an unpackaged proxy. It is not a
    general egress allowance: the native proxy policy restricts outgoing
    sockets to this exact address and port. Never add egress allow rules.
    """
    command = _validate_command(command)
    proxy_port = _validate_proxy_port(proxy_port)
    environment = _validate_env(env, proxy_port)
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
            "ingress": {"default": "allow", "hostLoopback": "allow"},
        },
        "runtimeConfig": {"networkProxy": f"http://127.0.0.1:{proxy_port}"},
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


# MXC's plm.exe serves only its elevated denial-capture diagnostics, which this tool
# never requests. MXC 1.0.0 nevertheless vets plm.exe during every probe and panics when
# the first folder of its path starts with a non-ASCII character (C:\应用\…), because it
# slices the path at byte 4. Without plm.exe the probe skips that check.
UNUSED_RUNTIME_FILES = ("plm.exe",)
_PATH_PANIC = "is not a char boundary"


def retire_unused_runtime_files(directory: Path) -> None:
    """Remove runtime files this tool never uses that an older package or setup left behind."""
    for name in UNUSED_RUNTIME_FILES:
        try:
            (Path(directory) / name).unlink(missing_ok=True)
        except OSError:
            pass


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
            # MXC writes UTF-8. The default locale decoding (GBK on Chinese Windows) fails on it,
            # and a failed decode leaves the output empty.
            result = runner(
                [str(runtime), "--probe", "--config", str(config_path)],
                capture_output=True,
                encoding="utf-8",
                errors="replace",
                timeout=PROBE_TIMEOUT_SECONDS,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise UnsupportedRuntimeError(f"MXC support probe failed: {exc}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if _PATH_PANIC in detail:
            raise UnsupportedRuntimeError(
                "MXC 1.0.0 在顶层文件夹名以中文等非英文字符开头的位置（如 C:\\应用\\…）检查失败，这是 MXC 自身的问题。"
                "请把 RuleProxy-Web 文件夹移到如 C:\\RuleProxy-Web 的位置，再重新打开面板。"
                f"原始信息：{detail[:400]}"
            )
        raise UnsupportedRuntimeError(
            f"MXC support probe exited with status {result.returncode}" + (f": {detail[:600]}" if detail else "")
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
        if output["probes"].get("baseContainerApiPresent") is not True:
            raise UnsupportedRuntimeError(
                f"系统没有提供 BaseContainer 接口，MXC 只能选择 {output.get('tier')!r}，严格模式不接受。"
                "需要 Windows 11 24H2（26100.9278 及以后）或 25H2（26200.9278 及以后），请在 Windows 更新中装好最新更新。"
            )
        raise UnsupportedRuntimeError(
            f"MXC selected {output.get('tier')!r}; strict proxy mode requires base-container"
        )
    if output["probes"].get("baseContainerApiPresent") is not True:
        raise UnsupportedRuntimeError("MXC did not confirm the BaseContainer API set")
    if output.get("needsDaclAugmentation") is not False:
        raise UnsupportedRuntimeError("MXC probe did not confirm an unaugmented BaseContainer request")
    if policy.get("runtimeConfig", {}).get("networkProxy"):
        facts = output["probes"]
        if not (facts.get("baseContainerSupportsIdentitylessLoopbackProxy") is True
                or facts.get("baseContainerSupportsIngressHostLoopbackAllow") is True):
            raise UnsupportedRuntimeError(
                "运行组件未确认指定回环代理的内核支持。请使用本版本配套的 MXC 组件，并安装最新 Windows 更新。"
            )
    return output


def probe(
    runtime_path: str,
    proxy_port: int = 10809,
) -> dict[str, Any]:
    """Probe the actual proxy policy, without launching a workload."""
    limitations = [
        "当前结果表示系统具备隔离能力；实际阻断还需在启动时检查。",
        "仅从面板或快捷方式启动的实例受保护；启动检查失败就拒绝启动。",
        "应用使用独立配置，仅允许连接指定本机代理；不支持的网络流量会失败。",
        "本机代理没有容器身份绑定；本工具保护正常应用的直连行为，不防御同一用户下的恶意代理替换。",
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
                proxy_port,
            )
            output = _probe_request(runtime_path, policy)
        warnings = output.get("warnings") or []
        return {
            "supported": True,
            "backend": output.get("tier"),
            "detail": "系统支持指定代理端口的内核网络限制。应用启动前会检查代理通道和实际阻断。",
            "limitations": limitations + list(warnings),
        }
    except (ValueError, UnsupportedRuntimeError) as exc:
        return {
            "supported": False,
            "backend": None,
            "detail": "此设备当前不能启用严格隔离。" + str(exc),
            "limitations": [],
        }


def launch(
    command: list[str],
    env: dict[str, str],
    profile: Path,
    proxy_port: int,
    runtime_path: str,
    *,
    proxy_process: subprocess.Popen | None = None,
) -> tuple[subprocess.Popen, Any]:
    """Start the app only after proxy and controlled bypass checks pass."""
    proxy_port = _validate_proxy_port(proxy_port)
    command = _validate_command(command)
    env = _validate_env(env, proxy_port)
    profile = Path(profile).expanduser().resolve()
    _safe_app_id(profile)
    _require_proxy_endpoint(command, env, profile, proxy_port)
    runtime = Path(runtime_path).expanduser().resolve(strict=True)
    helper = Path(__file__).with_name("windows_guest.py").resolve(strict=True)
    python_executable = Path(sys.executable).expanduser().resolve(strict=True)
    profile.mkdir(parents=True, exist_ok=True)
    # Unique state prevents a previous launch from approving a new workload.
    nonce = secrets.token_hex(32)
    status_dir = profile / ".ruleproxy-runtime" / nonce
    status_dir.mkdir(parents=True)
    run_dir = tempfile.TemporaryDirectory(prefix="ruleproxy-mxc-run-")
    fixture = _HostLoopbackFixture()
    resources = _WindowsRuntimeResources(run_dir, fixture, status_dir)
    process = None
    try:
        policy = build_policy(
            command, env, profile, proxy_port,
            python_executable=python_executable, guest_helper=helper,
            runtime_config=Path(run_dir.name) / "guest-config.json",
        )
        _probe_request(runtime, policy)
        if proxy_process is not None:
            _assert_proxy_owner(proxy_port, proxy_process)
        fixture.start()
        guest_config = {
            "command": command,
            "env": _profile_environment(env, profile),
            "profile": str(profile),
            "proxy_port": proxy_port,
            "status_directory": str(status_dir),
            "nonce": nonce,
            "fixtures": fixture.endpoints,
        }
        (Path(run_dir.name) / "guest-config.json").write_text(
            json.dumps(guest_config, ensure_ascii=False), encoding="utf-8"
        )
        # Keep the full error locally rather than losing it in a hidden console.
        resources.log = (profile / "runtime.log").open("ab")
        process = subprocess.Popen(
            [str(runtime), "--config", str(_write_policy(policy, Path(run_dir.name)))],
            env=_profile_environment(os.environ.copy(), profile), shell=False,
            stdout=resources.log, stderr=subprocess.STDOUT,
        )
        resources.process = process
        _wait_for_status(status_dir, nonce, "READY", process, 30)
        # UDP send() can succeed even when WFP drops the datagram. Require that
        # controlled host receivers observed no packets, not a send() error.
        time.sleep(0.2)
        if fixture.accepted.is_set():
            raise UnsupportedRuntimeError("隔离内的测试流量到达了非代理端口，已拒绝启动应用。")
        if proxy_process is not None:
            _assert_proxy_owner(proxy_port, proxy_process)
        _write_decision(status_dir, nonce, "approved")
        _wait_for_status(status_dir, nonce, "APP_STARTED", process, 20)
        resources.detail = "指定代理通道及子进程阻断检查已通过；仅此容器实例受保护。"
        return process, resources
    except BaseException as exc:
        try:
            _write_decision(status_dir, nonce, "rejected")
        except OSError:
            pass
        if process is not None:
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired:
                # Stop the verified workload, allowing MXC to perform teardown.
                try:
                    stop(process)
                except Exception:
                    resources.failed_process = process
                    resources.detail = str(exc)
                    exc.process, exc.resource = process, resources
                    raise exc
        resources.close()
        raise


def _assert_proxy_owner(port: int, process: subprocess.Popen) -> None:
    """Check that the managed, still-live core owns the exact proxy listener."""
    if process.poll() is not None:
        raise UnsupportedRuntimeError("代理核心在应用启动前退出了，已拒绝启动。")
    if os.name != "nt":
        raise UnsupportedRuntimeError("Windows listener ownership verification is unavailable")
    api = ctypes.WinDLL("iphlpapi", use_last_error=True).GetExtendedTcpTable
    api.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), wintypes.BOOL,
                    wintypes.ULONG, wintypes.ULONG, wintypes.ULONG]
    api.restype = wintypes.DWORD
    size = wintypes.DWORD()
    error = api(None, ctypes.byref(size), False, socket.AF_INET, 3, 0)  # TCP_TABLE_OWNER_PID_LISTENER
    if error not in (0, 122) or not 4 <= size.value <= 1024 * 1024:
        raise UnsupportedRuntimeError(f"无法读取代理监听器的进程归属（{error}）。")
    for _ in range(3):
        buffer = ctypes.create_string_buffer(size.value)
        error = api(buffer, ctypes.byref(size), False, socket.AF_INET, 3, 0)
        if error == 122 and size.value <= 1024 * 1024:
            continue
        if error:
            raise UnsupportedRuntimeError(f"无法确认代理监听器的进程归属（{error}）。")
        owners = _tcp_listener_owners(buffer.raw, port)
        if owners != {int(process.pid)} or process.poll() is not None:
            raise UnsupportedRuntimeError("指定代理端口不属于面板管理的核心，已拒绝启动。")
        return
    raise UnsupportedRuntimeError("监听器状态持续变化，无法安全启动。")


def _tcp_listener_owners(raw: bytes, port: int) -> set[int]:
    import struct
    if len(raw) < 4:
        raise UnsupportedRuntimeError("Windows TCP table is truncated")
    count = struct.unpack_from("<I", raw)[0]
    if count > (len(raw) - 4) // 24:
        raise UnsupportedRuntimeError("Windows TCP table has an invalid row count")
    result = set()
    for index in range(count):
        state, address, local_port, _, _, pid = struct.unpack_from("<6I", raw, 4 + 24 * index)
        # Wildcard listeners are deliberately not accepted as loopback-only.
        if state == 2 and address == 0x0100007F and socket.ntohs(local_port & 0xFFFF) == port:
            result.add(pid)
    return result


def _require_proxy_endpoint(command: Sequence[str], env: Mapping[str, str], profile: Path, port: int) -> None:
    endpoint = f"http://127.0.0.1:{port}"
    if any(arg.startswith("--proxy-server=") and arg != f"--proxy-server={endpoint}" for arg in command):
        raise ValueError("prepared Chromium proxy endpoint does not match the kernel policy")
    # Firefox persists its adapter in user.js rather than a command flag.
    if "-profile" in command:
        user_js = profile / "user.js"
        if not user_js.is_file() or f'network.proxy.socks_port", {port});' not in user_js.read_text(encoding="utf-8"):
            raise ValueError("prepared Firefox proxy endpoint does not match the kernel policy")


def _write_decision(directory: Path, nonce: str, decision: str) -> None:
    path = directory / "host-decision.json"
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps({"nonce": nonce, "decision": decision}), encoding="ascii")
    os.replace(temporary, path)


class _HostLoopbackFixture:
    """Controlled TCP/UDP receivers; a bypass must never reach any receiver."""

    def __init__(self) -> None:
        self.accepted = threading.Event()
        self.stop_event = threading.Event()
        self.sockets: list[socket.socket] = []
        self.threads: list[threading.Thread] = []
        self.endpoints: list[dict[str, Any]] = []
        try:
            for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
                for kind, protocol in ((socket.SOCK_STREAM, "tcp"), (socket.SOCK_DGRAM, "udp")):
                    sock = socket.socket(family, kind)
                    try:
                        if family == socket.AF_INET6:
                            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                        sock.bind((address, 0))
                        if kind == socket.SOCK_STREAM:
                            sock.listen(4)
                        sock.settimeout(0.1)
                    except OSError:
                        sock.close()
                        if family == socket.AF_INET6:
                            continue
                        raise
                    self.sockets.append(sock)
                    self.endpoints.append({"address": address, "port": sock.getsockname()[1], "protocol": protocol})
        except BaseException:
            self.close()
            raise

    def start(self) -> None:
        def receive(sock: socket.socket, protocol: str) -> None:
            while not self.stop_event.is_set():
                try:
                    if protocol == "tcp":
                        connection, _ = sock.accept()
                        connection.close()
                    else:
                        sock.recvfrom(4096)
                    self.accepted.set()
                except socket.timeout:
                    continue
                except OSError:
                    return
        for sock, endpoint in zip(self.sockets, self.endpoints):
            worker = threading.Thread(target=receive, args=(sock, endpoint["protocol"]), daemon=True)
            self.threads.append(worker)
            worker.start()

    def close(self) -> None:
        self.stop_event.set()
        for sock in self.sockets:
            sock.close()
        for worker in self.threads:
            worker.join(timeout=1)


def _wait_for_status(directory: Path, nonce: str, state: str, process: Any, timeout: float) -> None:
    status = directory / "guest-status.json"
    deadline = time.monotonic() + timeout
    last = ""
    while time.monotonic() < deadline:
        try:
            with status.open("rb") as stream:
                raw = stream.read(16_385)
            if len(raw) > 16_384:
                raise UnsupportedRuntimeError("contained status exceeded its size limit")
            value = json.loads(raw.decode("ascii"))
            if isinstance(value, dict) and value.get("nonce") == nonce:
                if (value.get("state") == state or
                        (state == "APP_STARTED" and value.get("state") == "APP_EXITED" and value.get("started") is True)):
                    return
                if value.get("state") == "FAILED":
                    raise UnsupportedRuntimeError("隔离启动检查失败：" + str(value.get("detail", ""))[:1800])
                last = str(value.get("state", ""))
        except (OSError, ValueError):
            pass
        if process.poll() is not None:
            raise UnsupportedRuntimeError(f"隔离助手提前退出（{process.returncode}）。请检查应用配置目录的 runtime.log。")
        time.sleep(0.05)
    raise UnsupportedRuntimeError(f"隔离助手等待 {state} 超时（最后状态 {last or '未返回'}）。")


class _WindowsRuntimeResources:
    def __init__(self, run_dir: tempfile.TemporaryDirectory[str], fixture: _HostLoopbackFixture, status_dir: Path) -> None:
        self.run_dir = run_dir
        self.fixture = fixture
        self.status_dir = status_dir
        self.log = None
        self.process = None
        self.failed_process = None
        self.detail = ""
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        if self.process is not None and self.process.poll() is None:
            raise SafeStopError("cannot release runtime resources while MXC wrapper is still running")
        self.fixture.close()
        if self.log is not None:
            self.log.close()
        self.run_dir.cleanup()
        shutil.rmtree(self.status_dir)
        try:
            self.status_dir.parent.rmdir()
        except OSError:
            pass
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
