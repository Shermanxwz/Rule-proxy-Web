"""Strict MXC 1.0.0 BaseContainer integration for Windows proxy launches.

The application has one exact internal TCP allowance under deny-default egress,
with external ingress and host loopback denied.
This module never installs firewall rules or downloads runtime dependencies;
the caller supplies the MXC executable path.
"""

from __future__ import annotations

import json
import hashlib
import ntpath
import os
import re
import secrets
import socket
import stat
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
_PRODUCT_EXECUTOR_MAX_BYTES = 32 * 1024 * 1024


def verify_product_executor_identity(runtime_path: str | os.PathLike[str]) -> Path:
    """Accept only the pinned product G executor, including byte-identical copies.

    This check is intentionally separate from ``launch``: source diagnostics may
    exercise other pinned executors, while the shipped Manager must always use G.
    """
    from .windows_runtime_pins import MXC_G_EXECUTOR_SHA256

    path = Path(runtime_path)

    def file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
        return (
            int(info.st_dev),
            int(info.st_ino),
            int(info.st_size),
            int(getattr(info, "st_mtime_ns", info.st_mtime * 1_000_000_000)),
        )

    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise UnsupportedRuntimeError("MXC 程序必须是普通文件，不能是链接或重解析点。")
        attributes = getattr(info, "st_file_attributes", 0)
        if attributes & 0x400:  # FILE_ATTRIBUTE_REPARSE_POINT
            raise UnsupportedRuntimeError("MXC 程序不能是重解析点。")
        initial_identity = file_identity(info)
        if info.st_size <= 0 or info.st_size > _PRODUCT_EXECUTOR_MAX_BYTES:
            raise UnsupportedRuntimeError("MXC 程序大小异常，已拒绝启动。")
        digest = hashlib.sha256()
        total = 0
        with path.open("rb") as source:
            opened = os.fstat(source.fileno())
            if not stat.S_ISREG(opened.st_mode) or file_identity(opened) != initial_identity:
                raise UnsupportedRuntimeError("MXC 程序在检查期间发生变化，已拒绝启动。")
            while True:
                chunk = source.read(min(1024 * 1024, _PRODUCT_EXECUTOR_MAX_BYTES + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > _PRODUCT_EXECUTOR_MAX_BYTES:
                    raise UnsupportedRuntimeError("MXC 程序大小异常，已拒绝启动。")
                digest.update(chunk)
            after = os.fstat(source.fileno())
        if total != info.st_size or file_identity(after) != initial_identity:
            raise UnsupportedRuntimeError("MXC 程序在检查期间发生变化，已拒绝启动。")
        current = path.lstat()
        if (
            not stat.S_ISREG(current.st_mode)
            or getattr(current, "st_file_attributes", 0) & 0x400
            or file_identity(current) != initial_identity
        ):
            raise UnsupportedRuntimeError("MXC 程序在检查期间发生变化，已拒绝启动。")
        if digest.hexdigest() != MXC_G_EXECUTOR_SHA256:
            raise UnsupportedRuntimeError(
                "所选 MXC 版本不是本工具支持的固定版本。请清空自定义路径以使用内置版本；"
                "源码目录运行 Setup-Windows.cmd 更新运行组件，运行包请重新解压更新。"
            )
        # Pass the exact absolute pathname that was checked. A relative command
        # could otherwise be resolved through PATH or the working directory.
        return path.resolve(strict=True)
    except UnsupportedRuntimeError:
        raise
    except OSError as exc:
        raise UnsupportedRuntimeError(
            "找不到可用的 MXC 运行组件。请清空自定义路径以使用内置版本；"
            "源码目录运行 Setup-Windows.cmd 更新运行组件，运行包请重新解压更新。"
        ) from exc


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
        k.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)
        ]
        k.QueryFullProcessImageNameW.restype = wintypes.BOOL
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

    def process_image(self, handle: int) -> str:
        buffer = ctypes.create_unicode_buffer(32768)
        length = wintypes.DWORD(len(buffer))
        if not self.kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(length)):
            raise ctypes.WinError(ctypes.get_last_error())
        if not 0 < length.value < len(buffer) or not ntpath.isabs(buffer.value):
            raise SafeStopError("process image query was incomplete")
        return buffer.value

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
        # after holding query-only candidate handles, then reopen with stop
        # access and compare creation times. A stale PPID from an older process
        # must be excluded before requesting its termination permission.
        first = self._snapshot_parent_ids()
        candidates: dict[int, tuple[int, int]] = {}
        verified: list[tuple[int, int]] = []
        keep_verified = False
        try:
            for pid, reported_parent in first.items():
                if pid == parent_pid or reported_parent != parent_pid:
                    continue
                handle = self.kernel32.OpenProcess(self.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
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
        if not self.kernel32.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


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
        # Win32 names are not shell identifiers: ProgramFiles(x86),
        # CommonProgramFiles(Arm), spaces and Unicode are valid. The policy
        # carries separate JSON KEY=VALUE strings, never shell source; only
        # '=' and NUL can change the environment entry/block boundaries.
        if not isinstance(key, str) or not key or "=" in key or "\0" in key:
            raise ValueError(f"invalid environment variable name: {key!r}")
        try:
            key.encode("utf-8")
        except UnicodeError:
            raise ValueError("invalid environment variable name: not valid Unicode text") from None
        if not isinstance(value, str) or "\0" in value:
            raise ValueError(f"invalid environment value for {key}")
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise ValueError(f"invalid environment value for {key!r}: not valid Unicode text") from None
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
    # Win32's default LocalAppData Known Folder resolves under USERPROFILE\AppData\Local.
    # Keep the redirected environment directories above intact, while ensuring
    # that the standard Known Folder tree also exists within this private profile.
    known_local = home / "AppData" / "Local"
    known_roaming = home / "AppData" / "Roaming"
    for directory in (local, roaming, temp, home):
        directory.mkdir(parents=True, exist_ok=True)
    # A previous contained process can change its writable profile. Do not
    # follow a junction or symlink while creating the new standard children.
    for directory in (home, home / "AppData", known_local, known_roaming):
        try:
            info = directory.lstat()
        except FileNotFoundError:
            directory.mkdir()
            info = directory.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            raise ValueError("profile Known Folder parents must be ordinary directories")

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
    enumerate_path: str | Path | None = None,
    ingress_default_allow_control: bool = False,
) -> dict[str, Any]:
    """Allow only the trusted helper's exact internal IPv4 TCP endpoint."""
    command = _validate_command(command)
    if type(ingress_default_allow_control) is not bool:
        raise ValueError("ingress_default_allow_control must be a strict boolean")
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
    enumerate_path = _validate_enumerate_path(enumerate_path)
    if ingress_default_allow_control and enumerate_path is None:
        raise ValueError("ingress default allow control requires the pinned LocalAppData enumerate path")
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
    process_container = {"ui": {"isolation": "container", "ime": True}}
    if enumerate_path is not None:
        process_container["filesystem"] = {"enumeratePaths": [str(enumerate_path)]}
    return {
        "$schema": "https://github.com/microsoft/mxc/schemas/stable/mxc-config.schema.1.0.0.json",
        "version": CONTRACT_VERSION,
        "containment": "processcontainer",
        "fallback": {"allowDaclMutation": False},
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
        # Enable normal clipboard and Chinese input alongside visible windows;
        # injection, system controls and container handle isolation stay at
        # their defaults. These input controls grant no network access.
        "ui": {"disable": False, "clipboard": "all"},
        "processContainer": process_container,
        "network": {
            "egress": {
                "default": "deny",
                "allow": [{
                    "to": [{"cidr": "127.0.0.1/32"}],
                    "ports": [{"protocol": "tcp", "port": guest_listener_port}],
                }],
            },
            "ingress": {"default": "allow" if ingress_default_allow_control else "deny",
                        "hostLoopback": "deny"},
        },
    }


def _validate_enumerate_path(value: str | Path | None) -> Path | None:
    """Validate the one source-diagnostic directory query grant."""
    if value is None:
        return None
    try:
        supplied = Path(value)
        if not supplied.is_absolute() or "\0" in str(supplied):
            raise ValueError("enumeration path must be absolute")
        if supplied.is_symlink():
            raise ValueError("enumeration path must not be a symbolic link")
        resolved = supplied.resolve(strict=True)
        if not resolved.is_dir() or resolved == Path(resolved.anchor):
            raise ValueError("enumeration path must be an existing non-root directory")
        return resolved
    except (OSError, RuntimeError) as exc:
        raise ValueError("enumeration path must be an existing non-root directory") from exc


def _require_enumerate_path_support(probe_output: Mapping[str, Any], requested: Path | None) -> None:
    if requested is None:
        return
    probes = probe_output.get("probes") if isinstance(probe_output, Mapping) else None
    if not isinstance(probes, Mapping) or probes.get("baseContainerSupportsEnumeratePaths") is not True:
        raise UnsupportedRuntimeError(
            "MXC did not confirm BaseContainer filesystem enumeratePaths support"
        )


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
                "MXC 1.0.0 对完整请求的运行时探测决定是否支持；"
                "Windows 版本或更新编号不能保证支持，请安装适用的官方更新后重新探测。"
            )
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
    """Probe the exact BaseContainer policy; this does not run socket checks."""
    limitations = [
        "当前结果表示系统具备隔离能力；实际阻断还需在启动时检查。",
        "仅从面板或快捷方式启动的实例受保护；启动检查失败就拒绝启动。",
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
            "detail": "系统支持该网络隔离请求。应用启动前会检查代理通道及实际阻断。",
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
    guest_listener_port: int | None = None,
    enumerate_path: str | Path | None = None,
    ingress_default_allow_control: bool = False,
) -> tuple[subprocess.Popen, Any]:
    """Launch the trusted helper, gating the app on proxy and denial checks."""
    if type(ingress_default_allow_control) is not bool:
        raise ValueError("ingress_default_allow_control must be a strict boolean")
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
    enumerate_path = _validate_enumerate_path(enumerate_path)
    if ingress_default_allow_control and enumerate_path is None:
        raise ValueError("ingress default allow control requires the pinned LocalAppData enumerate path")
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
    phase = "probe_request"
    wrapper_process_started: bool | None = False
    try:
        policy = build_policy(
            command,
            env,
            profile,
            guest_listener_port,
            python_executable=python_executable,
            guest_helper=helper,
            runtime_config=Path(run_dir.name) / "guest-config.json",
            enumerate_path=enumerate_path,
            ingress_default_allow_control=ingress_default_allow_control,
        )
        # This request-scoped MXC probe confirms that BaseContainer accepts
        # the exact directory-enumeration grant before any wrapper is started.
        probe_output = _probe_request(runtime, policy)
        _require_enumerate_path_support(probe_output, enumerate_path)
        phase = "bridge_setup"
        bridge = FileProxyBridge(host_proxy_port, bridge_dir)
        resources.bridge = bridge
        resources.udp_fixture = _HostUDPFixture(bridge.nonce)
        phase = "host_controls"
        resources.udp_fixture.control_before()
        resources.host_ipv6_observation = _host_ipv6_route_probe()
        host_ipv6_unavailable = resources.host_ipv6_observation["host_ipv6_route_unavailable"]
        fixture.start()
        config_path = Path(run_dir.name) / "guest-config.json"
        app_environment = _profile_environment(env, profile)
        app_environment["RULEPROXY_RUNTIME_CONFIG"] = str(config_path)
        guest_config = {
            "schema_version": 1,
            "command": command,
            "env": app_environment,
            "profile": str(profile),
            "listener_port": guest_listener_port,
            "bridge_directory": str(bridge.directory),
            "bridge_nonce": bridge.nonce,
            "host_fixture_port": fixture.port,
            "host_udp_ports": list(resources.udp_fixture.ports),
            "host_ipv6_route_unavailable": host_ipv6_unavailable,
        }
        config_path.write_text(json.dumps(guest_config, ensure_ascii=False), encoding="utf-8")
        runtime_config = _profile_environment(os.environ.copy(), profile)
        phase = "wrapper_spawn"
        wrapper_process_started = None
        process = subprocess.Popen(
            [str(runtime), "--config", str(_write_policy(policy, Path(run_dir.name)))],
            env=runtime_config,
            shell=False,
        )
        resources.process = process
        wrapper_process_started = True
        process._ruleproxy_python_executable = str(python_executable)

        # Guest startup includes up to 10 seconds of bridge initialization and
        # a bounded 22-second parent/child check. Preserve its diagnostics even
        # when ordinary socket timeouts, rather than immediate denials, occur.
        phase = "bridge_ready"
        if not bridge.wait_ready(45):
            raise UnsupportedRuntimeError(
                getattr(bridge, "last_error", None) or "contained guest self-check did not become ready"
            )
        phase = "host_tcp_check"
        if _host_can_reach_guest(guest_listener_port):
            bridge.reject("host-to-guest loopback check was reachable")
            raise UnsupportedRuntimeError("host unexpectedly reached the contained guest listener")
        if fixture.accepted.is_set():
            bridge.reject("guest reached a non-proxy host loopback fixture")
            raise UnsupportedRuntimeError("contained guest unexpectedly reached a host loopback listener")
        phase = "startup_report"
        report = _read_startup_report(bridge.directory, bridge.nonce,
                                      host_ipv6_route_unavailable=host_ipv6_unavailable)
        resources.startup_diagnostics = report
        phase = "udp_check"
        resources.udp_observation = resources.udp_fixture.verify(report)
        phase = "bind_workload"
        _bind_startup_workload(process, report, str(python_executable))
        _write_host_approval(Path(run_dir.name), bridge.nonce)
        bridge.approve()
        phase = "app_started"
        if not _wait_for_status(bridge.directory, bridge.nonce, "APP_STARTED", process, 20):
            raise UnsupportedRuntimeError("contained helper did not confirm application startup")
        resources.detail = (
            "已通过代理入口和本机隔离启动检查，使用独立应用配置。"
        )
        return process, resources
    except BaseException as exc:
        if bridge is not None:
            try:
                bridge.reject(str(exc)[:512])
            except Exception:
                pass
        if process is not None:
            try:
                process.wait(timeout=12)
            except subprocess.TimeoutExpired as wait_error:
                # Keep the wrapper and resources alive so MXC can complete its
                # normal PSEC teardown; never kill the runtime wrapper here.
                resources.failed_process = process
                resources.detail = str(exc)
                exc.process = process
                exc.resource = resources
                _attach_launch_failure_facts(
                    exc, phase=phase, wrapper_process_started=wrapper_process_started,
                    process=process, guest_status=_safe_bounded_guest_status(resources),
                    cleanup_proven=False, resources_closed=False,
                )
                raise exc from wait_error
        guest_status = _safe_bounded_guest_status(resources)
        try:
            resources.close()
        except Exception as cleanup_error:
            resources.failed_process = process
            resources.detail = str(exc)
            cleanup_error.process = process
            cleanup_error.resource = resources
            _attach_launch_failure_facts(
                cleanup_error, phase=phase, wrapper_process_started=wrapper_process_started,
                process=process, guest_status=guest_status,
                cleanup_proven=False, resources_closed=bool(resources._closed),
            )
            raise cleanup_error from exc
        _attach_launch_failure_facts(
            exc, phase=phase, wrapper_process_started=wrapper_process_started,
            process=process, guest_status=guest_status,
            cleanup_proven=True, resources_closed=True,
        )
        raise


_LAUNCH_FAILURE_PHASES = frozenset({
    "probe_request", "bridge_setup", "host_controls", "wrapper_spawn", "bridge_ready",
    "host_tcp_check", "startup_report", "udp_check", "bind_workload", "app_started",
})


def _safe_bounded_guest_status(resources: Any) -> dict[str, Any]:
    """Collect optional status facts without risking launch cleanup or errors."""
    try:
        value = resources.bounded_guest_status()
        if isinstance(value, dict):
            return value
    except Exception:
        pass
    return {"status": "unavailable"}


def _attach_launch_failure_facts(
    error: BaseException,
    *,
    phase: str,
    wrapper_process_started: bool | None,
    process: Any,
    guest_status: dict[str, Any] | None = None,
    cleanup_proven: bool | None,
    resources_closed: bool | None,
) -> None:
    """Attach bounded scalar facts without replacing the original error or owner."""
    if phase not in _LAUNCH_FAILURE_PHASES:
        phase = "unknown"
    exit_observed = False
    exit_code = None
    if process is not None:
        try:
            exit_observed = process.poll() is not None
            if exit_observed:
                code = process.returncode
                if (isinstance(code, int) and not isinstance(code, bool)
                        and -(1 << 31) <= code <= 0xFFFFFFFF):
                    exit_code = code
        except Exception:
            exit_observed = False
    facts = {
        "schema_version": 1,
        "phase": phase,
        "wrapper_process_started": wrapper_process_started,
        "wrapper_exit_observed": exit_observed,
        "wrapper_exit_code": exit_code,
        "guest_status": guest_status if isinstance(guest_status, dict) else {"status": "unavailable"},
        "cleanup_proven": cleanup_proven,
        "resources_closed": resources_closed,
    }
    try:
        error._ruleproxy_launch_facts = facts
    except Exception:
        pass


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
            if self.thread.is_alive():
                raise SafeStopError("host TCP fixture thread remained alive")


def _host_ipv6_route_probe() -> dict[str, Any]:
    observation = {"scope": "fixed_ipv6_tcp_route_probe", "host_ipv6_route_unavailable": False,
                   "code": "connected", "kernel_denial_proven": False}
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as connection:
            connection.settimeout(1)
            connection.connect(("2606:4700:4700::1111", 443, 0, 0))
    except OSError as exc:
        winerror = getattr(exc, "winerror", None)
        observation["host_ipv6_route_unavailable"] = winerror == 10051
        observation["code"] = winerror or exc.errno or ("timeout" if isinstance(exc, TimeoutError) else "io")
    return observation


def _read_startup_report(directory: Path, nonce: str, *, host_ipv6_route_unavailable: bool = False) -> dict[str, Any]:
    from . import windows_guest
    path = Path(directory) / "network-probe.json"
    try:
        attrs = path.lstat()
        if path.is_symlink() or getattr(attrs, "st_file_attributes", 0) & 0x400:
            raise ValueError("startup report is a reparse point")
        with path.open("rb") as stream:
            raw = stream.read(windows_guest._MAX_PROBE_OUTPUT_BYTES + 1)
        if not raw or len(raw) > windows_guest._MAX_PROBE_OUTPUT_BYTES:
            raise ValueError("startup report size is invalid")
        value = json.loads(raw.decode("ascii"), object_pairs_hook=windows_guest._json_object)
        windows_guest._validate_startup_report(value, nonce)
        if not value["config_readonly"]["ok"]:
            raise ValueError("config readonly check failed")
        if not windows_guest._startup_checks_passed(value, host_ipv6_route_unavailable=host_ipv6_route_unavailable):
            raise ValueError("mandatory startup checks failed")
        return value
    except (OSError, ValueError, TypeError, UnicodeError):
        raise UnsupportedRuntimeError("contained startup report was invalid or incomplete") from None


def _write_host_approval(directory: Path, nonce: str) -> None:
    # This directory is mounted read-only in the PSEC policy. The app profile
    # and its bridge files are writable, so they cannot alone authorize launch.
    path = directory / "host-approval.json"
    temporary = path.with_name(path.name + ".host-tmp")
    with temporary.open("w", encoding="ascii", newline="") as stream:
        json.dump({"schema_version": 1, "nonce": nonce, "state": "APPROVED"}, stream, separators=(",", ":"))
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


class _HostUDPFixture:
    """Authoritative observation of two fixed host-local endpoints, no relay."""

    CONTROL_TIMEOUT = 0.75
    SETTLE_SECONDS = 0.2

    def __init__(self, nonce: str) -> None:
        from . import windows_guest
        if not windows_guest._valid_nonce(nonce):
            raise ValueError("invalid UDP fixture nonce")
        self.nonce = nonce
        self.sockets: list[socket.socket] = []
        self.threads: list[threading.Thread] = []
        self.closed = threading.Event()
        self.lock = threading.Lock()
        self.errors: list[str] = []
        self.unknown = 0
        self.counts = {(family, role): 0 for family in ("ipv4", "ipv6")
                       for role in ("before", "parent", "child", "after")}
        self.controls = {(family, role): threading.Event() for family in ("ipv4", "ipv6") for role in ("before", "after")}
        self.markers = {}
        self._before_complete = False
        self._verified = False
        control_secret = secrets.token_bytes(32)
        try:
            for family, address_family, host in (("ipv4", socket.AF_INET, "127.0.0.1"),
                                                 ("ipv6", socket.AF_INET6, "::1")):
                markers = {role: windows_guest._local_udp_marker(nonce, role, family) for role in ("parent", "child")}
                markers.update({role: b"RuleProxy-control-v1\0" + control_secret + family.encode("ascii") + role.encode("ascii")
                                for role in ("before", "after")})
                self.markers[family] = markers
                sock = socket.socket(address_family, socket.SOCK_DGRAM)
                self.sockets.append(sock)
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                if address_family == socket.AF_INET6:
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                sock.bind((host, 0))
                sock.settimeout(0.05)
                thread = threading.Thread(target=self._observe, args=(family, sock),
                                          name="RuleProxyUDP-" + family, daemon=True)
                self.threads.append(thread)
                thread.start()
            self.ports = tuple(int(sock.getsockname()[1]) for sock in self.sockets)
        except BaseException:
            self.close()
            raise

    def _observe(self, family, sock):
        while not self.closed.is_set():
            try:
                packet, _peer = sock.recvfrom(513)
            except socket.timeout:
                continue
            except OSError:
                if not self.closed.is_set():
                    with self.lock:
                        self.errors.append("receive_error")
                return
            role = next((name for name, marker in self.markers[family].items() if packet == marker), None)
            with self.lock:
                if role is None:
                    self.unknown += 1
                else:
                    self.counts[family, role] += 1
                    if role in {"before", "after"}:
                        self.controls[family, role].set()

    def _control(self, role):
        if self.closed.is_set() or any(not thread.is_alive() for thread in self.threads):
            raise UnsupportedRuntimeError("host UDP observer was not live")
        deadline = time.monotonic() + self.CONTROL_TIMEOUT
        for family, sock in zip(("ipv4", "ipv6"), self.sockets):
            host = "127.0.0.1" if family == "ipv4" else "::1"
            with socket.socket(sock.family, socket.SOCK_DGRAM) as sender:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise UnsupportedRuntimeError("host UDP positive control timed out")
                sender.settimeout(remaining)
                sender.bind((host, 0))
                marker = self.markers[family][role]
                if sender.sendto(marker, sock.getsockname()) != len(marker):
                    raise UnsupportedRuntimeError("host UDP positive control was incomplete")
        for family in ("ipv4", "ipv6"):
            if not self.controls[family, role].wait(max(0, deadline - time.monotonic())):
                raise UnsupportedRuntimeError("host UDP positive control was not received")

    def control_before(self):
        if self._before_complete:
            raise UnsupportedRuntimeError("host UDP control was repeated")
        self._control("before")
        self._before_complete = True

    def verify(self, report):
        from . import windows_guest
        if not self._before_complete or self._verified:
            raise UnsupportedRuntimeError("host UDP observation ordering was invalid")
        windows_guest._validate_startup_report(report, self.nonce)
        if any(item["state"] == "invalid" for role in ("parent", "child") for item in report[role]["local_udp"].values()):
            raise UnsupportedRuntimeError("contained local UDP attempt was incomplete")
        self._control("after")
        if self.closed.wait(self.SETTLE_SECONDS):
            raise UnsupportedRuntimeError("host UDP observer closed before its verdict")
        with self.lock:
            if self.errors or self.unknown or any(not thread.is_alive() for thread in self.threads):
                raise UnsupportedRuntimeError("host UDP observation was unhealthy or contaminated")
            if any(self.counts[family, role] < 1 for family in ("ipv4", "ipv6") for role in ("before", "after")):
                raise UnsupportedRuntimeError("host UDP positive controls were incomplete")
            if any(self.counts[family, role] for family in ("ipv4", "ipv6") for role in ("parent", "child")):
                raise UnsupportedRuntimeError("contained UDP probe reached a fixed host endpoint")
            observations = {family: {"before_received": self.counts[family, "before"],
                                      "after_received": self.counts[family, "after"],
                                      "parent_received": self.counts[family, "parent"],
                                      "child_received": self.counts[family, "child"]}
                            for family in ("ipv4", "ipv6")}
        self._verified = True
        return {"scope": "fixed_host_loopback_endpoints", "non_delivery_observed": True,
                "kernel_denial_proven": False, "public_udp_proven": False, "dns_proven": False,
                "observations": observations}

    def close(self):
        self.closed.set()
        failures = []
        for sock in self.sockets:
            try:
                sock.close()
            except OSError:
                failures.append("socket_close")
        for thread in self.threads:
            if thread.ident is not None:
                thread.join(0.5)
                if thread.is_alive():
                    failures.append("thread_alive")
        if failures:
            raise SafeStopError("host UDP fixture cleanup was not completed")


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
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            pass
        time.sleep(0.05)
    return False


class _WindowsRuntimeResources:
    def __init__(self, run_dir: tempfile.TemporaryDirectory[str], fixture: _HostLoopbackFixture, bridge: Any = None) -> None:
        self.run_dir = run_dir
        self.fixture = fixture
        self.bridge = bridge
        self.udp_fixture = None
        self.udp_observation = None
        self.startup_diagnostics = None
        self.host_ipv6_observation = None
        self.process = None
        self.failed_process = None
        self.detail = ""
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        if self.process is not None and self.process.poll() is None:
            raise SafeStopError("cannot release runtime resources while MXC wrapper is still running")
        owned = _owned_stop_state(self.process)
        if owned is not None:
            owned.release_exited()
        bridge_dir = Path(self.bridge.directory) if self.bridge is not None else None
        error: Exception | None = None
        try:
            if self.bridge is not None:
                self.bridge.close()
        except Exception as exc:
            error = exc
        # Close all independent resources even if one fails. Preserve bridge
        # files whenever any teardown is incomplete so a retry has evidence.
        for fixture in (self.fixture, self.udp_fixture):
            if fixture is not None:
                try:
                    fixture.close()
                except Exception as exc:
                    if error is None:
                        error = exc
        self.run_dir.cleanup()
        if error is not None:
            raise error
        if bridge_dir is not None:
            shutil.rmtree(bridge_dir, ignore_errors=True)
        self._closed = True

    def bounded_guest_status(self) -> dict[str, Any]:
        """Retain only nonce-bound state and numeric app exit/error categories."""
        bridge = self.bridge
        if bridge is None:
            return {"status": "unavailable"}
        try:
            path = Path(bridge.directory) / "guest-status.json"
            with path.open("rb") as stream:
                raw = stream.read(8193)
            if not raw or len(raw) > 8192:
                return {"status": "invalid"}
            value = json.loads(raw.decode("ascii"))
            if (not isinstance(value, dict) or value.get("nonce") != bridge.nonce
                    or value.get("state") not in {"GUEST_READY", "APP_STARTED", "APP_EXITED", "FAILED", "REJECTED"}):
                return {"status": "unmatched"}
            state = value["state"]
            result: dict[str, Any] = {"status": "observed", "state": state}
            detail = value.get("detail")
            if state == "APP_EXITED":
                if isinstance(detail, str) and re.fullmatch(r"-?[0-9]{1,10}", detail):
                    result["app_exit"] = int(detail)
                else:
                    result["app_exit"] = None
                    result["detail_error_category"] = "invalid_app_exit"
            elif state == "FAILED":
                result["detail_error_category"] = "guest_failed"
            return result
        except FileNotFoundError:
            return {"status": "missing"}
        except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError, AttributeError):
            return {"status": "invalid"}


class _OwnedStopState:
    """Retain creation HANDLEs; only the startup-bound helper may be killed."""

    def __init__(self, process: Any, api: Any, wrapper_created: int) -> None:
        self.process, self.api = process, api
        self.wrapper_pid = int(process.pid)
        self.wrapper_handle = _raw_handle(process._handle)
        self.wrapper_created = wrapper_created
        self.children: dict[tuple[int, int], int] = {}
        self.workload: tuple[int, int] | None = None
        self.closed = False
        self.lock = threading.RLock()

    def retain(self, children: list[tuple[int, int]]) -> None:
        # Even a failed binding keeps all opened ownership HANDLEs until their
        # kernel exit is proved. Never reopen a PID to recover a lost identity.
        pending = list(children)
        try:
            while pending:
                pid, handle = pending[0]
                created = self.api.process_creation_time(handle)
                if created < self.wrapper_created:
                    raise SafeStopError("owned child predates its MXC wrapper")
                key = (pid, created)
                if key in self.children:
                    self.api.close(handle)
                else:
                    self.children[key] = handle
                pending.pop(0)
        finally:
            # Keep unprocessed HANDLEs too, including a query failure: an
            # unknown generation can never authorize termination, but must
            # still reach kernel exit before resources are discarded.
            for pid, handle in pending:
                self.children[(pid, -handle)] = handle

    def release_exited(self) -> None:
        with self.lock:
            if self.closed:
                return
            if self.process.poll() is None:
                raise SafeStopError("MXC wrapper remains alive; owned process handles were retained")
            if not all(self.api.wait(handle, 0) for handle in self.children.values()):
                raise SafeStopError("an owned MXC child remains alive; resources and handles were retained")
            for key, handle in list(self.children.items()):
                self.api.close(handle)
                del self.children[key]
            self.closed = True

    def stop(self, *, timeout: float, refresh: bool = True) -> None:
        with self.lock:
            deadline = time.monotonic() + timeout
            if self.process.poll() is None:
                if (int(self.process.pid) != self.wrapper_pid
                        or _raw_handle(self.process._handle) != self.wrapper_handle
                        or self.api.process_creation_time(self.wrapper_handle) != self.wrapper_created):
                    raise SafeStopError("MXC wrapper identity changed; owned process handles were retained")
                if not self.api.process_alive(self.wrapper_handle):
                    self.process.wait(timeout=0)
                else:
                    if self.workload is None or self.workload not in self.children:
                        raise SafeStopError("no startup-bound trusted workload; MXC wrapper was left running")
                    if refresh:
                        self.retain(self.api.direct_children(self.wrapper_pid, self.wrapper_created))
                    handle = self.children[self.workload]
                    if self.api.process_alive(handle):
                        self.api.terminate(handle)
                    remaining = max(0.0, deadline - time.monotonic())
                    if not self.api.wait(handle, int(remaining * 1000)):
                        raise SafeStopError("trusted MXC workload did not exit; owned process handles were retained")
                    try:
                        self.process.wait(timeout=max(0.0, deadline - time.monotonic()))
                    except subprocess.TimeoutExpired as exc:
                        raise SafeStopError("MXC wrapper did not complete normal teardown; owned process handles were retained") from exc
            else:
                self.process.wait(timeout=0)
            for handle in self.children.values():
                if not self.api.wait(handle, int(max(0.0, deadline - time.monotonic()) * 1000)):
                    raise SafeStopError("an owned MXC child survived SDK teardown; resources and handles were retained")
            self.release_exited()


def _owned_stop_state(process: Any) -> _OwnedStopState | None:
    value = getattr(process, "_ruleproxy_stop_state", None)
    return value if isinstance(value, _OwnedStopState) else None


def _bind_startup_workload(process: Any, report: Mapping[str, Any], python_executable: str,
                           *, api: Any = None) -> _OwnedStopState:
    """Bind one exact Python workload using startup and two kernel snapshots."""
    from . import windows_guest
    windows_guest._validate_startup_report(report, report.get("nonce"))
    api = _WinProcessApi() if api is None else api
    wrapper_handle = getattr(process, "_handle", None)
    if wrapper_handle is None or process.poll() is not None:
        raise SafeStopError("MXC wrapper was not alive for startup identity binding")
    created = api.process_creation_time(_raw_handle(wrapper_handle))
    state = _OwnedStopState(process, api, created)
    process._ruleproxy_stop_state = state
    state.retain(api.direct_children(state.wrapper_pid, created))
    parent = report["parent"]
    key = (parent["pid"], parent["process_created"])
    expected = ntpath.normcase(ntpath.normpath(python_executable))
    matches = []
    for child, handle in state.children.items():
        if api.process_alive(handle) and ntpath.normcase(ntpath.normpath(api.process_image(handle))) == expected:
            matches.append(child)
    if (parent["parent_pid"] != state.wrapper_pid or key not in state.children
            or matches != [key] or not api.process_alive(state.wrapper_handle)
            or process.poll() is not None):
        raise SafeStopError("startup report did not identify one exact trusted Python workload")
    state.workload = key
    return state


def _stop_with_api(
    process: Any,
    api: Any,
    *,
    timeout: float,
    poll_interval: float,
) -> None:
    """Stop the direct MXC workload and let its wrapper perform teardown."""
    state = _owned_stop_state(process)
    if state is not None:
        try:
            state.stop(timeout=timeout)
        except SafeStopError:
            raise
        except Exception as exc:
            raise SafeStopError("owned MXC teardown failed; resources and process handles were retained") from exc
        return
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

        expected_image = getattr(process, "_ruleproxy_python_executable", None)
        if children and isinstance(expected_image, str):
            state = _OwnedStopState(process, api, wrapper_created)
            process._ruleproxy_stop_state = state
            try:
                state.retain(children)
            except Exception as exc:
                raise SafeStopError("could not retain owned MXC children; resources and handles were retained") from exc

        try:
            wrapper_alive = process.poll() is None and api.process_alive(_raw_handle(wrapper_handle))
        except Exception as exc:
            if state is None:
                for _, handle in children:
                    api.close(handle)
            raise SafeStopError(
                f"could not verify MXC wrapper is still running; wrapper was left running: {exc}"
            ) from exc
        if not wrapper_alive:
            if state is not None:
                state.stop(timeout=max(0.0, deadline - time.monotonic()))
                return
            for _, handle in children:
                api.close(handle)
            process.wait(timeout=0)
            return

        if len(children) > 1:
            if state is None:
                for _, handle in children:
                    api.close(handle)
            raise SafeStopError(
                "multiple verified direct children make the MXC workload ambiguous; wrapper was left running"
            )
        if not children:
            time.sleep(min(poll_interval, remaining))
            continue

        # Startup may fail before publishing a report. Preserve the old
        # conservative single-child fallback; multiple children never acquire
        # termination authority merely by being observed at stop time.
        if state is None:
            state = _OwnedStopState(process, api, wrapper_created)
            process._ruleproxy_stop_state = state
            state.retain(children)
        try:
            key = next(iter(state.children))
            if isinstance(expected_image, str) and (ntpath.normcase(ntpath.normpath(
                    api.process_image(state.children[key]))) != ntpath.normcase(ntpath.normpath(expected_image))):
                raise SafeStopError("unreported direct child is not the trusted Python workload; wrapper was left running")
            state.workload = key
            state.stop(timeout=max(0.0, deadline - time.monotonic()), refresh=False)
        except SafeStopError:
            raise
        except Exception as exc:
            raise SafeStopError(
                "could not terminate or wait for verified MXC workload; resources and handles were retained"
            ) from exc
        return


def stop(process: subprocess.Popen, timeout: float = 15.0) -> None:
    """Stop an MXC-owned workload while leaving cleanup to MXC itself.

    MXC v1.0.0 launches the BaseContainer workload with `CreateProcessW` from
    the runtime process. Startup binds its exact trusted Python helper while
    retaining any other directly owned process handles. This terminates only
    that helper, then waits for MXC's normal wait path to kill any job descendants and close the
    Process Security Environment. This function never terminates the runtime
    wrapper. If enumeration, identity checks, or normal teardown fail, it
    raises `SafeStopError` and retains ownership handles and launch resources
    for a retry, including when the wrapper already exited.
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
