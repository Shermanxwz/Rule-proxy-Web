"""Launch an ordinary Windows application in an owned process-family Job.

This is process ownership, not a network isolation boundary. The caller must
enable its transparent proxy rules before calling ``launch``. No shell,
administrator broker, proxy environment, or PID-based termination is used.
"""

from __future__ import annotations

import ctypes
import math
import os
import subprocess
import threading
import time
from typing import Mapping, Sequence


_DWORD = ctypes.c_uint32
_HANDLE = ctypes.c_void_p
_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 258
_INFINITE = 0xFFFFFFFF
_DUPLICATE_SAME_ACCESS = 2


class _StartupInfo(ctypes.Structure):
    _fields_ = [
        ("cb", _DWORD), ("lpReserved", ctypes.c_wchar_p),
        ("lpDesktop", ctypes.c_wchar_p), ("lpTitle", ctypes.c_wchar_p),
        ("dwX", _DWORD), ("dwY", _DWORD), ("dwXSize", _DWORD),
        ("dwYSize", _DWORD), ("dwXCountChars", _DWORD),
        ("dwYCountChars", _DWORD), ("dwFillAttribute", _DWORD),
        ("dwFlags", _DWORD), ("wShowWindow", ctypes.c_uint16),
        ("cbReserved2", ctypes.c_uint16), ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", _HANDLE), ("hStdOutput", _HANDLE), ("hStdError", _HANDLE),
    ]


class _ProcessInfo(ctypes.Structure):
    _fields_ = [("hProcess", _HANDLE), ("hThread", _HANDLE),
                ("dwProcessId", _DWORD), ("dwThreadId", _DWORD)]


class _JobBasicLimitInfo(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64), ("LimitFlags", _DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", _DWORD), ("Affinity", ctypes.c_size_t),
        ("PriorityClass", _DWORD), ("SchedulingClass", _DWORD),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
    )]


class _JobExtendedLimitInfo(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _JobBasicLimitInfo), ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t), ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t), ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def _environment_block(env: Mapping[str, str]) -> str:
    """Build a complete Unicode environment without inherited proxy settings."""
    clean: dict[str, str] = {}
    seen: set[str] = set()
    for key, value in env.items():
        if not isinstance(key, str) or not isinstance(value, str):
            raise TypeError("Environment names and values must be strings")
        if not key or "=" in key or "\0" in key or "\0" in value:
            raise ValueError("Invalid Windows environment entry")
        folded = key.upper()
        # Includes HTTP(S), FTP(S), SOCKS, ALL and NO_PROXY in any casing.
        if folded.endswith("_PROXY"):
            continue
        if folded in seen:
            raise ValueError("Duplicate case-insensitive environment name")
        seen.add(folded)
        clean[key] = value
    return "\0".join(f"{key}={clean[key]}" for key in sorted(clean, key=str.upper)) + "\0\0"


class _KernelAPI:
    """Load and type Windows APIs only when a native launch is requested."""

    def __init__(self) -> None:
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        signatures = {
            "GetCurrentProcess": ([], _HANDLE),
            "CreateJobObjectW": ([ctypes.c_void_p, ctypes.c_wchar_p], _HANDLE),
            "SetInformationJobObject": ([_HANDLE, ctypes.c_int, ctypes.c_void_p, _DWORD], ctypes.c_int),
            "CreateProcessW": ([ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_void_p,
                                ctypes.c_void_p, ctypes.c_int, _DWORD, ctypes.c_void_p,
                                ctypes.c_wchar_p, ctypes.POINTER(_StartupInfo),
                                ctypes.POINTER(_ProcessInfo)], ctypes.c_int),
            "AssignProcessToJobObject": ([_HANDLE, _HANDLE], ctypes.c_int),
            "ResumeThread": ([_HANDLE], _DWORD),
            "TerminateProcess": ([_HANDLE, _DWORD], ctypes.c_int),
            "TerminateJobObject": ([_HANDLE, _DWORD], ctypes.c_int),
            "WaitForSingleObject": ([_HANDLE, _DWORD], _DWORD),
            "GetExitCodeProcess": ([_HANDLE, ctypes.POINTER(_DWORD)], ctypes.c_int),
            "DuplicateHandle": ([_HANDLE, _HANDLE, _HANDLE, ctypes.POINTER(_HANDLE),
                                 _DWORD, ctypes.c_int, _DWORD], ctypes.c_int),
            "CloseHandle": ([_HANDLE], ctypes.c_int),
        }
        for name, (args, result) in signatures.items():
            function = getattr(self.kernel, name)
            function.argtypes, function.restype = args, result
        self.advapi.OpenProcessToken.argtypes = [_HANDLE, _DWORD, ctypes.POINTER(_HANDLE)]
        self.advapi.OpenProcessToken.restype = ctypes.c_int
        self.advapi.GetTokenInformation.argtypes = [_HANDLE, ctypes.c_int, ctypes.c_void_p,
                                                   _DWORD, ctypes.POINTER(_DWORD)]
        self.advapi.GetTokenInformation.restype = ctypes.c_int

    @staticmethod
    def _check(ok: object) -> None:
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def assert_unelevated(self) -> None:
        token = _HANDLE()
        self._check(self.advapi.OpenProcessToken(self.kernel.GetCurrentProcess(), 0x0008,
                                                ctypes.byref(token)))
        try:
            elevated, size = _DWORD(), _DWORD()
            self._check(self.advapi.GetTokenInformation(token, 20, ctypes.byref(elevated),
                                                       ctypes.sizeof(elevated), ctypes.byref(size)))
            if size.value != ctypes.sizeof(elevated):
                raise OSError("Unexpected TokenElevation information size")
            if elevated.value:
                raise PermissionError("Applications must be launched by the ordinary user panel, not an elevated process")
        finally:
            self.close_handle(token.value)

    def create_job(self) -> int:
        handle = self.kernel.CreateJobObjectW(None, None)
        self._check(handle)
        return handle

    def configure_job(self, handle: int, flags: int) -> None:
        limits = _JobExtendedLimitInfo()
        limits.BasicLimitInformation.LimitFlags = flags
        self._check(self.kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits),
                                                       ctypes.sizeof(limits)))

    def create_process(self, command: Sequence[str], environment: str, cwd: str | None,
                       info: _ProcessInfo) -> None:
        startup = _StartupInfo()
        startup.cb = ctypes.sizeof(startup)
        command_line = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
        environment_buffer = ctypes.create_unicode_buffer(environment)
        self._check(self.kernel.CreateProcessW(
            command[0], command_line, None, None, False,
            _CREATE_SUSPENDED | _CREATE_UNICODE_ENVIRONMENT,
            environment_buffer, cwd, ctypes.byref(startup), ctypes.byref(info),
        ))

    def assign_job(self, job: int, process: int) -> None:
        self._check(self.kernel.AssignProcessToJobObject(job, process))

    def resume_thread(self, thread: int) -> None:
        previous = self.kernel.ResumeThread(thread)
        if previous == 0xFFFFFFFF:
            self._check(False)
        if previous != 1:
            raise OSError("Unexpected initial thread suspend count")

    def terminate_process(self, process: int) -> None:
        self._check(self.kernel.TerminateProcess(process, 1))

    def terminate_job(self, job: int) -> None:
        self._check(self.kernel.TerminateJobObject(job, 1))

    def wait_process(self, process: int, milliseconds: int) -> int:
        result = self.kernel.WaitForSingleObject(process, milliseconds)
        if result not in (_WAIT_OBJECT_0, _WAIT_TIMEOUT):
            self._check(False)
        return result

    def exit_code(self, process: int) -> int:
        code = _DWORD()
        self._check(self.kernel.GetExitCodeProcess(process, ctypes.byref(code)))
        return code.value

    def duplicate_handle(self, handle: int) -> int:
        duplicate = _HANDLE()
        current = self.kernel.GetCurrentProcess()
        self._check(self.kernel.DuplicateHandle(current, handle, current, ctypes.byref(duplicate),
                                                0, False, _DUPLICATE_SAME_ACCESS))
        return duplicate.value

    def close_handle(self, handle: int) -> None:
        self._check(self.kernel.CloseHandle(handle))


def _get_api() -> _KernelAPI:
    if os.name != "nt":
        raise OSError("Native application launching is only available on Windows")
    return _KernelAPI()


def _close_all(api: _KernelAPI, handles: Sequence[int | None]) -> None:
    errors = []
    for handle in handles:
        if handle:
            try:
                api.close_handle(handle)
            except OSError as error:
                errors.append(error)
    if errors:
        raise OSError("Could not close all owned Windows handles") from errors[0]


class WindowsAppProcess:
    """A Popen-like handle owner. Termination always targets the whole Job.

    Observing the root process exit closes its Job, terminating surviving
    descendants. Waiting uses a duplicate handle so concurrent stop/poll calls
    cannot invalidate a handle that Windows is currently waiting on.
    """

    def __init__(self, api: _KernelAPI, info: _ProcessInfo, job: int, command: list[str]):
        self.args = command
        self.pid = int(info.dwProcessId)
        self.returncode: int | None = None
        self._api = api
        self._process: int | None = info.hProcess
        self._job: int | None = job
        self._lock = threading.RLock()

    def _finish(self, process: int) -> int:
        with self._lock:
            if self.returncode is None:
                self.returncode = self._api.exit_code(process)
                job, handle = self._job, self._process
                self._job = self._process = None
                _close_all(self._api, (job, handle))
            return self.returncode

    def poll(self) -> int | None:
        with self._lock:
            if self.returncode is not None:
                return self.returncode
            if self._api.wait_process(self._process, 0) == _WAIT_OBJECT_0:
                return self._finish(self._process)
            return None

    def wait(self, timeout: float | None = None) -> int:
        with self._lock:
            if self.returncode is not None:
                return self.returncode
            process = self._api.duplicate_handle(self._process)
        try:
            if timeout is None:
                milliseconds = _INFINITE
                deadline = None
            else:
                if not math.isfinite(timeout):
                    raise ValueError("Timeout must be finite or None")
                deadline = time.monotonic() + max(0.0, timeout)
                milliseconds = min(math.ceil(max(0.0, timeout) * 1000), _INFINITE - 1)
            while True:
                if self._api.wait_process(process, milliseconds) == _WAIT_OBJECT_0:
                    return self._finish(process)
                # DWORD milliseconds cannot represent an arbitrarily long
                # timeout. Continue bounded native waits instead of expiring it
                # prematurely or accidentally passing the INFINITE sentinel.
                if deadline is None or milliseconds < _INFINITE - 1:
                    raise subprocess.TimeoutExpired(self.args, timeout)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(self.args, timeout)
                milliseconds = min(math.ceil(remaining * 1000), _INFINITE - 1)
        finally:
            self._api.close_handle(process)

    def terminate(self) -> None:
        with self._lock:
            if self.returncode is None and self._job:
                self._api.terminate_job(self._job)

    def kill(self) -> None:
        self.terminate()

    def __del__(self) -> None:
        # Closing the last non-inheritable Job handle is the crash/GC fallback.
        # Explicit terminate()/wait() remain the normal, observable cleanup path.
        api = getattr(self, "_api", None)
        if api is not None:
            job, process = getattr(self, "_job", None), getattr(self, "_process", None)
            self._job = self._process = None
            try:
                _close_all(api, (job, process))
            except OSError:
                pass


def launch(command: list[str], env: Mapping[str, str], cwd: str | None = None) -> WindowsAppProcess:
    """Create suspended, assign the non-breakaway Job, then start the app.

    Errors abort the new process before returning. A pre-existing parent Job
    that prevents assignment causes a clean failure; there is no breakaway or
    unsupervised-launch fallback.
    """
    if not isinstance(command, (list, tuple)) or not command:
        raise ValueError("A non-empty application command is required")
    if any(not isinstance(part, str) or "\0" in part for part in command) or not command[0]:
        raise ValueError("Application command must contain valid strings")
    if cwd is not None and (not isinstance(cwd, str) or "\0" in cwd):
        raise ValueError("Invalid application working directory")
    environment = _environment_block(env)
    api = _get_api()
    api.assert_unelevated()
    job = None
    info = _ProcessInfo()
    assigned = False
    try:
        job = api.create_job()
        api.configure_job(job, _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        api.create_process(command, environment, cwd, info)
        api.assign_job(job, info.hProcess)
        assigned = True
        api.resume_thread(info.hThread)
        api.close_handle(info.hThread)
        info.hThread = None
        result = WindowsAppProcess(api, info, job, list(command))
        # Ownership of both remaining kernel handles transfers only on success.
        job = None
        info.hProcess = None
        return result
    except BaseException as original:
        cleanup_error = None
        if info.hProcess:
            try:
                if assigned:
                    api.terminate_job(job)
                else:
                    api.terminate_process(info.hProcess)
                if api.wait_process(info.hProcess, 5000) != _WAIT_OBJECT_0:
                    raise OSError("New application did not terminate after launch failure")
            except OSError as error:
                cleanup_error = error
        try:
            _close_all(api, (info.hThread, job, info.hProcess))
        except OSError as error:
            cleanup_error = cleanup_error or error
        if cleanup_error is not None:
            raise RuntimeError("Application launch failed and cleanup could not be confirmed") from original
        raise
