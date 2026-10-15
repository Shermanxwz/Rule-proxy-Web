"""Disposable VM controller: launch its already logged-on ordinary user.

This helper is never part of the installed product or its privileged broker.
"""
from __future__ import annotations

import ctypes
import math
import os
import re
import subprocess


D = ctypes.c_uint32
H = ctypes.c_void_p
P = ctypes.c_wchar_p
INVALID_SESSION = 0xFFFFFFFF


class Startup(ctypes.Structure):
    _fields_ = [("cb", D), ("reserved", P), ("desktop", P), ("title", P),
                *[(name, D) for name in ("x", "y", "width", "height", "cx", "cy", "fill", "flags")],
                ("show", ctypes.c_uint16), ("reserved_count", ctypes.c_uint16),
                ("reserved_data", H), ("stdin", H), ("stdout", H), ("stderr", H)]


class Info(ctypes.Structure):
    _fields_ = [("process", H), ("thread", H), ("pid", D), ("tid", D)]


class Session(ctypes.Structure):
    _fields_ = [("id", D), ("station", P), ("state", ctypes.c_int)]


class WindowsAPI:
    def __init__(self):
        if os.name != "nt":
            raise OSError("Interactive qualification requires Windows")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        self.wts = ctypes.WinDLL("wtsapi32", use_last_error=True)
        self.userenv = ctypes.WinDLL("userenv", use_last_error=True)
        signatures = [
            (self.kernel, "GetCurrentProcess", [], H),
            (self.kernel, "CloseHandle", [H], ctypes.c_int),
            (self.kernel, "LocalFree", [H], H),
            (self.kernel, "WaitForSingleObject", [H, D], D),
            (self.kernel, "GetExitCodeProcess", [H, ctypes.POINTER(D)], ctypes.c_int),
            (self.kernel, "TerminateProcess", [H, D], ctypes.c_int),
            (self.kernel, "ResumeThread", [H], D),
            (self.advapi, "OpenProcessToken", [H, D, ctypes.POINTER(H)], ctypes.c_int),
            (self.advapi, "GetTokenInformation", [H, ctypes.c_int, H, D, ctypes.POINTER(D)], ctypes.c_int),
            (self.advapi, "ConvertSidToStringSidW", [H, ctypes.POINTER(P)], ctypes.c_int),
            (self.advapi, "CreateProcessAsUserW", [H, P, P, H, H, ctypes.c_int, D, H, P,
                                                   ctypes.POINTER(Startup), ctypes.POINTER(Info)], ctypes.c_int),
            (self.wts, "WTSEnumerateSessionsW", [H, D, D, ctypes.POINTER(H), ctypes.POINTER(D)], ctypes.c_int),
            (self.wts, "WTSQuerySessionInformationW", [H, D, ctypes.c_int, ctypes.POINTER(H), ctypes.POINTER(D)], ctypes.c_int),
            (self.wts, "WTSQueryUserToken", [D, ctypes.POINTER(H)], ctypes.c_int),
            (self.wts, "WTSFreeMemory", [H], None),
            (self.userenv, "CreateEnvironmentBlock", [ctypes.POINTER(H), H, ctypes.c_int], ctypes.c_int),
            (self.userenv, "DestroyEnvironmentBlock", [H], ctypes.c_int),
        ]
        for dll, name, args, result in signatures:
            function = getattr(dll, name)
            function.argtypes, function.restype = args, result

    @staticmethod
    def checked(ok):
        if not ok:
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self, handle):
        if handle:
            self.kernel.CloseHandle(handle)

    def process_token(self, handle):
        token = H()
        self.checked(self.advapi.OpenProcessToken(handle, 8, ctypes.byref(token)))
        return token.value

    def identity(self, token):
        size = D()
        self.advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        if not 1 <= size.value <= 65536:
            raise OSError("Invalid token identity length")
        buffer = ctypes.create_string_buffer(size.value)
        self.checked(self.advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)))
        sid = ctypes.cast(buffer, ctypes.POINTER(H))[0]
        text = P()
        self.checked(self.advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)))
        try:
            sid_text = text.value
        finally:
            self.kernel.LocalFree(ctypes.cast(text, H))
        values = []
        for kind in (12, 20):  # TokenSessionId, TokenElevation
            value = D()
            self.checked(self.advapi.GetTokenInformation(token, kind, ctypes.byref(value),
                                                         ctypes.sizeof(value), ctypes.byref(size)))
            values.append(value.value)
        return {"sid": sid_text, "session_id": values[0], "elevated": bool(values[1])}

    def caller(self):
        token = self.process_token(self.kernel.GetCurrentProcess())
        try:
            return self.identity(token)
        finally:
            self.close(token)

    def sessions(self):
        pointer, count = H(), D()
        self.checked(self.wts.WTSEnumerateSessionsW(None, 0, 1, ctypes.byref(pointer), ctypes.byref(count)))
        try:
            result = []
            for index in range(count.value):
                entry = Session.from_address(pointer.value + index * ctypes.sizeof(Session))
                if entry.state != 0:  # WTSActive
                    continue
                name, length = H(), D()
                self.checked(self.wts.WTSQuerySessionInformationW(None, entry.id, 5,
                                                                  ctypes.byref(name), ctypes.byref(length)))
                try:
                    result.append({"session_id": entry.id, "username": ctypes.wstring_at(name.value) if name.value else "",
                                   "active": True})
                finally:
                    self.wts.WTSFreeMemory(name)
            return result
        finally:
            self.wts.WTSFreeMemory(pointer)

    def user_token(self, session):
        token = H()
        self.checked(self.wts.WTSQueryUserToken(session, ctypes.byref(token)))
        return token.value

    def environment(self, token):
        environment = H()
        self.checked(self.userenv.CreateEnvironmentBlock(ctypes.byref(environment), token, False))
        return environment.value

    def free_environment(self, environment):
        self.checked(self.userenv.DestroyEnvironmentBlock(environment))

    def create(self, token, command, cwd, environment):
        startup, info = Startup(), Info()
        startup.cb, startup.desktop = ctypes.sizeof(Startup), r"winsta0\default"
        text = ctypes.create_unicode_buffer(subprocess.list2cmdline(command))
        # Verify the returned process token before executing any user code.
        self.checked(self.advapi.CreateProcessAsUserW(token, command[0], text, None, None, False,
            0x08000000 | 0x400 | 4, environment, cwd, ctypes.byref(startup), ctypes.byref(info)))
        return info.process, info.thread, info.pid

    def resume(self, thread):
        if self.kernel.ResumeThread(thread) == 0xFFFFFFFF:
            raise ctypes.WinError(ctypes.get_last_error())

    def wait(self, handle, milliseconds):
        result = self.kernel.WaitForSingleObject(handle, milliseconds)
        if result not in (0, 258):
            raise ctypes.WinError(ctypes.get_last_error())
        return result

    def exit_code(self, handle):
        code = D()
        self.checked(self.kernel.GetExitCodeProcess(handle, ctypes.byref(code)))
        return code.value

    def terminate(self, handle):
        self.checked(self.kernel.TerminateProcess(handle, 125))


def _get_api():
    return WindowsAPI()


class UserProcess:
    launch_method = "WTSQueryUserToken+CreateProcessAsUserW"

    def __init__(self, api, handle, pid, command, caller_sid, session_id):
        self.api, self.handle, self.pid = api, handle, pid
        self.command, self.caller_sid, self.session_id = command, caller_sid, session_id

    def poll(self):
        if self.handle is None:
            raise ValueError("Interactive process handle is closed")
        return None if self.api.wait(self.handle, 0) == 258 else self.api.exit_code(self.handle)

    def wait(self, timeout=None):
        if self.handle is None:
            raise ValueError("Interactive process handle is closed")
        milliseconds = 0xFFFFFFFF if timeout is None else min(0xFFFFFFFE, max(0, math.ceil(timeout * 1000)))
        if self.api.wait(self.handle, milliseconds) == 258:
            raise subprocess.TimeoutExpired(self.command, timeout)
        return self.api.exit_code(self.handle)

    def kill(self):
        if self.poll() is None:
            self.api.terminate(self.handle)

    terminate = kill

    def close(self):
        if self.handle is not None:
            self.api.close(self.handle)
            self.handle = None


def launch_user(command, expected_sid, expected_session, cwd):
    if (not isinstance(expected_sid, str) or not re.fullmatch(r"S-1-5-21-(?:\d+-){3}\d+", expected_sid)
            or type(expected_session) is not int or not 0 < expected_session < INVALID_SESSION):
        raise ValueError("Expected a specific ordinary account and interactive session")
    command = [os.fspath(value) for value in command]
    if not command or any(not value or "\0" in value for value in command):
        raise ValueError("Invalid interactive command")
    api = _get_api()
    caller = api.caller()
    if caller["sid"] != "S-1-5-18":
        raise PermissionError("WTS qualification launcher requires LocalSystem")
    matches = [entry for entry in api.sessions() if entry["active"]
               and entry["session_id"] == expected_session and entry["username"].casefold() == "ruleproxyci"]
    if len(matches) != 1:
        raise PermissionError("Expected RuleProxyCI interactive session is not active")
    token = environment = process = thread = None
    try:
        token = api.user_token(expected_session)
        def verify(identity):
            if (identity["sid"] != expected_sid or identity["session_id"] != expected_session
                    or identity["elevated"]):
                raise PermissionError("Interactive process identity/session/elevation mismatch")
        verify(api.identity(token))
        environment = api.environment(token)
        process, thread, pid = api.create(token, command, os.fspath(cwd) if cwd is not None else None, environment)
        actual = api.process_token(process)
        try:
            verify(api.identity(actual))
        finally:
            api.close(actual)
        # Release launch-only resources while the child is still suspended. If
        # cleanup fails, the failure path can still terminate this exact handle.
        api.free_environment(environment)
        environment = None
        api.close(token)
        token = None
        api.resume(thread)
        result = UserProcess(api, process, pid, command, caller["sid"], expected_session)
        process = None
        return result
    finally:
        try:
            if process is not None:
                try:
                    api.terminate(process)
                    api.wait(process, 5000)
                finally:
                    api.close(process)
        finally:
            try:
                if thread is not None:
                    api.close(thread)
                if environment is not None:
                    api.free_environment(environment)
            finally:
                if token is not None:
                    api.close(token)
