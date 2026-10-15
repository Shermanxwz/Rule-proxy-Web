"""Ordinary-user client for the installed RuleProxy named-pipe broker."""
from __future__ import annotations

import ctypes
from ctypes import wintypes
import json
import os
import uuid

from .windows_proxy_policy import MAX_MESSAGE, SERVICE_NAME, ProxyError


def current_user_sid() -> str:
    if os.name != "nt":
        raise ProxyError("unsupported_platform", "Windows 后端仅适用于 Windows。")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID,
                                          wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.argtypes = [wintypes.HANDLE]
    kernel.LocalFree.restype = wintypes.HANDLE
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        buffer = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(token, 1, buffer, needed, ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        sid_pointer = ctypes.cast(buffer, ctypes.POINTER(wintypes.LPVOID))[0]
        text = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid_pointer, ctypes.byref(text)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            return text.value
        finally:
            kernel.LocalFree(ctypes.cast(text, wintypes.HANDLE))
    finally:
        kernel.CloseHandle(token)


class Client:
    def __init__(self, pipe: str):
        if not isinstance(pipe, str) or not pipe.startswith("RuleProxyControl-v1-") or "\\" in pipe:
            raise ProxyError("invalid_deployment", "控制管道名称无效。")
        self.pipe = "\\\\.\\pipe\\" + pipe

    def request(self, operation: str, **fields) -> dict:
        if os.name != "nt":
            raise ProxyError("unsupported_platform", "Windows 后端仅适用于 Windows。")
        request = {"schema_version": 1, "request_id": uuid.uuid4().hex,
                   "op": operation, "client_pid": os.getpid(), **fields}
        raw = json.dumps(request, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        if len(raw) > MAX_MESSAGE:
            raise ProxyError("invalid_request", "控制请求过大。")
        from .windows_proxy_service import PipeAPI, ServiceControl
        api = PipeAPI()
        kernel = api.kernel
        kernel.WaitNamedPipeW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD]
        kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        kernel.CreateFileW.restype = wintypes.HANDLE
        kernel.SetNamedPipeHandleState.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
                                                  wintypes.LPVOID, wintypes.LPVOID]
        kernel.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
        if not kernel.WaitNamedPipeW(self.pipe, 45000):
            error = ctypes.get_last_error()
            raise ProxyError("setup_required" if error in (2, 3) else "backend_unavailable",
                             "Windows 代理控制服务不可用，请运行安装或修复。错误码：" + str(error))
        handle = kernel.CreateFileW(self.pipe, 0xC0000000, 0, None, 3, 0x40000000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise ProxyError("backend_unavailable", "无法打开 Windows 代理控制管道。")
        try:
            server_pid = wintypes.ULONG()
            if not kernel.GetNamedPipeServerProcessId(handle, ctypes.byref(server_pid)):
                raise ctypes.WinError(ctypes.get_last_error())
            # Authenticated users can query SCM status; they need not open the
            # LocalSystem server's access token to authenticate this pipe.
            registered = ServiceControl().status(SERVICE_NAME)
            if registered["state"] != 4 or registered["pid"] != server_pid.value:
                raise ProxyError("access_denied", "控制管道不属于已安装的 Windows 服务。")
            mode = wintypes.DWORD(2)
            if not kernel.SetNamedPipeHandleState(handle, ctypes.byref(mode), None, None):
                raise ctypes.WinError(ctypes.get_last_error())
            api.operation(handle, "write", buffer=ctypes.create_string_buffer(raw, len(raw)), timeout=45)
            output = ctypes.create_string_buffer(MAX_MESSAGE)
            returned = api.operation(handle, "read", buffer=output, timeout=45)
            # The broker waits for this bounded ACK before disconnecting, so a
            # completed write cannot discard a response still in the pipe.
            api.operation(handle, "write", buffer=ctypes.create_string_buffer(b"1", 1), timeout=2)
        finally:
            kernel.CloseHandle(handle)
        try:
            response = json.loads(output.raw[:returned].decode("utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise ProxyError("invalid_response", "Windows 控制服务返回无效响应。") from exc
        if (not isinstance(response, dict) or response.get("schema_version") != 1
                or response.get("request_id") != request["request_id"]):
            raise ProxyError("invalid_response", "Windows 控制服务响应身份不匹配。")
        if response.get("ok") is not True:
            raise ProxyError(str(response.get("code", "backend_error")),
                             str(response.get("message", "Windows 代理操作失败。")))
        result = response.get("result")
        if not isinstance(result, dict):
            raise ProxyError("invalid_response", "Windows 控制服务状态无效。")
        return result
