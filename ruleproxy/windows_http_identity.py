"""Authenticate elevated-panel HTTP clients using their actual Windows token.

The local TCP four-tuple is resolved using timestamped OWNER_MODULE rows. A
held process handle and creation-time check reject stale rows and recycled
PIDs; errors deny access. This authenticates an account, not an individual
program within that account.
"""
from __future__ import annotations

import ctypes
import os
import re
import socket


_DWORD = ctypes.c_uint32
_HANDLE = ctypes.c_void_p
_MAX_TABLE = 16 * 1024**2


class _TcpRow(ctypes.Structure):
    # SDK layout and FILETIME semantics:
    # https://learn.microsoft.com/windows/win32/api/tcpmib/ns-tcpmib-mib_tcprow_owner_module
    _fields_ = [('state', _DWORD), ('local_address', _DWORD), ('local_port', _DWORD),
                ('remote_address', _DWORD), ('remote_port', _DWORD), ('pid', _DWORD),
                ('created', ctypes.c_int64), ('module', ctypes.c_uint64 * 16)]


class _TcpTable(ctypes.Structure):
    _fields_ = [('count', _DWORD), ('rows', _TcpRow * 1)]


class _FileTime(ctypes.Structure):
    _fields_ = [('low', _DWORD), ('high', _DWORD)]


def _matching_row(data: bytes, client: tuple[str, int], server: tuple[str, int]) -> tuple[int, int]:
    offset, width = _TcpTable.rows.offset, ctypes.sizeof(_TcpRow)
    if len(data) < offset:
        raise OSError('Truncated Windows TCP owner table')
    count = _DWORD.from_buffer_copy(data[:4]).value
    if count > (len(data) - offset) // width:
        raise OSError('Truncated Windows TCP owner rows')
    local = int.from_bytes(socket.inet_aton(client[0]), 'little')
    remote = int.from_bytes(socket.inet_aton(server[0]), 'little')
    found = []
    for index in range(count):
        row = _TcpRow.from_buffer_copy(data[offset + index * width:offset + (index + 1) * width])
        if (row.state == 5 and row.local_address == local and row.remote_address == remote
                and socket.ntohs(row.local_port & 0xffff) == client[1]
                and socket.ntohs(row.remote_port & 0xffff) == server[1]):
            found.append((row.pid, row.created))
    if len(found) != 1 or found[0][0] <= 0 or found[0][1] <= 0:
        raise OSError('No unique live timestamped Windows TCP owner')
    return found[0]


class _WindowsAPI:
    def __init__(self):
        if os.name != 'nt':
            raise OSError('Windows HTTP identity is Windows-only')
        self.kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        self.advapi = ctypes.WinDLL('advapi32', use_last_error=True)
        self.ip = ctypes.WinDLL('iphlpapi', use_last_error=True)
        signatures = [
            (self.kernel, 'GetCurrentProcess', [], _HANDLE),
            (self.kernel, 'OpenProcess', [_DWORD, ctypes.c_int, _DWORD], _HANDLE),
            (self.kernel, 'CloseHandle', [_HANDLE], ctypes.c_int),
            (self.kernel, 'WaitForSingleObject', [_HANDLE, _DWORD], _DWORD),
            (self.kernel, 'GetProcessTimes', [_HANDLE, *([ctypes.POINTER(_FileTime)] * 4)], ctypes.c_int),
            (self.kernel, 'LocalFree', [_HANDLE], _HANDLE),
            (self.advapi, 'OpenProcessToken', [_HANDLE, _DWORD, ctypes.POINTER(_HANDLE)], ctypes.c_int),
            (self.advapi, 'GetTokenInformation', [_HANDLE, ctypes.c_int, _HANDLE, _DWORD,
                                                ctypes.POINTER(_DWORD)], ctypes.c_int),
            (self.advapi, 'ConvertSidToStringSidW', [_HANDLE, ctypes.POINTER(ctypes.c_wchar_p)], ctypes.c_int),
            (self.ip, 'GetExtendedTcpTable', [_HANDLE, ctypes.POINTER(_DWORD), ctypes.c_int,
                                             _DWORD, ctypes.c_int, _DWORD], _DWORD),
        ]
        for library, name, arguments, result in signatures:
            method = getattr(library, name)
            method.argtypes, method.restype = arguments, result

    @staticmethod
    def _check(result):
        if not result:
            raise ctypes.WinError(ctypes.get_last_error())

    def row(self, client, server):
        size = _DWORD()
        result = self.ip.GetExtendedTcpTable(None, ctypes.byref(size), False, socket.AF_INET, 8, 0)
        for _attempt in range(3):
            if result != 122 or not _TcpTable.rows.offset <= size.value <= _MAX_TABLE:
                raise OSError('Windows TCP owner table unavailable')
            capacity = size.value
            data = ctypes.create_string_buffer(capacity)
            result = self.ip.GetExtendedTcpTable(data, ctypes.byref(size), False, socket.AF_INET, 8, 0)
            if result == 0:
                if size.value > capacity:
                    raise OSError('Invalid Windows TCP owner table length')
                return _matching_row(data.raw[:size.value], client, server)
        raise OSError('Windows TCP owner table changed repeatedly')

    def open(self, pid):
        handle = self.kernel.OpenProcess(0x100000 | 0x1000, False, pid)
        self._check(handle)
        return handle

    def close(self, handle):
        self._check(self.kernel.CloseHandle(handle))

    def alive(self, handle):
        return self.kernel.WaitForSingleObject(handle, 0) == 258

    def created(self, handle):
        # Same 100 ns epoch as the TCP context-bind timestamp above.
        created, exited, kernel, user = (_FileTime() for _ in range(4))
        self._check(self.kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                               ctypes.byref(kernel), ctypes.byref(user)))
        return created.low | (created.high << 32)

    def sid(self, handle):
        token = _HANDLE()
        self._check(self.advapi.OpenProcessToken(handle, 8, ctypes.byref(token)))
        try:
            size = _DWORD()
            result = self.advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
            if result or ctypes.get_last_error() != 122 or not ctypes.sizeof(_HANDLE) <= size.value <= 65536:
                raise OSError('Invalid Windows token user size')
            data = ctypes.create_string_buffer(size.value)
            self._check(self.advapi.GetTokenInformation(token, 1, data, size, ctypes.byref(size)))
            sid = ctypes.cast(data, ctypes.POINTER(_HANDLE))[0]
            text = ctypes.c_wchar_p()
            self._check(self.advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)))
            try:
                return text.value
            finally:
                self.kernel.LocalFree(ctypes.cast(text, _HANDLE))
        finally:
            self.close(token)

    def current_sid(self):
        return self.sid(self.kernel.GetCurrentProcess())


class WindowsHTTPIdentity:
    def __init__(self, expected_sid: str | None = None, *, api=None):
        self.api = _WindowsAPI() if api is None else api
        self.expected_sid = self.api.current_sid() if expected_sid is None else expected_sid
        if not isinstance(self.expected_sid, str) or not re.fullmatch(r'S-\d+(?:-\d+)+', self.expected_sid):
            raise OSError('Invalid Windows HTTP owner identity')

    def authorize(self, connection: socket.socket) -> bool:
        handle = None
        allowed = False
        try:
            client, server = connection.getpeername(), connection.getsockname()
            if (connection.family != socket.AF_INET or len(client) != 2 or len(server) != 2
                    or client[0] != '127.0.0.1' or server[0] != '127.0.0.1'):
                return False
            before = self.api.row(client, server)
            handle = self.api.open(before[0])
            created = self.api.created(handle)
            if (not self.api.alive(handle) or created <= 0 or created > before[1]
                    or self.api.sid(handle) != self.expected_sid):
                return False
            after = self.api.row(client, server)
            allowed = after == before and self.api.alive(handle)
        except Exception:
            allowed = False
        finally:
            if handle is not None:
                try:
                    self.api.close(handle)
                except Exception:
                    allowed = False
        return allowed
