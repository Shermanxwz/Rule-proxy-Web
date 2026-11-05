"""Native Gemini profile binding for the independently verified installed build."""
import ctypes
from ctypes import wintypes
import hashlib
import os
import time
from pathlib import Path

from .windows_gemini import is_gemini
from .windows_gemini_preferences import acquire, recover, _safe, _Lock

VERIFIED_ASAR = '8c6cc82837089c0bc0e478521f2cdb10712d40ddc8b63afab5d7b52c2aa74056'


def require_idle():
    """Fail closed if any Gemini-named process exists; never terminate it.

    Conservatively includes other installations with the same executable name.
    Enumeration failures are errors, not an empty process list.
    """
    class Entry(ctypes.Structure):
        _fields_ = [('dwSize', wintypes.DWORD), ('cntUsage', wintypes.DWORD),
                    ('th32ProcessID', wintypes.DWORD), ('th32DefaultHeapID', ctypes.c_size_t),
                    ('th32ModuleID', wintypes.DWORD), ('cntThreads', wintypes.DWORD),
                    ('th32ParentProcessID', wintypes.DWORD), ('pcPriClassBase', wintypes.LONG),
                    ('dwFlags', wintypes.DWORD), ('szExeFile', wintypes.WCHAR * 260)]
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    for name in ('Process32FirstW', 'Process32NextW'):
        call = getattr(kernel, name)
        call.argtypes = [wintypes.HANDLE, ctypes.POINTER(Entry)]
        call.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateToolhelp32Snapshot(2, 0)
    if handle == ctypes.c_void_p(-1).value:
        raise OSError('Gemini process inventory failed')
    try:
        row = Entry(); row.dwSize = ctypes.sizeof(row)
        ok = kernel.Process32FirstW(handle, ctypes.byref(row))
        while ok:
            if row.szExeFile.casefold() in ('gemini.exe', 'geminiapplauncher.exe'):
                raise ValueError('请先关闭仍在运行的 Gemini 窗口，再启动或恢复其代理资料。')
            ok = kernel.Process32NextW(handle, ctypes.byref(row))
        if ctypes.get_last_error() != 18:  # ERROR_NO_MORE_FILES
            raise OSError('Gemini process inventory incomplete')
    finally:
        kernel.CloseHandle(handle)


def wait_for_idle():
    """Wait briefly for terminated Job descendants; never kill named processes.

    Root process wait does not imply every Job member has finished exiting.
    Keep the lease/receipt intact on timeout or inventory error. Initial acquire
    still uses immediate require_idle so an unmanaged running app is rejected.
    """
    deadline = time.monotonic() + 5.0
    while True:
        try:
            require_idle()
            return
        except ValueError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            time.sleep(min(.1, remaining))


def pending_receipt():
    roaming = os.environ.get('APPDATA')
    if not roaming or not Path(roaming).is_absolute():
        return None
    receipt = Path(roaming) / 'Gemini' / '.ruleproxy-proxy-recovery.json'
    return receipt if receipt.exists() else None


def recover_pending():
    receipt = pending_receipt()
    if receipt is not None:
        lock = _Lock(receipt)
        try:
            require_idle()
            recover(receipt.parent, receipt)
        finally:
            lock.close()


def prepare(command, port):
    """Return lease or None; only called in selected-app guarded Windows mode."""
    if not is_gemini(command[0]):
        return None
    for arg in command[1:]:
        option = arg.lstrip('-/').split('=', 1)[0].casefold()
        if option in ('user-data-dir', 'profile-directory'):
            raise ValueError('Gemini 原资料代理与自定义资料参数冲突。')
    asar = _safe(Path(command[0]).parent / 'resources' / 'app.asar')
    # hashlib.file_digest requires Python 3.11; keep the content gate on 3.10
    # without loading the entire archive or touching the profile before approval.
    hasher = hashlib.sha256()
    with asar.open('rb') as source:
        for chunk in iter(lambda: source.read(256 * 1024), b''):
            hasher.update(chunk)
    digest = hasher.hexdigest()
    if digest != VERIFIED_ASAR:
        raise ValueError('Gemini 版本已变化，保留原资料；此版本的原生代理偏好需重新验证。')
    roaming = os.environ.get('APPDATA')
    if not roaming or not Path(roaming).is_absolute():
        raise ValueError('Gemini 原资料目录不可确定。')
    # Verified packaged main sets app.name = Gemini and does not override
    # userData. Explicitly bind this same native directory, never a fresh profile.
    profile = _safe(Path(roaming) / 'Gemini')
    lease = acquire(profile, profile / '.ruleproxy-proxy-recovery.json', port, require_idle)
    # Only close waits: startup validation and durable receipt creation remain immediate.
    lease.check_idle = wait_for_idle
    command.append(f'--user-data-dir={profile}')
    return lease
