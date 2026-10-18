"""Ordinary global mode: point the desktop's system proxy at the local core.

Nothing privileged is touched: no TUN, no firewall rules and no DNS policy.
The previous user settings are journalled before changing the desktop. Failed
restoration keeps that journal for another attempt. A killed panel cannot run
cleanup; reopening the panel recovers its saved settings.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

BACKUP = 'system-proxy.json'
MAX_JOURNAL = 64 * 1024
_BYPASS = ['localhost', '127.0.0.1', '::1', '10.*', '172.16.*', '192.168.*']


class SystemProxyError(ValueError):
    pass


# Windows: per-user WinINet settings, honoured by Edge, Chrome and most apps.
_WIN_KEY = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
_WIN_VALUES = ('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect')


def _win_location(owner_sid=None):
    import winreg
    if owner_sid is None:
        return winreg.HKEY_CURRENT_USER, _WIN_KEY
    if not isinstance(owner_sid, str) or not re.fullmatch(r'S-1-5-21-(?:[0-9]+-){3}[0-9]+', owner_sid):
        raise SystemProxyError('Invalid Windows desktop owner SID')
    return winreg.HKEY_USERS, owner_sid + '\\' + _WIN_KEY


def _win_read(owner_sid=None):
    import winreg
    saved = {}
    with winreg.OpenKey(*_win_location(owner_sid)) as key:
        for name in _WIN_VALUES:
            try:
                value, kind = winreg.QueryValueEx(key, name)
                saved[name] = [value, kind]
            except FileNotFoundError:
                saved[name] = None
    return saved


def _win_write(values, owner_sid=None):
    import ctypes
    import winreg
    with winreg.OpenKey(*_win_location(owner_sid), 0, winreg.KEY_SET_VALUE) as key:
        for name, item in values.items():
            if item is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, name, 0, item[1], item[0])
    # An elevated uninstaller may run as a different UAC account. Never refresh
    # or restore that administrator's HKCU instead of the installation owner.
    notify = owner_sid is None
    if owner_sid is not None:
        from .windows_proxy_client import current_user_sid
        notify = owner_sid == current_user_sid()
    if notify:
        wininet = ctypes.WinDLL('wininet', use_last_error=True)
        if not wininet.InternetSetOptionW(None, 39, None, 0):
            raise ctypes.WinError(ctypes.get_last_error())
        if not wininet.InternetSetOptionW(None, 37, None, 0):
            raise ctypes.WinError(ctypes.get_last_error())


def _win_ours(port):
    import winreg
    return {'ProxyEnable': [1, winreg.REG_DWORD],
            'ProxyServer': [f'127.0.0.1:{port}', winreg.REG_SZ],
            'ProxyOverride': [';'.join([*_BYPASS, '<local>']), winreg.REG_SZ],
            # A PAC script or auto-detection would take precedence over the
            # manual proxy, so both are paused while global mode is on.
            'AutoConfigURL': None, 'AutoDetect': [0, winreg.REG_DWORD]}


def _win_is_ours(port):
    current = _win_read()
    return ((current.get('ProxyEnable') or [0])[0] == 1
            and (current.get('ProxyServer') or [''])[0] == f'127.0.0.1:{port}')


# Linux: GNOME-compatible desktops (GNOME, Cinnamon, Budgie, Unity) through
# gsettings. Apps started from the panel also get proxy variables.
_GNOME = 'org.gnome.system.proxy'
_GNOME_KEYS = [(_GNOME, 'mode'), (_GNOME, 'ignore-hosts')] + [
    (f'{_GNOME}.{kind}', field) for kind in ('http', 'https', 'socks') for field in ('host', 'port')]


def _gsettings(*args):
    tool = shutil.which('gsettings')
    if not tool:
        raise SystemProxyError('未找到 gsettings；当前桌面不支持自动设置系统代理。')
    result = subprocess.run([tool, *args], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise SystemProxyError('设置桌面系统代理失败：' + (result.stderr.strip() or 'gsettings 出错'))
    return result.stdout.strip()


def _gnome_read():
    return {f'{schema} {key}': _gsettings('get', schema, key) for schema, key in _GNOME_KEYS}


def _gnome_write(values):
    # The mode goes last so desktops never see a half-written manual proxy.
    for name, value in sorted(values.items(), key=lambda item: item[0] == f'{_GNOME} mode'):
        schema, key = name.split(' ', 1)
        _gsettings('set', schema, key, value)


def _gnome_ours(port):
    values = {f'{_GNOME}.{kind} host': "'127.0.0.1'" for kind in ('http', 'https', 'socks')}
    values.update({f'{_GNOME}.{kind} port': str(port) for kind in ('http', 'https', 'socks')})
    values[f'{_GNOME} ignore-hosts'] = '[' + ', '.join(f"'{host}'" for host in _BYPASS) + ']'
    values[f'{_GNOME} mode'] = "'manual'"
    return values


def _gnome_is_ours(port):
    return (_gsettings('get', _GNOME, 'mode') == "'manual'"
            and _gsettings('get', f'{_GNOME}.http', 'host') == "'127.0.0.1'"
            and _gsettings('get', f'{_GNOME}.http', 'port') == str(port))


def _backend():
    if sys.platform == 'win32':
        return 'wininet', _win_read, _win_write, _win_ours, _win_is_ours
    if sys.platform.startswith('linux'):
        return 'gnome', _gnome_read, _gnome_write, _gnome_ours, _gnome_is_ours
    raise SystemProxyError('当前系统不支持自动设置系统代理。')


def available() -> tuple[bool, str]:
    if sys.platform == 'win32':
        return True, '全局代理通过 Windows 系统代理接管，不安装 TUN，不改防火墙和 DNS。'
    if sys.platform.startswith('linux') and shutil.which('gsettings') and (
            os.environ.get('DBUS_SESSION_BUS_ADDRESS') or os.environ.get('XDG_RUNTIME_DIR')):
        return True, '全局代理通过桌面系统代理（gsettings）接管，不安装 TUN，不改防火墙和 DNS。'
    return False, '当前桌面不支持自动设置系统代理；可在系统设置中手动把 HTTP/SOCKS 代理设为 127.0.0.1 和面板端口。'


def enable(directory: Path, port: int, *, watchdog_session=None) -> None:
    from .system_proxy_watchdog import transaction_lock
    if watchdog_session is not None and (not isinstance(watchdog_session, str) or
                                        not re.fullmatch(r'[0-9a-f]{32}', watchdog_session)):
        raise SystemProxyError('Invalid proxy recovery session')
    with transaction_lock(directory):
        _enable_locked(directory, port, watchdog_session)


def _enable_locked(directory, port, watchdog_session):
    from .manager import write_private
    if type(port) is not int or not 1025 <= port <= 65535:
        raise SystemProxyError('Invalid local proxy port')
    kind, read, write, ours, _is_ours = _backend()
    backup = Path(directory) / BACKUP
    if backup.exists():
        # Recover the previous transaction before starting a new one; never
        # overwrite the only copy of the user's settings with our own endpoint.
        _restore_locked(directory)
    data = {'schema': 1, 'kind': kind, 'port': port, 'phase': 'applying',
            'previous': read(), 'target': ours(port)}
    if watchdog_session is not None:
        data['watchdog_session'] = watchdog_session
    write_private(backup, json.dumps(data))
    try:
        write(data['target'])
        if read() != data['target']:
            raise SystemProxyError('系统代理设置未能回读确认。')
        data['phase'] = 'active'
        write_private(backup, json.dumps(data))
    except Exception:
        try:
            _restore_locked(directory)
        except Exception as recovery:
            raise SystemProxyError('系统代理设置失败，恢复记录已保留；请点击停止重试恢复。') from recovery
        raise


def _journal(raw, kind, ours):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise SystemProxyError('系统代理恢复记录包含重复字段。')
            value[key] = item
        return value
    try:
        if len(raw) > MAX_JOURNAL:
            raise ValueError('oversized journal')
        data = json.loads(raw, object_pairs_hook=unique)
        if (not isinstance(data, dict) or data.get('kind') != kind or
                type(data.get('port')) is not int or not 1025 <= data['port'] <= 65535 or
                not isinstance(data.get('previous'), dict)):
            raise ValueError('invalid journal identity')
        target = ours(data['port'])
        # Accept rc.15's older three-field journal, but apply the same bounded
        # field-level rollback to it instead of assuming the write was atomic.
        if 'schema' in data and (type(data['schema']) is not int or data['schema'] != 1 or data.get('phase') not in {'applying', 'active'}
                                 or data.get('target') != target):
            raise ValueError('invalid journal transaction')
        previous = data['previous']
        if set(previous) != set(target):
            raise ValueError('invalid journal settings')
        if kind == 'wininet':
            for name, item in previous.items():
                if item is None:
                    continue
                if not isinstance(item, list) or len(item) != 2 or type(item[1]) is not int:
                    raise ValueError('invalid registry entry')
                if name in {'ProxyEnable', 'AutoDetect'}:
                    if item[1] != 4 or type(item[0]) is not int or not 0 <= item[0] <= 0xffffffff:
                        raise ValueError('invalid registry integer')
                elif item[1] not in {1, 2} or not isinstance(item[0], str) or len(item[0]) > 8192 or '\0' in item[0]:
                    raise ValueError('invalid registry text')
        elif kind == 'gnome' and any(not isinstance(item, str) or len(item) > 8192 or '\0' in item
                                      for item in previous.values()):
            raise ValueError('invalid desktop setting')
        return data, target
    except (ValueError, TypeError, KeyError, UnicodeError) as error:
        raise SystemProxyError('系统代理恢复记录损坏或不匹配；记录已保留，请检查系统代理设置。') from error


def _restore_values(data, target, read, write):
    previous = data['previous']
    current = read()
    # A user-selected different endpoint takes priority. A mixture of old and
    # target values is our interrupted transaction and must remain recoverable.
    endpoint_keys = ({'ProxyServer'} if data['kind'] == 'wininet' else
                     {f'{_GNOME}.http host', f'{_GNOME}.http port'} if data['kind'] == 'gnome' else
                     set(target))
    if any(current.get(key) not in (previous.get(key), target.get(key)) for key in endpoint_keys):
        return
    changes = {key: value for key, value in previous.items()
               if current.get(key) == target[key] and current.get(key) != value}
    if changes or data['kind'] == 'wininet':
        write(changes)
        observed = read()
        if any(observed.get(key) != value for key, value in changes.items()):
            raise SystemProxyError('系统代理恢复未能回读确认，恢复记录已保留。')


def restore(directory: Path, *, expected_session=None) -> bool:
    """Recover a complete or partial write; failures retain the recovery journal."""
    from .system_proxy_watchdog import transaction_lock
    if expected_session is not None and (not isinstance(expected_session, str) or
                                        not re.fullmatch(r'[0-9a-f]{32}', expected_session)):
        raise SystemProxyError('Invalid proxy recovery session')
    with transaction_lock(directory):
        return _restore_locked(directory, expected_session=expected_session)


def _restore_locked(directory, *, expected_session=None):
    backup = Path(directory) / BACKUP
    try:
        with backup.open('rb') as source:
            raw = source.read(MAX_JOURNAL + 1)
    except FileNotFoundError:
        return False
    kind, read, write, ours, _is_ours = _backend()
    data, target = _journal(raw, kind, ours)
    if expected_session is not None and data.get('watchdog_session') != expected_session:
        return False
    _restore_values(data, target, read, write)
    backup.unlink(missing_ok=True)
    return True


def _read_owner_journal(path):
    """Read an untrusted user's journal through a nonredirected, held handle.

    Elevated recovery never writes/deletes files in the user's directory. The
    ordinary panel will discard the already-recovered journal on its next run.
    """
    import ctypes
    from ctypes import wintypes
    import msvcrt
    import ntpath
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                  wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, wintypes.LPVOID]
    kernel.GetFileType.argtypes = [wintypes.HANDLE]
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    # READ, share READ only, OPEN_EXISTING, OPEN_REPARSE_POINT. Do not follow a
    # final symlink or allow another process to mutate/delete the held file.
    handle = kernel.CreateFileW(str(path), 0x80000000, 1, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        error = ctypes.get_last_error()
        if error in {2, 3}:
            return None
        raise ctypes.WinError(error)
    try:
        info = ctypes.create_string_buffer(52)
        if not kernel.GetFileInformationByHandle(handle, info):
            raise ctypes.WinError(ctypes.get_last_error())
        if int.from_bytes(info.raw[:4], 'little') & 0x410 or kernel.GetFileType(handle) != 1:
            raise SystemProxyError('Owner proxy journal must be a regular non-reparse file')
        length = kernel.GetFinalPathNameByHandleW(handle, None, 0, 0)
        if not 1 <= length <= 32768:
            raise SystemProxyError('Owner proxy journal path could not be verified')
        final = ctypes.create_unicode_buffer(length + 1)
        copied = kernel.GetFinalPathNameByHandleW(handle, final, len(final), 0)
        if not 0 < copied < len(final):
            raise SystemProxyError('Owner proxy journal path changed')
        actual = final.value.removeprefix('\\\\?\\')
        if ntpath.normcase(actual) != ntpath.normcase(ntpath.abspath(str(path))):
            raise SystemProxyError('Redirected owner proxy journal refused')
        descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None  # fdopen owns and closes the same verified handle.
        with os.fdopen(descriptor, 'rb') as source:
            return source.read(MAX_JOURNAL + 1)
    finally:
        if handle is not None:
            kernel.CloseHandle(handle)


def restore_windows_owner(owner_sid: str) -> bool:
    """Uninstaller recovery for the protected deployment's actual owner SID.

    The caller validates the deployment and elevation first. Only five fixed
    proxy values in that owner's already-loaded HKU hive can be restored;
    journal data cannot choose a registry path or cause an elevated file write.
    """
    import winreg
    _win_location(owner_sid)  # Validate before any profile/registry access.
    key = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' + '\\' + owner_sid
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as profile:
        directory, kind = winreg.QueryValueEx(profile, 'ProfileImagePath')
    if kind not in {winreg.REG_SZ, winreg.REG_EXPAND_SZ} or not isinstance(directory, str):
        raise SystemProxyError('The installation owner profile could not be verified')
    directory = winreg.ExpandEnvironmentStrings(directory)
    from pathlib import PureWindowsPath
    profile = PureWindowsPath(directory)
    if not profile.is_absolute() or profile.drive.startswith('\\\\') or '..' in profile.parts:
        raise SystemProxyError('Invalid installation owner profile path')
    path = profile / 'AppData' / 'Local' / 'RuleProxyWebSafe' / BACKUP
    raw = _read_owner_journal(path)
    if raw is None:
        return False
    data, target = _journal(raw, 'wininet', _win_ours)
    _restore_values(data, target, lambda: _win_read(owner_sid),
                    lambda values: _win_write(values, owner_sid))
    return True
