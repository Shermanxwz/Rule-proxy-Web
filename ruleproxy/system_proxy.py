"""Ordinary global mode: point the desktop's system proxy at the local core.

Nothing privileged is touched: no TUN, no firewall rules and no DNS policy.
The previous user settings are saved before the first change and restored on
stop, on core exit and on the next panel start after a crash, so a failure
can never leave the machine without a network.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

BACKUP = 'system-proxy.json'
_BYPASS = ['localhost', '127.0.0.1', '::1', '10.*', '172.16.*', '192.168.*']


class SystemProxyError(ValueError):
    pass


# Windows: per-user WinINet settings, honoured by Edge, Chrome and most apps.
_WIN_KEY = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
_WIN_VALUES = ('ProxyEnable', 'ProxyServer', 'ProxyOverride', 'AutoConfigURL', 'AutoDetect')


def _win_read():
    import winreg
    saved = {}
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_KEY) as key:
        for name in _WIN_VALUES:
            try:
                value, kind = winreg.QueryValueEx(key, name)
                saved[name] = [value, kind]
            except FileNotFoundError:
                saved[name] = None
    return saved


def _win_write(values):
    import ctypes
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _WIN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        for name, item in values.items():
            if item is None:
                try:
                    winreg.DeleteValue(key, name)
                except FileNotFoundError:
                    pass
            else:
                winreg.SetValueEx(key, name, 0, item[1], item[0])
    wininet = ctypes.WinDLL('wininet', use_last_error=True)
    wininet.InternetSetOptionW(None, 39, None, 0)  # INTERNET_OPTION_SETTINGS_CHANGED
    wininet.InternetSetOptionW(None, 37, None, 0)  # INTERNET_OPTION_REFRESH


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


def enable(directory: Path, port: int) -> None:
    from .manager import write_private
    kind, read, write, ours, _is_ours = _backend()
    backup = Path(directory) / BACKUP
    if backup.exists():
        # A backup left by an earlier crash still holds the user's real settings.
        data = json.loads(backup.read_text(encoding='utf-8'))
        data['port'] = port
    else:
        data = {'kind': kind, 'port': port, 'previous': read()}
    write_private(backup, json.dumps(data))
    try:
        write(ours(port))
    except Exception:
        restore(directory)
        raise


def restore(directory: Path) -> bool:
    """Put back the saved settings. Returns True when a backup was handled."""
    backup = Path(directory) / BACKUP
    try:
        data = json.loads(backup.read_text(encoding='utf-8'))
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        backup.unlink(missing_ok=True)
        return True
    kind, _read, write, _ours, is_ours = _backend()
    if data.get('kind') == kind and isinstance(data.get('previous'), dict):
        # If the user already changed the proxy elsewhere, keep their choice.
        if type(data.get('port')) is not int or is_ours(data['port']):
            write(data['previous'])
    backup.unlink(missing_ok=True)
    return True
