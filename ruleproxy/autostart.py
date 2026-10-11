"""Start the panel in the background when the user logs in.

The entry is per user and needs no administrator rights: a value under the
user's Run key on Windows, an XDG autostart entry on Linux. It starts the panel
without a window or a browser, on the ports and data folder of the panel that
set it up, and leaves the core stopped until an app is launched.

A Windows service would not work here: services run in session 0, whose
windows never reach the user's desktop, and as SYSTEM, which would let any
local program use the panel to start programs with full rights.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

from .shortcuts import _desktop_exec, _write_file, background_argv

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
# Task Manager's "Startup apps" switch stores its choice here, apart from the Run value.
APPROVED_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"
RUN_VALUE = "RuleProxy Web"
DESKTOP_FILE = "ruleproxy-web.desktop"
_MARK = "X-RuleProxy-Autostart=true"


def command(state_dir: Path, ports: tuple[int, int, int]) -> list[str]:
    return background_argv(state_dir, ports, "--no-browser")


def supported() -> bool:
    return sys.platform == "win32" or sys.platform.startswith("linux")


def status(state_dir: Path, ports: tuple[int, int, int]) -> str:
    """'on' when login starts this panel; 'stale' when the entry starts another copy or other ports; else 'off'."""
    if not supported():
        return "unsupported"
    current = _windows_read() if sys.platform == "win32" else _linux_read()
    if current is None:
        return "off"
    expected = subprocess.list2cmdline(command(state_dir, ports)) if sys.platform == "win32" else _desktop_exec(command(state_dir, ports))
    return "on" if current == expected else "stale"


def enable(state_dir: Path, ports: tuple[int, int, int]) -> None:
    if not supported():
        raise ValueError("当前系统不支持登录后自动启动。")
    argv = command(state_dir, ports)
    if sys.platform == "win32":
        _windows_write(subprocess.list2cmdline(argv))
    else:
        _write_file(_linux_path(), _desktop_entry(argv), 0o644)


def disable() -> None:
    if sys.platform == "win32":
        _windows_remove()
    elif sys.platform.startswith("linux"):
        path = _linux_path()
        if _linux_read(include_disabled=True) is not None:
            path.unlink(missing_ok=True)


def _linux_path() -> Path:
    config = Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config")).expanduser()
    return config / "autostart" / DESKTOP_FILE


def _desktop_entry(argv: list[str]) -> str:
    return "\n".join([
        "[Desktop Entry]",
        "Type=Application",
        "Name=RuleProxy Web",
        "Comment=登录后在后台启动 RuleProxy 面板",
        f"Exec={_desktop_exec(argv)}",
        "Terminal=false",
        "NoDisplay=true",
        "X-GNOME-Autostart-enabled=true",
        _MARK,
        "",
    ])


def _linux_read(*, include_disabled: bool = False) -> str | None:
    """The Exec line of our entry, or None when there is none (or the desktop's startup settings turned it off)."""
    try:
        lines = _linux_path().read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    if _MARK not in lines:
        return None  # not ours; leave it alone
    values = dict(line.split("=", 1) for line in lines if "=" in line and not line.startswith("#"))
    if not include_disabled and (values.get("Hidden") == "true" or values.get("X-GNOME-Autostart-enabled") == "false"):
        return None
    return values.get("Exec", "")


def _windows_read() -> str | None:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            value, kind = winreg.QueryValueEx(key, RUN_VALUE)
    except OSError:
        return None
    if _windows_switched_off():
        return None  # Windows will not run it, so it reads as off
    return value if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) and isinstance(value, str) else ""


def _windows_switched_off() -> bool:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, APPROVED_KEY) as key:
            data, _ = winreg.QueryValueEx(key, RUN_VALUE)
    except OSError:
        return False
    # The first byte is even when the item is allowed to start and odd when it was switched off.
    return isinstance(data, bytes) and len(data) > 0 and data[0] & 1 == 1


def _windows_write(command_line: str) -> None:
    import winreg

    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, RUN_VALUE, 0, winreg.REG_SZ, command_line)
    _windows_clear_switch()  # turning it on here also undoes an earlier "off" in Task Manager


def _windows_remove() -> None:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, RUN_VALUE)
    except FileNotFoundError:
        pass
    _windows_clear_switch()


def _windows_clear_switch() -> None:
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, APPROVED_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, RUN_VALUE)
    except FileNotFoundError:
        pass
