"""Locate existing Linux application profiles without changing or copying them.

The caller must bind only the returned profile into its existing sandbox. This
module never opens the desktop bus or exports the user's encryption keys.
"""
from __future__ import annotations

import configparser
import errno
import json
import os
from pathlib import Path
import socket
import stat
import sys

MAX_METADATA_BYTES = 8 * 1024**2


def _error(detail: str) -> ValueError:
    return ValueError('无法共用原应用资料：' + detail)


def _checked(path: Path, *, directory: bool) -> Path:
    path = Path(path).expanduser()
    if not path.is_absolute():
        raise _error('资料路径必须是绝对路径。')
    if '..' in path.parts:
        raise _error('资料路径不能包含上级目录跳转。')
    try:
        for part in (*reversed(path.parents), path):
            info = part.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise _error('资料路径不能经过符号链接。')
        info = path.lstat()
    except OSError as exc:
        raise _error('找不到或无法读取原应用资料，请先在原应用中建立配置。') from exc
    if (directory and not stat.S_ISDIR(info.st_mode)) or (not directory and not stat.S_ISREG(info.st_mode)):
        raise _error('资料必须是普通目录或文件。')
    if info.st_uid != os.getuid():
        raise _error('原应用资料必须属于当前桌面用户。')
    return path


def _text(path: Path) -> str:
    _checked(path, directory=False)
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as stream:
            data = stream.read(MAX_METADATA_BYTES + 1)
        if len(data) > MAX_METADATA_BYTES:
            raise _error('资料索引过大，无法安全识别。')
        return data.decode('utf-8-sig')
    except (OSError, UnicodeError) as exc:
        raise _error('无法读取原应用的资料索引。') from exc


def _json_object(path: Path) -> None:
    try:
        value = json.loads(_text(path))
    except (ValueError, RecursionError) as exc:
        raise _error('原应用资料索引损坏。') from exc
    if not isinstance(value, dict):
        raise _error('原应用资料索引无效。')


def _config_home() -> Path:
    value = os.environ.get('CHROME_CONFIG_HOME') or os.environ.get('XDG_CONFIG_HOME')
    root = Path(value).expanduser() if value else Path.home() / '.config'
    if not root.is_absolute():
        raise _error('XDG/Chrome 配置目录必须是绝对路径。')
    return root


def _chromium_location(app: dict) -> tuple[list[Path], bool]:
    executable = Path(app.get('path', ''))
    name, parent = executable.name.casefold(), executable.parent.name.casefold()
    channel = name + '/' + parent
    folder = None
    if name in {'chrome', 'chrome-bin', 'google-chrome', 'google-chrome-stable', 'google-chrome-beta', 'google-chrome-unstable', 'google-chrome-canary'}:
        suffix = '-beta' if 'beta' in channel else '-unstable' if 'unstable' in channel else '-canary' if 'canary' in channel else ''
        folder = 'google-chrome' + suffix
    elif name in {'chromium', 'chromium-browser'}:
        folder = 'chromium'
    elif name in {'msedge', 'microsoft-edge', 'microsoft-edge-stable', 'microsoft-edge-beta', 'microsoft-edge-dev'}:
        suffix = '-beta' if 'beta' in channel else '-dev' if 'dev' in channel else ''
        folder = 'microsoft-edge' + suffix
    elif name in {'brave', 'brave-browser', 'brave-browser-beta', 'brave-browser-nightly'}:
        suffix = '-Beta' if 'beta' in channel else '-Nightly' if 'nightly' in channel else ''
        folder = 'BraveSoftware/Brave-Browser' + suffix
    if folder is not None:
        override = os.environ.get('CHROME_USER_DATA_DIR')
        return [Path(override).expanduser() if override else _config_home() / folder], False
    electron = {'chatgpt': ('ChatGPT', 'chatgpt'), 'discord': ('discord',),
                'discordcanary': ('discordcanary',), 'discordptb': ('discordptb',),
                'code': ('Code',), 'code-insiders': ('Code - Insiders',)}
    if name in electron:
        # Electron follows XDG_CONFIG_HOME; Chrome-specific overrides do not
        # describe Electron's app.getPath('userData').
        configured = os.environ.get('XDG_CONFIG_HOME')
        base = Path(configured).expanduser() if configured else Path.home() / '.config'
        if not base.is_absolute():
            raise _error('XDG 配置目录必须是绝对路径。')
        return [base / item for item in electron[name]], True
    raise _error('尚不能可靠识别此应用的原资料目录，请继续使用独立配置。')


def _firefox_location(app: dict) -> Path:
    name = Path(app.get('path', '')).name.casefold()
    bases = {'firefox': '.mozilla/firefox', 'firefox-bin': '.mozilla/firefox',
             'firefox-esr': '.mozilla/firefox', 'librewolf': '.librewolf', 'waterfox': '.waterfox'}
    if name not in bases:
        raise _error('尚不能可靠识别此 Firefox 应用的原资料目录。')
    base = Path.home() / bases[name]
    if name in ('firefox', 'firefox-bin', 'firefox-esr'):
        configured = os.environ.get('XDG_CONFIG_HOME')
        config = Path(configured).expanduser() if configured else Path.home() / '.config'
        if not config.is_absolute():
            raise _error('XDG 配置目录必须是绝对路径。')
        # Current Firefox can use XDG for a new installation. Older/legacy
        # installs retain .mozilla; never guess when both have profile indexes.
        candidates = [base, config / 'mozilla/firefox']
        indexed = [candidate for candidate in candidates
                   if (candidate / 'profiles.ini').exists() or (candidate / 'profiles.ini').is_symlink()]
        if len(indexed) > 1:
            raise _error('Firefox 存在多个可能的资料根目录，无法可靠选择。')
        if indexed:
            base = indexed[0]
    base = _checked(base, directory=True)
    profiles, defaults, installs = [], [], []
    for filename in ('profiles.ini', 'installs.ini'):
        path = base / filename
        if not path.exists() and not path.is_symlink():
            if filename == 'profiles.ini':
                raise _error('找不到 Firefox profiles.ini，请先启动并关闭原浏览器。')
            continue
        parser = configparser.RawConfigParser(interpolation=None, strict=True)
        try:
            parser.read_string(_text(path))
            for section in parser.sections():
                if filename == 'profiles.ini' and section.startswith('Profile'):
                    raw = parser.get(section, 'Path')
                    relative = parser.get(section, 'IsRelative', fallback='1')
                    if relative not in ('0', '1'):
                        raise ValueError('invalid relative mode')
                    candidate = Path(raw) if relative == '0' else base / raw
                    if relative == '1' and Path(raw).is_absolute():
                        raise ValueError('invalid relative path')
                    profiles.append(candidate)
                    if parser.get(section, 'Default', fallback='0') == '1':
                        defaults.append(candidate)
                elif filename == 'installs.ini' or section.startswith('Install'):
                    raw = parser.get(section, 'Default', fallback='')
                    if raw:
                        installs.append(Path(raw) if Path(raw).is_absolute() else base / raw)
        except (configparser.Error, ValueError) as exc:
            raise _error('Firefox 配置索引损坏或路径无效。') from exc
    # Different Firefox installations can select different defaults. Without
    # their install hash, guessing one would open the wrong user's profile.
    choices = set(installs or defaults or profiles)
    if len(choices) != 1:
        raise _error('Firefox 存在多个可能的默认配置，无法可靠选择。')
    return choices.pop()


def _validate_layout(source: Path, adapter: str, electron: bool = False) -> Path:
    source = _checked(source, directory=True)
    home = Path.home().absolute()
    if source == home or source in home.parents:
        raise _error('不能把整个家目录作为应用资料共享。')
    if adapter == 'firefox':
        _checked(source / 'prefs.js', directory=False)
        return source
    _json_object(source / 'Local State')
    if electron:
        for marker in ('Preferences', 'Cookies', 'Network/Cookies', 'Local Storage', 'IndexedDB', 'User'):
            candidate = source / marker
            if candidate.exists() or candidate.is_symlink():
                _checked(candidate, directory=candidate.is_dir())
                return source
    else:
        for index, candidate in enumerate(source.iterdir()):
            if index >= 1024:
                raise _error('原应用资料索引条目过多，无法可靠识别。')
            if candidate.name == 'Default' or candidate.name.startswith('Profile '):
                if (candidate / 'Preferences').exists() or (candidate / 'Preferences').is_symlink():
                    _json_object(candidate / 'Preferences')
                    return source
    raise _error('原资料目录尚未初始化，不能用空目录代替原数据。')


def _assert_not_running(source: Path, adapter: str) -> None:
    if adapter == 'chromium':
        lock = source / 'SingletonLock'
        try:
            info = lock.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISLNK(info.st_mode):
            raise _error('原应用资料锁无法确认，请先完全关闭原应用。')
        target = os.readlink(lock)
        hostname, separator, raw_pid = target.rpartition('-')
        if not separator or hostname != socket.gethostname() or not raw_pid.isdecimal() or int(raw_pid) <= 0:
            raise _error('原应用资料由其他会话占用，请先完全关闭原应用。')
        try:
            os.kill(int(raw_pid), 0)
        except ProcessLookupError:
            raise _error('检测到旧资料锁，请启动并正常退出原应用以释放旧锁。') from None
        except OSError as exc:
            if exc.errno == errno.ESRCH:
                raise _error('检测到旧资料锁，请启动并正常退出原应用以释放旧锁。') from None
        raise _error('原应用仍在运行，请先完全关闭原应用。')
    import fcntl

    for name in ('.parentlock', 'parent.lock', 'lock'):
        lock = source / name
        try:
            info = lock.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode):
            raise _error('Firefox 资料锁无法确认，请先完全关闭原浏览器。')
        descriptor = os.open(lock, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            # Firefox's write lock conflicts with this shared read lock. A
            # leftover ordinary .parentlock file alone is not proof of use.
            try:
                fcntl.lockf(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno in (errno.EACCES, errno.EAGAIN):
                    raise _error('Firefox 原配置仍在使用，请先完全关闭原浏览器。') from exc
                raise
            fcntl.lockf(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def original_profile_source(app: dict) -> Path:
    """Return an initialized, owned, unoccupied original profile; never copy it."""
    if not sys.platform.startswith('linux'):
        raise _error('此资料目录识别只用于 Linux。')
    adapter = app.get('adapter')
    if adapter == 'firefox':
        source = _validate_layout(_firefox_location(app), adapter)
    elif adapter == 'chromium':
        candidates, electron = _chromium_location(app)
        existing = [path for path in candidates if path.exists() or path.is_symlink()]
        if len(existing) != 1:
            raise _error('找不到唯一的原应用资料目录，请先在原应用中建立配置。')
        source = _validate_layout(existing[0], adapter, electron)
    else:
        raise _error('此启动方式尚不支持共用原应用资料。')
    _assert_not_running(source, adapter)
    return source
