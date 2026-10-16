"""Restricted host services for a browser using its original Linux profile.

Only a filtered keyring connection is exposed. Desktop portals, other apps and
the system bus remain inaccessible; the proxy exits when its parent lifeline
closes, including when the panel crashes.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time
from urllib.parse import unquote


KEYRING_NAMES = ('org.freedesktop.secrets', 'org.kde.kwalletd',
                 'org.kde.kwalletd5', 'org.kde.kwalletd6')
START_TIMEOUT = 5
MAX_PROFILE_ENTRIES = 100000
MAX_PROFILE_SECONDS = 5
MAX_PROFILE_DEPTH = 64


def session_address(env: dict[str, str]) -> str | None:
    """Accept only one local Unix session bus, never a TCP or multi-address bus."""
    address = env.get('DBUS_SESSION_BUS_ADDRESS', '')
    if not address:
        runtime = env.get('XDG_RUNTIME_DIR', '')
        candidate = Path(runtime) / 'bus' if runtime else None
        if candidate is None or not candidate.is_socket():
            return None
        address = 'unix:path=' + str(candidate)
    if (not isinstance(address, str) or len(address) > 4096 or not address.startswith('unix:')
            or any(char in address for char in (';', '\0', '\n', '\r'))):
        raise ValueError('原应用资料需要本机桌面会话的 Unix 密钥服务连接；不支持其他 D-Bus 地址。')
    try:
        entries = address[5:].split(',')
        fields = dict(entry.split('=', 1) for entry in entries)
        if (len(fields) != len(entries) or set(fields) - {'path', 'abstract', 'guid'}
                or ('path' in fields) == ('abstract' in fields)):
            raise ValueError
        endpoint = unquote(fields.get('path', fields.get('abstract', '')))
        if not endpoint or '\0' in endpoint or ('path' in fields and not endpoint.startswith('/')):
            raise ValueError
    except ValueError:
        raise ValueError('无法识别桌面密钥服务地址；请从当前桌面会话启动面板。') from None
    return address


def has_saved_chromium_secrets(profile: Path) -> bool:
    """Conservatively require the desktop keyring for an existing login store."""
    profile = Path(profile)
    try:
        folders = [profile]
        for index, path in enumerate(profile.iterdir()):
            if index >= 512:
                return True
            if (path.is_dir() and not path.is_symlink()
                    and (path.name == 'Default' or path.name.startswith('Profile '))):
                folders.append(path)
        if any((folder / name).is_file() for folder in folders
               for name in ('Cookies', 'Network/Cookies', 'Login Data', 'Login Data For Account')):
            return True
        metadata = profile / 'Local State'
        if metadata.is_file():
            with metadata.open('rb') as source:
                data = source.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                return True
            value = json.loads(data)
            return isinstance(value, dict) and bool(value.get('os_crypt'))
    except (OSError, ValueError, UnicodeError, RecursionError):
        # A store that cannot be checked is not evidence that keyring access
        # is unnecessary. Never force Chromium to a basic password store.
        return True
    return False


def require_wallet_provider(env: dict[str, str], address: str) -> None:
    """Check service names only; never request, export or inspect any key."""
    executable = shutil.which('dbus-send')
    if not executable:
        raise ValueError('无法检查原浏览器的桌面密钥服务；请重新运行 Linux 安装脚本以安装 dbus。')
    names = set()
    for method in ('ListNames', 'ListActivatableNames'):
        try:
            response = subprocess.run([executable, '--bus=' + address, '--type=method_call', '--print-reply',
                '--reply-timeout=2000', '--dest=org.freedesktop.DBus', '/org/freedesktop/DBus',
                'org.freedesktop.DBus.' + method], capture_output=True, text=True, timeout=3)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError('无法确认原浏览器使用的桌面密钥服务；请从原桌面会话启动面板后重试。') from exc
        if response.returncode or len(response.stdout) > 1024 * 1024:
            raise ValueError('无法确认原浏览器使用的桌面密钥服务；原应用资料尚未打开。')
        names.update(re.findall(r'^\s*string "([A-Za-z0-9_.:-]+)"\s*$', response.stdout, re.MULTILINE))
    desktop = (env.get('XDG_CURRENT_DESKTOP', '') + ' ' + env.get('DESKTOP_SESSION', '')).casefold()
    if 'kde' in desktop or 'plasma' in desktop:
        allowed = set(KEYRING_NAMES) - {'org.freedesktop.secrets'}
    elif any(name in desktop for name in ('gnome', 'unity', 'cinnamon', 'mate', 'xfce', 'lxde', 'pantheon')):
        allowed = {'org.freedesktop.secrets'}
    else:
        allowed = set(KEYRING_NAMES)
    if not names & allowed:
        raise ValueError('原浏览器已有登录资料，但桌面密钥服务不存在或无法激活。请启动原桌面的密钥环/钱包后重试；不会改用基础密码存储。')


class FilteredKeyringProxy:
    def __init__(self, address: str):
        executable = shutil.which('xdg-dbus-proxy')
        if not executable:
            raise ValueError('共用原浏览器资料需要 xdg-dbus-proxy；请重新运行 Linux 安装脚本。')
        self.directory = tempfile.TemporaryDirectory(prefix='ruleproxy-keyring-')
        self.path = Path(self.directory.name) / 'bus'
        self.process = None
        self._lifeline = None
        self._lock = threading.Lock()
        parent, child = socket.socketpair()
        try:
            self._lifeline = parent
            args = [executable, '--fd=' + str(child.fileno()), address, str(self.path), '--filter',
                    *('--talk=' + name for name in KEYRING_NAMES)]
            self.process = subprocess.Popen(args, pass_fds=(child.fileno(),), stdin=subprocess.DEVNULL,
                                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child.close()
            ready, _, _ = select.select([parent], [], [], START_TIMEOUT)
            if (not ready or not parent.recv(1) or self.process.poll() is not None
                    or not self.path.is_socket()):
                raise ValueError('无法建立受限的桌面密钥服务连接；请确认桌面会话正常后重试。')
            os.chmod(self.path, 0o600)
        except Exception:
            child.close()
            self.close()
            raise

    def close(self) -> None:
        with self._lock:
            if self._lifeline is not None:
                self._lifeline.close()
                self._lifeline = None
            if self.process is not None and self.process.poll() is None:
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            self.directory.cleanup()


def prepare_keyring(env: dict[str, str], profile: Path, adapter: str) -> FilteredKeyringProxy | None:
    if adapter != 'chromium':
        return None
    needs_wallet = has_saved_chromium_secrets(profile)
    address = session_address(env)
    if address is None:
        if needs_wallet:
            raise ValueError('原浏览器已有登录资料，但当前没有可用的桌面密钥服务。请从原桌面会话启动面板；不会改用基础密码存储。')
        return None
    proxy = FilteredKeyringProxy(address)
    try:
        if needs_wallet:
            require_wallet_provider(env, 'unix:path=' + str(proxy.path))
        return proxy
    except Exception:
        proxy.close()
        raise


def shared_profile(path: Path, workspace: Path) -> Path:
    """Recheck the selected directory before granting its explicit read/write bind."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('原应用资料必须是明确的绝对目录。')
    try:
        for candidate in (*reversed(path.parents), path):
            if candidate.is_symlink():
                raise ValueError('原应用资料路径不能经过符号链接。')
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('原应用资料必须是当前用户拥有的普通目录。')
    except OSError as exc:
        raise ValueError('无法访问原应用资料；请确认目录仍然存在。') from exc
    home, workspace = Path.home().resolve(), workspace.resolve()
    if (path == home or path in home.parents or path == workspace or path in workspace.parents
            or workspace in path.parents or str(path) in {'/tmp', '/run', '/etc', '/usr', '/var', '/opt', '/home'}):
        raise ValueError('不能把整个家目录、系统目录或工具工作目录作为原应用资料。')
    _check_profile_entries(path)
    return path


def _check_profile_entries(root: Path) -> None:
    """A bound pathname socket can reach host brokers despite a network namespace.

    Inspect metadata only and never follow a symlink or remove a browser lock.
    Existing normal browser files remain untouched on every failure path.
    """
    started, count, pending = time.monotonic(), 0, [(root, 0)]
    try:
        while pending:
            directory, depth = pending.pop()
            if depth > MAX_PROFILE_DEPTH or time.monotonic() - started > MAX_PROFILE_SECONDS:
                raise ValueError('原应用资料检查超过层次或时间限制；未打开或修改原资料。')
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with os.scandir(descriptor) as entries:
                    for entry in entries:
                        count += 1
                        if count > MAX_PROFILE_ENTRIES or time.monotonic() - started > MAX_PROFILE_SECONDS:
                            raise ValueError('原应用资料检查超过数量或时间限制；未打开或修改原资料。')
                        mode = entry.stat(follow_symlinks=False).st_mode
                        if stat.S_ISDIR(mode):
                            pending.append((directory / entry.name, depth + 1))
                        elif not (stat.S_ISREG(mode) or stat.S_ISLNK(mode)):
                            raise ValueError('原应用资料中存在套接字、管道或设备，不能安全共用；请关闭原应用后重试。')
            finally:
                os.close(descriptor)
    except OSError as exc:
        raise ValueError('原应用资料在检查期间不可读或发生变化；未打开或修改原资料。') from exc


def policy_overlay_args(mounts: list[tuple[Path, Path]]) -> list[str]:
    """Overlay only policy parents inside the namespace, even when a child is absent.

    A read-only /etc or application tree cannot acquire a new policy directory.
    Rebuild its nearest existing parent in tmpfs using read-only sibling binds;
    then the private policy can be mounted without changing the host tree.
    """
    result, checked, anchors = [], {}, []
    for source, target in mounts:
        source, target = Path(source), Path(target)
        if not source.is_dir() or not target.is_absolute():
            raise ValueError('Firefox 的临时策略目录无效。')
        anchor = target.parent
        while not anchor.exists():
            anchor = anchor.parent
        if anchor == Path('/') or not anchor.is_dir() or anchor.is_symlink():
            raise ValueError('无法在隔离空间中挂载 Firefox 策略。')
        if target in checked or any(target in other.parents or other in target.parents for other in checked):
            raise ValueError('Firefox 的临时策略目录不能重复或相互包含。')
        checked[target] = source
        anchors.append(anchor)
    # Several absent policy parents may share /etc. Rebuild that anchor once;
    # a later tmpfs on /etc would otherwise erase the earlier Firefox mount.
    roots = []
    for anchor in sorted(set(anchors), key=lambda path: (len(path.parts), str(path))):
        if not any(anchor == root or root in anchor.parents for root in roots):
            roots.append(anchor)
    count = 0

    def rebuild(directory: Path, targets: list[Path]) -> None:
        nonlocal count
        existing = {path.name: path for path in directory.iterdir()} if directory.is_dir() else {}
        names = set(existing) | {target.relative_to(directory).parts[0] for target in targets}
        count += len(names)
        if count > 4096:
            raise ValueError('Firefox 策略所在目录条目过多，无法安全挂载。')
        for name in sorted(names):
            path = directory / name
            if path in checked:
                result.extend(['--ro-bind', str(checked[path]), str(path)])
                continue
            descendants = [target for target in targets if path in target.parents]
            if descendants:
                if path.is_symlink() or path.exists() and not path.is_dir():
                    raise ValueError('Firefox 策略的上级目录无效。')
                result.extend(['--dir', str(path)])
                rebuild(path, descendants)
            elif path.is_symlink():
                result.extend(['--symlink', os.readlink(path), str(path)])
            else:
                result.extend(['--ro-bind', str(path), str(path)])

    for anchor in roots:
        result += ['--tmpfs', str(anchor)]
        rebuild(anchor, [target for target in checked if anchor in target.parents])
    return result
