"""Prepare Firefox proxy policies for read-only mounts inside one namespace.

Firefox's Proxy policy sets locked DEFAULT preferences, rather than writing the
original profile's user.js or proxy user preferences. The browser still saves
the user's other changes in its original, shared profile.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import time

SYSTEM_POLICY_DIRS = (Path('/etc/firefox/policies'), Path('/etc/firefox-esr/policies'))
MAX_POLICY_FILES = 512
MAX_POLICY_BYTES = 32 * 1024**2
MAX_POLICY_SECONDS = 5.0


def _fail(detail: str) -> ValueError:
    return ValueError('无法为原 Firefox 配置建立临时代理策略：' + detail)


def _plain(path: Path, *, directory: bool) -> None:
    if not path.is_absolute() or '..' in path.parts:
        raise _fail('路径必须是绝对路径且不能包含上级跳转。')
    for part in (*reversed(path.parents), path):
        if stat.S_ISLNK(part.lstat().st_mode):
            raise _fail('原策略目录不能经过符号链接。')
    mode = path.lstat().st_mode
    if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
        raise _fail('原策略必须是普通目录或文件。')


def _copy_directory(source: Path, target: Path, budget: dict) -> None:
    target.mkdir(mode=0o700)
    if not source.exists() and not source.is_symlink():
        return
    _plain(source, directory=True)
    pending = [(source, target, 0)]
    while pending:
        original, copied, depth = pending.pop()
        if depth > 8:
            raise _fail('原策略目录层次超过安全限制。')
        with os.scandir(original) as entries:
            for entry in entries:
                if time.monotonic() - budget['started'] > MAX_POLICY_SECONDS:
                    raise _fail('准备策略超过时间限制。')
                budget['files'] += 1
                if budget['files'] > MAX_POLICY_FILES:
                    raise _fail('原策略目录条目过多。')
                info = entry.stat(follow_symlinks=False)
                destination = copied / entry.name
                if stat.S_ISDIR(info.st_mode):
                    destination.mkdir(mode=0o700)
                    pending.append((Path(entry.path), destination, depth + 1))
                elif stat.S_ISREG(info.st_mode):
                    descriptor = os.open(entry.path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
                    with os.fdopen(descriptor, 'rb') as incoming, destination.open('xb') as outgoing:
                        os.chmod(destination, 0o600)
                        opened = os.fstat(incoming.fileno())
                        if not stat.S_ISREG(opened.st_mode) or opened.st_ino != info.st_ino:
                            raise _fail('原策略文件在准备期间发生变化。')
                        while True:
                            data = incoming.read(1024 * 1024)
                            if not data:
                                break
                            budget['bytes'] += len(data)
                            if budget['bytes'] > MAX_POLICY_BYTES or time.monotonic() - budget['started'] > MAX_POLICY_SECONDS:
                                raise _fail('原策略目录超过大小或时间限制。')
                            outgoing.write(data)
                        final = os.fstat(incoming.fileno())
                        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns) != (final.st_size, final.st_mtime_ns, final.st_ctime_ns):
                            raise _fail('原策略文件在准备期间发生变化。')
                else:
                    raise _fail('原策略目录包含链接、套接字或其他不支持的对象。')


def _merge_proxy(directory: Path, port: int) -> None:
    path = directory / 'policies.json'
    document = {}
    if path.exists():
        try:
            document = json.loads(path.read_text(encoding='utf-8-sig'))
        except (OSError, ValueError, RecursionError) as exc:
            raise _fail('原 policies.json 损坏。') from exc
    if not isinstance(document, dict) or not isinstance(document.get('policies', {}), dict):
        raise _fail('原 policies.json 格式无效。')
    policies = document.setdefault('policies', {})
    for key in ('DisableEnterprisePolicies', 'DisableLocalPolicies'):
        if policies.get(key) not in (None, False):
            raise _fail('原设置禁用了企业或本地策略，不能安全覆盖。')
    preferences = policies.setdefault('Preferences', {})
    if not isinstance(preferences, dict):
        raise _fail('原 Preferences 策略格式无效。')
    # ProxyPolicies ignores empty HTTPProxy/AutoConfigURL strings. Explicitly
    # lock empty DEFAULT values instead, so original user/policy HTTP and PAC
    # settings cannot take precedence over our SOCKS proxy. Other preferences
    # remain intact, and the original user-pref files are never rewritten.
    for name, value in {'network.proxy.http': '', 'network.proxy.http_port': 0,
                        'network.proxy.ssl': '', 'network.proxy.ssl_port': 0,
                        'network.proxy.ftp': '', 'network.proxy.ftp_port': 0,
                        'network.proxy.autoconfig_url': ''}.items():
        preferences[name] = {'Value': value, 'Status': 'locked',
                             'Type': 'number' if isinstance(value, int) else 'string'}
    policies['Proxy'] = {'Mode': 'manual', 'Locked': True, 'SOCKSProxy': f'127.0.0.1:{port}',
                         'SOCKSVersion': 5, 'UseProxyForDNS': True, 'Passthrough': '',
                         'UseHTTPProxyForAllProtocols': False}
    path.write_text(json.dumps(document, ensure_ascii=False, sort_keys=True) + '\n', encoding='utf-8')
    os.chmod(path, 0o600)


def prepare_policy_mounts(executable: Path, workspace: Path, port: int) -> list[tuple[Path, Path]]:
    """Return private policy-directory mounts; the caller owns workspace cleanup.

    No original profile or system file is modified. Existing unrelated policy
    and distribution files remain visible through the copied directory mounts.
    """
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise _fail('代理端口无效。')
    executable, workspace = Path(executable).absolute(), Path(workspace).absolute()
    _plain(executable, directory=False)
    sources = [*SYSTEM_POLICY_DIRS, executable.parent / 'distribution']
    if any(workspace == source or source in workspace.parents for source in sources):
        raise _fail('临时工作目录不能位于原策略目录内。')
    _plain(workspace.parent, directory=True)
    workspace.mkdir(mode=0o700, exist_ok=True)
    _plain(workspace, directory=True)
    if workspace.stat().st_uid != os.getuid():
        raise _fail('临时工作目录不属于当前用户。')
    private = Path(tempfile.mkdtemp(prefix='firefox-policy-', dir=workspace))
    budget = {'started': time.monotonic(), 'files': 0, 'bytes': 0}
    try:
        mounts = []
        for index, source in enumerate(sources):
            copied = private / str(index)
            _copy_directory(source, copied, budget)
            _merge_proxy(copied, port)
            mounts.append((copied, source))
        return mounts
    except Exception:
        shutil.rmtree(private)
        raise
