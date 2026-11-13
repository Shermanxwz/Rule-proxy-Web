"""Discover installed Chromium web-app shortcuts without starting a browser.

Only launch identity and HTTP(S) start URLs are retained. The selected profile's
WebApp registry (or legacy hosted-app manifest) is metadata, not a source of
cookies, passwords, history or files to copy into the launcher-owned profile.
An installed app-id is *not* an installation in a new --user-data-dir: isolated
mode opens a validated start URL with --app= instead. Explicit original-data
mode retains the identified browser/profile/app-id, without copying its files.

Metadata schema references (no network access is used at runtime):
https://chromium.googlesource.com/chromium/src/+/main/chrome/browser/web_applications/proto/web_app.proto
https://chromium.googlesource.com/chromium/src/+/main/components/sync/protocol/web_app_specifics.proto
https://chromium.googlesource.com/chromium/src/+/main/components/sync/model/blocking_data_type_store_impl.cc
"""
from __future__ import annotations

import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlsplit


_APP_ID = re.compile(r'[a-p]{32}\Z')
_PROFILE = re.compile(r'(?:Default|Profile [0-9]{1,6})\Z')
_FIELDS = frozenset({'browser', 'profile_directory', 'app_id', 'start_url', 'launch_mode'})
_EXECUTABLES = {'chrome': {'chrome.exe'}, 'edge': {'msedge.exe'},
                'brave': {'brave.exe'}, 'chromium': {'chrome.exe', 'chromium.exe'},
                'vivaldi': {'vivaldi.exe'}}
_PROXIES = {'chrome_proxy.exe': 'chrome.exe', 'msedge_proxy.exe': 'msedge.exe',
            'brave_proxy.exe': 'brave.exe', 'vivaldi_proxy.exe': 'vivaldi.exe'}
_MAX_OUTPUT = 2 * 1024**2
_MAX_SHORTCUTS = 2048
_MAX_METADATA = 8 * 1024**2
_DISCOVERY_SECONDS = 12

WEB_APP_DETAIL = ('以已验证的 HTTP(S) 启动网址打开独立应用窗口，而非复用原 PWA 安装。'
                  '网址来自快捷方式或本地安装元数据，格式校验不代表联网成功。'
                  '首次需重新登录；后续保留此条目的独立资料，不读取或复制原浏览器登录数据。'
                  'Windows 按浏览器程序路径代理，同一浏览器的其它窗口和 Web 应用也受启用规则影响；'
                  '停用单个条目不代表同路径流量直连。')
WEB_APP_ORIGINAL_DETAIL = ('使用所选浏览器的原配置；有安装 ID 时按原 PWA 启动，'
                          '无安装 ID 时在同一配置以网址打开应用窗口。'
                          '浏览器直接使用原资料，修改会同步；本工具不读取或复制登录数据。'
                          '启动请求可能交给已有窗口，启动进程退出不表示窗口已关闭；'
                          '接力到已有浏览器时仍沿用其启动和代理设置；'
                          '已有进程不会由面板接管或关闭。'
                          '本工具新建的浏览器实例，其共用窗口会随实例一同关闭。'
                          'Windows 应用模式按浏览器程序路径代理，同一浏览器的其它窗口和 Web 应用也受启用规则影响；'
                          '停用单个条目不代表同路径流量直连。')

# GetFolderPath uses the interactive process owner's known folders, including a
# redirected Desktop. Never enumerate other users or resolve/execute a .lnk.
# CreateShortcut reads TargetPath/Arguments; Save and Run are deliberately absent.
_QUERY_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$shell = New-Object -ComObject WScript.Shell
$roots = @('Programs', 'CommonPrograms', 'DesktopDirectory', 'CommonDesktopDirectory') |
    ForEach-Object { [Environment]::GetFolderPath($_) } | Where-Object { $_ } | Select-Object -Unique
$queue = New-Object 'System.Collections.Generic.Queue[object]'
foreach ($root in $roots) { $queue.Enqueue(@($root, 0)) }
$rows = New-Object 'System.Collections.Generic.List[object]'
$directories = 0
while ($queue.Count -gt 0 -and $directories -lt 512 -and $rows.Count -lt 2048) {
    $item = $queue.Dequeue(); $directories++
    try {
        $folder = Get-Item -LiteralPath $item[0] -Force -ErrorAction Stop
        if (($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        foreach ($entry in @(Get-ChildItem -LiteralPath $item[0] -Force -ErrorAction Stop | Select-Object -First 4096)) {
            if (($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            if ($entry.PSIsContainer) {
                if ($item[1] -lt 6 -and $queue.Count -lt 512) { $queue.Enqueue(@($entry.FullName, ($item[1] + 1))) }
                continue
            }
            if ($entry.Extension -ine '.lnk' -or $entry.Length -gt 1048576) { continue }
            if ($rows.Count -ge 2048) { break }
            try {
                $link = $shell.CreateShortcut($entry.FullName)
                $target = [string]$link.TargetPath; $arguments = [string]$link.Arguments
                if ($target.Length -gt 4096 -or $arguments.Length -gt 16384 -or $entry.BaseName.Length -gt 200) { continue }
                [void]$rows.Add([ordered]@{label=$entry.BaseName; target=$target; arguments=$arguments})
            } catch { continue }
        }
    } catch { continue }
}
$json = ConvertTo-Json -InputObject ([ordered]@{schema_version=1; shortcuts=@($rows.ToArray())}) -Depth 4 -Compress
$bytes = [Text.Encoding]::UTF8.GetBytes($json)
if ($bytes.Length -gt 2097152) { exit 2 }
$stream = [Console]::OpenStandardOutput(); $stream.Write($bytes, 0, $bytes.Length); $stream.Flush()
'''


def _text(value, maximum: int) -> str:
    if (not isinstance(value, str) or len(value) > maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('Web 应用元数据文本无效。')
    value.encode('utf-8')
    return value


def validate_start_url(value) -> str:
    """Validate syntax, not connectivity; no HTTP request is made during discovery."""
    value = _text(value, 4096)
    if (not value or any(c.isspace() for c in value) or any(c in value for c in '\\"<>`')
            or re.search(r'%(?![0-9a-fA-F]{2})', value)):
        raise ValueError('Web 应用需要有效的 HTTP(S) 启动网址。')
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        if (parsed.scheme not in ('http', 'https') or not host or parsed.username is not None
                or parsed.password is not None or '@' in parsed.netloc or '%' in host
                or (parsed.port is not None and not 1 <= parsed.port <= 65535)):
            raise ValueError('invalid URL authority')
        if ':' in host:
            ipaddress.IPv6Address(host)
        else:
            ascii_host = host.encode('idna').decode('ascii')
            if (len(ascii_host) > 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
                                           for label in ascii_host.rstrip('.').split('.'))):
                raise ValueError('invalid URL hostname')
    except (ValueError, UnicodeError) as exc:
        raise ValueError('Web 应用需要有效的 HTTP(S) 启动网址。') from exc
    return value


def validate_web_app(value, executable: Path) -> dict[str, str]:
    """Strict saved/API schema. No original-profile reads while restoring settings."""
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError('Web 应用元数据字段无效。')
    browser = _text(value['browser'], 16)
    profile = _text(value['profile_directory'], 128)
    app_id = _text(value['app_id'], 32)
    if (browser not in _EXECUTABLES or executable.name.casefold() not in _EXECUTABLES[browser]
            or not _PROFILE.fullmatch(profile) or (app_id and not _APP_ID.fullmatch(app_id))
            or value['launch_mode'] != 'isolated_url'):
        raise ValueError('Web 应用浏览器、配置身份或启动模式无效。')
    url = validate_start_url(value['start_url'])
    return {'browser': browser, 'profile_directory': profile, 'app_id': app_id,
            'start_url': url, 'launch_mode': 'isolated_url'}


def split_windows_arguments(value: str) -> list[str]:
    """The backslash/quote rules of CommandLineToArgvW, without running a shell."""
    _text(value.replace('\t', ' ') if isinstance(value, str) else value, 16384)
    args, token, quoted, started, i = [], [], False, False, 0
    while i < len(value):
        char = value[i]
        if char in ' \t' and not quoted:
            if started:
                args.append(''.join(token)); token, started = [], False
            i += 1
            continue
        started = True
        if char == '\\':
            end = i
            while end < len(value) and value[end] == '\\':
                end += 1
            count = end - i
            if end < len(value) and value[end] == '"':
                token.extend('\\' * (count // 2))
                if count % 2:
                    token.append('"')
                else:
                    quoted = not quoted
                i = end + 1
            else:
                token.extend('\\' * count); i = end
        elif char == '"':
            if quoted and i + 1 < len(value) and value[i + 1] == '"':
                token.append('"'); i += 2
            else:
                quoted = not quoted; i += 1
        else:
            token.append(char); i += 1
    if quoted:
        raise ValueError('Web 应用快捷方式引号未闭合。')
    if started:
        args.append(''.join(token))
    if len(args) > 64:
        raise ValueError('Web 应用快捷方式参数过多。')
    return args


def _switches(arguments: str) -> dict[str, str]:
    args = split_windows_arguments(arguments)
    result, i = {}, 0
    while i < len(args):
        name, separator, value = args[i].partition('=')
        if name not in ('--app-id', '--app', '--app-url', '--profile-directory', '--app-launch-source') or name in result:
            raise ValueError('Unsupported or repeated shortcut switch')
        if not separator:
            i += 1
            if i >= len(args) or args[i].startswith('--'):
                raise ValueError('Missing shortcut switch value')
            value = args[i]
        if not value or len(value) > 4096:
            raise ValueError('Invalid shortcut switch value')
        result[name] = value
        i += 1
    if '--app-launch-source' in result and not re.fullmatch(r'[0-9]{1,3}', result['--app-launch-source']):
        raise ValueError('Invalid app launch source')
    return result


def _browser_target(raw: str) -> tuple[str, Path]:
    raw = _text(raw, 4096)
    target = Path(raw)
    if not target.is_absolute() or raw.startswith(('\\\\', '//')):
        raise ValueError('Shortcut target must be a local absolute executable')
    target = target.resolve(strict=True)
    name = target.name.casefold()
    if name in _PROXIES:
        actual = target.parent / _PROXIES[name]
        if not actual.is_file() and re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,4}', target.parent.name):
            actual = target.parent.parent / _PROXIES[name]
        target = actual.resolve(strict=True)
        name = target.name.casefold()
    matches = [browser for browser, names in _EXECUTABLES.items() if name in names]
    if not matches or not target.is_file():
        raise ValueError('Unsupported web app browser')
    browser = matches[0]
    if name == 'chrome.exe' and any(part.casefold() == 'chromium' for part in target.parts):
        browser = 'chromium'
    with target.open('rb') as stream:
        if stream.read(2) != b'MZ':
            raise ValueError('Web app target is not a Windows executable')
    return browser, target


def _plain(path: Path, *, directory: bool) -> os.stat_result:
    if not path.is_absolute() or str(path).startswith(('\\\\', '//')) or '..' in path.parts:
        raise ValueError('Metadata must be a local absolute path')
    for parent in reversed(path.parents):
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, 'st_file_attributes', 0) & 0x400):
            raise ValueError('Metadata directory is not plain')
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400
            or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise ValueError('Metadata is not an ordinary file or directory')
    return info


def _profile_path(executable: Path, browser: str, profile: str) -> Path:
    # A portable/custom --user-data-dir is deliberately not guessed. Recognize
    # product/channel directories separately; never look in another browser.
    products = {
        'chrome': [('Google', name) for name in ('Chrome', 'Chrome Beta', 'Chrome Dev', 'Chrome SxS')],
        'edge': [('Microsoft', name) for name in ('Edge', 'Edge Beta', 'Edge Dev', 'Edge SxS')],
        'brave': [('BraveSoftware', name) for name in ('Brave-Browser', 'Brave-Browser-Beta', 'Brave-Browser-Nightly')],
        'chromium': [('Chromium',)], 'vivaldi': [('Vivaldi',)],
    }
    if browser not in products:
        raise ValueError('Unsupported browser profile root')
    parts = tuple(part.casefold() for part in executable.parts)
    choices = [product for product in products[browser] if any(
        parts[index:index + len(product)] == tuple(part.casefold() for part in product)
        for index in range(len(parts) - len(product) + 1))]
    if len(choices) != 1 or not _PROFILE.fullmatch(profile):
        raise ValueError('Browser profile root is ambiguous')
    local = Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData/Local'))
    result = local.joinpath(*choices[0], 'User Data', profile)
    _plain(result, directory=True)
    return result


def original_profile_directory(value, executable: Path) -> Path:
    """Check an existing native profile without opening any browser data files.

    Called only for an explicit mode change or launch, never settings restore.
    A missing/ambiguous root must not make Chromium create a new named profile
    while the panel reports that it reused the original data.
    """
    metadata = validate_web_app(value, executable)
    if sys.platform != 'win32' or not os.environ.get('LOCALAPPDATA'):
        raise ValueError('请在 Windows 当前用户会话中使用已识别的原浏览器资料。')
    try:
        return _profile_path(executable, metadata['browser'], metadata['profile_directory'])
    except (OSError, ValueError) as exc:
        raise ValueError('原浏览器资料目录缺失或身份不明确，请刷新 Web 应用列表后重试。') from exc


def _protobuf_fields(data: bytes) -> dict[int, list[bytes | int]]:
    """Read only WebApp / WebAppSpecifics envelopes, not arbitrary nested fields."""
    if len(data) > _MAX_METADATA:
        raise ValueError('Web app protobuf exceeds metadata limit')
    result, position, count = {}, 0, 0

    def varint():
        nonlocal position
        value = 0
        for shift in range(0, 70, 7):
            if position >= len(data):
                raise ValueError('Truncated Web app protobuf')
            byte = data[position]; position += 1
            value |= (byte & 127) << shift
            if not byte & 128:
                return value
        raise ValueError('Invalid protobuf varint')

    while position < len(data):
        tag = varint(); field, wire = tag >> 3, tag & 7
        count += 1
        if not 0 < field < (1 << 29) or count > 4096:
            raise ValueError('Invalid Web app protobuf fields')
        if wire == 0:
            value = varint()
        elif wire in (1, 2, 5):
            length = varint() if wire == 2 else 8 if wire == 1 else 4
            if position + length > len(data):
                raise ValueError('Truncated Web app protobuf field')
            value = data[position:position + length]; position += length
        else:
            raise ValueError('Unsupported protobuf wire type')
        result.setdefault(field, []).append(value)
    return result


def _start_url_from_proto(data: bytes) -> str:
    # Chromium: WebApp.sync_data=1 -> WebAppSpecifics.start_url=1. The storage
    # key, not a URL-looking string elsewhere in the record, binds this app-id.
    fields = _protobuf_fields(data)
    if (fields.get(8) not in ([1], [2]) or fields.get(9, [0]) != [0]
            or fields.get(45, [0]) != [0] or 60 in fields):
        raise ValueError('Web app is not a current installed HTTP(S) app')
    sync = fields.get(1, [])
    if len(sync) != 1 or not isinstance(sync[0], bytes):
        raise ValueError('Missing Web app sync data')
    urls = _protobuf_fields(sync[0]).get(1, [])
    if len(urls) != 1 or not isinstance(urls[0], bytes):
        raise ValueError('Missing Web app start URL')
    return validate_start_url(urls[0].decode('utf-8'))


def _legacy_start_url(profile: Path, app_id: str) -> str | None:
    from .web_app_leveldb import read_metadata_file

    def unique_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError('Ambiguous browser preferences')
            value[key] = item
        return value

    for name in ('Preferences', 'Secure Preferences'):
        try:
            data = read_metadata_file(profile, name)
        except FileNotFoundError:
            continue
        if data is None:
            continue
        if len(data) > _MAX_METADATA:
            raise ValueError('Browser preferences exceed metadata limit')
        document = json.loads(data.decode('utf-8-sig'), object_pairs_hook=unique_object)
        if not isinstance(document, dict):
            raise ValueError('Invalid browser preferences')
        extensions = document.get('extensions', {})
        settings = extensions.get('settings', {}) if isinstance(extensions, dict) else {}
        app = settings.get(app_id) if isinstance(settings, dict) else None
        if not isinstance(app, dict) or app.get('state', 1) != 1:
            continue
        manifest = app.get('manifest', {})
        hosted = manifest.get('app', {}) if isinstance(manifest, dict) else {}
        launch = hosted.get('launch', {}) if isinstance(hosted, dict) else {}
        url = launch.get('web_url') if isinstance(launch, dict) else None
        if url is not None:
            return validate_start_url(url)
    return None


def resolve_start_url(executable: Path, browser: str, profile: str, app_id: str) -> str | None:
    """Read only the matching installed-app metadata; never scan a user's files."""
    if not _APP_ID.fullmatch(app_id):
        raise ValueError('Invalid Chromium app-id')
    root = _profile_path(executable, browser, profile)
    from .web_app_leveldb import read_values
    key = b'web_apps-dt-' + app_id.encode('ascii')
    for database in (root / 'Sync Data/LevelDB', root / 'Web Applications/WebApp Database'):
        if database.exists():
            _plain(database, directory=True)
            values = read_values(database, {key})
            # An absent/deleted modern record must not resurrect an old cache.
            return _start_url_from_proto(values[key]) if key in values else None
    return _legacy_start_url(root, app_id)


def _query() -> bytes:
    from .windows_store_apps import _system_powershell
    powershell = _system_powershell()
    command = [str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
               '-EncodedCommand', base64.b64encode(_QUERY_SCRIPT.encode('utf-16-le')).decode('ascii')]
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
            cwd=powershell.parent, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            timeout=_DISCOVERY_SECONDS, check=False)
        if type(result.returncode) is not int or result.returncode != 0:
            raise OSError('Web app shortcut discovery failed')
        output.seek(0); data = output.read(_MAX_OUTPUT + 1)
    if len(data) > _MAX_OUTPUT:
        raise ValueError('Web app shortcut discovery exceeds limit')
    return data


def parse_shortcuts(data: bytes) -> list[dict]:
    if len(data) > _MAX_OUTPUT:
        raise ValueError('Web app shortcut discovery exceeds limit')
    document = json.loads(data.decode('utf-8-sig'))
    if (not isinstance(document, dict) or type(document.get('schema_version')) is not int
            or document['schema_version'] != 1 or not isinstance(document.get('shortcuts'), list)
            or len(document['shortcuts']) > _MAX_SHORTCUTS):
        raise ValueError('Invalid web app shortcut discovery document')
    result, seen, cached = [], {}, {}
    deadline = time.monotonic() + _DISCOVERY_SECONDS
    for row in document['shortcuts']:
        if time.monotonic() >= deadline:
            break
        try:
            if not isinstance(row, dict):
                continue
            label = _text(row.get('label'), 200).strip()
            if not label:
                continue
            switches = _switches(row.get('arguments'))
            if not any(key in switches for key in ('--app-id', '--app')):
                continue
            browser, executable = _browser_target(row.get('target'))
            app_id, profile = switches.get('--app-id', ''), switches.get('--profile-directory', 'Default')
            if (not _PROFILE.fullmatch(profile) or (app_id and not _APP_ID.fullmatch(app_id))
                    or (app_id and '--profile-directory' not in switches)):
                # Without a profile switch Chromium may pick its last-used
                # profile. Do not silently associate that install with Default.
                continue
            urls = {validate_start_url(switches[key]) for key in ('--app', '--app-url') if key in switches}
            if len(urls) > 1 or ('--app' in switches and app_id):
                continue
            url = next(iter(urls), '')
            identity = (str(executable).casefold(), profile.casefold(), app_id or url)
            if app_id and not url:
                if identity not in cached:
                    try:
                        cached[identity] = resolve_start_url(executable, browser, profile, app_id) or ''
                    except (OSError, ValueError, UnicodeError, RuntimeError, RecursionError):
                        cached[identity] = ''
                url = cached[identity]
            if identity in seen:
                previous = seen[identity]
                if previous.get('unavailable_reason') == '同一 Web 应用身份对应多个启动网址，请检查原快捷方式后重新扫描。':
                    continue
                if url and previous['launchable'] and previous['web_app']['start_url'] != url:
                    previous['web_app']['start_url'] = ''
                    previous['launchable'] = False
                    previous['unavailable_reason'] = '同一 Web 应用身份对应多个启动网址，请检查原快捷方式后重新扫描。'
                    continue
                # Prefer a duplicate shortcut containing an explicit start URL
                # to one whose profile metadata is currently locked/unreadable.
                if not url or seen[identity]['launchable']:
                    continue
                result.remove(seen[identity])
            web_app = {'browser': browser, 'profile_directory': profile, 'app_id': app_id,
                       'start_url': url, 'launch_mode': 'isolated_url'}
            entry = {'label': label, 'path': str(executable), 'adapter': 'chromium', 'args': [],
                     'web_app': web_app, 'use_original_data': False, 'category': 'web-app',
                     'source': 'windows-web-app', 'launchable': bool(url), 'compatibility': WEB_APP_DETAIL}
            if not url:
                entry['unavailable_reason'] = ('已识别安装身份，但尚未解析到有效的 HTTP(S) 启动网址。'
                    '请关闭浏览器后重新扫描；自定义资料目录和未支持的元数据版本暂不列为可启动项。')
            result.append(entry); seen[identity] = entry
        except (OSError, ValueError, UnicodeError, RuntimeError, RecursionError):
            continue
    return result


def discover_web_apps() -> list[dict]:
    if sys.platform != 'win32':
        return []
    try:
        return parse_shortcuts(_query())
    except Exception:
        # Missing Windows COM/PowerShell must not hide ordinary desktop apps.
        return []
