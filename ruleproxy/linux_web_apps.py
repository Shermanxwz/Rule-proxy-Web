"""Read installed Linux Chromium Web/PWA identities without launching programs.

Only fixed desktop switches and the selected app's installation metadata are
used. System browser wrappers have an explicit binary map, not a script parser.
By default the URL opens in a launcher-owned profile, never forwarding an
installed app-id into that unrelated profile. Explicit original-data mode uses
the exact recognized browser/channel and selected profile instead.
"""
from __future__ import annotations

import os
from pathlib import Path
import re
import shlex
import shutil
import stat

from .windows_web_apps import (
    _APP_ID, _FIELDS, _PROFILE, _legacy_start_url, _start_url_from_proto, _text,
    validate_start_url,
)


_WEB_APP_PRIVATE_DATA_DETAIL = (
    '以已验证的 HTTP(S) 启动网址打开独立应用窗口，而非复用原 PWA 安装。'
    '网址来自桌面入口或本地安装元数据，格式校验不代表联网成功。'
    '首次需重新登录；后续保留此条目的独立资料，不读取或复制原浏览器登录数据。'
)
_WEB_APP_ORIGINAL_DATA_DETAIL = (
    '使用所选浏览器及频道的原配置；有安装 ID 时按原 PWA 启动，'
    '无安装 ID 时在同一配置以网址打开应用窗口。'
    '浏览器直接使用原资料，修改会同步；本工具不读取或复制登录数据。'
    '请先完全关闭原浏览器及其后台进程；检测到资料占用时停止启动，不接管或关闭外部已有窗口。'
)
WEB_APP_DETAIL = _WEB_APP_PRIVATE_DATA_DETAIL + (
    'Linux 应用模式下仅保护由 RuleProxy 新启动的网络命名空间实例；'
    '系统中已运行的浏览器和原 PWA 窗口不受此条目影响。'
)
WEB_APP_ORIGINAL_DETAIL = _WEB_APP_ORIGINAL_DATA_DETAIL + (
    'Linux 应用模式保留网络、进程和家目录隔离，仅共享已验证的浏览器资料，'
    '密钥服务使用受限连接；使用期间请勿同时启动原浏览器。'
)


def web_app_detail(use_original_data: bool, *, global_mode: bool = False) -> str:
    """Describe data selection separately from the actual Linux launch mode."""
    if not global_mode:
        return WEB_APP_ORIGINAL_DETAIL if use_original_data else WEB_APP_DETAIL
    data = _WEB_APP_ORIGINAL_DATA_DETAIL if use_original_data else _WEB_APP_PRIVATE_DATA_DETAIL
    return data + 'Linux 全局模式使用系统代理；应用模式的独立网络命名空间隔离不适用于此启动。'


# Linux names are case-sensitive. These names are accepted only after an ELF
# check during discovery/launch; a familiar name alone does not admit a script.
_EXECUTABLES = {
    'chrome': frozenset({'chrome', 'google-chrome', 'google-chrome-stable',
                         'google-chrome-beta', 'google-chrome-unstable'}),
    'chromium': frozenset({'chromium', 'chromium-browser'}),
    'edge': frozenset({'msedge', 'microsoft-edge', 'microsoft-edge-stable',
                       'microsoft-edge-beta', 'microsoft-edge-dev'}),
    'brave': frozenset({'brave', 'brave-browser', 'brave-browser-beta',
                        'brave-browser-nightly'}),
    'vivaldi': frozenset({'vivaldi', 'vivaldi-bin', 'vivaldi-stable'}),
}

# (browser, config subdirectory, actual binaries, known system wrappers).
# No globbing, sibling search, script inspection, or portable-profile guesses.
_INSTALLS = (
    ('chrome', 'google-chrome', ('/opt/google/chrome/chrome',),
     ('/usr/bin/google-chrome', '/usr/bin/google-chrome-stable',
      '/opt/google/chrome/google-chrome')),
    ('chrome', 'google-chrome-beta', ('/opt/google/chrome-beta/chrome',),
     ('/usr/bin/google-chrome-beta', '/opt/google/chrome-beta/google-chrome')),
    ('chrome', 'google-chrome-unstable', ('/opt/google/chrome-unstable/chrome',),
     ('/usr/bin/google-chrome-unstable', '/opt/google/chrome-unstable/google-chrome')),
    ('chromium', 'chromium',
     ('/usr/lib/chromium/chromium', '/usr/lib64/chromium/chromium'),
     ('/usr/bin/chromium',)),
    ('chromium', 'chromium',
     ('/usr/lib/chromium-browser/chromium-browser', '/usr/lib64/chromium-browser/chromium-browser'),
     ('/usr/bin/chromium-browser',)),
    ('edge', 'microsoft-edge', ('/opt/microsoft/msedge/msedge',),
     ('/usr/bin/microsoft-edge', '/usr/bin/microsoft-edge-stable',
      '/opt/microsoft/msedge/microsoft-edge')),
    ('edge', 'microsoft-edge-beta', ('/opt/microsoft/msedge-beta/msedge',),
     ('/usr/bin/microsoft-edge-beta', '/opt/microsoft/msedge-beta/microsoft-edge')),
    ('edge', 'microsoft-edge-dev', ('/opt/microsoft/msedge-dev/msedge',),
     ('/usr/bin/microsoft-edge-dev', '/opt/microsoft/msedge-dev/microsoft-edge')),
    ('brave', 'BraveSoftware/Brave-Browser', ('/opt/brave.com/brave/brave',),
     ('/usr/bin/brave-browser', '/usr/bin/brave', '/opt/brave.com/brave/brave-browser')),
    ('brave', 'BraveSoftware/Brave-Browser-Beta', ('/opt/brave.com/brave-beta/brave',),
     ('/usr/bin/brave-browser-beta', '/opt/brave.com/brave-beta/brave-browser')),
    ('brave', 'BraveSoftware/Brave-Browser-Nightly', ('/opt/brave.com/brave-nightly/brave',),
     ('/usr/bin/brave-browser-nightly', '/opt/brave.com/brave-nightly/brave-browser')),
    ('vivaldi', 'vivaldi', ('/opt/vivaldi/vivaldi-bin',),
     ('/usr/bin/vivaldi', '/usr/bin/vivaldi-stable', '/opt/vivaldi/vivaldi')),
)
_BROWSER_LOCATIONS = {
    Path(binary): (browser, config)
    for browser, config, binaries, _ in _INSTALLS for binary in binaries
}
_WRAPPER_TARGETS = {
    Path(wrapper): tuple(Path(binary) for binary in binaries)
    for _, _, binaries, wrappers in _INSTALLS for wrapper in wrappers
}
_FIELD_CODES = frozenset('%' + code for code in 'fFuUickdDnNvm')
_WEB_INTENT = re.compile(r'''(?:^|[\s'";|])--app(?:-[A-Za-z0-9_-]+)?(?==|[\s'"]|$)''', re.IGNORECASE)
_ERRORS = (OSError, ValueError, UnicodeError, RuntimeError, RecursionError)


def _check_browser_path(executable: Path) -> None:
    """Pure structural limits for the runtime's existing executable-dir bind.

    A browser placed directly in HOME/an ancestor would expose that whole
    directory through the existing runtime mount. Likewise, config trees must
    never become browser installation mounts. Do not resolve or read HOME or
    profile paths here: saved-state validation is intentionally filesystem-free.
    """
    home = Path.home()
    if executable.parent in {Path('/'), Path('/home'), Path('/root'), home, *home.parents}:
        raise ValueError('Browser executable would expose a home or ancestor directory')
    config_roots = {home / '.config'}
    for name in ('XDG_CONFIG_HOME', 'CHROME_CONFIG_HOME'):
        value = os.environ.get(name)
        if value:
            config = Path(os.path.normpath(value))
            if config.is_absolute():
                config_roots.add(config)
    if any(executable == root or root in executable.parents or executable.parent in root.parents
           for root in config_roots):
        raise ValueError('Browser executable must be outside browser configuration trees')


def validate_web_app(value, executable: Path) -> dict[str, str]:
    """Validate saved identity only; never stat a binary or read source profiles.

    The launcher owns the file/ELF/X_OK check when check_exists=True. Keeping
    this function pure also permits restoring a temporarily missing executable.
    """
    if not isinstance(value, dict) or set(value) != _FIELDS:
        raise ValueError('Web 应用元数据字段无效。')
    browser = _text(value['browser'], 16)
    profile = _text(value['profile_directory'], 128)
    app_id = _text(value['app_id'], 32)
    if (not isinstance(executable, Path) or not executable.is_absolute()
            or '..' in executable.parts or browser not in _EXECUTABLES
            or executable.name not in _EXECUTABLES[browser]
            or not _PROFILE.fullmatch(profile) or (app_id and not _APP_ID.fullmatch(app_id))
            or value['launch_mode'] != 'isolated_url'):
        raise ValueError('Web 应用浏览器、配置身份或启动模式无效。')
    _text(str(executable), 4096)
    _check_browser_path(executable)
    return {'browser': browser, 'profile_directory': profile, 'app_id': app_id,
            'start_url': validate_start_url(value['start_url']), 'launch_mode': 'isolated_url'}


def _literal_token(token: str) -> str:
    """Decode %% only; embedded/unknown fieldcodes are not removable arguments."""
    _text(token, 4096)
    result, index = [], 0
    while index < len(token):
        if token[index] == '%':
            if token[index:index + 2] != '%%':
                raise ValueError('Embedded or unknown desktop field code')
            index += 1
        result.append(token[index])
        index += 1
    return ''.join(result)


def _exec_tokens(value: str) -> list[str]:
    _text(value.replace('\t', ' '), 16384)
    tokens = shlex.split(value, posix=True)
    if not tokens or len(tokens) > 64:
        raise ValueError('Invalid desktop command length')
    return tokens


def _switches(tokens: list[str]) -> dict[str, str]:
    result, index = {}, 0
    while index < len(tokens):
        name, separator, value = tokens[index].partition('=')
        if name not in ('--app-id', '--app', '--profile-directory') or name in result:
            raise ValueError('Unsupported or repeated desktop switch')
        if not separator:
            index += 1
            if index >= len(tokens) or tokens[index].startswith('--'):
                raise ValueError('Missing desktop switch value')
            value = tokens[index]
        if not value:
            raise ValueError('Empty desktop switch value')
        result[name] = value
        index += 1
    return result


def _browser_name(name: str) -> str:
    for browser, names in _EXECUTABLES.items():
        if name in names:
            return browser
    raise ValueError('Unsupported Linux web app executable')


def _elf(path: Path) -> bool:
    """Read four magic bytes only, through a nonblocking no-follow file handle."""
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
        return False
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode)
                or (info.st_dev, info.st_ino, info.st_mode) != (opened.st_dev, opened.st_ino, opened.st_mode)):
            return False
        return os.read(descriptor, 4) == b'\x7fELF'
    finally:
        os.close(descriptor)


def _browser_target(program: str) -> tuple[str, Path]:
    browser = _browser_name(Path(program).name)
    target = Path(program)
    if not target.is_absolute():
        # Desktop Exec does not establish a trusted working directory. Only a
        # plain PATH program name, not ./chrome, ~/chrome or env, is supported.
        if target.name != program:
            raise ValueError('Relative browser path is ambiguous')
        located = shutil.which(program)
        if not located:
            raise ValueError('Browser executable is missing')
        target = Path(located)
    if not target.is_absolute() or '..' in target.parts:
        raise ValueError('Browser path must be absolute')
    resolved = target.resolve(strict=True)
    _check_browser_path(resolved)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise ValueError('Browser executable is not executable')
    mapped = _WRAPPER_TARGETS.get(target) or _WRAPPER_TARGETS.get(resolved)
    if mapped:
        # In particular, do not open a known wrapper even to read its shebang.
        found = set()
        for actual in mapped:
            try:
                actual = actual.resolve(strict=True)
                _check_browser_path(actual)
                if _browser_name(actual.name) == browser and _elf(actual):
                    found.add(actual)
            except _ERRORS:
                continue
        if len(found) == 1:
            return browser, found.pop()
        raise ValueError('Known browser wrapper has no unambiguous actual ELF binary')
    if _browser_name(resolved.name) != browser or not _elf(resolved):
        raise ValueError('Web app target is not a supported browser ELF')
    return browser, resolved


def _plain_directory(path: Path) -> None:
    """A stat-only preflight; metadata reads independently hold no-follow handles."""
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('Invalid metadata directory')
    for parent in (*reversed(path.parents), path):
        if not stat.S_ISDIR(parent.lstat().st_mode):
            raise ValueError('Metadata directory is not plain')


def _profile_path(executable: Path, browser: str, profile: str) -> Path:
    known = _BROWSER_LOCATIONS.get(executable)
    if not known or known[0] != browser or not _PROFILE.fullmatch(profile):
        raise ValueError('Browser installation or channel is unknown')
    if os.environ.get('CHROME_USER_DATA_DIR'):
        raise ValueError('Custom user data directory is unsupported')
    configured = os.environ.get('CHROME_CONFIG_HOME') or os.environ.get('XDG_CONFIG_HOME')
    config = Path(_text(configured, 4096)) if configured else Path.home() / '.config'
    if (not config.is_absolute() or str(config).startswith('//')
            or '..' in config.parts or '\\' in str(config) or ':' in str(config)):
        raise ValueError('Browser config root is ambiguous')
    result = config / known[1] / profile
    _plain_directory(result)
    return result


def original_profile_directory(value, executable: Path) -> Path:
    """Resolve one existing installed profile, never during saved-state restore.

    Reuse discovery's exact installation/channel map, not ordinary-browser
    basename guesses. Only the ELF header and directory metadata are checked
    here; app_profile_data validates ownership, initialization and root locks.
    """
    metadata = validate_web_app(value, executable)
    try:
        # A known lexical installation must not alias another executable tree.
        # _elf rejects a link at the file itself; check every parent as well.
        _plain_directory(executable.parent)
        selected = _profile_path(executable, metadata['browser'], metadata['profile_directory'])
        if not _elf(executable):
            raise ValueError('Original Web app requires an installed browser ELF')
        return selected
    except (OSError, ValueError) as exc:
        raise ValueError('原浏览器程序或资料目录缺失或身份不明确，请刷新 Web 应用列表后重试。') from exc


def resolve_start_url(executable: Path, browser: str, profile: str, app_id: str) -> str | None:
    """Read exactly the selected app key or fixed legacy metadata files."""
    if not _APP_ID.fullmatch(app_id):
        raise ValueError('Invalid Chromium app-id')
    root = _profile_path(executable, browser, profile)
    from .web_app_leveldb import read_values
    key = b'web_apps-dt-' + app_id.encode('ascii')
    for database in (root / 'Sync Data/LevelDB', root / 'Web Applications/WebApp Database'):
        try:
            _plain_directory(database)
        except FileNotFoundError:
            continue
        values = read_values(database, {key})
        # An existing modern registry is authoritative, including deletions and
        # unsupported/corrupt snapshots. Never resurrect a legacy cached entry.
        return _start_url_from_proto(values[key]) if key in values else None
    return _legacy_start_url(root, app_id)


def from_desktop_entry(fields: dict[str, str]) -> tuple[bool, dict | None]:
    """Return (Web/PWA intent, candidate) without falling back on bad Web args.

    ``fields`` is the launcher's parsed [Desktop Entry] section; it must reject
    duplicate desktop keys before constructing this dictionary. Repeated Exec
    switches, unlike duplicate file keys, are checked here.
    """
    if not isinstance(fields, dict):
        return False, None
    raw = fields.get('Exec', '')
    if not isinstance(raw, str):
        return False, None
    # Removing quote/escape characters here is only a conservative intent hint,
    # never the command parser. It retains intent for --a"pp" even when another
    # token has invalid quoting, control characters or excessive length.
    intent_hint = raw.replace('"', '').replace("'", '').replace('\\', '')
    intent = bool(_WEB_INTENT.search(raw) or _WEB_INTENT.search(intent_hint))
    try:
        tokens = _exec_tokens(raw)
        # shlex can join --a"pp" into --app. Detect parsed intent as well as the
        # raw form, which deliberately survives malformed quoting/field codes.
        intent = intent or any(_WEB_INTENT.match(token) for token in tokens[1:])
        if not intent:
            return False, None
        # Detect intent before field-code validation, including shlex-joined
        # switches followed by an invalid embedded placeholder. A field code in
        # the program position is never an executable. Deprecated independent
        # codes are discarded as required by the Desktop Entry specification.
        tokens = [_literal_token(token) for index, token in enumerate(tokens)
                  if not (index and token in _FIELD_CODES)]
        if (fields.get('Type') != 'Application'
                or any(fields.get(key, 'false') != 'false' for key in ('Hidden', 'NoDisplay'))):
            return True, None
        label = _text(fields.get('Name', ''), 200).strip()
        if not label:
            return True, None
        switches = _switches(tokens[1:])
        app_id = switches.get('--app-id', '')
        profile = switches.get('--profile-directory', 'Default')
        if (('--app-id' in switches) == ('--app' in switches)
                or not _PROFILE.fullmatch(profile)
                or (app_id and (not _APP_ID.fullmatch(app_id) or '--profile-directory' not in switches))):
            return True, None
        url = validate_start_url(switches['--app']) if '--app' in switches else ''
        browser, executable = _browser_target(tokens[0])
        try_exec = _text(fields.get('TryExec', ''), 4096).strip()
        if try_exec and _browser_target(try_exec) != (browser, executable):
            return True, None
        if app_id:
            try:
                found = resolve_start_url(executable, browser, profile, app_id)
                url = validate_start_url(found) if found else ''
            except _ERRORS:
                url = ''
        web_app = {'browser': browser, 'profile_directory': profile, 'app_id': app_id,
                   'start_url': url, 'launch_mode': 'isolated_url'}
        candidate = {'label': label, 'path': str(executable), 'adapter': 'chromium', 'args': [],
                     'web_app': web_app, 'use_original_data': False, 'category': 'web-app',
                     'source': 'linux-web-app', 'launchable': bool(url), 'compatibility': WEB_APP_DETAIL}
        if not url:
            candidate['unavailable_reason'] = (
                '已识别安装身份，但尚未解析到有效的 HTTP(S) 启动网址。'
                '请关闭浏览器后重新扫描；未知安装位置、频道、自定义资料目录'
                '和未支持的元数据版本暂不列为可启动项。')
        return True, candidate
    except _ERRORS:
        return intent, None
