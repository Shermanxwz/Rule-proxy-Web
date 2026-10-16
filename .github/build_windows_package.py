"""Build the personal Windows x64 offline package from pinned official inputs."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
import install_runtime
from ruleproxy import __version__
from ruleproxy import windows_proxy_pins as pins

PYTHON_VERSION = pins.PYTHON_VERSION
PYTHON_URL = pins.ASSETS['python']['url']
PYTHON_SHA256 = pins.ASSETS['python']['sha256']
PYTHON_PTH = pins.PYTHON_PTH
PYTHON_STDLIB = pins.PYTHON_STDLIB
PYYAML_VERSION = pins.PYYAML_VERSION
PYYAML_URL = pins.ASSETS['pyyaml']['url']
PYYAML_SHA256 = pins.ASSETS['pyyaml']['sha256']
PTH_TEXT = pins.PTH_TEXT
FOLDER = pins.INSTALL_FOLDER
INCLUDE = ('Run-RuleProxy.py', 'Start-Windows.cmd', 'Setup-Windows.cmd',
           'README.md', 'CHANGELOG.md', 'LICENSE', 'THIRD-PARTY.md', 'ruleproxy/', 'web/',
           'scripts/windows-setup.ps1', 'scripts/windows-uninstall.ps1')
MAX_DOWNLOAD = 64 * 1024**2
ASSET_CACHE = None
LICENSE_KEYS = ('mihomo_license', 'proxifyre_license', 'ndisapi_license')
BUNDLED_LICENSE_SOURCES = tuple('ruleproxy/licenses/' + pins.ASSETS[key]['name'] for key in LICENSE_KEYS)


def download(url: str, sha256: str) -> bytes:
    matches = [asset for asset in pins.ASSETS.values() if asset['url'] == url]
    asset = dict(matches[0]) if matches else {'name': url.rsplit('/', 1)[-1], 'url': url, 'sha256': sha256}
    if asset['sha256'] != sha256:
        raise ValueError('Conflicting asset pin')
    return pins.fetch_asset(asset, ASSET_CACHE)


def safe_extract(data: bytes, target: Path) -> None:
    total, seen = 0, set()
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for item in archive.infolist():
            name = PurePosixPath(item.filename)
            if (name.is_absolute() or '..' in name.parts or ':' in item.filename
                    or '\\' in item.filename or item.orig_filename != item.filename
                    or item.filename.casefold() in seen or stat.S_ISLNK(item.external_attr >> 16)):
                raise ValueError('Unsafe or duplicate archive path')
            seen.add(item.filename.casefold())
            total += item.file_size
            if item.file_size > MAX_DOWNLOAD or total > 192 * 1024**2:
                raise ValueError('Expanded archive exceeds bound')
        archive.extractall(target)


def project_files() -> list[str]:
    # Only program roots are eligible. Source/user YAML, profiles, credentials,
    # CI fixtures and existing runtime/state directories are never copied.
    files = []
    for item in INCLUDE:
        path = ROOT / item
        if not path.exists() or path.is_symlink():
            raise ValueError('Required package source is missing: ' + item)
        candidates = path.rglob('*') if path.is_dir() else [path]
        for candidate in candidates:
            relative = candidate.relative_to(ROOT)
            if (candidate.is_file() and not candidate.is_symlink()
                    and '__pycache__' not in relative.parts
                    and not any(part.startswith('.') for part in relative.parts)
                    and candidate.suffix.lower() not in ('.pyc', '.yaml', '.yml', '.sqlite', '.db')):
                files.append(relative.as_posix())
    files = sorted(set(files))
    # License notices are part of the source bootstrap, so installation never
    # needs raw.githubusercontent.com just to obtain these fixed text files.
    # Verify the upstream pins before either online or offline packaging.
    for key, name in zip(LICENSE_KEYS, BUNDLED_LICENSE_SOURCES):
        asset = pins.ASSETS[key]
        if name not in files:
            raise ValueError('Required bundled Windows license is missing: ' + name)
        data = (ROOT / name).read_bytes()
        if (hashlib.sha256(data).hexdigest() != asset['sha256']
                or 'size' in asset and len(data) != asset['size']):
            raise ValueError('Bundled Windows license failed its size/SHA-256 check: ' + name)
    return files


def stage(target: Path, *, asset_cache: Path | None = None, **legacy_options) -> None:
    if legacy_options:
        raise ValueError('MXC is not part of the Windows product package')
    if target.exists() and (target.is_symlink() or not target.is_dir() or any(target.iterdir())):
        raise ValueError('Offline package staging requires an empty directory')
    global ASSET_CACHE
    ASSET_CACHE = Path(asset_cache) if asset_cache is not None else None
    target.mkdir(parents=True, exist_ok=True)
    for name in project_files():
        data = (ROOT / name).read_bytes()
        if name.endswith('.cmd'):
            data = data.replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
        destination = target / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
    safe_extract(download(PYTHON_URL, PYTHON_SHA256), target / 'python')
    if not all((target / 'python' / name).is_file() for name in
               (PYTHON_PTH, PYTHON_STDLIB, 'python.exe', 'pythonw.exe', 'LICENSE.txt')):
        raise ValueError('Fixed embedded Python layout changed')
    (target / 'python' / PYTHON_PTH).write_text(PTH_TEXT, encoding='ascii', newline='')
    safe_extract(download(PYYAML_URL, PYYAML_SHA256), target / 'vendor')
    install_runtime.install_windows_proxy(target, cache=ASSET_CACHE)
    if not install_runtime.installed_windows_proxy(target):
        raise ValueError('Windows product runtime failed verification')
    installers = target / 'installers'
    installers.mkdir()
    for key in ('vc_redist', 'ndis_msi', 'proxifyre_msi', 'proxifyre_setup'):
        asset = pins.ASSETS[key]
        (installers / asset['name']).write_bytes(download(asset['url'], asset['sha256']))
    layout = pins.validate_burn_layout(installers)
    (installers / 'offline-layout.json').write_text(json.dumps(layout, sort_keys=True, indent=2) + '\n', encoding='utf-8')
    licenses = target / 'licenses'
    licenses.mkdir()
    for key in ('proxifyre_license', 'ndisapi_license'):
        asset = pins.ASSETS[key]
        (licenses / asset['name']).write_bytes(download(asset['url'], asset['sha256']))
    (licenses / 'WINDOWS-DEPENDENCIES.txt').write_text(
        'Personal offline deployment only. ProxiFyre: AGPL-3.0. Windows Packet Filter is a separate '
        'product, free for personal use: https://www.ntkernel.com/windows-packet-filter/licensing/\n'
        'Microsoft Visual C++ Redistributable is provided unchanged with its Microsoft license. '
        'Public redistribution requires independent license review.\n', encoding='utf-8')
    files = {path.relative_to(target).as_posix(): pins.digest(path)
             for path in sorted(target.rglob('*')) if path.is_file()}
    manifest = {'schema_version': 1, 'platform': 'windows-amd64', 'version': __version__,
                'backend': 'proxifyre', 'personal_use_only': True,
                'public_binary_release_eligible': False, 'files': files,
                'installers': {key: pins.ASSETS[key] for key in ('vc_redist', 'ndis_msi', 'proxifyre_msi', 'proxifyre_setup')}}
    (target / 'package-manifest.json').write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n', encoding='utf-8')


def write_zip(source: Path, path: Path) -> None:
    with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        # Path ordering is case-insensitive on Windows. Archive ordering uses
        # the same POSIX relative strings on every build host.
        for file in sorted((item for item in source.rglob('*') if item.is_file()),
                           key=lambda item: item.relative_to(source).as_posix()):
            entry = zipfile.ZipInfo(f'{FOLDER}/{file.relative_to(source).as_posix()}', (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, file.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def changes() -> str:
    text = (ROOT / 'CHANGELOG.md').read_text(encoding='utf-8')
    heading = f'## {__version__}\n'
    if heading not in text:
        raise ValueError('Current version has no changelog entry')
    return text.split(heading, 1)[1].split('\n## ', 1)[0].strip()


def release_notes(zip_name: str, digest: str, **_legacy) -> str:
    return (f'Windows x64 personal offline candidate: {zip_name}\nSHA-256: {digest}\n\n'
            'Target: Windows 11 x64. Server 2025, native Windows 11 and visible GUI qualification '
            'are determined only by reports for the same ZIP SHA-256 in the '
            '[verification status](https://github.com/Shermanxwz/Rule-proxy-Web/blob/main/'
            'verification/windows-2026-10-16/proxifyre-product/current-status.json); '
            'compare its package SHA-256 with this ZIP before applying that result. '
            'A successful build does not establish qualification. Real Internet exit IP, disconnected '
            'installation, browser login persistence and downloads each require explicit matching evidence.\n\n'
            'Extract and open Setup-Windows.cmd once; installation requests administrator approval. '
            'If setup returns 3010, restart Windows and repeat setup. '
            'After installation, use the same installation account to open Start-Windows.lnk. '
            'Standard and administrator startup are supported without changing UAC; the panel and selected '
            'applications inherit the current account token. Elevated HTTP access is limited to that account. '
            'Import your own YAML through the Web panel. No user configuration or node credential is included.\n'
            'Backend: ProxiFyre 2.6.4 + Mihomo 1.19.32, no TUN. Dependencies are included for offline setup. '
            'Path rules also affect other matching instances; UDP 53 and system DNS can go direct, '
            'IPv6 fragments can go direct, and engine failure can restore direct access. '
            'See the included README.md for routing and fault boundaries. '
            'This package does not promise Linux-equivalent isolation or publish a public binary release.\n')


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output_dir', type=Path)
    parser.add_argument('--stage-only', action='store_true')
    parser.add_argument('--asset-cache', type=Path)
    args = parser.parse_args(argv)
    output = args.output_dir.resolve()
    if args.stage_only:
        stage(output, asset_cache=args.asset_cache)
        return 0
    output.mkdir(parents=True, exist_ok=True)
    name = f'RuleProxy-Web-{__version__}-windows-x64-personal.zip'
    with tempfile.TemporaryDirectory(prefix='ruleproxy-offline-') as directory:
        source = Path(directory) / FOLDER
        stage(source, asset_cache=args.asset_cache)
        write_zip(source, output / name)
    digest = pins.digest(output / name)
    (output / 'SHA256SUMS.txt').write_text(f'{digest}  {name}\n', encoding='ascii')
    (output / 'release-notes.md').write_text(release_notes(name, digest), encoding='utf-8')
    print(f'Built {output / name}: SHA-256 {digest}', flush=True)
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
