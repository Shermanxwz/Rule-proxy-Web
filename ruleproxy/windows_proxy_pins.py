"""Fixed inputs for the personal, offline Windows x64 deployment."""
from __future__ import annotations

import errno
import hashlib
import http.client
import os
from pathlib import Path
import re
import socket
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

PROXIFYRE_VERSION = "2.6.4"
MIHOMO_VERSION = "v1.19.32"
SERVICE_NAME = "RuleProxyControl"
PROXIFYRE_SERVICE_NAME = "ProxiFyreService"
PIPE_PREFIX = "RuleProxyControl-v1-"
INSTALL_FOLDER = "RuleProxy-Web"
PYTHON_VERSION = "3.14.8"
PYTHON_PTH = "python314._pth"
PYTHON_STDLIB = "python314.zip"
PTH_TEXT = "python314.zip\r\n.\r\n..\r\n..\\vendor\r\n"
PYYAML_VERSION = "6.0.3"
BURN_REGISTRATION = "{0E6374A5-1B73-4710-80EA-43784F0BC546}"
BURN_MANIFEST_SHA256 = "86416f33dd60003c7a580bdf48f6d6dcdf10c963b04866af3175fecd69b1ab87"

ASSETS = {
    "proxifyre_setup": {"name": "ProxiFyre-2.6.4-win-x64-setup.exe", "size": 2889730,
        "url": "https://github.com/wiresock/proxifyre/releases/download/v2.6.4/ProxiFyre-2.6.4-win-x64-setup.exe",
        "sha256": "afaf3ac8a2069f9653adb1b4a63b31d1edd8aa109ccdc367cf0d4462e78f5027"},
    "proxifyre_msi": {"name": "ProxiFyre-2.6.4-win-x64.msi", "size": 1802240,
        "url": "https://github.com/wiresock/proxifyre/releases/download/v2.6.4/ProxiFyre-2.6.4-win-x64.msi",
        "sha256": "ef64b295485cd16ad3e41a6b7d56e7ab46da2093ff64389edc17545157777de1"},
    "ndis_msi": {"name": "Windows.Packet.Filter.3.6.2.1.x64.msi", "size": 819200,
        "url": "https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.x64.msi",
        "sha256": "9c388c0b7f189f7fa98720bae2caecf7d64f30910838b80b438ecf8956b8502c"},
    "vc_redist": {"name": "VC_redist.x64.exe", "size": 25635768,
        "url": "https://download.visualstudio.microsoft.com/download/pr/0b44c2d1-8944-4834-a01a-c9a225f8088a/CC0FF0EB1DC3F5188AE6300FAEF32BF5BEEBA4BDD6E8E445A9184072096B713B/VC_redist.x64.exe",
        "sha256": "cc0ff0eb1dc3f5188ae6300faef32bf5beeba4bdd6e8e445a9184072096b713b"},
    "python": {"name": "python-3.14.8-embed-amd64.zip", "size": 12601679,
        "url": "https://www.python.org/ftp/python/3.14.8/python-3.14.8-embed-amd64.zip",
        "sha256": "a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310"},
    "pyyaml": {"name": "pyyaml-6.0.3-cp314-cp314-win_amd64.whl",
        "url": "https://files.pythonhosted.org/packages/23/20/bb6982b26a40bb43951265ba29d4c246ef0ff59c9fdcdf0ed04e0687de4d/pyyaml-6.0.3-cp314-cp314-win_amd64.whl",
        "sha256": "4a2e8cebe2ff6ab7d1050ecd59c25d4c8bd7e6f400f5f82b96557ac0abafd0ac"},
    "mihomo": {"name": "mihomo-windows-amd64-compatible-v1.19.32.zip", "size": 22525067,
        "url": "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-windows-amd64-compatible-v1.19.32.zip",
        "sha256": "974a4d7ad69aed27aa2e8f91d61113573c14dadb14562c63e58effabf59816f0"},
    "mihomo_license": {"name": "MIHOMO-LICENSE",
        "url": "https://raw.githubusercontent.com/MetaCubeX/mihomo/v1.19.32/LICENSE",
        "sha256": "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986"},
    "proxifyre_license": {"name": "PROXIFYRE-LICENSE", "size": 34523,
        "url": "https://raw.githubusercontent.com/wiresock/proxifyre/v2.6.4/LICENSE",
        "sha256": "8486a10c4393cee1c25392769ddd3b2d6c242d6ec7928e1414efff7dfb2f07ef"},
    "ndisapi_license": {"name": "NDISAPI-LICENSE", "size": 1070,
        "url": "https://raw.githubusercontent.com/wiresock/ndisapi/v3.6.2/LICENSE",
        "sha256": "b12f4cfcce43cef59100cf8c4eaf67ae5246c9a047e00f6059655f6694030efe"},
}


def validate_burn_layout(installers: Path, *, manifest: bytes | None = None) -> dict:
    """Verify the flat local-source layout against the pinned official manifest.

    XML is the unmodified UX CAB member 0 extracted once from the fixed official
    setup using 7z. Its hash binds the reviewed source metadata; the full setup
    executable is independently SHA-256 pinned. No Windows executable runs
    while building on Linux.
    """
    if manifest is None:
        manifest = Path(__file__).with_name('windows_proxy_burn_manifest.xml').read_bytes()
    if hashlib.sha256(manifest).hexdigest() != BURN_MANIFEST_SHA256:
        raise ValueError('Official Burn manifest changed')
    root = ET.fromstring(manifest)
    namespace = {'b': 'http://wixtoolset.org/schemas/v4/2008/Burn'}
    external = root.findall("b:Payload[@Packaging='external']", namespace)
    expected = {'VisualCppRuntime': 'vc_redist', 'WindowsPacketFilter': 'ndis_msi'}
    if {node.get('Id') for node in external} != set(expected) or len(external) != 2:
        raise ValueError('Unexpected official Burn external payload')
    records = {}
    for node in external:
        asset = ASSETS[expected[node.get('Id')]]
        if (node.get('FilePath') != asset['name'] or node.get('SourcePath') != asset['name']
                or node.get('FileSize') != str(asset['size']) or node.get('DownloadUrl') != asset['url']):
            raise ValueError('Official Burn payload identity differs from fixed asset')
        data = (Path(installers) / asset['name']).read_bytes()
        if (len(data) != asset['size'] or hashlib.sha256(data).hexdigest() != asset['sha256']
                or hashlib.sha512(data).hexdigest().upper() != node.get('Hash')):
            raise ValueError('Official Burn local payload failed digest verification')
        records[node.get('Id')] = dict(node.attrib)
    registration = root.find('b:Registration', namespace)
    if registration is None or registration.get('Code') != BURN_REGISTRATION:
        raise ValueError('Official Burn registration changed')
    return {'schema_version': 1, 'bundle_code': BURN_REGISTRATION,
            'manifest_sha256': BURN_MANIFEST_SHA256, 'external_payloads': records}


def pipe_name(owner_sid: str) -> str:
    if not isinstance(owner_sid, str) or not re.fullmatch(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+", owner_sid):
        raise ValueError("Expected an ordinary Windows account SID")
    return PIPE_PREFIX + hashlib.sha256(owner_sid.encode("ascii")).hexdigest()[:16]


def expected_runtime_record() -> dict:
    return {"mihomo": MIHOMO_VERSION,
            "windows_backend": {"name": "proxifyre", "version": PROXIFYRE_VERSION}}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def proxifyre_removal_plan(root: Path, static_files: dict) -> list[str]:
    """Preflight owned MSI leftovers; reject every unknown or linked object.

    Used before and after MSI uninstall. Planning never deletes anything.
    """
    root = Path(root)
    try:
        info = root.lstat()
    except FileNotFoundError:
        return []
    if root.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
        raise ValueError('Linked ProxiFyre residue root is not owned')
    if not root.is_dir():
        raise ValueError('ProxiFyre residue root is not a directory')
    static = {}
    if not isinstance(static_files, dict) or not static_files:
        raise ValueError('Missing owned ProxiFyre file manifest')
    for name, expected in static_files.items():
        if (not isinstance(name, str) or '/' in name or '\\' in name or ':' in name
                or name in ('', '.', '..') or not re.fullmatch('[a-f0-9]{64}', str(expected))
                or name.casefold() in static):
            raise ValueError('Invalid owned ProxiFyre file manifest')
        static[name.casefold()] = expected
    mutable = {'app-config.json', 'app-config.json.bak', 'app-config.ruleproxy.tmp'}
    result = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        current = Path(directory)
        for path in [current, *(current / name for name in dirs), *(current / name for name in files)]:
            if path.is_symlink() or getattr(path.lstat(), 'st_file_attributes', 0) & 0x400:
                raise ValueError('Linked ProxiFyre residue is not owned')
        relative_directory = current.relative_to(root).as_posix()
        if relative_directory not in ('.', 'logs', 'logs/archive'):
            raise ValueError('Unknown ProxiFyre residue directory')
        for name in files:
            path = current / name
            relative = path.relative_to(root).as_posix()
            key = name.casefold()
            if relative_directory == '.' and key in static:
                if digest(path) != static[key]:
                    raise ValueError('Changed ProxiFyre static file is not removable')
            elif relative_directory == '.' and key in mutable:
                pass
            elif relative == 'logs/logfile.txt' or re.fullmatch(r'logs/archive/logfile_[0-9]+\.txt', relative):
                pass
            else:
                raise ValueError('Unknown ProxiFyre residue file')
            result.append(relative)
    return sorted(result)


def _verified_asset(asset: dict, data: bytes) -> bytes:
    if (len(data) > 64 * 1024**2 or ("size" in asset and len(data) != asset["size"])
            or hashlib.sha256(data).hexdigest() != asset["sha256"]):
        raise ValueError("Fixed Windows asset failed its size/SHA-256 check: " + asset["name"])
    return data


def _transient_download_error(error: BaseException) -> bool:
    if isinstance(error, urllib.error.HTTPError):
        return error.code in (408, 425, 429, 500, 502, 503, 504)
    if isinstance(error, urllib.error.URLError):
        return isinstance(error.reason, BaseException) and _transient_download_error(error.reason)
    if isinstance(error, ssl.SSLCertVerificationError):
        return False
    if isinstance(error, (TimeoutError, ConnectionError, http.client.IncompleteRead, ssl.SSLEOFError)):
        return True
    if isinstance(error, socket.gaierror):
        return error.errno == socket.EAI_AGAIN
    return isinstance(error, OSError) and (
        error.errno in (errno.ECONNRESET, errno.ECONNABORTED, errno.ETIMEDOUT,
                        errno.ECONNREFUSED, errno.ENETDOWN, errno.ENETUNREACH,
                        errno.EHOSTUNREACH, errno.EPIPE)
        or getattr(error, 'winerror', None) in (10050, 10051, 10052, 10053, 10054,
                                               10060, 10061, 10065, 11002))


def fetch_asset(asset: dict, cache: Path | None = None) -> bytes:
    # Licenses are small, reviewed release inputs. Installing must not depend
    # on a second network request to raw.githubusercontent.com for these bytes.
    for key in ('mihomo_license', 'proxifyre_license', 'ndisapi_license'):
        if asset == ASSETS[key]:
            license_path = Path(__file__).with_name('licenses') / asset['name']
            if not license_path.is_file() or license_path.is_symlink():
                raise ValueError('Bundled Windows license is missing or linked: ' + asset['name'])
            return _verified_asset(asset, license_path.read_bytes())
    target = Path(cache) / asset["name"] if cache is not None else None
    if target is not None and target.is_file() and not target.is_symlink():
        return _verified_asset(asset, target.read_bytes())
    attempts = 3
    for attempt in range(1, attempts + 1):
        print(f'Downloading {asset["name"]} (attempt {attempt}/{attempts})\n  {asset["url"]}',
              file=sys.stderr, flush=True)
        request = urllib.request.Request(asset["url"], headers={"User-Agent": "RuleProxy-offline-x64/1"})
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                data = response.read(64 * 1024**2 + 1)
        except (OSError, http.client.HTTPException) as error:
            if isinstance(error, urllib.error.HTTPError):
                error.close()
            if attempt == attempts or not _transient_download_error(error):
                raise RuntimeError(
                    f'Cannot download fixed Windows asset {asset["name"]} from {asset["url"]} '
                    f'after {attempt} attempt(s): {error}. Check connectivity and run setup again; '
                    'already verified downloads remain cached.') from error
            print(f'Download interrupted for {asset["name"]}: {error}. '
                  f'Retrying in {attempt} second(s).', file=sys.stderr, flush=True)
            time.sleep(attempt)
            continue
        _verified_asset(asset, data)
        break
    if target is not None:
        target.parent.mkdir(parents=True, exist_ok=True)
        # A unique temporary file cannot follow a pre-existing .partial link.
        # The final cache name appears only after all bytes pass their pins.
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=target.parent, prefix=target.name + '.',
                                             suffix='.partial', delete=False) as output:
                temporary = Path(output.name)
                output.write(data)
            temporary.replace(target)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return data
