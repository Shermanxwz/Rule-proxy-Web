"""Read current-user MSIX desktop application metadata without activating apps.

Only in-package full-trust executable candidates are returned. A manifest match
does not establish that an application supports direct CreateProcess startup.
UWP/hosted apps, execution aliases and external-location executables are omitted.
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import subprocess
import sys
import tempfile
import time


_MAX_OUTPUT = 2 * 1024 * 1024
_MAX_PACKAGES = 512
_MAX_APPLICATIONS = 1024
_QUERY_SECONDS = 16
_PARSE_SECONDS = 3
_IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z')

# XML is obtained through registration APIs, never by walking WindowsApps.
# The explicit stdout stream writes UTF-8 bytes even without a console. Setting
# Console.OutputEncoding can fail in a CREATE_NO_WINDOW PowerShell process.
_QUERY_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$env:PSModulePath = Join-Path $PSHOME 'Modules'
Import-Module Appx -ErrorAction Stop | Out-Null
$names = @{}
try {
    Import-Module StartLayout -ErrorAction Stop | Out-Null
    foreach ($entry in @(Get-StartApps -ErrorAction Stop | Select-Object -First 2048)) {
        if ($entry.AppID -is [string] -and $entry.Name -is [string] -and
            $entry.AppID.Length -le 512 -and $entry.Name.Length -le 512) {
            $names[$entry.AppID] = $entry.Name
        }
    }
} catch { }
function Read-AppAttribute($Node, [string]$Name, [string[]]$Namespaces = @('')) {
    $attributes = @($Node.Attributes | Where-Object { $_.LocalName -ceq $Name })
    if ($attributes.Count -eq 0) { return '' }
    if ($attributes.Count -ne 1 -or $Namespaces -cnotcontains $attributes[0].NamespaceURI) {
        throw 'Conflicting or unsupported application attribute namespace'
    }
    $value = $attributes[0].Value
    if ($value.Length -gt 4096) { throw 'Application attribute exceeds discovery bound' }
    return [string]$value
}
$rows = New-Object 'System.Collections.Generic.List[object]'
$namespace = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/10'
$namespace11 = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/11'
foreach ($package in @(Get-AppxPackage -PackageTypeFilter Main -ErrorAction Stop | Select-Object -First 512)) {
    if ($rows.Count -ge 1024) { break }
    try {
        if ($package.IsFramework -or $package.IsResourcePackage -or $package.IsBundle -or
            -not $package.InstallLocation -or -not $package.PackageFamilyName) { continue }
        $manifest = Get-AppxPackageManifest -Package $package.PackageFullName -ErrorAction Stop
        foreach ($application in $manifest.SelectNodes("/*[local-name()='Package']/*[local-name()='Applications']/*[local-name()='Application']")) {
            if ($rows.Count -ge 1024) { break }
            $id = Read-AppAttribute $application 'Id'
            $label = $names[([string]$package.PackageFamilyName + '!' + $id)]
            if (-not $label) {
                $visual = $application.SelectSingleNode("./*[local-name()='VisualElements']")
                if ($visual) { $label = Read-AppAttribute $visual 'DisplayName' }
            }
            $hostId = Read-AppAttribute $application 'HostId' $namespace
            $hostRuntime = Read-AppAttribute $application 'HostRuntimeId' $namespace
            [void]$rows.Add([ordered]@{
                label=[string]$label; package_name=[string]$package.Name;
                package_family_name=[string]$package.PackageFamilyName; application_id=$id;
                install_location=[string]$package.InstallLocation;
                executable=(Read-AppAttribute $application 'Executable');
                entry_point=(Read-AppAttribute $application 'EntryPoint');
                runtime_behavior=(Read-AppAttribute $application 'RuntimeBehavior' $namespace);
                trust_level=(Read-AppAttribute $application 'TrustLevel' $namespace);
                host_id=($hostId + $hostRuntime); start_page=(Read-AppAttribute $application 'StartPage');
                parameters=(Read-AppAttribute $application 'Parameters' @($namespace,$namespace11));
                current_directory=(Read-AppAttribute $application 'CurrentDirectoryPath' @($namespace,$namespace11));
                is_framework=[bool]$package.IsFramework; is_resource=[bool]$package.IsResourcePackage
            })
        }
    } catch { continue }
}
$document = [ordered]@{schema_version=1; applications=@($rows.ToArray())}
$json = ConvertTo-Json -InputObject $document -Depth 5 -Compress
$bytes = [Text.Encoding]::UTF8.GetBytes($json)
if ($bytes.Length -gt 2097152) { exit 2 }
$stream = [Console]::OpenStandardOutput()
$stream.Write($bytes, 0, $bytes.Length)
$stream.Flush()
'''


def _system_powershell() -> Path:
    """Use the OS system directory, independent of PATH/SystemRoot overrides."""
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32]
    kernel.GetSystemDirectoryW.restype = ctypes.c_uint32
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < length < len(buffer):
        raise OSError('Cannot locate the native Windows system directory')
    executable = Path(buffer.value) / 'WindowsPowerShell/v1.0/powershell.exe'
    if not executable.is_absolute() or not executable.is_file():
        raise OSError('System Windows PowerShell is unavailable')
    return executable


def _query(powershell: Path) -> bytes:
    command = [str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive',
               '-ExecutionPolicy', 'Bypass', '-EncodedCommand',
               base64.b64encode(_QUERY_SCRIPT.encode('utf-16-le')).decode('ascii')]
    environment = {**os.environ, 'PSModulePath': str(powershell.parent / 'Modules')}
    # The script bounds stdout before writing; the temporary stream also keeps
    # stdout out of unbounded communicate() memory buffers. No log is retained.
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
            stderr=subprocess.DEVNULL, cwd=powershell.parent, env=environment,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0), timeout=_QUERY_SECONDS,
            check=False)
        if type(result.returncode) is not int or result.returncode != 0:
            raise OSError('Windows package metadata query failed')
        output.seek(0)
        data = output.read(_MAX_OUTPUT + 1)
    if len(data) > _MAX_OUTPUT:
        raise ValueError('Windows package metadata output exceeds bound')
    return data


def _text(row: dict, key: str, maximum: int = 4096) -> str:
    value = row.get(key, '')
    if not isinstance(value, str) or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError('Invalid package metadata field')
    return value


def _full_trust(row: dict) -> bool:
    if any(row.get(key, False) is not False for key in ('is_framework', 'is_resource')):
        return False
    if any(_text(row, key) for key in ('host_id', 'start_page', 'parameters', 'current_directory')):
        return False
    entry = _text(row, 'entry_point').casefold()
    runtime = _text(row, 'runtime_behavior').casefold()
    trust = _text(row, 'trust_level').casefold()
    full_trust = 'windows.fulltrustapplication'
    if entry not in ('', full_trust) or runtime not in ('', 'packagedclassicapp', 'win32app'):
        return False
    if trust not in ('', 'mediumil'):
        return False
    return (entry == full_trust or
            (runtime in ('packagedclassicapp', 'win32app') and trust == 'mediumil'))


def _plain(path: Path, *, directory: bool, deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise TimeoutError('Package metadata inspection deadline exceeded')
    value = path.lstat()
    if (stat.S_ISLNK(value.st_mode) or getattr(value, 'st_file_attributes', 0) & 0x400
            or not (stat.S_ISDIR(value.st_mode) if directory else stat.S_ISREG(value.st_mode))):
        raise ValueError('Package path is not an ordinary file or directory')


def _executable(row: dict, deadline: float) -> Path:
    raw_root, raw_executable = _text(row, 'install_location'), _text(row, 'executable')
    root = Path(raw_root)
    relative = PureWindowsPath(raw_executable)
    if (not root.is_absolute() or raw_root.startswith(('\\', '//')) or len(root.parts) > 64 or not raw_executable
            or relative.anchor or relative.drive or relative.suffix.casefold() != '.exe'
            or len(relative.parts) > 64 or any(c in raw_executable for c in ':*?<>|%$"')
            or any(part in ('.', '..') for part in re.split(r'[\\/]', raw_executable))
            or any(part.endswith((' ', '.')) for part in relative.parts)):
        raise ValueError('Executable must be a plain package-relative exe')
    for parent in (root, *root.parents):
        _plain(parent, directory=True, deadline=deadline)
    root = root.resolve(strict=True)
    target = root
    for index, part in enumerate(relative.parts):
        target /= part
        _plain(target, directory=index < len(relative.parts) - 1, deadline=deadline)
    resolved = target.resolve(strict=True)
    resolved.relative_to(root)
    with resolved.open('rb') as executable:
        if executable.read(2) != b'MZ':
            raise ValueError('Package executable is not a Windows executable file')
    return resolved


def _parse(data: bytes) -> list[dict[str, str]]:
    if len(data) > _MAX_OUTPUT:
        raise ValueError('Windows package metadata output exceeds bound')
    document = json.loads(data.decode('utf-8-sig'))
    if (not isinstance(document, dict) or type(document.get('schema_version')) is not int
            or document['schema_version'] != 1 or not isinstance(document.get('applications'), list)
            or len(document['applications']) > _MAX_APPLICATIONS):
        raise ValueError('Invalid package discovery document')
    deadline = time.monotonic() + _PARSE_SECONDS
    result, paths, families = [], set(), set()
    for row in document['applications']:
        if time.monotonic() >= deadline:
            break
        try:
            if not isinstance(row, dict) or not _full_trust(row):
                continue
            family, app_id = _text(row, 'package_family_name', 255), _text(row, 'application_id', 128)
            if not _IDENTIFIER.fullmatch(family) or not _IDENTIFIER.fullmatch(app_id):
                continue
            if family not in families and len(families) >= _MAX_PACKAGES:
                continue
            families.add(family)
            executable = _executable(row, deadline)
            key = str(executable).casefold()
            if key in paths:
                continue
            labels = [_text(row, 'label', 512), _text(row, 'package_name', 255), executable.stem]
            label = next(value for value in labels if value and not value.casefold().startswith('ms-resource:'))
            result.append({'label': ' '.join(label.split())[:200], 'path': str(executable),
                           'package_family_name': family, 'application_id': app_id})
            paths.add(key)
        except (OSError, ValueError, RuntimeError):
            continue
    return result


def discover_store_apps() -> list[dict[str, str]]:
    """Best-effort, bounded current-user package discovery; never launch apps."""
    if sys.platform != 'win32':
        return []
    try:
        return _parse(_query(_system_powershell()))
    except Exception:
        # Missing Appx support or an unreadable package must not break the
        # existing ordinary desktop application discovery path.
        return []
