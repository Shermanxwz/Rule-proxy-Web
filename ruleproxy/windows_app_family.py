"""Resolve a current user's Store package without activating its applications.

The stable binding names a package family and a manifest application, never a
version directory. Routing scope is deliberately the *whole package*: manifest
metadata cannot establish which of several applications owns a shared helper.
The caller must describe that scope when enabling this automatic mode.

Resolution is strict. Missing registration, ambiguity, unsupported entry points,
unreadable paths and inspection limits raise ``FamilyResolutionError``; callers
must not start a supposedly protected application with an incomplete rule set.
Only concrete, checked executable paths are returned, never folder wildcards.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

from . import windows_store_apps as store


_MAX_OUTPUT = 256 * 1024
_MAX_APPLICATIONS = 128
_MAX_PATHS = 128
_MAX_ENTRIES = 16384
_MAX_DIRECTORIES = 2048
_MAX_DEPTH = 32
_QUERY_SECONDS = 16
_INSPECTION_SECONDS = 5
_IDENTIFIER = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z')
_QUERY_FAMILY_ENV = 'RULEPROXY_STORE_FAMILY_QUERY'
_QUERY_TARGET_ENV = 'RULEPROXY_STORE_TARGET_QUERY'


class FamilyResolutionError(ValueError):
    """The complete current package routing policy could not be established."""


@dataclass(frozen=True)
class ResolvedFamily:
    package_family_name: str
    application_id: str
    package_full_name: str
    entry_path: str
    paths: tuple[str, ...]
    other_application_ids: tuple[str, ...]


def validate_binding(value: dict) -> dict[str, str]:
    """Validate the small, portable identity persisted in application settings."""
    expected = {'package_family_name', 'application_id', 'scope'}
    if not isinstance(value, dict) or set(value) != expected or value.get('scope') != 'package':
        raise FamilyResolutionError('商店应用自动识别身份无效；请重新扫描并添加应用。')
    family, app_id = value.get('package_family_name'), value.get('application_id')
    if (not isinstance(family, str) or not _IDENTIFIER.fullmatch(family)
            or '_' not in family or not all(family.rsplit('_', 1)) or not isinstance(app_id, str)
            or len(app_id) > 128 or not _IDENTIFIER.fullmatch(app_id)):
        raise FamilyResolutionError('商店应用自动识别身份无效；请重新扫描并添加应用。')
    return {'package_family_name': family, 'application_id': app_id, 'scope': 'package'}


# The only dynamic input is a validated family identifier in the environment.
# Get-AppxPackage is restricted to the current user and exact package name;
# family matching additionally includes the publisher identity. No WindowsApps
# directory is walked to find a registration, and no candidate is activated.
_QUERY_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$env:PSModulePath = Join-Path $PSHOME 'Modules'
Import-Module Appx -ErrorAction Stop | Out-Null
$family = $env:RULEPROXY_STORE_FAMILY_QUERY
if (-not $family -or $family -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$' -or -not $family.Contains('_')) {
    throw 'Invalid package family'
}
$name = $family.Substring(0, $family.LastIndexOf('_'))
$packages = @(Get-AppxPackage -Name $name -PackageTypeFilter Main -ErrorAction Stop |
    Where-Object { $_.PackageFamilyName -eq $family } | Select-Object -First 2)
if ($packages.Count -ne 1) { throw 'Current package registration is missing or ambiguous' }
$package = $packages[0]
if ($package.IsFramework -or $package.IsResourcePackage -or $package.IsBundle -or
    -not $package.InstallLocation -or -not $package.PackageFullName) { throw 'Unsupported package registration' }
function Read-AppAttribute($Node, [string]$Name, [string[]]$Namespaces = @('')) {
    $attributes = @($Node.Attributes | Where-Object { $_.LocalName -ceq $Name })
    if ($attributes.Count -eq 0) { return '' }
    if ($attributes.Count -ne 1 -or $Namespaces -cnotcontains $attributes[0].NamespaceURI) {
        throw 'Conflicting or unsupported application attribute namespace'
    }
    if ($attributes[0].Value.Length -gt 4096) { throw 'Application attribute exceeds bound' }
    return [string]$attributes[0].Value
}
$manifest = Get-AppxPackageManifest -Package $package.PackageFullName -ErrorAction Stop
$applications = New-Object 'System.Collections.Generic.List[object]'
$namespace = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/10'
$namespace11 = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/11'
foreach ($application in $manifest.SelectNodes("/*[local-name()='Package']/*[local-name()='Applications']/*[local-name()='Application']")) {
    if ($applications.Count -ge 128) { throw 'Too many package applications' }
    [void]$applications.Add([ordered]@{
        application_id=(Read-AppAttribute $application 'Id');
        executable=(Read-AppAttribute $application 'Executable');
        entry_point=(Read-AppAttribute $application 'EntryPoint');
        runtime_behavior=(Read-AppAttribute $application 'RuntimeBehavior' $namespace);
        trust_level=(Read-AppAttribute $application 'TrustLevel' $namespace);
        host_id=((Read-AppAttribute $application 'HostId' $namespace)+(Read-AppAttribute $application 'HostRuntimeId' $namespace));
        start_page=(Read-AppAttribute $application 'StartPage');
        parameters=(Read-AppAttribute $application 'Parameters' @($namespace,$namespace11));
        current_directory=(Read-AppAttribute $application 'CurrentDirectoryPath' @($namespace,$namespace11))
    })
}
$document = [ordered]@{schema_version=1;packages=@([ordered]@{
    package_family_name=[string]$package.PackageFamilyName;
    package_full_name=[string]$package.PackageFullName;
    install_location=[string]$package.InstallLocation;
    is_framework=[bool]$package.IsFramework;is_resource=[bool]$package.IsResourcePackage;is_bundle=[bool]$package.IsBundle;
    applications=@($applications.ToArray())
})}
$bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $document -Depth 7 -Compress))
if ($bytes.Length -gt 262144) { throw 'Package metadata exceeds output bound' }
$stream = [Console]::OpenStandardOutput()
$stream.Write($bytes, 0, $bytes.Length)
$stream.Flush()
'''


_BINDING_QUERY_SCRIPT = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$env:PSModulePath = Join-Path $PSHOME 'Modules'
Import-Module Appx -ErrorAction Stop | Out-Null
$target = [IO.Path]::GetFullPath($env:RULEPROXY_STORE_TARGET_QUERY)
$registered = @(Get-AppxPackage -PackageTypeFilter Main -ErrorAction Stop | Select-Object -First 513)
if ($registered.Count -gt 512) { throw 'Package registration query exceeds bound' }
function Read-AppAttribute($Node, [string]$Name, [string[]]$Namespaces = @('')) {
    $attributes = @($Node.Attributes | Where-Object { $_.LocalName -ceq $Name })
    if ($attributes.Count -eq 0) { return '' }
    if ($attributes.Count -ne 1 -or $Namespaces -cnotcontains $attributes[0].NamespaceURI) {
        throw 'Conflicting or unsupported application attribute namespace'
    }
    if ($attributes[0].Value.Length -gt 4096) { throw 'Application attribute exceeds bound' }
    return [string]$attributes[0].Value
}
$packages = New-Object 'System.Collections.Generic.List[object]'
$namespace = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/10'
$namespace11 = 'http://schemas.microsoft.com/appx/manifest/uap/windows10/11'
foreach ($package in $registered) {
    if ($package.IsFramework -or $package.IsResourcePackage -or $package.IsBundle -or -not $package.InstallLocation) { continue }
    $root = [IO.Path]::GetFullPath([string]$package.InstallLocation).TrimEnd('\')
    if (-not $target.StartsWith(($root + '\'), [StringComparison]::OrdinalIgnoreCase)) { continue }
    if ($packages.Count -ge 2) { throw 'Package registration is ambiguous' }
    $manifest = Get-AppxPackageManifest -Package $package.PackageFullName -ErrorAction Stop
    $applications = New-Object 'System.Collections.Generic.List[object]'
    foreach ($application in $manifest.SelectNodes("/*[local-name()='Package']/*[local-name()='Applications']/*[local-name()='Application']")) {
        if ($applications.Count -ge 128) { throw 'Too many package applications' }
        [void]$applications.Add([ordered]@{
            application_id=(Read-AppAttribute $application 'Id');
            executable=(Read-AppAttribute $application 'Executable');
            entry_point=(Read-AppAttribute $application 'EntryPoint');
            runtime_behavior=(Read-AppAttribute $application 'RuntimeBehavior' $namespace);
            trust_level=(Read-AppAttribute $application 'TrustLevel' $namespace);
            host_id=((Read-AppAttribute $application 'HostId' $namespace)+(Read-AppAttribute $application 'HostRuntimeId' $namespace));
            start_page=(Read-AppAttribute $application 'StartPage');
            parameters=(Read-AppAttribute $application 'Parameters' @($namespace,$namespace11));
            current_directory=(Read-AppAttribute $application 'CurrentDirectoryPath' @($namespace,$namespace11))
        })
    }
    [void]$packages.Add([ordered]@{
        package_family_name=[string]$package.PackageFamilyName;
        package_full_name=[string]$package.PackageFullName;
        install_location=[string]$package.InstallLocation;
        is_framework=[bool]$package.IsFramework;is_resource=[bool]$package.IsResourcePackage;is_bundle=[bool]$package.IsBundle;
        applications=@($applications.ToArray())
    })
}
$document = [ordered]@{schema_version=1;packages=@($packages.ToArray())}
$bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $document -Depth 7 -Compress))
if ($bytes.Length -gt 262144) { throw 'Package metadata exceeds output bound' }
$stream = [Console]::OpenStandardOutput()
$stream.Write($bytes, 0, $bytes.Length)
$stream.Flush()
'''


def _run_query(script: str, query_environment: dict[str, str]) -> bytes:
    powershell = store._system_powershell()
    command = [str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive',
               '-ExecutionPolicy', 'Bypass', '-EncodedCommand',
               base64.b64encode(script.encode('utf-16-le')).decode('ascii')]
    environment = {**os.environ, 'PSModulePath': str(powershell.parent / 'Modules'),
                   **query_environment}
    with tempfile.TemporaryFile() as output:
        result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=output,
            stderr=subprocess.DEVNULL, cwd=powershell.parent, env=environment,
            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            timeout=_QUERY_SECONDS, check=False)
        if type(result.returncode) is not int or result.returncode != 0:
            raise FamilyResolutionError('无法确定当前账户唯一的商店应用版本；请确认应用已安装并重新扫描。')
        output.seek(0)
        data = output.read(_MAX_OUTPUT + 1)
    if len(data) > _MAX_OUTPUT:
        raise FamilyResolutionError('商店应用身份数据超过安全上限，已停止受保护启动。')
    return data


def _query(binding: dict[str, str]) -> bytes:
    return _run_query(_QUERY_SCRIPT, {_QUERY_FAMILY_ENV: binding['package_family_name']})


def _query_binding(path: Path) -> bytes:
    return _run_query(_BINDING_QUERY_SCRIPT, {_QUERY_TARGET_ENV: str(path)})


def _text(row: dict, key: str, maximum: int = 4096) -> str:
    value = store._text(row, key, maximum)
    if not value:
        raise FamilyResolutionError('商店应用身份数据缺失，已停止受保护启动。')
    return value


def _json_unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise FamilyResolutionError('商店应用身份数据含有重复字段。')
        value[key] = item
    return value


def _identity(package: dict) -> tuple[str, str]:
    if any(package.get(flag) is not False for flag in ('is_framework', 'is_resource', 'is_bundle')):
        raise FamilyResolutionError('此商店软件包类型不支持直接受保护启动。')
    family = _text(package, 'package_family_name', 255)
    full_name = _text(package, 'package_full_name', 255)
    if not _IDENTIFIER.fullmatch(family) or not _IDENTIFIER.fullmatch(full_name) or '_' not in family:
        raise FamilyResolutionError('商店应用当前注册身份无效。')
    full_parts = full_name.rsplit('_', 4)
    family_parts = family.rsplit('_', 1)
    if (len(full_parts) != 5 or not all(family_parts)
            or full_parts[0].casefold() != family_parts[0].casefold()
            or full_parts[-1].casefold() != family_parts[-1].casefold()
            or not re.fullmatch(r'\d+\.\d+\.\d+\.\d+', full_parts[1])
            or full_parts[2].casefold() not in ('x64', 'x86', 'arm', 'arm64', 'neutral')):
        raise FamilyResolutionError('商店应用完整包身份与保存的软件包家族不一致。')
    return family, full_name


def _applications(package: dict) -> dict[str, dict]:
    applications = package.get('applications')
    if not isinstance(applications, list) or not 1 <= len(applications) <= _MAX_APPLICATIONS:
        raise FamilyResolutionError('商店应用入口清单无效或超过安全上限。')
    by_id = {}
    for row in applications:
        if not isinstance(row, dict):
            raise FamilyResolutionError('商店应用入口身份无效。')
        app_id = _text(row, 'application_id', 128)
        if not _IDENTIFIER.fullmatch(app_id) or app_id.casefold() in by_id:
            raise FamilyResolutionError('商店应用入口身份无效或存在歧义。')
        by_id[app_id.casefold()] = row
    return by_id


def _scan(root: Path, deadline: float) -> tuple[str, ...]:
    """Inspect every entry of one registered package; never accept a prefix."""
    pending = [(root, 0)]
    paths, seen, entries, directories = [], set(), 0, 1
    while pending:
        directory, depth = pending.pop()
        store._plain(directory, directory=True, deadline=deadline)
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                if entries > _MAX_ENTRIES or time.monotonic() >= deadline:
                    raise FamilyResolutionError('商店软件包扫描超过安全上限，未启用不完整的代理规则。')
                attributes = child.stat(follow_symlinks=False)
                if stat.S_ISLNK(attributes.st_mode) or getattr(attributes, 'st_file_attributes', 0) & 0x400:
                    raise FamilyResolutionError('商店软件包含有链接或重解析点，已停止受保护启动。')
                if stat.S_ISDIR(attributes.st_mode):
                    directories += 1
                    if depth >= _MAX_DEPTH or directories > _MAX_DIRECTORIES:
                        raise FamilyResolutionError('商店软件包目录超过安全上限，未启用不完整的代理规则。')
                    pending.append((Path(child.path), depth + 1))
                elif stat.S_ISREG(attributes.st_mode):
                    if Path(child.name).suffix.casefold() != '.exe':
                        continue
                    relative = Path(child.path).relative_to(root)
                    target = store._executable({'install_location': str(root),
                        'executable': str(relative)}, deadline)
                    key = str(target).casefold()
                    if key in seen:
                        raise FamilyResolutionError('商店软件包程序路径存在歧义，已停止受保护启动。')
                    seen.add(key)
                    paths.append(str(target))
                    if len(paths) > _MAX_PATHS:
                        raise FamilyResolutionError('商店软件包超过 128 个程序路径，未启用不完整的代理规则。')
                else:
                    raise FamilyResolutionError('商店软件包含有非常规文件，已停止受保护启动。')
    return tuple(sorted(paths, key=str.casefold))


def resolve_metadata(binding: dict, data: bytes) -> ResolvedFamily:
    """Resolve trusted registration output, enforcing complete package checks.

    Public for focused verification; production callers use ``resolve_store_family``
    so that the registration is freshly queried for the current user.
    """
    binding = validate_binding(binding)
    try:
        if not isinstance(data, bytes) or len(data) > _MAX_OUTPUT:
            raise FamilyResolutionError('商店应用身份数据超过安全上限。')
        document = json.loads(data.decode('utf-8-sig'), object_pairs_hook=_json_unique)
        if (not isinstance(document, dict) or type(document.get('schema_version')) is not int
                or document['schema_version'] != 1 or not isinstance(document.get('packages'), list)
                or len(document['packages']) != 1):
            raise FamilyResolutionError('无法确定当前账户唯一的商店应用版本。')
        package = document['packages'][0]
        if not isinstance(package, dict):
            raise FamilyResolutionError('商店应用身份数据无效。')
        family, full_name = _identity(package)
        if family.casefold() != binding['package_family_name'].casefold():
            raise FamilyResolutionError('商店应用当前注册与保存身份不一致。')
        by_id = _applications(package)
        selected = by_id.get(binding['application_id'].casefold())
        if not selected or selected['application_id'] != binding['application_id'] or not store._full_trust(selected):
            raise FamilyResolutionError('商店应用入口已变更或不支持直接启动；请重新扫描。')
        deadline = time.monotonic() + _INSPECTION_SECONDS
        entry = store._executable({**selected, 'install_location': _text(package, 'install_location')}, deadline)
        root = Path(package['install_location']).resolve(strict=True)
        paths = _scan(root, deadline)
        if str(entry).casefold() not in {path.casefold() for path in paths}:
            raise FamilyResolutionError('商店应用入口在扫描期间发生变更，已停止受保护启动。')
        # Recheck the launch target and its full ancestor chain after enumeration.
        checked = store._executable({**selected, 'install_location': str(root)}, deadline)
        if checked != entry:
            raise FamilyResolutionError('商店应用入口在扫描期间发生变更，已停止受保护启动。')
        others = tuple(row['application_id'] for row in by_id.values() if row is not selected)
        return ResolvedFamily(family, binding['application_id'], full_name, str(entry), paths, others)
    except FamilyResolutionError:
        raise
    except (OSError, ValueError, RuntimeError, UnicodeError, RecursionError) as error:
        raise FamilyResolutionError('无法完整验证商店软件包的程序路径，已停止受保护启动；请重新扫描后重试。') from error


def resolve_store_family(binding: dict) -> ResolvedFamily:
    """Freshly resolve the current account's unique registered package version."""
    binding = validate_binding(binding)
    if sys.platform != 'win32':
        raise FamilyResolutionError('商店应用自动识别仅适用于 Windows。')
    try:
        return resolve_metadata(binding, _query(binding))
    except FamilyResolutionError:
        raise
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise FamilyResolutionError('查询当前账户的商店软件包失败，已停止受保护启动；请重新扫描后重试。') from error


def _binding_metadata(path: Path, data: bytes) -> dict[str, str] | None:
    if not isinstance(data, bytes) or len(data) > _MAX_OUTPUT:
        raise FamilyResolutionError('商店应用身份数据超过安全上限。')
    document = json.loads(data.decode('utf-8-sig'), object_pairs_hook=_json_unique)
    if (not isinstance(document, dict) or type(document.get('schema_version')) is not int
            or document['schema_version'] != 1 or not isinstance(document.get('packages'), list)
            or len(document['packages']) > 2):
        raise FamilyResolutionError('商店应用身份查询不完整。')
    deadline = time.monotonic() + _INSPECTION_SECONDS
    matches = []
    for package in document['packages']:
        if not isinstance(package, dict):
            raise FamilyResolutionError('商店应用身份数据无效。')
        family, _full_name = _identity(package)
        root = _text(package, 'install_location')
        for row in _applications(package).values():
            if not store._full_trust(row):
                continue
            executable = store._executable({**row, 'install_location': root}, deadline)
            if str(executable).casefold() == str(path).casefold():
                matches.append(validate_binding({'package_family_name': family,
                    'application_id': row['application_id'], 'scope': 'package'}))
    return matches[0] if len(matches) == 1 else None


def binding_for_path(value: str | Path) -> dict[str, str] | None:
    """Bind a real manifest entry only when current registration is unambiguous.

    This is a best-effort migration/discovery helper, never proof that protection
    is running. A non-manifest helper, missing package, failed/incomplete query,
    ambiguous entry or invalid path returns ``None``. No identity is inferred
    from directory names, executable names or an arbitrary caller-supplied PFN.
    The caller must still freshly resolve the returned binding before startup.
    """
    if sys.platform != 'win32':
        return None
    try:
        if not isinstance(value, (str, Path)):
            return None
        raw = str(value)
        path = Path(raw)
        if (not raw or len(raw) > 4096 or '\0' in raw or raw.startswith(('\\', '//'))
                or not path.is_absolute() or path.suffix.casefold() != '.exe'):
            return None
        deadline = time.monotonic() + _INSPECTION_SECONDS
        for parent in path.parents:
            store._plain(parent, directory=True, deadline=deadline)
        store._plain(path, directory=False, deadline=deadline)
        path = path.resolve(strict=True)
        return _binding_metadata(path, _query_binding(path))
    except (OSError, ValueError, RuntimeError, UnicodeError, RecursionError, subprocess.SubprocessError):
        return None
