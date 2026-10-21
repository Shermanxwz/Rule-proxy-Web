#requires -Version 5.1
<#
.SYNOPSIS
Compiles, hashes, and records the standalone N0a actor. Never executes it.
.DESCRIPTION
Run from an MSVC Native Tools developer shell with a Windows 8+ SDK.
No elevation, firewall rules, token creation, ACL changes, or test execution.
The output directory must not already exist. An optional expected SHA-256
pins the reviewed source; the source is also checked for changes during build.
The N0a source includes the unchanged IdentityOnly actor as a pinned dependency.
Both source digests are recorded and checked before and after compilation.
This helper does not execute the network-capable output.
.EXAMPLE
.\.github\build_windows_n0a_actor.ps1 -OutputDirectory C:\proof\actor-build `
    -ExpectedSourceSha256 <reviewed-source-sha256>
#>
[CmdletBinding()]
param(
    [string] $SourcePath = (Join-Path $PSScriptRoot 'native\windows_n0a_actor.cpp'),
    [string] $OutputDirectory = (
        Join-Path ([System.IO.Path]::GetTempPath()) (
            'ruleproxy-n0a-actor-' + [guid]::NewGuid().ToString('N')
        )
    ),
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $ExpectedSourceSha256,
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $ExpectedIdentitySourceSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'This compile-only helper requires Windows and the Windows SDK.'
}
$source = Get-Item -LiteralPath $SourcePath -ErrorAction Stop
if ($source.PSIsContainer -or (($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    throw 'SourcePath must name the native actor source file.'
}
$sourceHash = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ExpectedSourceSha256 -and ($sourceHash -ne $ExpectedSourceSha256.ToLowerInvariant())) {
    throw 'The native actor source does not match ExpectedSourceSha256.'
}

$identitySource = Get-Item -LiteralPath (Join-Path $source.DirectoryName 'windows_identity_actor.cpp') -ErrorAction Stop
if ($identitySource.PSIsContainer -or (($identitySource.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Identity dependency must be a source file.' }
$identityHash = (Get-FileHash -LiteralPath $identitySource.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ExpectedIdentitySourceSha256 -and ($identityHash -ne $ExpectedIdentitySourceSha256.ToLowerInvariant())) {
    throw 'Identity dependency does not match ExpectedIdentitySourceSha256.'
}

$compiler = Get-Command 'cl.exe' -CommandType Application -ErrorAction Stop |
    Select-Object -First 1
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $outputPath) {
    throw 'OutputDirectory must not already exist; build outputs will not be overwritten.'
}
$output = New-Item -Path $outputPath -ItemType Directory -ErrorAction Stop
$exePath = Join-Path $output.FullName 'windows_n0a_actor.exe'
$objPath = Join-Path $output.FullName 'windows_n0a_actor.obj'
$manifestPath = Join-Path $output.FullName 'build-manifest.json'
$compilerArguments = @(
    '/nologo',
    '/W4',
    '/WX',
    '/std:c++17',
    '/EHsc',
    '/MT',
    '/O2',
    '/utf-8',
    '/guard:cf'
)
$compilerArguments += @(
    "/Fo$objPath",
    "/Fe$exePath",
    $source.FullName,
    '/link',
    '/INCREMENTAL:NO',
    '/DYNAMICBASE',
    '/NXCOMPAT',
    '/GUARD:CF'
)

Write-Host "Source SHA-256: $sourceHash"
& $compiler.Source @compilerArguments | ForEach-Object { Write-Host $_ }
$compilerExitCode = $LASTEXITCODE
if ($compilerExitCode -ne 0) {
    throw "cl.exe failed with exit code $compilerExitCode. No actor was run."
}
if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
    throw 'cl.exe reported success without producing the expected executable.'
}
$sourceHashAfter = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sourceHashAfter -ne $sourceHash) {
    throw 'The source changed during compilation. Do not use this build.'
}
$identityHashAfter = (Get-FileHash -LiteralPath $identitySource.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($identityHashAfter -ne $identityHash) { throw 'Identity dependency changed during compilation.' }
$exeHash = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = [ordered]@{
    schemaVersion = 1
    sourceSha256 = $sourceHash
    identitySourceSha256 = $identityHash
    executableSha256 = $exeHash
    targetArchitecture = $env:VSCMD_ARG_TGT_ARCH
    staticCrt = $true
    httpCompiled = $false
    rawTcpCompiled = $true
    compileOnly = $true
    testOnly = $false
    actorRole = 'n0a-tcp'
    builtAtUtc = [DateTime]::UtcNow.ToString('o')
}
$manifestJson = $manifest | ConvertTo-Json -Depth 5
$utf8WithoutBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($manifestPath, $manifestJson + "`n", $utf8WithoutBom)

[pscustomobject]@{
    SourceSha256 = $sourceHash
    ExecutablePath = $exePath
    ExecutableSha256 = $exeHash
    ManifestPath = $manifestPath
    HttpCompiled = $false
    RawTcpCompiled = $true
    IdentitySourceSha256 = $identityHash
    Executed = $false
}
