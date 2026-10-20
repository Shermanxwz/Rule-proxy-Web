#requires -Version 5.1
<#
.SYNOPSIS
Compiles, hashes, and records the native identity actor. Never executes it.
.DESCRIPTION
Run from an MSVC Native Tools developer shell with a Windows 8+ SDK.
No elevation, firewall rules, token creation, ACL changes, or test execution.
The output directory must not already exist. An optional expected SHA-256
pins the reviewed source; the source is also checked for changes during build.
.EXAMPLE
.\.github\build_windows_identity_actor.ps1 -OutputDirectory C:\proof\actor-build `
    -ExpectedSourceSha256 <reviewed-source-sha256>
#>
[CmdletBinding()]
param(
    [string] $SourcePath = (Join-Path $PSScriptRoot 'native\windows_identity_actor.cpp'),
    [string] $OutputDirectory = (
        Join-Path ([System.IO.Path]::GetTempPath()) (
            'ruleproxy-identity-actor-' + [guid]::NewGuid().ToString('N')
        )
    ),
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $ExpectedSourceSha256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
    throw 'This compile-only helper requires Windows and the Windows SDK.'
}
$source = Get-Item -LiteralPath $SourcePath -ErrorAction Stop
if ($source.PSIsContainer) {
    throw 'SourcePath must name the native actor source file.'
}
$sourceHash = (Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ExpectedSourceSha256 -and ($sourceHash -ne $ExpectedSourceSha256.ToLowerInvariant())) {
    throw 'The native actor source does not match ExpectedSourceSha256.'
}

$compiler = Get-Command 'cl.exe' -CommandType Application -ErrorAction Stop |
    Select-Object -First 1
$outputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $outputPath) {
    throw 'OutputDirectory must not already exist; build outputs will not be overwritten.'
}
$output = New-Item -Path $outputPath -ItemType Directory -ErrorAction Stop
$exePath = Join-Path $output.FullName 'windows_identity_actor.exe'
$objPath = Join-Path $output.FullName 'windows_identity_actor.obj'
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
    '/guard:cf',
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
$exeHash = (Get-FileHash -LiteralPath $exePath -Algorithm SHA256).Hash.ToLowerInvariant()
$manifest = [ordered]@{
    schemaVersion = 1
    sourcePath = $source.FullName
    sourceSha256 = $sourceHash
    executablePath = $exePath
    executableSha256 = $exeHash
    compilerPath = $compiler.Source
    compilerArguments = $compilerArguments
    targetArchitecture = $env:VSCMD_ARG_TGT_ARCH
    staticCrt = $true
    compileOnly = $true
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
    Executed = $false
}
