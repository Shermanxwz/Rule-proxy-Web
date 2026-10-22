#requires -Version 5.1
<# Compile only. Does not execute an actor, open a socket or change security. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string] $OutputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedActorSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedOriginActorSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedIdentitySha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedCoreSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedPipeHelperSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedOriginTransportSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedLiveContractSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows compiler required.' }
if ($env:VSCMD_ARG_TGT_ARCH -cne 'x64') { throw 'Explicit x64 compiler required.' }
$names=@('windows_identity_proxy_c_actor.cpp','windows_identity_proxy_origin_actor.cpp','windows_identity_actor.cpp',
    'windows_identity_proxy_bridge_core.hpp','windows_identity_proxy_pipe_actor.cpp',
    'windows_identity_proxy_origin_transport.hpp','windows_identity_proxy_c_contract.hpp')
$expected=@($ExpectedActorSha256,$ExpectedOriginActorSha256,$ExpectedIdentitySha256,$ExpectedCoreSha256,
    $ExpectedPipeHelperSha256,$ExpectedOriginTransportSha256,$ExpectedLiveContractSha256)
$files=@();$hashes=@()
for ($i=0;$i -lt $names.Count;$i++) {
    $file=Get-Item -LiteralPath (Join-Path $PSScriptRoot ('native\'+$names[$i])) -ErrorAction Stop
    if ($file.PSIsContainer -or (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Source rejected.' }
    $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne $expected[$i].ToLowerInvariant()) { throw 'Source hash mismatch.' }
    $files+=,$file;$hashes+=,$hash
}
$path=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $path) { throw 'Output directory must be new.' }
$directory=New-Item -Path $path -ItemType Directory -ErrorAction Stop
$exe=Join-Path $directory.FullName 'windows_identity_proxy_c_actor.exe'
$obj=Join-Path $directory.FullName 'windows_identity_proxy_c_actor.obj'
$compiler=Get-Command cl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
& $compiler.Source '/nologo' '/W4' '/WX' '/std:c++17' '/EHsc' '/MT' '/O2' '/utf-8' '/guard:cf' "/Fo$obj" "/Fe$exe" $files[0].FullName '/link' '/SUBSYSTEM:WINDOWS' '/INCREMENTAL:NO' '/DYNAMICBASE' '/NXCOMPAT' '/GUARD:CF'
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Compilation failed.' }
$artifact=Get-Item -LiteralPath $exe -ErrorAction Stop
if ($artifact.Length -lt 512 -or $artifact.Length -gt 8388608 -or (($artifact.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Artifact rejected.' }
for ($i=0;$i -lt $names.Count;$i++) {
    if ((Get-FileHash -LiteralPath $files[$i].FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$i]) { throw 'Source changed during compilation.' }
}
$manifest=[ordered]@{
    schemaVersion=1;compileOnly=$true;runtimeAcceptance=$false
    actorSourceSha256=$hashes[0];originActorSha256=$hashes[1];identitySourceSha256=$hashes[2];coreSha256=$hashes[3]
    pipeHelperSha256=$hashes[4];originTransportSha256=$hashes[5];liveContractSha256=$hashes[6]
    executableSha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
}
[IO.File]::WriteAllText((Join-Path $directory.FullName 'identity-proxy-c-manifest.json'),
    (($manifest|ConvertTo-Json -Depth 3)+[Environment]::NewLine),(New-Object Text.UTF8Encoding($false)))
[pscustomobject]@{CompileOnly=$true;RuntimeAcceptance=$false;ExecutableSha256=$manifest.executableSha256;Executed=$false}
