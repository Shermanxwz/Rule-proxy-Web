#requires -Version 5.1
<# Compile only: never executes the DNS actor or changes resolver settings. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedActorSourceSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedIdentitySourceSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedDnsProbeSha256
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if ($env:OS -ne 'Windows_NT' -or $env:VSCMD_ARG_TGT_ARCH -cne 'x64') { throw 'Windows x64 compiler required.' }
$names=@('windows_identity_dns_v1_actor.cpp','windows_identity_actor.cpp','windows_identity_dns_v1_probe.hpp')
$expected=@($ExpectedActorSourceSha256,$ExpectedIdentitySourceSha256,$ExpectedDnsProbeSha256)
$files=@()
for ($i=0;$i -lt $names.Count;$i++) {
    $item=Get-Item -LiteralPath (Join-Path $PSScriptRoot ('native/'+$names[$i])) -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'source path rejected' }
    if ((Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected[$i]) { throw 'source binding failed' }
    $files+=,$item.FullName
}
$target=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $target) { throw 'fresh output required' }
New-Item -ItemType Directory -Path $target | Out-Null
$exe=Join-Path $target 'windows_identity_dns_v1_actor.exe'
$obj=Join-Path $target 'windows_identity_dns_v1_actor.obj'
& cl.exe /nologo /W4 /WX /std:c++17 /EHsc /MT /O2 /utf-8 /guard:cf $files[0] "/Fo$obj" "/Fe$exe" /link /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT /GUARD:CF
if ($LASTEXITCODE -ne 0) { throw 'compilation failed' }
for ($i=0;$i -lt $names.Count;$i++) {
    if ((Get-FileHash -LiteralPath $files[$i] -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected[$i]) { throw 'source changed during compile' }
}
$manifest=[ordered]@{schemaVersion=1;compileOnly=$true;runtimeAcceptance=$false
    actorSourceSha256=$expected[0];identitySourceSha256=$expected[1];dnsProbeSha256=$expected[2]
    executableSha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()}
[IO.File]::WriteAllText((Join-Path $target 'identity-dns-v1-manifest.json'),(($manifest|ConvertTo-Json)+[Environment]::NewLine),(New-Object Text.UTF8Encoding($false)))
[pscustomobject]@{CompileOnly=$true;Executed=$false;ExecutableSha256=$manifest.executableSha256}
