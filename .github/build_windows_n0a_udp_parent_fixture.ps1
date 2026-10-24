#requires -Version 5.1
<# Compile only. Separate pinned socket-free UDP parent TEST_ONLY fixture output; never runs or uploads it. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string] $OutputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedParentSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedChildSourceSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedIdentitySha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedFixtureSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows compiler required.' }
if ($env:VSCMD_ARG_TGT_ARCH -cne 'x64') { throw 'Explicit x64 compiler required.' }
$names=@('windows_n0a_udp_parent_fixture.cpp','windows_n0a_udp_parent.cpp','windows_identity_actor.cpp','windows_n0a_udp_actor.cpp')
$expected=@($ExpectedFixtureSha256,$ExpectedParentSha256,$ExpectedIdentitySha256,$ExpectedChildSourceSha256)
$files=@(); $hashes=@()
for ($i=0; $i -lt $names.Count; $i++) {
    $file=Get-Item -LiteralPath (Join-Path $PSScriptRoot ('native\'+$names[$i])) -ErrorAction Stop
    if ($file.PSIsContainer -or (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Source rejected.' }
    $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne $expected[$i].ToLowerInvariant()) { throw 'Source hash mismatch.' }
    $files+=,$file; $hashes+=,$hash
}
$path=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $path) { throw 'Output directory must be new.' }
$directory=New-Item -Path $path -ItemType Directory -ErrorAction Stop
$exe=Join-Path $directory.FullName 'windows_n0a_UDP_PARENT_TEST_ONLY_fixture.exe'
$obj=Join-Path $directory.FullName 'windows_n0a_UDP_PARENT_TEST_ONLY_fixture.obj'
$compiler=Get-Command cl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
& $compiler.Source '/nologo' '/W4' '/WX' '/std:c++17' '/EHsc' '/MT' '/O2' '/utf-8' '/guard:cf' '/UN0A_UDP_PARENT_TEST_ONLY' "/Fo$obj" "/Fe$exe" $files[0].FullName '/link' '/INCREMENTAL:NO' '/DYNAMICBASE' '/NXCOMPAT' '/GUARD:CF'
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Compilation failed.' }
for ($i=0; $i -lt $names.Count; $i++) {
    if ((Get-FileHash -LiteralPath $files[$i].FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$i]) { throw 'Source changed during compilation.' }
}
$manifest=[ordered]@{
    schemaVersion=1; testOnly=$true; deployable=$false; compileOnly=$true
    parentSourceSha256=$hashes[1]; identitySourceSha256=$hashes[2]; childActorSourceSha256=$hashes[3]; fixtureSourceSha256=$hashes[0]
    executableSha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
}
[IO.File]::WriteAllText((Join-Path $directory.FullName 'PARENT-TEST-ONLY-manifest.json'),($manifest|ConvertTo-Json -Depth 3)+"`n",(New-Object Text.UTF8Encoding($false)))
[pscustomobject]@{ TestOnly=$true; Deployable=$false; ExecutableSha256=$manifest.executableSha256; Executed=$false }
