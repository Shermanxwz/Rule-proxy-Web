#requires -Version 5.1
<# TEST ONLY compile helper. Never executes output. Its distinct output directory,
   executable and manifest must never be included in a guest/deployment artifact. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string] $OutputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedFixtureSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedActorSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedIdentitySha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows compiler fixture required.' }
$names=@('windows_n0a_fixture.cpp','windows_n0a_actor.cpp','windows_identity_actor.cpp')
$expected=@($ExpectedFixtureSha256,$ExpectedActorSha256,$ExpectedIdentitySha256)
$files=@(); $hashes=@()
for ($i=0; $i -lt 3; $i++) {
    $file=Get-Item -LiteralPath (Join-Path $PSScriptRoot ('native\'+$names[$i])) -ErrorAction Stop
    if ($file.PSIsContainer -or (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Fixture source rejected.' }
    $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne $expected[$i].ToLowerInvariant()) { throw 'Fixture dependency hash mismatch.' }
    $files+=,$file; $hashes+=,$hash
}
$path=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $path) { throw 'Fixture output directory must be new.' }
$directory=New-Item -Path $path -ItemType Directory -ErrorAction Stop
$exe=Join-Path $directory.FullName 'windows_n0a_TEST_ONLY_fixture.exe'
$obj=Join-Path $directory.FullName 'windows_n0a_TEST_ONLY_fixture.obj'
$compiler=Get-Command cl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
& $compiler.Source '/nologo' '/W4' '/WX' '/std:c++17' '/EHsc' '/MT' '/O2' '/utf-8' '/guard:cf' "/Fo$obj" "/Fe$exe" $files[0].FullName '/link' '/INCREMENTAL:NO' '/DYNAMICBASE' '/NXCOMPAT' '/GUARD:CF'
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Fixture compilation failed.' }
for ($i=0; $i -lt 3; $i++) {
    if ((Get-FileHash -LiteralPath $files[$i].FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$i]) { throw 'Fixture source changed during compilation.' }
}
$manifest=[ordered]@{
    schemaVersion=1; testOnly=$true; deployable=$false; compileOnly=$true
    fixtureSourceSha256=$hashes[0]; actorSourceSha256=$hashes[1]; identitySourceSha256=$hashes[2]
    executableSha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
}
[IO.File]::WriteAllText((Join-Path $directory.FullName 'TEST-ONLY-manifest.json'),($manifest|ConvertTo-Json -Depth 3)+"`n",(New-Object Text.UTF8Encoding($false)))
[pscustomobject]@{ TestOnly=$true; Deployable=$false; ExecutablePath=$exe; ExecutableSha256=$manifest.executableSha256 }
