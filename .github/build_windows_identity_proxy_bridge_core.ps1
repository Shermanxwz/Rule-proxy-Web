#requires -Version 5.1
<# Pure conformance compilation only. Never executes the resulting binary. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string] $OutputDirectory,
    [Parameter(Mandatory=$true)][string] $PythonExecutable,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedCoreSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedConformanceSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedFixtureSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedCodecSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedModelSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows compiler required.' }
if ($env:VSCMD_ARG_TGT_ARCH -cne 'x64') { throw 'Explicit x64 compiler required.' }
$root=Split-Path -Parent $PSScriptRoot
$relative=@('.github/native/windows_identity_proxy_bridge_core.hpp', '.github/native/windows_identity_proxy_bridge_conformance.cpp', 'tests/test_windows_identity_proxy_bridge_native.py', '.github/windows_identity_proxy_bridge_codec.py', '.github/windows_identity_proxy_bridge_model.py')
$expected=@($ExpectedCoreSha256,$ExpectedConformanceSha256,$ExpectedFixtureSha256,$ExpectedCodecSha256,$ExpectedModelSha256)
$files=@(); $hashes=@()
for ($i=0; $i -lt $relative.Count; $i++) {
    $file=Get-Item -LiteralPath (Join-Path $root $relative[$i]) -ErrorAction Stop
    if ($file.PSIsContainer -or (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Source rejected.' }
    $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($hash -cne $expected[$i].ToLowerInvariant()) { throw 'Source hash mismatch.' }
    $files+=,$file; $hashes+=,$hash
}
$python=Get-Item -LiteralPath $PythonExecutable -ErrorAction Stop
if ($python.PSIsContainer -or (($python.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Python executable rejected.' }
$path=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $path) { throw 'Output directory must be new.' }
$directory=New-Item -Path $path -ItemType Directory -ErrorAction Stop
$header=Join-Path $directory.FullName 'windows_identity_proxy_bridge_cases.h'
& $python.FullName '-I' '-S' '-B' $files[2].FullName '--export-corpus' $header
if ($LASTEXITCODE -ne 0) { throw 'Corpus generation failed.' }
$generated=Get-Item -LiteralPath $header -ErrorAction Stop
if ($generated.PSIsContainer -or $generated.Length -gt 16777216 -or (($generated.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Generated header rejected.' }
$headerHash=(Get-FileHash -LiteralPath $header -Algorithm SHA256).Hash.ToLowerInvariant()
$exe=Join-Path $directory.FullName 'windows_identity_proxy_bridge_conformance.exe'
$obj=Join-Path $directory.FullName 'windows_identity_proxy_bridge_conformance.obj'
$compiler=Get-Command cl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
& $compiler.Source '/nologo' '/W4' '/WX' '/std:c++17' '/EHsc' '/MT' '/O2' '/utf-8' "/I$($directory.FullName)" "/Fo$obj" "/Fe$exe" $files[1].FullName '/link' '/INCREMENTAL:NO' '/DYNAMICBASE' '/NXCOMPAT'
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Compilation failed.' }
for ($i=0; $i -lt $files.Count; $i++) {
    if ((Get-FileHash -LiteralPath $files[$i].FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hashes[$i]) { throw 'Source changed during compilation.' }
}
if ((Get-FileHash -LiteralPath $header -Algorithm SHA256).Hash.ToLowerInvariant() -cne $headerHash) { throw 'Generated header changed during compilation.' }
$manifest=[ordered]@{
    schemaVersion=1; modelOnly=$true; runtimeAcceptance=$false; compileOnly=$true; executed=$false
    coreSha256=$hashes[0]; conformanceSha256=$hashes[1]; fixtureSha256=$hashes[2]
    codecSha256=$hashes[3]; modelSha256=$hashes[4]; generatedHeaderSha256=$headerHash
    executableSha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
}
[IO.File]::WriteAllText((Join-Path $directory.FullName 'BRIDGE-CORE-model-manifest.json'),($manifest|ConvertTo-Json -Depth 3)+"`n",(New-Object Text.UTF8Encoding($false)))
[pscustomobject]@{ ModelOnly=$true; RuntimeAcceptance=$false; Executed=$false }
