#requires -Version 5.1
<# TEST ONLY installed-SDK compile gate. Never runs output, exports a deployment
   artifact, or modifies DNS configuration. Output must stay outside guest payloads. #>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string] $OutputDirectory,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9a-fA-F]{64}$')][string] $ExpectedSourceSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:OS -ne 'Windows_NT') { throw 'Windows SDK fixture required.' }
$source=Get-Item -LiteralPath (Join-Path $PSScriptRoot 'native\windows_n0a_dns_fixture.cpp') -ErrorAction Stop
if ($source.PSIsContainer -or (($source.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Fixture source rejected.' }
$sourceHash=(Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
if ($sourceHash -cne $ExpectedSourceSha256.ToLowerInvariant()) { throw 'Fixture source hash mismatch.' }
if ([string]::IsNullOrEmpty($env:WindowsSDKVersion)) { throw 'Installed SDK version unavailable.' }
$sdkVersion=$env:WindowsSDKVersion.TrimEnd('\')
if ($sdkVersion -cnotmatch '^\d+\.\d+\.\d+\.\d+$') { throw 'Installed SDK version rejected.' }
if ([string]::IsNullOrEmpty($env:WindowsSdkDir)) { throw 'Installed SDK root unavailable.' }
$sdkInclude=[IO.Path]::GetFullPath((Join-Path (Join-Path $env:WindowsSdkDir 'Include') $sdkVersion))
if ([string]::IsNullOrEmpty($env:INCLUDE)) { throw 'Compiler include path unavailable.' }
$headerFiles=@(); $headers=@()
foreach ($name in @('windns.h','windnsdef.h','ws2ipdef.h')) {
    $header=$null
    foreach ($include in $env:INCLUDE.Split(';')) {
        if ([string]::IsNullOrWhiteSpace($include)) { continue }
        $candidate=Join-Path $include $name
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            $header=Get-Item -LiteralPath $candidate -ErrorAction Stop
            break
        }
    }
    if ($null -eq $header -or (($header.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) { throw 'Official SDK header unavailable.' }
    $section=if ($name -ceq 'windns.h') { 'um' } else { 'shared' }
    $expectedHeader=[IO.Path]::GetFullPath((Join-Path (Join-Path $sdkInclude $section) $name))
    if (-not [string]::Equals($header.FullName,$expectedHeader,[StringComparison]::OrdinalIgnoreCase)) { throw 'SDK include shadow rejected.' }
    $headerFiles+=,$header
    $headers+=,[ordered]@{name=$name;sha256=(Get-FileHash -LiteralPath $header.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
}
$path=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if (Test-Path -LiteralPath $path) { throw 'Fixture output directory must be new.' }
$directory=New-Item -Path $path -ItemType Directory -ErrorAction Stop
$exe=Join-Path $directory.FullName 'windows_n0a_DNS_TEST_ONLY_fixture.exe'
$obj=Join-Path $directory.FullName 'windows_n0a_DNS_TEST_ONLY_fixture.obj'
$compiler=Get-Command cl.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1
& $compiler.Source '/nologo' '/W4' '/WX' '/std:c++17' '/EHsc' '/MT' '/O2' '/utf-8' '/guard:cf' '/DN0A_DNS_TEST_ONLY=1' "/Fo$obj" "/Fe$exe" $source.FullName '/link' '/INCREMENTAL:NO' '/DYNAMICBASE' '/NXCOMPAT' '/GUARD:CF'
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw 'Official REQUEST3 SDK compilation failed.' }
if ((Get-FileHash -LiteralPath $source.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $sourceHash) { throw 'Fixture source changed during compilation.' }
for ($i=0; $i -lt $headerFiles.Count; $i++) {
    if ((Get-FileHash -LiteralPath $headerFiles[$i].FullName -Algorithm SHA256).Hash.ToLowerInvariant() -cne $headers[$i].sha256) { throw 'SDK header changed during compilation.' }
}
$manifest=[ordered]@{
    schemaVersion=1; testOnly=$true; deployable=$false; compileOnly=$true
    requestVersion=3; customServerType='UDP'; installedSdkVersion=$sdkVersion
    sourceSha256=$sourceHash; sdkHeaders=$headers
    executableSha256=(Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
}
[IO.File]::WriteAllText((Join-Path $directory.FullName 'DNS-TEST-ONLY-manifest.json'),($manifest|ConvertTo-Json -Depth 4)+"`n",(New-Object Text.UTF8Encoding($false)))
[pscustomobject]@{ TestOnly=$true; Deployable=$false; InstalledSdkVersion=$sdkVersion; ExecutableSha256=$manifest.executableSha256 }
