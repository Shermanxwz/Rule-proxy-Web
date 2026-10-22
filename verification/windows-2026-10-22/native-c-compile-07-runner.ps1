$ErrorActionPreference='Stop'
Import-Module 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/Tools/Microsoft.VisualStudio.DevShell.dll'
Enter-VsDevShell -VsInstallPath 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools' -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
$repo=Join-Path $PSScriptRoot 'Rule-proxy-Web'
$native=Join-Path $repo '.github/native'
$mapping=@{
    ExpectedActorSha256='windows_identity_proxy_c_actor.cpp'
    ExpectedOriginActorSha256='windows_identity_proxy_origin_actor.cpp'
    ExpectedIdentitySha256='windows_identity_actor.cpp'
    ExpectedCoreSha256='windows_identity_proxy_bridge_core.hpp'
    ExpectedPipeHelperSha256='windows_identity_proxy_pipe_actor.cpp'
    ExpectedOriginTransportSha256='windows_identity_proxy_origin_transport.hpp'
    ExpectedLiveContractSha256='windows_identity_proxy_c_contract.hpp'
    ExpectedDnsStandardProbeSha256='windows_identity_dns_standard_probe.hpp'
    ExpectedDnsRawUdpSha256='windows_identity_dns_raw_udp.hpp'
}
$arguments=@{OutputDirectory=(Join-Path $PSScriptRoot 'proxy-c-compile-07')}
foreach($key in $mapping.Keys){$arguments[$key]=(Get-FileHash -LiteralPath (Join-Path $native $mapping[$key]) -Algorithm SHA256).Hash.ToLowerInvariant()}
& (Join-Path $repo '.github/build_windows_identity_proxy_c_actor.ps1') @arguments
if($LASTEXITCODE -ne 0){throw 'compile failed'}
& dumpbin.exe /imports (Join-Path $PSScriptRoot 'proxy-c-compile-07/windows_identity_proxy_c_actor.exe') | Out-File -LiteralPath (Join-Path $PSScriptRoot 'proxy-c-compile-07/imports.txt') -Encoding utf8
if($LASTEXITCODE -ne 0){throw 'imports failed'}
$env:PYTHONPATH=$null
python -I -S -B -m unittest discover -s (Join-Path $repo 'tests') -p 'test_windows_identity_proxy_c_native.py' -v
if($LASTEXITCODE -ne 0){throw 'native pure failed'}
python -I -S -B -m unittest discover -s (Join-Path $repo 'tests') -p 'test_windows_identity_proxy_c_dns_candidate.py' -v
if($LASTEXITCODE -ne 0){throw 'DNS pure failed'}

python -I -S -B -m unittest discover -s (Join-Path $repo 'tests') -p 'test_windows_identity_proxy_c_raw_udp_candidate.py' -v
if($LASTEXITCODE -ne 0){throw 'raw UDP pure failed'}
