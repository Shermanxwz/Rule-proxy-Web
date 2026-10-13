# Compile a user-mode Windows SDK experiment; no kernel driver is built/loaded.
param(
    [string]$Output = (Join-Path $env:RUNNER_TEMP 'ruleproxy-wfp-native-lab.exe'),
    [string]$Evidence = (Join-Path $PSScriptRoot '..\..\native-wfp-evidence')
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or -not $env:RUNNER_TEMP) { throw 'Requires a disposable GitHub Actions runner' }
New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vs) { throw 'Visual C++ build tools are unavailable' }
$architecture = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'x64_arm64' } else { 'x64' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
$source = Join-Path $PSScriptRoot 'wfp_native_lab.cpp'
$output = [IO.Path]::GetFullPath($Output)
$build = Join-Path $env:RUNNER_TEMP ('ruleproxy-wfp-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $build | Out-Null
try {
    # All paths are locally determined and quoted. Compile with static CRT so
    # copied synthetic probes have no deployment/runtime dependency.
    $line = 'call "' + $vcvars + '" ' + $architecture + ' && cl /nologo /std:c++17 /W4 /WX /EHsc /MT /DUNICODE /D_UNICODE "' + $source + '" /Fe:"' + $output + '" /link fwpuclnt.lib rpcrt4.lib ws2_32.lib uuid.lib advapi32.lib'
    Push-Location $build
    try {
        & cmd.exe /d /s /c $line 2>&1 | Tee-Object -FilePath (Join-Path $Evidence 'build.txt')
        if ($LASTEXITCODE -ne 0) { throw "Native lab build failed: $LASTEXITCODE" }
    }
    finally { Pop-Location }
    Write-Output "Built native WFP lab for $architecture : $output"
} finally { Remove-Item -LiteralPath $build -Recurse -Force -ErrorAction SilentlyContinue }
exit 0
