# Compile evidence only. Never install/load a driver or alter signing/boot policy.
param([string]$Evidence = (Join-Path $PSScriptRoot '..\..\ale-redirect-evidence'))
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or -not $env:RUNNER_TEMP) { throw 'Requires a disposable GitHub Actions runner' }
New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
$version = '10.0.26100.2454'
$target = if ($env:RUNNER_ARCH -eq 'ARM64') { 'ARM64' } else { 'x64' }
$defines = if ($target -eq 'ARM64') { '/D_ARM64_=1' } else { '/D_AMD64_=1' }
$compiler = if ($target -eq 'ARM64') { 'x64_arm64' } else { 'x64' }
$work = Join-Path $env:RUNNER_TEMP ('ruleproxy-ale-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
$source = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\native\windows\redirect_driver.c'))
$header = Join-Path (Split-Path $source) 'redirect_protocol.h'
$manifest = [ordered]@{
    source_commit = $env:GITHUB_SHA
    source_sha256 = (Get-FileHash $source -Algorithm SHA256).Hash.ToLower()
    header_sha256 = (Get-FileHash $header -Algorithm SHA256).Hash.ToLower()
    build_script_sha256 = (Get-FileHash $PSCommandPath -Algorithm SHA256).Hash.ToLower()
    architecture = $target
    wdk_version = $version
    packages = @()
    built = $false
    loaded = $false
    live_redirect_tested = $false
    accepted = $false
    product_backend_enabled = $false
    error = $null
}
try {
    # Microsoft's version-pinned, repository-signed NuGet WDK and its SDK
    # dependency. Package hashes and signature verification are retained.
    $packages = Join-Path $work 'packages'
    & nuget.exe install "Microsoft.Windows.WDK.$target" -Version $version -Source 'https://api.nuget.org/v3/index.json' -NonInteractive -DirectDownload -OutputDirectory $packages -PackageSaveMode nupkg 2>&1 | Tee-Object (Join-Path $Evidence 'wdk-restore.txt')
    if ($LASTEXITCODE -ne 0) { throw "WDK restore failed: $LASTEXITCODE" }
    $receipts = @()
    foreach ($archive in Get-ChildItem -LiteralPath $packages -Recurse -File -Filter '*.nupkg') {
        & nuget.exe verify -Signatures $archive.FullName 2>&1 | Tee-Object -Append (Join-Path $Evidence 'wdk-signatures.txt')
        if ($LASTEXITCODE -ne 0) { throw "NuGet signature verification failed: $($archive.Name)" }
        $receipts += [ordered]@{ name = $archive.Name; sha256 = (Get-FileHash $archive.FullName -Algorithm SHA256).Hash.ToLower() }
    }
    if (-not $receipts.Count) { throw 'No WDK package receipts were preserved' }
    $manifest.packages = $receipts
    $wdk = Join-Path $packages "Microsoft.Windows.WDK.$target.$version"
    $kmHeader = @(Get-ChildItem -LiteralPath $wdk -Recurse -File -Filter 'ntddk.h')
    $kmLibrary = @(Get-ChildItem -LiteralPath $wdk -Recurse -File -Filter 'ntoskrnl.lib' | Where-Object { $_.Directory.Name -ieq $target })
    $sharedHeader = @(Get-ChildItem -LiteralPath $packages -Recurse -File -Filter 'sdkddkver.h' | Where-Object { $_.Directory.Name -eq 'shared' })
    if ($kmHeader.Count -ne 1 -or $kmLibrary.Count -ne 1 -or $sharedHeader.Count -ne 1) { throw 'Unexpected WDK/SDK package layout' }
    $km = $kmHeader[0].Directory.FullName
    $shared = $sharedHeader[0].Directory.FullName
    $lib = $kmLibrary[0].Directory.FullName
    # The ARM64 WDK provides the fast-fail kernel GS library rather than the
    # legacy x64 BufferOverflowK name. Keep /GS and its GsDriverEntry wrapper.
    $gs = if (Test-Path (Join-Path $lib 'BufferOverflowFastFailK.lib')) { 'BufferOverflowFastFailK.lib' } elseif (Test-Path (Join-Path $lib 'BufferOverflowK.lib')) { 'BufferOverflowK.lib' } else { throw 'No kernel GS support library is available' }
    $manifest.gs_library = $gs
    $armRuntime = if ($target -eq 'ARM64') {
        $runtime = @(Get-ChildItem -LiteralPath $packages -Recurse -File -Filter 'arm64rt.lib' | Where-Object { $_.Directory.Name -ieq 'ARM64' })
        if ($runtime.Count -ne 1) { throw 'The pinned SDK/WDK ARM64 runtime library is missing or ambiguous' }
        $manifest.arm_runtime_package_path = $runtime[0].FullName.Substring($packages.Length + 1)
        '"' + $runtime[0].FullName + '"'
    } else { '' }
    $manifest.arm_runtime_library = $armRuntime
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    $vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw 'Visual C++ build tools are unavailable' }
    $vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvarsall.bat'
    $output = Join-Path $Evidence 'ruleproxy-ale-redirect.sys'
    $output = [IO.Path]::GetFullPath($output)
    $line = 'call "' + $vcvars + '" ' + $compiler + ' && cl /nologo /TC /kernel /W4 /WX /GS /Zl /O2 ' + $defines + ' /DNDIS630=1 /DUNICODE /D_UNICODE /D_WIN32_WINNT=0x0A00 /DNTDDI_VERSION=0x0A00000B /I"' + $km + '" /I"' + $km + '\crt" /I"' + $shared + '" /c "' + $source + '" /Fo:redirect_driver.obj && link /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:GsDriverEntry /INTEGRITYCHECK /RELEASE /NODEFAULTLIB /MACHINE:' + $target + ' /LIBPATH:"' + $lib + '" redirect_driver.obj ntoskrnl.lib hal.lib fwpkclnt.lib wdmsec.lib ' + $gs + ' ' + $armRuntime + ' /OUT:"' + $output + '"'
    Push-Location $work
    try {
        & cmd.exe /d /s /c $line 2>&1 | Tee-Object -FilePath (Join-Path $Evidence 'build.txt')
        if ($LASTEXITCODE -ne 0) { throw "ALE redirect driver build failed: $LASTEXITCODE" }
    } finally { Pop-Location }
    $manifest.built = $true
    $signature = Get-AuthenticodeSignature -LiteralPath $output
    $manifest.binary_sha256 = (Get-FileHash $output -Algorithm SHA256).Hash.ToLower()
    $manifest.signature_status = $signature.Status.ToString()
} catch {
    $manifest.error = $_.Exception.Message
    throw
} finally {
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $Evidence 'build-provenance.json') -Encoding utf8
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
exit 0
