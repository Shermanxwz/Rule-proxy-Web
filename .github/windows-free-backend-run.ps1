# Ordinary-user interactive probe only. The desktop process is never launched
# by the SYSTEM installer task. This entrypoint runs from the disposable VM's
# per-user Startup folder after the verified CU/backend installation stages.
$ErrorActionPreference = 'Stop'
$utf8 = New-Object Text.UTF8Encoding($false)
$configuration = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'ruleproxy-vm-config.json') -Raw | ConvertFrom-Json
$result = @{ schema_version = 1; status = 'failed'; diagnostic_only = $true;
    product_acceptance_passed = $false; backend = [string]$configuration.free_backend;
    ordinary_user = $false; is_elevated = $null; is_administrator = $null;
    phases = @(); reports = @{}; logs = @{}; capture = $null }
$reportPath = Join-Path $PSScriptRoot 'results\free-backend-probe.json'
$installReportPath = Join-Path $PSScriptRoot 'free-backend-install.json'
$installStatePath = Join-Path $PSScriptRoot 'free-backend-install-state.json'
$updateStatePath = 'C:\RuleProxyCIUpdates\update-state.json'
$bundle = Join-Path $PSScriptRoot 'bundle'
$artifacts = Join-Path $PSScriptRoot 'artifacts'
$captureStarted = $false

function Get-UpdateSafeError($Record) {
    return @{ type = $Record.Exception.GetType().Name; code = [long]$Record.Exception.HResult }
}
function Write-GuestResult($Value) {
    $body = $Value | ConvertTo-Json -Depth 20 -Compress
    if ([Text.Encoding]::UTF8.GetByteCount($body) -gt 2097152) { throw 'Guest result exceeded its bound' }
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'results\guest-result.json'), $body, $utf8)
    $delivered = $false
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri ($configuration.host_url + '/result') -Method Post `
                -ContentType 'application/json' -Body $utf8.GetBytes($body) -TimeoutSec 30 | Out-Null
            $delivered = $true
            break
        } catch { Start-Sleep -Seconds 5 }
    }
    if (-not $delivered) { throw 'Could not return the bounded guest result' }
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $result.ordinary_user = ($identity.Name -match '\\RuleProxyCI$' -and -not $admin -and
        $identity.User.Value -match '^S-1-5-21-[0-9-]+$')
    $result.is_elevated = [bool]$identity.IsSystem
    $result.is_administrator = [bool]$admin
    if (-not $result.ordinary_user -or $result.is_elevated) { throw 'Probe did not run as the expected ordinary interactive user' }
    $deadline = [DateTime]::UtcNow.AddMinutes(100)
    do {
        if ((Test-Path -LiteralPath $updateStatePath) -and (Test-Path -LiteralPath $installStatePath)) {
            $update = Get-Content -LiteralPath $updateStatePath -Raw | ConvertFrom-Json
            $install = Get-Content -LiteralPath $installStatePath -Raw | ConvertFrom-Json
            if ($update.status -eq 'failed' -or $install.status -eq 'failed') { throw 'Verified setup task reported failure' }
            if ($update.status -eq 'completed' -and $install.status -eq 'completed') { break }
        }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Official update/backend install did not finish before the user probe deadline' }
        Start-Sleep -Seconds 5
    } while ($true)
    # The autologon can happen on the original ISO build before servicing has
    # started. Wait for both SYSTEM tasks, then attest the post-update/reboot OS.
    $os = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $result.windows_build = [int]$os.CurrentBuildNumber
    $result.windows_ubr = [int]$os.UBR
    if ($result.windows_build -ne [int]$configuration.update_build -or $result.windows_ubr -lt [int]$configuration.update_ubr) {
        throw 'Native guest is not at the fixed target Windows build/revision'
    }
    if (-not (Test-Path -LiteralPath $installReportPath) -or (Get-Item -LiteralPath $installReportPath).Length -gt 65536) {
        throw 'Bounded SYSTEM install report is missing'
    }
    $installReport = Get-Content -LiteralPath $installReportPath -Raw | ConvertFrom-Json
    if ($installReport.schema_version -ne 1 -or $installReport.backend -ne $configuration.free_backend -or
        $installReport.phase -ne 'install' -or $installReport.status -ne 'passed' -or
        $installReport.reboot_required -isnot [bool]) { throw 'SYSTEM install report is invalid' }
    $result.reports.install = $installReport
    $result.install_state = @{ status = [string]$install.status; reboot_count = [int]$install.reboot_count;
        reboot_observed = [bool]$install.reboot_observed }

    New-Item -ItemType Directory -Path $artifacts -Force | Out-Null
    $control = Join-Path $bundle ("scripts\windows_{0}_control.py" -f $configuration.free_backend)
    $python = Join-Path $bundle 'python\python.exe'
    $manifest = Join-Path $bundle 'manifest.json'
    foreach ($path in @($control, $python, $manifest)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'Pinned backend control files are incomplete' }
    }

    # Capture begins only when update and backend setup are complete and the
    # interactive ordinary-user probe is about to run. Raw PCAP stays in the
    # host artifact directory; no PSEC-specific interpretation is asserted.
    $body = $utf8.GetBytes('{}')
    Invoke-WebRequest -UseBasicParsing -Uri ($configuration.host_url + '/capture/start') -Method Post `
        -ContentType 'application/json' -Body $body -TimeoutSec 15 | Out-Null
    $captureStarted = $true
    $probeArgs = @('-B', $control, '--phase', 'probe', '--bundle', $bundle, '--manifest', $manifest,
        '--report', $reportPath, '--install-report', $installReportPath, '--artifacts', $artifacts)
    # Bound a blocked driver/service call without waiting for the whole VM budget.
    $quotedProbeArgs = $probeArgs | ForEach-Object { '"' + ([string]$_).Replace('"', '\"') + '"' }
    $probeProcess = Start-Process -FilePath $python -ArgumentList $quotedProbeArgs -PassThru `
        -RedirectStandardOutput (Join-Path $artifacts 'free-backend-probe.stdout.log') `
        -RedirectStandardError (Join-Path $artifacts 'free-backend-probe.stderr.log')
    if (-not $probeProcess.WaitForExit(900000)) {
        $probeProcess.Kill()
        $probeProcess.WaitForExit()
        throw 'Backend probe exceeded its bounded fifteen minute execution window'
    }
    $probeExit = $probeProcess.ExitCode
    if (-not (Test-Path -LiteralPath $reportPath) -or (Get-Item -LiteralPath $reportPath).Length -gt 262144) {
        throw 'Backend probe returned no bounded report'
    }
    $probe = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if ($probe.schema_version -ne 1 -or $probe.backend -ne $configuration.free_backend -or
        $probe.phase -ne 'probe' -or $probe.status -notin @('passed', 'failed') -or
        $probe.ordinary_user -ne $true -or $probe.is_elevated -ne $false -or
        $probe.is_administrator -ne $false -or $probe.windows_build -ne $result.windows_build -or
        $probe.windows_ubr -ne $result.windows_ubr) { throw 'Ordinary-user backend probe report failed strict identity/schema checks' }
    $result.reports.probe = $probe
    $result.probe_exit_code = [int]$probeExit
    $result.phases += @{ name = 'install'; status = 'passed'; identity = 'system_setup'; reboot_observed = [bool]$install.reboot_observed }
    $result.phases += @{ name = 'ordinary_user_probe'; status = if ($probeExit -eq 0 -and $probe.status -eq 'passed') { 'passed' } else { 'failed' }; identity = 'RuleProxyCI' }
    if ($probeExit -ne 0 -or $probe.status -ne 'passed') { throw 'Ordinary-user backend probe failed' }
    $result.status = 'passed'
} catch {
    $result.status = 'failed'
    $result.error = Get-UpdateSafeError $_
} finally {
    # Preserve setup failures as observations even if a later strict gate fails.
    foreach ($stateItem in @(@('install_state', $installStatePath), @('update_state', $updateStatePath))) {
        try {
            if ((Test-Path -LiteralPath $stateItem[1]) -and (Get-Item -LiteralPath $stateItem[1]).Length -le 65536) {
                $result[$stateItem[0]] = Get-Content -LiteralPath $stateItem[1] -Raw | ConvertFrom-Json
            }
        } catch { }
    }
    foreach ($reportItem in @(@('install', $installReportPath), @('probe', $reportPath))) {
        try {
            if ((Test-Path -LiteralPath $reportItem[1]) -and (Get-Item -LiteralPath $reportItem[1]).Length -le 262144) {
                $result.reports[$reportItem[0]] = Get-Content -LiteralPath $reportItem[1] -Raw | ConvertFrom-Json
            }
        } catch { }
    }
    foreach ($logPath in @((Join-Path $PSScriptRoot 'free-backend-install.log'),
                          (Join-Path $artifacts 'free-backend-probe.stderr.log'))) {
        try {
            if ((Test-Path -LiteralPath $logPath) -and (Get-Item -LiteralPath $logPath).Length -le 32768) {
                $result.logs[[IO.Path]::GetFileName($logPath)] = [IO.File]::ReadAllText($logPath)
            }
        } catch { }
    }
    if ($captureStarted) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri ($configuration.host_url + '/capture/finish') -Method Post `
                -ContentType 'application/json' -Body $utf8.GetBytes('{"probe_window_finished":true}') -TimeoutSec 15 | Out-Null
            $result.capture = @{ status = 'stopped'; scope = 'qemu_vm_nic_probe_window_only' }
        } catch { $result.capture = @{ status = 'failed'; scope = 'qemu_vm_nic_probe_window_only'; error = Get-UpdateSafeError $_ }; $result.status = 'failed' }
    } else { $result.capture = @{ status = 'not_started'; scope = 'qemu_vm_nic_probe_window_only' } }
    try { Write-GuestResult $result } catch { }
    & shutdown.exe /s /t 0 | Out-Null
}
