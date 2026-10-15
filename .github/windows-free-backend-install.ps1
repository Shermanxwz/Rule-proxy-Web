# SYSTEM scheduled task in the disposable Windows VM. Never launches a GUI.
$ErrorActionPreference = 'Stop'
$root = 'C:\RuleProxyCI'
$statePath = Join-Path $root 'free-backend-install-state.json'
$reportPath = Join-Path $root 'free-backend-install.json'
$updateStatePath = 'C:\RuleProxyCIUpdates\update-state.json'
$utf8 = New-Object Text.UTF8Encoding($false)

function Write-State($Value) {
    $tmp = $statePath + '.tmp'
    [IO.File]::WriteAllText($tmp, ($Value | ConvertTo-Json -Depth 8 -Compress), $utf8)
    Move-Item -LiteralPath $tmp -Destination $statePath -Force
}
function Write-Failure([string]$Code) {
    Write-State @{ schema_version = 1; backend = $configuration.free_backend; status = 'failed';
        error_code = $Code; reboot_count = [int]$script:rebootCount }
}

$configuration = Get-Content -LiteralPath (Join-Path $root 'ruleproxy-vm-config.json') -Raw | ConvertFrom-Json
if ($configuration.free_backend -notin @('sandboxie', 'proxybridge')) { Write-Failure 'invalid_backend'; exit 2 }
$script:rebootCount = 0
if (Test-Path -LiteralPath $statePath) {
    try {
        $old = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
        if ($old.status -eq 'completed') { exit 0 }
        if ($old.status -eq 'reboot_pending' -and $old.reboot_count -eq 1) {
            $boot = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).LastBootUpTime
            if ([DateTime]$boot -le [DateTime]$old.install_time_utc) { Write-Failure 'reboot_not_observed'; exit 2 }
            $script:rebootCount = 1
            Write-State @{ schema_version = 1; backend = $configuration.free_backend; status = 'completed';
                reboot_count = 1; reboot_observed = $true; install_report_available = (Test-Path -LiteralPath $reportPath) }
            exit 0
        }
    } catch { Write-Failure 'install_state_invalid'; exit 2 }
}

$deadline = [DateTime]::UtcNow.AddMinutes(100)
$updateReady = $false
do {
    if (Test-Path -LiteralPath $updateStatePath) {
        try {
            $update = Get-Content -LiteralPath $updateStatePath -Raw | ConvertFrom-Json
            if ($update.status -eq 'failed') { Write-Failure 'official_update_failed'; exit 2 }
            if ($update.status -eq 'completed' -and $update.completed -eq $true -and
                $update.packages_verified -eq $true -and $update.task_unregistered -eq $true) {
                $os = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
                if ([int]$os.CurrentBuildNumber -ne [int]$configuration.update_build -or
                    [int]$os.UBR -lt [int]$configuration.update_ubr) { Write-Failure 'target_build_unverified'; exit 2 }
                $updateReady = $true
                break
            }
        } catch { Write-Failure 'official_update_state_invalid'; exit 2 }
    }
    if ([DateTime]::UtcNow -ge $deadline) { Write-Failure 'official_update_timeout'; exit 2 }
    Start-Sleep -Seconds 5
} while ($true)
if (-not $updateReady) { Write-Failure 'official_update_incomplete'; exit 2 }

try {
    $identity = New-Object Security.Principal.NTAccount("$env:COMPUTERNAME\RuleProxyCI")
    $probeSid = $identity.Translate([Security.Principal.SecurityIdentifier]).Value
    if ($probeSid -notmatch '^S-1-5-21-[0-9-]+$') { throw 'Invalid probe user SID' }
    $backendScript = Join-Path $root ("bundle\scripts\windows_{0}_control.py" -f $configuration.free_backend)
    $python = Join-Path $root 'bundle\python\python.exe'
    $manifest = Join-Path $root 'bundle\manifest.json'
    if (-not (Test-Path -LiteralPath $backendScript -PathType Leaf) -or
        -not (Test-Path -LiteralPath $python -PathType Leaf) -or
        -not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        throw 'Pinned guest backend paths are incomplete'
    }
    $args = @('-B', $backendScript, '--phase', 'install', '--bundle', (Join-Path $root 'bundle'),
              '--manifest', $manifest, '--report', $reportPath, '--probe-user', 'RuleProxyCI', '--probe-user-sid', $probeSid)
    & $python @args *> (Join-Path $root 'free-backend-install.log')
    $exit = $LASTEXITCODE
    if ($exit -ne 0 -or -not (Test-Path -LiteralPath $reportPath)) { throw 'Backend installer phase failed' }
    if ((Get-Item -LiteralPath $reportPath).Length -gt 65536) { throw 'Backend install report exceeded its bound' }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    if ($report.schema_version -ne 1 -or $report.backend -ne $configuration.free_backend -or
        $report.phase -ne 'install' -or $report.status -ne 'passed' -or
        $report.ordinary_user -ne $false -or $report.is_elevated -ne $true -or
        $report.reboot_required -isnot [bool]) { throw 'Backend install report did not satisfy its schema' }
    if ($report.reboot_required) {
        Write-State @{ schema_version = 1; backend = $configuration.free_backend; status = 'reboot_pending';
            reboot_count = 1; install_time_utc = [DateTime]::UtcNow.ToString('o'); install_report_available = $true }
        & shutdown.exe /r /t 5 /f
        if ($LASTEXITCODE -ne 0) { Write-Failure 'backend_reboot_failed'; exit 2 }
        exit 0
    }
    Write-State @{ schema_version = 1; backend = $configuration.free_backend; status = 'completed';
        reboot_count = 0; reboot_observed = $false; install_report_available = $true }
} catch {
    Write-Failure ('backend_install_' + $_.Exception.GetType().Name)
    exit 2
}
