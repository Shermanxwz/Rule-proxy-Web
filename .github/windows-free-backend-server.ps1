# Fast Windows Server ordinary-user diagnostic for the pinned free-backend
# bundles. This is a disposable hosted-runner control, never product setup.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('sandboxie', 'proxybridge')]
    [string]$Backend,
    [Parameter(Mandatory = $true)]
    [string]$BundleZip,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$root = 'C:\RuleProxyCI'
$results = Join-Path $root 'results'
$artifacts = Join-Path $root 'artifacts'
$installReport = Join-Path $root 'install-report.json'
$installLog = Join-Path $results 'install.log'
$statePath = Join-Path $OutputDirectory 'server-probe-state.json'
$utf8 = New-Object Text.UTF8Encoding($false)
$runtimeDiagnostics = New-Object Collections.Generic.List[object]

function Test-PythonLaunch([string]$Stage, [bool]$Redirect) {
    $row = [ordered]@{ stage = $Stage; redirect = $Redirect; started = $false; paths = @() }
    foreach ($path in @($root, $bundleRoot, (Split-Path $python), $python, $results)) {
        $item = Get-Item -LiteralPath $path -Force
        $row.paths += @{ path = $path; attributes = [string]$item.Attributes;
            sddl = (Get-Acl -LiteralPath $path).Sddl }
    }
    $row.python_size = (Get-Item -LiteralPath $python).Length
    $row.python_sha256 = (Get-FileHash -LiteralPath $python -Algorithm SHA256).Hash.ToLowerInvariant()
    $process = New-Object Diagnostics.Process
    $process.StartInfo.FileName = $python
    $process.StartInfo.Arguments = '--version'
    $process.StartInfo.WorkingDirectory = $root
    $process.StartInfo.UseShellExecute = $false
    $process.StartInfo.RedirectStandardOutput = $Redirect
    $process.StartInfo.RedirectStandardError = $Redirect
    try {
        $row.started = $process.Start()
        if (-not $process.WaitForExit(15000)) {
            $process.Kill()
            $process.WaitForExit()
            $row.timeout = $true
        } else {
            $row.exit_code = $process.ExitCode
        }
        if ($Redirect) {
            $row.stdout = $process.StandardOutput.ReadToEnd().Trim()
            $row.stderr = $process.StandardError.ReadToEnd().Trim()
        }
    } catch {
        $row.errors = @()
        $exception = $_.Exception
        while ($null -ne $exception) {
            $row.errors += @{ type = $exception.GetType().FullName; hresult = $exception.HResult;
                native_error = $exception.NativeErrorCode; message = $exception.Message.Substring(0, [Math]::Min(800, $exception.Message.Length)) }
            $exception = $exception.InnerException
        }
    } finally {
        $process.Dispose()
        $runtimeDiagnostics.Add($row)
        [IO.File]::WriteAllText((Join-Path $OutputDirectory 'runtime-launch-diagnostics.json'),
            (ConvertTo-Json -InputObject $runtimeDiagnostics.ToArray() -Depth 10), $utf8)
    }
}

function Write-State([string]$Status, [string]$Code) {
    $value = [ordered]@{ schema_version = 1; backend = $Backend; status = $Status;
        failure_code = $Code; server_os = [Environment]::OSVersion.VersionString;
        new_logon_satisfies_group_refresh = [bool]$script:newLogonSatisfiesGroupRefresh;
        diagnostic_only = $true; windows_11_verified = $false; product_acceptance_passed = $false }
    $tmp = $statePath + '.tmp'
    [IO.File]::WriteAllText($tmp, ($value | ConvertTo-Json -Compress), $utf8)
    Move-Item -LiteralPath $tmp -Destination $statePath -Force
}

function Protect-Directories {
    New-Item -ItemType Directory -Path $results, $artifacts -Force | Out-Null
    $null = & icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T /C
    if ($LASTEXITCODE -ne 0) { throw 'trusted_root_acl_failed' }
    foreach ($directory in @($results, $artifacts)) {
        $null = & icacls.exe $directory /grant '*S-1-5-32-545:(OI)(CI)M' /T /C
        if ($LASTEXITCODE -ne 0) { throw 'output_acl_failed' }
    }
}

$createdUser = $false
$script:newLogonSatisfiesGroupRefresh = $false
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'installer_stage_not_elevated'
    }
    if (Test-Path -LiteralPath $root) { throw 'disposable_server_root_already_exists' }
    if (-not (Test-Path -LiteralPath $BundleZip -PathType Leaf)) { throw 'bundle_zip_missing' }

    New-Item -ItemType Directory -Path $root, $results, $artifacts -Force | Out-Null
    $bundleRoot = Join-Path $root 'bundle'
    Expand-Archive -LiteralPath $BundleZip -DestinationPath $bundleRoot -Force
    $manifest = Join-Path $bundleRoot 'manifest.json'
    $python = Join-Path $bundleRoot 'python\python.exe'
    $control = Join-Path $bundleRoot "scripts\windows_${Backend}_control.py"
    $probe = Join-Path $root 'windows_free_backend_server_probe.py'
    $probeSource = Join-Path $PSScriptRoot 'windows_free_backend_server_probe.py'
    if (-not (Test-Path $manifest -PathType Leaf) -or -not (Test-Path $python -PathType Leaf) -or
        -not (Test-Path $control -PathType Leaf) -or -not (Test-Path $probeSource -PathType Leaf)) {
        throw 'fixed_bundle_or_server_probe_helper_missing'
    }
    Copy-Item -LiteralPath $probeSource -Destination $probe
    Test-PythonLaunch 'before_acl' $false
    Test-PythonLaunch 'before_acl' $true

    if (Get-LocalUser -Name 'RuleProxyCI' -ErrorAction SilentlyContinue) { throw 'probe_account_already_exists' }
    $passwordText = ([guid]::NewGuid().ToString('N') + 'Q7!')
    $password = ConvertTo-SecureString $passwordText -AsPlainText -Force
    New-LocalUser -Name 'RuleProxyCI' -Password $password -PasswordNeverExpires -UserMayNotChangePassword | Out-Null
    $createdUser = $true
    $sid = (Get-LocalUser -Name 'RuleProxyCI').SID.Value
    if ($sid -notmatch '^S-1-5-21-[0-9-]+$') { throw 'probe_account_sid_invalid' }
    $users = Get-LocalGroupMember -Group 'Users' | ForEach-Object { $_.SID.Value }
    if ($sid -notin $users) { Add-LocalGroupMember -Group 'Users' -Member 'RuleProxyCI' }
    $users = Get-LocalGroupMember -Group 'Users' | ForEach-Object { $_.SID.Value }
    if ($sid -notin $users) { throw 'probe_account_not_standard_user' }

    Protect-Directories
    Test-PythonLaunch 'after_acl' $false
    Test-PythonLaunch 'after_acl' $true
    $installerArgs = @('-B', $control, '--phase', 'install', '--bundle', $bundleRoot,
        '--manifest', $manifest, '--report', $installReport,
        '--probe-user', 'RuleProxyCI', '--probe-user-sid', $sid)
    $installerProcess = Start-Process -FilePath $python -ArgumentList $installerArgs -PassThru `
        -RedirectStandardOutput $installLog -RedirectStandardError (Join-Path $results 'install.stderr.log')
    if (-not $installerProcess.WaitForExit(600000)) {
        $installerProcess.Kill()
        $installerProcess.WaitForExit()
        throw 'installer_phase_timeout'
    }
    $installExit = $installerProcess.ExitCode
    if ($installExit -ne 0 -or -not (Test-Path -LiteralPath $installReport -PathType Leaf)) {
        Write-State 'failed' 'installer_phase_failed'
        throw 'backend_installer_phase_failed'
    }
    if ((Get-Item -LiteralPath $installReport).Length -gt 65536) { throw 'install_report_oversized' }
    $install = Get-Content -LiteralPath $installReport -Raw | ConvertFrom-Json
    if ($install.schema_version -ne 1 -or $install.backend -ne $Backend -or $install.phase -ne 'install' -or
        $install.status -ne 'passed' -or $install.ordinary_user -ne $false -or
        $install.is_elevated -ne $true -or $install.target_user_authorized -ne $true -or
        $install.driver_signature.status -ne 'Valid' -or $install.service_install.exists -ne $true -or
        $install.reboot_required -isnot [bool]) {
        Write-State 'failed' 'installer_report_gate_failed'
        throw 'backend_installer_report_failed_validation'
    }
    if ($Backend -eq 'sandboxie' -and $install.reboot_required) {
        Write-State 'incomplete' 'installer_requires_reboot'
        throw 'server_runner_does_not_reboot_between_probe_phases'
    }
    if ($Backend -eq 'proxybridge' -and $install.reboot_required) {
        # ProxyBridge reports a fresh-logon requirement when it adds the probe
        # SID to its service group. Start-Process -Credential below creates a
        # new token after that change without rebooting the hosted runner.
        $script:newLogonSatisfiesGroupRefresh = $true
    }

    # The account receives a password only through a PSCredential object. It
    # is never written to logs, workflow output, reports, or process arguments.
    $credential = New-Object Management.Automation.PSCredential("$env:COMPUTERNAME\RuleProxyCI", $password)
    $probeReport = Join-Path $results 'probe-report.json'
    $stdout = Join-Path $results 'probe.stdout.log'
    $stderr = Join-Path $results 'probe.stderr.log'
    $probeArgs = @('-B', $probe, '--backend', $Backend)
    $process = Start-Process -FilePath $python -ArgumentList $probeArgs -Credential $credential `
        -LoadUserProfile -WorkingDirectory $artifacts -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr -PassThru
    $deadline = [DateTime]::UtcNow.AddMinutes(15)
    while (-not $process.HasExited -and [DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds 2
        $process.Refresh()
    }
    if (-not $process.HasExited) {
        try { Stop-Process -Id $process.Id -Force -ErrorAction Stop } catch { }
        Write-State 'failed' 'ordinary_user_probe_timeout'
        throw 'ordinary_user_probe_timeout'
    }
    $process.WaitForExit()
    $probeExit = $process.ExitCode
    if (Test-Path -LiteralPath $probeReport -PathType Leaf) {
        if ((Get-Item -LiteralPath $probeReport).Length -gt 2MB) { throw 'probe_report_oversized' }
        $probeValue = Get-Content -LiteralPath $probeReport -Raw | ConvertFrom-Json
        if ($probeValue.schema_version -ne 1 -or $probeValue.backend -ne $Backend -or
            $probeValue.phase -ne 'server_network_probe' -or $probeValue.ordinary_user -ne $true -or
            $probeValue.is_elevated -ne $false -or $probeValue.is_administrator -ne $false -or
            $probeValue.product_acceptance_passed -ne $false) {
            Write-State 'failed' 'ordinary_user_probe_report_gate_failed'
            throw 'ordinary_user_probe_report_failed_validation'
        }
    } else {
        Write-State 'failed' 'ordinary_user_probe_report_missing'
        throw 'ordinary_user_probe_report_missing'
    }
    if ($probeExit -ne 0 -or $probeValue.status -ne 'diagnostic_completed' -or $probeValue.cleanup_proven -ne $true) {
        Write-State 'failed' 'ordinary_user_probe_failed_or_unrecovered'
        throw 'ordinary_user_probe_failed_or_unrecovered'
    }
    Write-State 'diagnostic_completed' 'server_probe_finished'
} catch {
    if (-not (Test-Path -LiteralPath $statePath)) {
        $code = $_.Exception.Message
        if ($code -notmatch '^[a-z0-9_]+$') { $code = 'server_probe_failed' }
        try { Write-State 'failed' $code } catch { }
    }
    throw
} finally {
    foreach ($name in @('install.log', 'install.stderr.log', 'probe-report.json',
                        'probe.stdout.log', 'probe.stderr.log')) {
        $source = Join-Path $results $name
        if (Test-Path -LiteralPath $source -PathType Leaf) {
            try { Copy-Item -LiteralPath $source -Destination $OutputDirectory -Force } catch { }
        }
    }
    if (Test-Path -LiteralPath $installReport -PathType Leaf) {
        try { Copy-Item -LiteralPath $installReport -Destination $OutputDirectory -Force } catch { }
    }
    # Reports/state are uploaded by the workflow even on failure. Do not emit
    # credentials or arbitrary exception text to Actions logs.
    $passwordText = $null
    $password = $null
    $credential = $null
}
