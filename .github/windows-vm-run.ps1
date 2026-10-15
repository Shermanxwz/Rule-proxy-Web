# Local guest execution. It enables no Windows remote service and changes no
# host proxy, DNS, route or firewall. All guest-to-host HTTP uses QEMU's private
# user network and a per-run capability URL bound to host loopback.
$ErrorActionPreference = 'Stop'
$utf8 = New-Object Text.UTF8Encoding($false)
$configuration = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'ruleproxy-vm-config.json') -Raw | ConvertFrom-Json
$result = @{ status = 'failed'; ordinary_user = $false; phases = @(); reports = @{}; logs = @{} }

function ConvertTo-UpdateSafeText([string]$Text, [int]$Limit = 400) {
    $value = $Text -replace '(?i)\bhttps?://[^\s]+', '[redacted-url]' -replace '(?i)[0-9a-f]{64}', '[redacted-token]' -replace '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', ' '
    return $value.Substring(0, [Math]::Min($Limit, $value.Length))
}

function ConvertTo-UpdateDiagnosticState($State) {
    # A bounded whitelist, never the manifest, URL or arbitrary nested fields.
    $safe = @{}
    foreach ($name in @('schema_version', 'target_build', 'target_ubr', 'actual_build', 'actual_ubr', 'attempts', 'reboot_count', 'dism_exit_code', 'error_line', 'downloaded_package_count', 'staged_package_count')) {
        $property = $State.PSObject.Properties[$name]
        if ($null -ne $property -and ($property.Value -is [int] -or $property.Value -is [long])) { $safe[$name] = $property.Value }
    }
    foreach ($name in @('completed', 'reboot_required', 'packages_verified', 'task_unregistered', 'installer_running')) {
        $property = $State.PSObject.Properties[$name]
        if ($null -ne $property -and $property.Value -is [bool]) { $safe[$name] = $property.Value }
    }
    foreach ($name in @('status', 'phase', 'error', 'error_type', 'error_detail')) {
        $property = $State.PSObject.Properties[$name]
        if ($null -ne $property -and $property.Value -is [string]) { $safe[$name] = ConvertTo-UpdateSafeText $property.Value }
    }
    return $safe
}

function Get-UpdateReadError($Record) {
    return @{ error_type = $Record.Exception.GetType().Name; error_code = [long]$Record.Exception.HResult }
}

function Get-UpdateFileFact([string]$Path, [switch]$Directory) {
    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return @{ status = 'reparse'; exists = $true } }
        if ([bool]$item.PSIsContainer -ne [bool]$Directory) { return @{ status = 'wrong_type'; exists = $true } }
        $fact = @{ status = 'present'; exists = $true }
        if (-not $Directory) { $fact.bytes = [long]$item.Length }
        return $fact
    } catch {
        $fact = Get-UpdateReadError $_
        $fact.status = if ($_.Exception -is [Management.Automation.ItemNotFoundException]) { 'missing' } else { 'unavailable' }
        $fact.exists = $null
        if ($fact.status -eq 'missing') { $fact.exists = $false }
        return $fact
    }
}

function Read-UpdateDiagnosticLog([string]$Path, $Fact) {
    if ($Fact.status -ne 'present') { return '' }
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try {
            $length = [int][Math]::Min($stream.Length, 131072)
            [void]$stream.Seek(-$length, [IO.SeekOrigin]::End)
            $buffer = New-Object byte[] $length
            $count = 0
            while ($count -lt $length) {
                $read = $stream.Read($buffer, $count, $length - $count)
                if ($read -eq 0) { break }
                $count += $read
            }
            $Fact.read_status, $Fact.bytes_read = 'read', $count
            $encoding = [Text.Encoding]::UTF8
            if ($count -ge 4 -and (($buffer[0] -eq 255 -and $buffer[1] -eq 254) -or ($buffer[1] -eq 0 -and $buffer[3] -eq 0))) { $encoding = [Text.Encoding]::Unicode }
            return ConvertTo-UpdateSafeText ($encoding.GetString($buffer, 0, $count)) 131072
        } finally { $stream.Dispose() }
    } catch {
        $Fact.read_status = 'unavailable'
        $Fact.read_error = Get-UpdateReadError $_
        return ''
    }
}

function Get-RuleProxyCIUpdateDiagnostics($Result) {
    # Read-only facts from this VM's fixed protected folder/task only.
    $directory = 'C:\RuleProxyCIUpdates'
    $diagnostic = @{ schema_version = 1; scope = 'disposable_vm_official_update'; files = @{};
        directory = (Get-UpdateFileFact $directory -Directory); task = @{} }
    foreach ($entry in @(@('state', 'update-state.json'), @('dism', 'dism.log'), @('worker', 'update-worker.log'))) {
        $diagnostic.files[$entry[0]] = Get-UpdateFileFact (Join-Path $directory $entry[1])
    }
    try {
        $os = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ([string]$os.CurrentBuildNumber -notmatch '^[0-9]{1,6}$' -or $null -eq $os.UBR) { throw 'Invalid current OS revision' }
        $diagnostic.os = @{ build = [int]$os.CurrentBuildNumber; ubr = [long]$os.UBR }
    } catch { $diagnostic.os = Get-UpdateReadError $_ }
    try {
        $task = Get-ScheduledTask -TaskName 'RuleProxyCI-InstallOfficialUpdate' -TaskPath '\' -ErrorAction Stop
        $info = Get-ScheduledTaskInfo -TaskName 'RuleProxyCI-InstallOfficialUpdate' -TaskPath '\' -ErrorAction Stop
        if ($task.State.ToString() -notin @('Unknown', 'Disabled', 'Queued', 'Ready', 'Running') -or
            -not ($info.LastTaskResult -is [int] -or $info.LastTaskResult -is [long] -or $info.LastTaskResult -is [uint32]) -or
            $info.LastRunTime -isnot [DateTime]) { throw 'Invalid task observation' }
        $diagnostic.task = @{ status = 'observed'; state = [string]$task.State;
            last_run_utc = $info.LastRunTime.ToUniversalTime().ToString('o'); last_task_result = [long]$info.LastTaskResult }
    } catch {
        $diagnostic.task = Get-UpdateReadError $_
        $diagnostic.task.status = 'unavailable'
    }
    $logs = @()
    foreach ($entry in @(@('dism', 'dism.log'), @('worker', 'update-worker.log'))) {
        $text = Read-UpdateDiagnosticLog (Join-Path $directory $entry[1]) $diagnostic.files[$entry[0]]
        if ($text) { $logs += ('[' + $entry[0] + "]`n" + $text) }
    }
    if ($logs.Count) { $Result.logs['windows_update'] = $logs -join "`n" }
    $Result.windows_update_diagnostics = $diagnostic
}

function Invoke-LocalProgram([string] $Executable, [string[]] $Arguments, [string] $Log, [int] $TimeoutSeconds) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = ($Arguments | ForEach-Object { '"' + $_.Replace('"', '\"') + '"' }) -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $start.StandardOutputEncoding = $utf8
    $start.StandardErrorEncoding = $utf8
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'Could not create the project test process' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            # The supervisor bounds each real test separately. This outer
            # budget handles supervisor failure; only its held process is
            # stopped, and the disposable VM is then shut down.
            $process.Kill()
            if (-not $process.WaitForExit(10000)) { throw 'Timed-out supervisor did not exit after termination' }
            throw 'Guest phase supervisor exceeded its total budget; its owned interpreter was stopped'
        }
        $text = $stdout.Result + "`r`nSTDERR:`r`n" + $stderr.Result
        [IO.File]::WriteAllText($Log, $text, $utf8)
        return $process.ExitCode
    } finally {
        $process.Dispose()
    }
}

try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Acceptance must run through an ordinary non-administrator login'
    }
    $result.ordinary_user = $true
    $result.user = $identity.Name
    $result.os = (Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture)
    if ($configuration.require_official_update) {
        $statePath = 'C:\RuleProxyCIUpdates\update-state.json'
        $updateDeadline = [DateTime]::UtcNow.AddMinutes(90)
        do {
            if (Test-Path -LiteralPath $statePath) {
                if ((Get-Item -LiteralPath $statePath).Length -gt 65536) { throw 'Windows update state exceeded its size limit' }
                $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
                $result.official_update_last_state = ConvertTo-UpdateDiagnosticState $state
                if ($state.status -eq 'failed') {
                    $result.official_update = $state
                    throw ('Official update failed: ' + [string] $state.error)
                }
                if ($state.status -eq 'completed' -and $state.completed -eq $true) {
                    $actual = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
                    if ([int] $actual.CurrentBuildNumber -ne [int] $configuration.update_build -or [int] $actual.UBR -lt [int] $configuration.update_ubr -or [int] $state.actual_build -ne [int] $configuration.update_build -or [int] $state.actual_ubr -lt [int] $configuration.update_ubr -or $state.packages_verified -ne $true -or $state.task_unregistered -ne $true) {
                        throw 'Official update state did not match the running Windows build/revision'
                    }
                    $result.official_update = $state
                    break
                }
            }
            if ([DateTime]::UtcNow -ge $updateDeadline) { throw 'Official cumulative update did not complete before the ordinary-user test deadline' }
            Start-Sleep -Seconds 5
        } while ($true)
    }
    $url = $configuration.host_url
    $deadline = [DateTime]::UtcNow.AddMinutes(5)
    $payload = Join-Path $PSScriptRoot 'payload.zip'
    do {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri ($url + '/payload.zip') -OutFile $payload -TimeoutSec 30
            break
        } catch {
            if ([DateTime]::UtcNow -ge $deadline) { throw }
            Start-Sleep -Seconds 5
        }
    } while ($true)
    if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.payload_sha256) {
        throw 'Local test payload checksum mismatch'
    }
    $workspace = Join-Path $PSScriptRoot 'payload'
    Expand-Archive -LiteralPath $payload -DestinationPath $workspace -Force
    $packageZip = Join-Path $workspace 'package.zip'
    if ((Get-FileHash -LiteralPath $packageZip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.package_sha256) {
        throw 'Release package checksum mismatch'
    }
    # Exercise the release in a Unicode/space path while keeping the top-level
    # folder ASCII, which avoids MXC 1.0.0's optional PLM path bug.
    $packageDirectory = Join-Path $PSScriptRoot '应用 测试'
    Expand-Archive -LiteralPath $packageZip -DestinationPath $packageDirectory -Force
    $package = Join-Path $packageDirectory 'RuleProxy-Web'
    $python = Join-Path $package 'python\python.exe'
    $supervisor = Join-Path $workspace '.github\windows_vm_test.py'
    $report = Join-Path $PSScriptRoot 'guest-phases.json'
    $log = Join-Path $PSScriptRoot 'supervisor.log'
    if (Test-Path -LiteralPath $report) { Remove-Item -LiteralPath $report -Force }
    $configurationPath = Join-Path $PSScriptRoot 'ruleproxy-vm-config.json'
    $code = Invoke-LocalProgram $python @('-X', 'utf8', '-B', $supervisor, '--guest-phases', '--root', $package, '--workspace', $workspace, '--vm-config', $configurationPath, '--report', $report) $log 4800
    if (-not (Test-Path -LiteralPath $report)) { throw 'Guest supervisor returned no report' }
    if ((Get-Item -LiteralPath $report).Length -gt 4194304) { throw 'Guest supervisor report exceeded its size limit' }
    $collected = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
    # Load failed reports too. A completed strict probe allows independent
    # fixtures, while retained cleanup errors block new contained launches.
    $result.phases = @($collected.phases)
    foreach ($name in @('gui_diagnostic_only', 'source_diagnostic_only', 'full_acceptance_passed', 'product_acceptance_passed', 'execution_mode', 'product_runtime_replaced')) {
        if ($collected.PSObject.Properties.Name -contains $name) { $result[$name] = $collected.$name }
    }
    if ($collected.experiments_phase) { $result.experiments_phase = $collected.experiments_phase }
    if ($collected.edge_ui_phase) { $result.edge_ui_phase = $collected.edge_ui_phase }
    if ($collected.outside_edge_phase) { $result.outside_edge_phase = $collected.outside_edge_phase }
    $result.recovery_records = @($collected.recovery_records)
    foreach ($property in $collected.reports.PSObject.Properties) { $result.reports[$property.Name] = $property.Value }
    foreach ($property in $collected.logs.PSObject.Properties) { $result.logs[$property.Name] = $property.Value }
    $result.logs['supervisor'] = [IO.File]::ReadAllText($log)
    if ($code -eq 0 -and $collected.status -eq 'passed') {
        $result.status = 'passed'
    } else {
        $result.error = [string] $collected.error
        if (-not $result.error) { $result.error = 'Guest phase supervisor failed, exit ' + $code }
    }
} catch {
    $result.status = 'failed'
    $result.error = $_.Exception.Message
} finally {
    try { Get-RuleProxyCIUpdateDiagnostics $result } catch { $result.windows_update_diagnostics = Get-UpdateReadError $_ }
    $body = $result | ConvertTo-Json -Depth 40 -Compress
    [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'guest-result.json'), $body, $utf8)
    $delivered = $false
    for ($attempt = 0; $attempt -lt 6; $attempt++) {
        try {
            Invoke-WebRequest -UseBasicParsing -Uri ($configuration.host_url + '/result') -Method Post -ContentType 'application/json' -Body $utf8.GetBytes($body) -TimeoutSec 30 | Out-Null
            $delivered = $true
            break
        } catch {
            Start-Sleep -Seconds 5
        }
    }
    if ($delivered) { & shutdown.exe /s /t 0 }
}
