# Local guest execution. It enables no Windows remote service and changes no
# host proxy, DNS, route or firewall. All guest-to-host HTTP uses QEMU's private
# user network and a per-run capability URL bound to host loopback.
$ErrorActionPreference = 'Stop'
$utf8 = New-Object Text.UTF8Encoding($false)
$configuration = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'ruleproxy-vm-config.json') -Raw | ConvertFrom-Json
$result = @{ status = 'failed'; ordinary_user = $false; phases = @(); reports = @{}; logs = @{} }

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
    $code = Invoke-LocalProgram $python @('-X', 'utf8', '-B', $supervisor, '--guest-phases', '--root', $package, '--workspace', $workspace, '--report', $report) $log 4200
    if (-not (Test-Path -LiteralPath $report)) { throw 'Guest supervisor returned no report' }
    if ((Get-Item -LiteralPath $report).Length -gt 4194304) { throw 'Guest supervisor report exceeded its size limit' }
    $collected = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
    # Load failed reports too. A completed strict probe allows independent
    # fixtures, while retained cleanup errors block new contained launches.
    $result.phases = @($collected.phases)
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
