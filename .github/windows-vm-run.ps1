# Local guest execution. It enables no Windows remote service and changes no
# host proxy, DNS, route or firewall. All guest-to-host HTTP uses QEMU's private
# user network and a per-run capability URL bound to host loopback.
$ErrorActionPreference = 'Stop'
$utf8 = New-Object Text.UTF8Encoding($false)
$configuration = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'ruleproxy-vm-config.json') -Raw | ConvertFrom-Json
$result = @{ status = 'failed'; ordinary_user = $false; phases = @(); reports = @{}; logs = @{} }

function Invoke-LocalProgram([string] $Executable, [string[]] $Arguments, [string] $Log) {
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
        if (-not $process.WaitForExit(900000)) {
            # Kill only the test interpreter retained by this Process object.
            # Any contained descendants remain in the disposable VM; the
            # timeout is a hard failure, and no subsequent phase will start.
            try {
                $process.Kill()
                $process.WaitForExit(10000) | Out-Null
            } finally {
                throw 'Project test process exceeded 15 minutes; its owned interpreter was stopped'
            }
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
    $acceptance = Join-Path $workspace 'scripts\windows-acceptance.py'
    foreach ($phase in @('probe', 'transport')) {
        $report = Join-Path $PSScriptRoot ($phase + '.json')
        $log = Join-Path $PSScriptRoot ($phase + '.log')
        $option = if ($phase -eq 'probe') { '--probe-only' } else { '--transport-fixture' }
        $code = Invoke-LocalProgram $python @('-X', 'utf8', '-B', $acceptance, '--root', $package, $option, '--report', $report) $log
        $result.phases += @{ name = $phase; exit_code = $code }
        $result.logs[$phase] = [IO.File]::ReadAllText($log)
        if (Test-Path -LiteralPath $report) { $result.reports[$phase] = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json }
        if ($code -ne 0) { throw ('Real Windows acceptance phase failed: ' + $phase + ', exit ' + $code) }
    }
    $browser = Join-Path $workspace '.github\windows_browser_check.py'
    $report = Join-Path $PSScriptRoot 'browser.json'
    $log = Join-Path $PSScriptRoot 'browser.log'
    $code = Invoke-LocalProgram $python @('-X', 'utf8', '-B', $browser, '--root', $package, '--report', $report) $log
    $result.phases += @{ name = 'browser'; exit_code = $code }
    $result.logs['browser'] = [IO.File]::ReadAllText($log)
    if (Test-Path -LiteralPath $report) { $result.reports['browser'] = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json }
    if ($code -ne 0) { throw ('Native Windows Edge fixture failed, exit ' + $code) }
    $runner = Join-Path $workspace '.github\run_tests.py'
    $log = Join-Path $PSScriptRoot 'tests.log'
    $code = Invoke-LocalProgram $python @('-X', 'utf8', '-B', $runner, '--code', $package) $log
    $result.phases += @{ name = 'package_tests'; exit_code = $code }
    $result.logs['tests'] = [IO.File]::ReadAllText($log)
    if ($code -ne 0) { throw 'Release package unit/integration tests failed' }
    $result.status = 'passed'
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
