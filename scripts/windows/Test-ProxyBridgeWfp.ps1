# Disposable Windows runner experiment, not a production installer or acceptance gate.
# Extract the pinned installer without executing its machine-wide NSIS actions.
param(
    [string]$Installer = (Join-Path $PSScriptRoot '..\..\bin\windows-candidate\ProxyBridge-Setup-4.1.1.exe'),
    [string]$Evidence = (Join-Path $PSScriptRoot '..\..\candidate-evidence')
)

$ErrorActionPreference = 'Stop'
$expectedHash = '754f45fb31f3953b9b81005090f9a479f89827adb628cf2c76bc4139f673a152'
$installer = [IO.Path]::GetFullPath($Installer)
$evidence = [IO.Path]::GetFullPath($Evidence)
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$report = [ordered]@{
    environment = 'GitHub-hosted Windows virtual machine; not a physical device'
    os = [Environment]::OSVersion.VersionString
    installer_sha256 = $null
    extracted_binary_sha256 = @{}
    firewall_profiles = @()
    baseline_direct_exit = $null
    no_wfp = @{}
    same_name_other = @{}
    with_wfp = @{}
    same_name_other_with_wfp = @{}
    after_cli_kill = @{}
    driver_before = ''
    driver_after = ''
    status = 'inconclusive'
    error = $null
}
$scratch = Join-Path $env:RUNNER_TEMP ('ruleproxy-pb-' + [guid]::NewGuid().ToString('N'))
$ruleName = 'RuleProxy-Disposable-Probe-' + [guid]::NewGuid().ToString('N')
$cli = $null
$witness = $null
$ruleAdded = $false
$driverWasAbsent = $false

function Invoke-Probe([string]$label, [string]$executable) {
    $out = Join-Path $evidence "$label.stdout.txt"
    $err = Join-Path $evidence "$label.stderr.txt"
    $p = Start-Process -FilePath $executable -ArgumentList @('--noproxy', '*', '--connect-timeout', '3', '--max-time', '6', '--silent', '--show-error', 'http://1.1.1.1/') -PassThru -Wait -RedirectStandardOutput $out -RedirectStandardError $err
    return [ordered]@{ exit = $p.ExitCode; stdout = (Get-Content -Raw -ErrorAction SilentlyContinue $out); stderr = (Get-Content -Raw -ErrorAction SilentlyContinue $err) }
}

function Witness-Count {
    if (-not (Test-Path $witnessLog)) { return 0 }
    return @(Get-Content $witnessLog).Count
}

try {
    if ((Get-FileHash -LiteralPath $installer -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
        throw 'Pinned ProxyBridge installer hash mismatch; no binary was run'
    }
    $report.installer_sha256 = $expectedHash
    $report.firewall_profiles = @(Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultOutboundAction)
    $report.driver_before = (& sc.exe query WinDivert 2>&1 | Out-String)
    $driverWasAbsent = $report.driver_before -match 'FAILED 1060'
    if (-not $driverWasAbsent) { throw 'WinDivert driver is present or cannot be inspected: refuse shared-runner experiment' }
    $sevenZip = 'C:\Program Files\7-Zip\7z.exe'
    if (-not (Test-Path $sevenZip)) { throw '7-Zip is unavailable on this Windows runner' }
    $curl = Join-Path $env:SystemRoot 'System32\curl.exe'
    if (-not (Test-Path $curl)) { throw 'Windows curl.exe is unavailable' }
    New-Item -ItemType Directory -Path $scratch -Force | Out-Null
    $extracted = Join-Path $scratch 'extracted'
    New-Item -ItemType Directory -Path $extracted | Out-Null
    & $sevenZip x -y "-o$extracted" $installer | Out-File (Join-Path $evidence 'extraction.txt')
    if ($LASTEXITCODE -ne 0) { throw "7-Zip extraction failed: $LASTEXITCODE" }
    $engine = Join-Path $scratch 'engine'
    New-Item -ItemType Directory -Path $engine | Out-Null
    foreach ($name in @('ProxyBridge_CLI.exe', 'ProxyBridgeCore.dll', 'WinDivert.dll', 'WinDivert64.sys')) {
        $matches = @(Get-ChildItem -Path $extracted -Recurse -File -Filter $name)
        if ($matches.Count -ne 1) { throw "Expected one $name in verified installer; found $($matches.Count)" }
        Copy-Item -LiteralPath $matches[0].FullName -Destination (Join-Path $engine $name)
        $report.extracted_binary_sha256[$name] = (Get-FileHash (Join-Path $engine $name) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $probe = Join-Path $scratch 'RuleProxyProbe.exe'
    Copy-Item -LiteralPath $curl -Destination $probe
    $otherFolder = Join-Path $scratch 'unrelated'
    New-Item -ItemType Directory -Path $otherFolder | Out-Null
    $otherProbe = Join-Path $otherFolder 'RuleProxyProbe.exe'
    Copy-Item -LiteralPath $curl -Destination $otherProbe
    $witnessLog = Join-Path $evidence 'socks-connect.jsonl'
    $portFile = Join-Path $scratch 'port.txt'
    $script = Join-Path $PSScriptRoot 'proxybridge_witness.py'
    $witness = Start-Process -FilePath (Get-Command python).Source -ArgumentList @('-B', $script, 'serve', $portFile, $witnessLog) -PassThru -RedirectStandardError (Join-Path $evidence 'witness.stderr.txt')
    for ($i = 0; $i -lt 50 -and -not (Test-Path $portFile); $i++) { Start-Sleep -Milliseconds 100 }
    if (-not (Test-Path $portFile)) { throw 'SOCKS witness did not become ready' }
    $port = [int](Get-Content -Raw $portFile)
    $profile = Join-Path $scratch 'probe.pbprofile'
    $env:PYTHONPATH = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    & python -B $script profile $profile $port $probe
    if ($LASTEXITCODE -ne 0) { throw 'Candidate profile compilation failed' }

    $report.baseline_direct_exit = (Invoke-Probe 'baseline-direct' $probe).exit
    $cli = Start-Process -FilePath (Join-Path $engine 'ProxyBridge_CLI.exe') -WorkingDirectory $engine -ArgumentList @('--profile', $profile, '--verbose', '3') -PassThru -RedirectStandardOutput (Join-Path $evidence 'proxybridge.stdout.txt') -RedirectStandardError (Join-Path $evidence 'proxybridge.stderr.txt')
    Start-Sleep -Seconds 3
    if ($cli.HasExited) { throw "ProxyBridge CLI exited during startup: $($cli.ExitCode)" }
    $before = Witness-Count
    $report.no_wfp = Invoke-Probe 'no-wfp' $probe
    Start-Sleep -Milliseconds 300
    $report.no_wfp['socks_connects'] = (Witness-Count) - $before
    $before = Witness-Count
    $report.same_name_other = Invoke-Probe 'same-name-other' $otherProbe
    Start-Sleep -Milliseconds 300
    $report.same_name_other['socks_connects'] = (Witness-Count) - $before

    New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Action Block -Program $probe -Protocol Any -Profile Any -Enabled True | Out-Null
    $ruleAdded = $true
    if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) { throw 'WFP firewall experiment rule not present' }
    Start-Sleep -Milliseconds 500
    $before = Witness-Count
    $report.with_wfp = Invoke-Probe 'with-wfp' $probe
    Start-Sleep -Milliseconds 300
    $report.with_wfp['socks_connects'] = (Witness-Count) - $before
    $before = Witness-Count
    $report.same_name_other_with_wfp = Invoke-Probe 'same-name-other-with-wfp' $otherProbe
    Start-Sleep -Milliseconds 300
    $report.same_name_other_with_wfp['socks_connects'] = (Witness-Count) - $before

    Stop-Process -Id $cli.Id -Force
    $cli.WaitForExit(5000) | Out-Null
    $before = Witness-Count
    $report.after_cli_kill = Invoke-Probe 'after-cli-kill' $probe
    Start-Sleep -Milliseconds 300
    $report.after_cli_kill['socks_connects'] = (Witness-Count) - $before
    $report.status = 'measured; inspect evidence, never an acceptance result'
} catch {
    $report.error = $_.Exception.ToString()
    Write-Warning $report.error
} finally {
    if ($cli -and -not $cli.HasExited) {
        Stop-Process -Id $cli.Id -Force -ErrorAction SilentlyContinue
        $cli.WaitForExit(5000) | Out-Null
    }
    if ($witness -and -not $witness.HasExited) { Stop-Process -Id $witness.Id -Force -ErrorAction SilentlyContinue }
    if ($ruleAdded) { Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue }
    $report['firewall_rule_removed'] = -not [bool](Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
    if (-not $report.firewall_rule_removed) { $report.error = 'Experiment firewall rule remains installed' }
    if ($driverWasAbsent) {
        # This dedicated runner started without the driver. WinDivert's service
        # remains RUNNING after a forced CLI kill; remove only our new instance.
        & sc.exe stop WinDivert | Out-Null
        & sc.exe delete WinDivert | Out-Null
        Start-Sleep -Milliseconds 300
    }
    $report.driver_after = (& sc.exe query WinDivert 2>&1 | Out-String)
    $report['driver_removed'] = $report.driver_after -match 'FAILED 1060'
    if (-not $report.driver_removed) { $report.error = 'Experiment WinDivert driver remains installed' }
    $report | ConvertTo-Json -Depth 10 | Set-Content -Path (Join-Path $evidence 'experiment.json') -Encoding utf8
    # The artifact is the full record. Echo the small, credential-free summary
    # so an automated reviewer can inspect measurements through CI job logs.
    Write-Output ($report | ConvertTo-Json -Depth 10)
    if (Test-Path $scratch) { Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue }
}
if ($report.error) { exit 1 }
exit 0
