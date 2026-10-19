param([Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'This account-creating experiment is only for disposable CI hosts' }
$repository=Split-Path $PSScriptRoot -Parent
$task='RuleProxyPrimary-' + [guid]::NewGuid().ToString('N')
$launch=Join-Path $env:SystemDrive ('RuleProxyPrimaryLaunch-' + [guid]::NewGuid().ToString('N'))
$work=Join-Path $env:SystemDrive ('RuleProxyPrimaryWork-' + [guid]::NewGuid().ToString('N'))
$target=[IO.Path]::GetFullPath($Output)
New-Item -ItemType Directory -Path $launch | Out-Null
New-Item -ItemType Directory -Path $target -Force | Out-Null
$python=(Get-Command python).Source
$arguments=@(
    '-I -S -B', ('"' + (Join-Path $PSScriptRoot 'windows_restricted_primary_lab.py') + '"'),
    '--lab-script', ('"' + (Join-Path $PSScriptRoot 'windows_compartment_lab.py') + '"'),
    '--probe-script', ('"' + (Join-Path $PSScriptRoot 'windows_dns_compartment_probe.py') + '"'),
    '--work', ('"' + $work + '"'),
    '--variants plain,write_custom_logon,write_custom_rc_logon --browsers edge') -join ' '
$command='@"' + $python + '" ' + $arguments + ' > "' + (Join-Path $launch 'stdout.log') + '" 2>&1'
$wrapper=Join-Path $launch 'run.cmd'
[IO.File]::WriteAllText($wrapper,$command + "`r`n",[Text.Encoding]::ASCII)
$action=New-ScheduledTaskAction -Execute "$env:SystemRoot\System32\cmd.exe" -Argument ('/d /c "' + $wrapper + '"')
$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 18)
$registered=$false
try {
    Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings | Out-Null
    $registered=$true
    $started=[DateTime]::Now
    Start-ScheduledTask -TaskName $task
    $deadline=[DateTime]::UtcNow.AddMinutes(18)
    $finished=$false
    do {
        Start-Sleep -Seconds 3
        $path=Join-Path $work 'report.json'
        if (Test-Path -LiteralPath $path) {
            try { $report=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; $finished=$null -ne $report.finished } catch { }
        }
        $info=Get-ScheduledTaskInfo -TaskName $task
        if ($info.LastRunTime -ge $started.AddSeconds(-2) -and (Get-ScheduledTask -TaskName $task).State -ne 'Running') { break }
    } while (-not $finished -and [DateTime]::UtcNow -lt $deadline)
    if (-not $finished) { throw 'Primary-token experiment incomplete; inspect artifacts' }
    if ($report.error) { throw 'Primary-token experiment setup failed; inspect report' }
} finally {
    if ($registered) {
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Get-ScheduledTaskInfo -TaskName $task | Select-Object LastRunTime,LastTaskResult | ConvertTo-Json | Set-Content (Join-Path $target 'task.json')
        Unregister-ScheduledTask -TaskName $task -Confirm:$false
    }
    if (Test-Path -LiteralPath (Join-Path $work 'report.json')) { Copy-Item -LiteralPath (Join-Path $work 'report.json') -Destination (Join-Path $target 'report.json') }
    if (Test-Path -LiteralPath (Join-Path $launch 'stdout.log')) { Get-Content -LiteralPath (Join-Path $launch 'stdout.log') -Tail 120 | Set-Content (Join-Path $target 'stdout.log') }
}
