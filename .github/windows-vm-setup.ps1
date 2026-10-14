# Runs once as SYSTEM during specialize. Tests themselves run as RuleProxyCI,
# a member of Users, through the ordinary interactive startup folder.
$ErrorActionPreference = 'Stop'
$destination = 'C:\RuleProxyCI'
New-Item -ItemType Directory -Path $destination -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'ruleproxy-vm-run.ps1') $destination
Copy-Item (Join-Path $PSScriptRoot 'ruleproxy-vm-config.json') $destination
$updateSource = Join-Path $PSScriptRoot 'ruleproxy-updates'
if (Test-Path -LiteralPath $updateSource) {
    $updateDirectory = 'C:\RuleProxyCIUpdates'
    New-Item -ItemType Directory -Path $updateDirectory -Force | Out-Null
    # Ordinary tests may read state/logs, but cannot replace a SYSTEM script,
    # manifest or MSU. This folder is separate from their writable workspace.
    & icacls.exe $updateDirectory /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not protect the disposable VM update directory' }
    Get-ChildItem -LiteralPath $updateSource | Copy-Item -Destination $updateDirectory -Recurse
    # Specialize only installs this owned task. Servicing runs after Windows
    # Setup completes and survives its required restart before ordinary tests.
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\RuleProxyCIUpdates\windows-vm-update.ps1'
    # oobeSystem creates RuleProxyCI after specialize. A general logon trigger
    # avoids resolving an account that does not exist yet in this private VM.
    $triggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn))
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 85) -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName 'RuleProxyCI-InstallOfficialUpdate' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
}
& icacls.exe $destination /grant '*S-1-5-32-545:(OI)(CI)M' /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not grant the test user access to its test directory' }
$startup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup\RuleProxyCi.cmd'
$command = "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\RuleProxyCI\ruleproxy-vm-run.ps1`r`n"
[IO.File]::WriteAllText($startup, $command, [Text.Encoding]::ASCII)
