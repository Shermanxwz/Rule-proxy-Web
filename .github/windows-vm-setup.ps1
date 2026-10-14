# Runs once as SYSTEM during specialize. Tests themselves run as RuleProxyCI,
# a member of Users, through the ordinary interactive startup folder.
$ErrorActionPreference = 'Stop'
$destination = 'C:\RuleProxyCI'
New-Item -ItemType Directory -Path $destination -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'ruleproxy-vm-run.ps1') $destination
Copy-Item (Join-Path $PSScriptRoot 'ruleproxy-vm-config.json') $destination
& icacls.exe $destination /grant '*S-1-5-32-545:(OI)(CI)M' /T | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not grant the test user access to its test directory' }
$startup = Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup\RuleProxyCi.cmd'
$command = "@echo off`r`npowershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\RuleProxyCI\ruleproxy-vm-run.ps1`r`n"
[IO.File]::WriteAllText($startup, $command, [Text.Encoding]::ASCII)
