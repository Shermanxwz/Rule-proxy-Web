# Disposable-VM bootstrap only. The legacy setup script stages the pinned CU
# task and ordinary-user startup entrypoint; this wrapper adds the fixed
# alternative backend and an independent SYSTEM installer task.
$ErrorActionPreference = 'Stop'
$base = Join-Path $PSScriptRoot 'ruleproxy-base-setup.ps1'
if (-not (Test-Path -LiteralPath $base -PathType Leaf)) { throw 'Base VM setup is missing' }
& $base

$configuration = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'ruleproxy-vm-config.json') -Raw | ConvertFrom-Json
if ($configuration.free_backend -notin @('sandboxie', 'proxybridge')) { throw 'Unknown fixed backend' }
$payload = 'C:\RuleProxyCI\payload.zip'
$deadline = [DateTime]::UtcNow.AddMinutes(5)
do {
    try {
        Invoke-WebRequest -UseBasicParsing -Uri ($configuration.host_url + '/payload.zip') -OutFile $payload -TimeoutSec 30
        break
    } catch {
        if ([DateTime]::UtcNow -ge $deadline) { throw }
        Start-Sleep -Seconds 5
    }
} while ($true)
if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.payload_sha256) {
    throw 'Pinned alternative-backend payload checksum mismatch'
}
$payloadRoot = 'C:\RuleProxyCI\payload'
if (Test-Path -LiteralPath $payloadRoot) { Remove-Item -LiteralPath $payloadRoot -Recurse -Force }
Expand-Archive -LiteralPath $payload -DestinationPath $payloadRoot -Force
$bundle = Join-Path $payloadRoot 'backend-bundle.zip'
if (-not (Test-Path -LiteralPath $bundle -PathType Leaf) -or
    (Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.free_backend_bundle_sha256) {
    throw 'Pinned backend bundle checksum mismatch'
}
$bundleRoot = 'C:\RuleProxyCI\bundle'
if (Test-Path -LiteralPath $bundleRoot) { Remove-Item -LiteralPath $bundleRoot -Recurse -Force }
Expand-Archive -LiteralPath $bundle -DestinationPath $bundleRoot -Force
if (-not (Test-Path -LiteralPath (Join-Path $bundleRoot 'manifest.json') -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $bundleRoot 'python\python.exe') -PathType Leaf)) {
    throw 'Backend bundle is missing its manifest or pinned Python runtime'
}
New-Item -ItemType Directory -Path 'C:\RuleProxyCI\artifacts' -Force | Out-Null
New-Item -ItemType Directory -Path 'C:\RuleProxyCI\results' -Force | Out-Null
$null = & icacls.exe $bundleRoot /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T
if ($LASTEXITCODE -ne 0) { throw 'Could not protect fixed backend bundle from ordinary-user modification' }
$null = & icacls.exe 'C:\RuleProxyCI\artifacts' /grant '*S-1-5-32-545:(OI)(CI)M' /T
if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the private probe artifact directory' }

$installWorker = Join-Path $PSScriptRoot 'windows-free-backend-install.ps1'
Copy-Item -LiteralPath $installWorker -Destination 'C:\RuleProxyCI\windows-free-backend-install.ps1' -Force
# The base VM setup grants Users modify on its general workspace. Replace that
# ACL before any SYSTEM task is registered: the autologon user may write only
# probe artifacts/results, never the config, scheduled-task entrypoint, state,
# install report, or fixed bundle used by SYSTEM.
Remove-Item -LiteralPath $payloadRoot -Recurse -Force
Remove-Item -LiteralPath $payload -Force
$root = 'C:\RuleProxyCI'
$null = & icacls.exe $root /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX' /T /C
if ($LASTEXITCODE -ne 0) { throw 'Could not protect SYSTEM backend scripts and state from ordinary-user modification' }
foreach ($writable in @((Join-Path $root 'artifacts'), (Join-Path $root 'results'))) {
    $null = & icacls.exe $writable /grant '*S-1-5-32-545:(OI)(CI)M' /T /C
    if ($LASTEXITCODE -ne 0) { throw 'Could not prepare the bounded ordinary-user output directories' }
}
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\RuleProxyCI\windows-free-backend-install.ps1'
$triggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn))
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 110) -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'RuleProxyCI-InstallFreeBackend' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
