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

$installWorker = Join-Path $PSScriptRoot 'windows-free-backend-install.ps1'
Copy-Item -LiteralPath $installWorker -Destination 'C:\RuleProxyCI\windows-free-backend-install.ps1' -Force
# The base VM setup grants Users modify on its general workspace. Replace that
# ACL before any SYSTEM task is registered: the autologon user may write only
# probe artifacts/results, never the config, scheduled-task entrypoint, state,
# install report, or fixed bundle used by SYSTEM.
Remove-Item -LiteralPath $payloadRoot -Recurse -Force
Remove-Item -LiteralPath $payload -Force
$root = 'C:\RuleProxyCI'
. (Join-Path $PSScriptRoot 'windows-free-backend-acl.ps1')
Protect-FreeBackendTree -Root $root
# Verify trusted code remains readable after protecting the SYSTEM boundary.
$null = Get-FileHash -LiteralPath (Join-Path $bundleRoot 'python\python.exe') -Algorithm SHA256
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -File C:\RuleProxyCI\windows-free-backend-install.ps1'
$triggers = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn))
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 110) -StartWhenAvailable -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName 'RuleProxyCI-InstallFreeBackend' -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
