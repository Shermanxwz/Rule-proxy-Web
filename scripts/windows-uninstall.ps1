[CmdletBinding()]
param([switch]$Elevated, [string]$OwnerSid)
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [IO.Path]::Combine($PSHOME,'Modules')
Import-Module -Name Microsoft.PowerShell.Security -ErrorAction Stop
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction Stop
$root = Join-Path $env:ProgramFiles 'RuleProxy-Web'
$pfRoot = Join-Path $env:ProgramFiles 'ProxiFyre'
$statePath = Join-Path $env:ProgramData 'RuleProxy-Web\install-state.json'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $Elevated) { $OwnerSid = $identity.User.Value }
if ($OwnerSid -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') { throw 'Invalid desktop owner SID' }
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or -not $Elevated) {
    if ($Elevated) { throw 'Uninstall elevation failed' }
    $script = Join-Path $root 'scripts\windows-uninstall.ps1'
    $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -Wait -PassThru -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -Elevated -OwnerSid ' + $OwnerSid)
    exit $process.ExitCode
}
function Assert-State([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse uninstall state rejected' }
    $acl = Get-Acl -LiteralPath $Path
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Untrusted uninstall state owner' }
    foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and (([long]$ace.FileSystemRights -band 0x000D0156) -ne 0)) { throw 'Uninstall state is not protected' }
    }
}
Assert-State $root
Assert-State $statePath
Assert-State (Join-Path $root 'deployment.json')
$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
$deployment = Get-Content -LiteralPath (Join-Path $root 'deployment.json') -Raw | ConvertFrom-Json
if ($state.schema_version -ne 1 -or $state.owner_sid -ne $OwnerSid -or $state.root -ne $root -or
    $state.proxifyre_root -ne $pfRoot -or $state.proxifyre_owned -ne $true -or
    $deployment.schema_version -ne 1 -or $deployment.owner_sid -ne $OwnerSid -or
    $deployment.root -ne $root -or $deployment.proxifyre_root -ne $pfRoot) { throw 'Refuse a deployment not owned by this installation' }
if ($state.phase -eq 'uninstall_reboot_required' -and $state.reboot_boot_marker) {
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    if ($boot -eq $state.reboot_boot_marker) {
        Write-Host 'Restart Windows, then rerun this uninstall script to finish.'
        exit 3010
    }
}
function Get-OwnedProxiFyreRemovalPlan {
    # Fixed code in the protected interpreter; no user-supplied command or module.
    $code = "import json,sys; from pathlib import Path; from ruleproxy.windows_proxy_pins import proxifyre_removal_plan; m=json.loads(Path(sys.argv[1]).read_text(encoding='utf-8')); print(json.dumps(proxifyre_removal_plan(Path(sys.argv[2]),m['proxifyre_files'])))"
    $result = & (Join-Path $root 'python\python.exe') -I -S -c $code (Join-Path $root 'deployment.json') $pfRoot
    if ($LASTEXITCODE -ne 0) { throw 'Unknown, changed or linked ProxiFyre content; uninstall refused' }
    return @($result | ConvertFrom-Json)
}
function Restore-OwnedGlobalNetwork {
    # This is a fixed administrator recovery action, not an owner-SID pipe
    # impersonation. The core must be gone before DNS/guard can be released.
    $core = Join-Path $root 'bin\windows-amd64\mihomo.exe'
    foreach ($process in Get-CimInstance Win32_Process -Filter "Name='mihomo.exe'") {
        if (-not $process.ExecutablePath) { throw 'Cannot verify a running Mihomo identity; global restoration refused' }
        if ([string]::Equals([string]$process.ExecutablePath,$core,[StringComparison]::OrdinalIgnoreCase)) {
            $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwnerSid
            if ($owner.ReturnValue -ne 0 -or -not $owner.Sid) { throw 'Cannot verify the installed core owner' }
            if ($owner.Sid -eq 'S-1-5-18') { throw 'The fixed SYSTEM Mihomo is still running; keep the recovery components installed' }
        }
    }
    $code = @'
import json,sys
from pathlib import Path
from ruleproxy.windows_proxy_service import load_deployment,ServiceControl
from ruleproxy.windows_proxy_policy import SERVICE_NAME
metadata=load_deployment(Path(sys.argv[1]))
try:
    service=ServiceControl().status(SERVICE_NAME)
except OSError as error:
    if getattr(error,'winerror',None)!=1060:
        raise
else:
    if service['state']!=1:
        raise RuntimeError('Stop the fixed control service before restoring global networking')
if metadata.get('global_backend_version')==1:
    from ruleproxy.windows_global_dns import DnsLease
    from ruleproxy.windows_global_guard import Guard
    dns=DnsLease(metadata).normal_stop()
    if dns.get('supported') is not True or dns.get('active') is not False:
        raise RuntimeError('Owned DNS restoration could not be confirmed; guard retained')
    guard=Guard(metadata).normal_stop()
    if guard.get('supported') is not True or guard.get('active') is not False:
        raise RuntimeError('Owned guard restoration could not be confirmed')
print(json.dumps({'restored':True}))
'@
    $global:LASTEXITCODE = $null
    $result = & (Join-Path $root 'python\python.exe') -I -S -c $code $root
    if ($null -eq $global:LASTEXITCODE -or $global:LASTEXITCODE -ne 0) {
        throw 'Global network restoration failed; owned services/code are retained for recovery'
    }
    $confirmation = $result | ConvertFrom-Json
    if ($confirmation.restored -ne $true) { throw 'Global network restoration was not confirmed' }
}
# Refuse foreign contents before changing services or invoking MSI.
if (Test-Path -LiteralPath $pfRoot) { Assert-State $pfRoot }
$null = Get-OwnedProxiFyreRemovalPlan
$expected = '"' + (Join-Path $root 'python\python.exe') + '" -I -S "' + (Join-Path $root 'ruleproxy\windows_proxy_service.py') + '" --service'
$service = Get-CimInstance Win32_Service -Filter "Name='RuleProxyControl'"
if ($service -and $service.PathName -ne $expected) { throw 'Refuse a substituted control service' }
if ($service) {
    Stop-Service RuleProxyControl -ErrorAction Stop
    (Get-Service RuleProxyControl).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
}
# A crashed core/service may have left persistent protection. The actual
# elevated administrator (including a different UAC account) may remove only
# this protected installation's exact DNS lease and WFP filters.
Restore-OwnedGlobalNetwork
if ($service) {
    & sc.exe delete RuleProxyControl | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Control service deletion failed' }
}
$pfService = Get-CimInstance Win32_Service -Filter "Name='ProxiFyreService'"
if ($pfService) {
    $registered = [string]$pfService.PathName
    if ($registered -notmatch ('^"?' + [regex]::Escape((Join-Path $pfRoot 'ProxiFyre.exe')) + '"?(?:\s.*)?$')) { throw 'Refuse a substituted ProxiFyre service' }
    Stop-Service ProxiFyreService -ErrorAction Stop
    (Get-Service ProxiFyreService).WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30))
}
$bundle = Join-Path $root 'installers\ProxiFyre-2.6.4-win-x64-setup.exe'
if ((Get-FileHash -LiteralPath $bundle -Algorithm SHA256).Hash.ToLowerInvariant() -ne 'afaf3ac8a2069f9653adb1b4a63b31d1edd8aa109ccdc367cf0d4462e78f5027') { throw 'Fixed official uninstall setup failed verification' }
$log = Join-Path $env:ProgramData 'RuleProxy-Web\uninstall-burn.log'
# Burn unregisters its own ARP entry; permanent shared VC/NDIS are retained.
$process = Start-Process -FilePath $bundle -ArgumentList ('/uninstall /quiet /norestart /log "' + $log + '"') -PassThru
if (-not $process.WaitForExit(240000)) { & taskkill.exe /PID $process.Id /T /F | Out-Null; throw 'ProxiFyre uninstall exceeded bound' }
if ($process.ExitCode -notin @(0,1641,3010,3017,1605)) { throw ('ProxiFyre uninstall failed: ' + $process.ExitCode) }
$reboot = $process.ExitCode -in @(1641,3010,3017)
if ($reboot) {
    # Keep both the ownership record and the installed cleanup tools until a
    # reboot has completed pending service/DLL deletion. Never mark complete.
    $state.phase = 'uninstall_reboot_required'
    $state.proxifyre_owned = $true
    $state.reboot_required = $true
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o')
    $state | Add-Member -NotePropertyName reboot_boot_marker -NotePropertyValue $boot -Force
    [IO.File]::WriteAllText($statePath,($state|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
    Write-Host 'Uninstall requires a restart. Program files and ownership are retained; rerun this script after restarting Windows.'
    exit 3010
}
if (Get-Service ProxiFyreService -ErrorAction SilentlyContinue) {
    throw 'ProxiFyre service still exists after MSI uninstall; restart Windows and retry uninstall'
}
# MSI deliberately preserves configuration/logs. Remove only our preflighted
# residual names so a subsequent fresh setup does not encounter an unowned root.
$remaining = Get-OwnedProxiFyreRemovalPlan
foreach ($name in $remaining) { Remove-Item -LiteralPath (Join-Path $pfRoot $name.Replace('/','\')) -Force }
foreach ($relative in @('logs\archive','logs','')) {
    $directory = if ($relative) { Join-Path $pfRoot $relative } else { $pfRoot }
    if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Force }
}
# Stop only this desktop owner's private runtime processes from this protected
# installation. Applications selected for proxying live elsewhere and are retained.
foreach ($ownedProcess in Get-CimInstance Win32_Process) {
    if ($ownedProcess.ExecutablePath -and $ownedProcess.ExecutablePath.StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase)) {
        $owner = Invoke-CimMethod -InputObject $ownedProcess -MethodName GetOwnerSid
        if ($owner.Sid -eq $OwnerSid) {
            Stop-Process -Id $ownedProcess.ProcessId -Force -ErrorAction Stop
        }
    }
}
# Own shortcuts/tasks are removed only if their targets point into this root.
$profile = Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $OwnerSid) -ErrorAction SilentlyContinue
if ($profile) {
    $ownerProfile = [Environment]::ExpandEnvironmentVariables($profile.ProfileImagePath)
    $folders = @((Join-Path $ownerProfile 'Desktop'), (Join-Path $ownerProfile 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\RuleProxy Web'))
    $userFolders = Get-ItemProperty -LiteralPath ('Registry::HKEY_USERS\' + $OwnerSid + '\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders') -ErrorAction SilentlyContinue
    if ($userFolders) {
        foreach ($name in @('Desktop','Programs')) {
            $configured = [string]$userFolders.$name
            if ($configured) {
                $configured = $configured.Replace('%USERPROFILE%',$ownerProfile).Replace('%APPDATA%',(Join-Path $ownerProfile 'AppData\Roaming'))
                if ($name -eq 'Programs') { $configured = Join-Path $configured 'RuleProxy Web' }
                $folders += $configured
            }
        }
    }
    $shell = New-Object -ComObject WScript.Shell
    foreach ($folder in ($folders | Select-Object -Unique)) {
        foreach ($shortcut in Get-ChildItem -LiteralPath $folder -Filter '*.lnk' -File -ErrorAction SilentlyContinue) {
            $link = $shell.CreateShortcut($shortcut.FullName)
            if ($link.TargetPath.StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase)) { Remove-Item -LiteralPath $shortcut.FullName -Force }
        }
    }
}
$runKey = 'Registry::HKEY_USERS\' + $OwnerSid + '\Software\Microsoft\Windows\CurrentVersion\Run'
$run = Get-ItemProperty -LiteralPath $runKey -Name 'RuleProxy Web' -ErrorAction SilentlyContinue
if ($run -and ([string]$run.'RuleProxy Web').IndexOf($root,[StringComparison]::OrdinalIgnoreCase) -ge 0) {
    Remove-ItemProperty -LiteralPath $runKey -Name 'RuleProxy Web' -ErrorAction Stop
}
Remove-Item -LiteralPath $root -Recurse -Force
$state.phase = 'uninstalled'
$state.proxifyre_owned = $false
$state.reboot_required = $reboot
[IO.File]::WriteAllText($statePath,($state|ConvertTo-Json -Compress),(New-Object Text.UTF8Encoding($false)))
Write-Host 'Uninstalled owned services and program files. User data, shared NDIS and VC runtime are retained.'
if ($reboot) { exit 3010 }
