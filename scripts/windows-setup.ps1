# Personal Windows 11 x64 deployment. All installer inputs are local after staging.
[CmdletBinding()]
param(
    [string]$SourceRoot = [IO.Path]::GetDirectoryName($PSScriptRoot),
    [string]$OwnerSid,
    [switch]$Elevated,
    [switch]$NoLaunch
)
$ErrorActionPreference = 'Stop'
$script:SetupTranscriptPath = $null
$script:SetupTranscriptActive = $false
trap {
    [Console]::Error.WriteLine(('RuleProxy setup failed: ' + $_.Exception.Message))
    if ($script:SetupTranscriptPath) {
        [Console]::Error.WriteLine(('Installation session log: ' + $script:SetupTranscriptPath))
    } else {
        [Console]::Error.WriteLine('This process has no protected session log. Keep the error shown here; administrator installation logs, when available, are under ProgramData\RuleProxy-Web\setup-logs.')
    }
    if ($script:SetupTranscriptActive) { try { Stop-Transcript | Out-Null } catch {} }
    exit 1
}
$env:PSModulePath = [IO.Path]::Combine($PSHOME,'Modules')
Import-Module -Name Microsoft.PowerShell.Security -ErrorAction Stop
Import-Module -Name Microsoft.PowerShell.Management -ErrorAction Stop
$utf8 = New-Object Text.UTF8Encoding($false)
$SourceRoot = [IO.Path]::GetFullPath($SourceRoot).TrimEnd('\')
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $Elevated) {
    # Capture the actual desktop owner before UAC may use another administrator.
    $OwnerSid = $identity.User.Value
}
if ($OwnerSid -notmatch '^S-1-5-21-(?:[0-9]+-){3}[0-9]+$') { throw 'Invalid desktop owner SID' }
if ($env:PROCESSOR_ARCHITEW6432 -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw 'Use native Windows x64 PowerShell; ARM64 and x86 are not qualified by this package'
}
if ([Environment]::OSVersion.Version.Build -lt 22000) { throw 'Windows 11 x64 is required' }
$manifestPath = Join-Path $SourceRoot 'package-manifest.json'

function Get-SetupExitCode($Process, [string]$Label) {
    if ($null -eq $Process) { throw ('No process result was returned: ' + $Label) }
    # Populate the native process exit information before reading ExitCode.
    # A missing code must never become `exit $null`, which reports success.
    [void]$Process.WaitForExit()
    [void]$Process.Refresh()
    $code = $Process.ExitCode
    if ($null -eq $code) { throw ('No exit code was returned: ' + $Label) }
    return [int]$code
}

function Test-OwnerPanel([string]$InstalledRoot) {
    $probe = @'
import sys, time
from ruleproxy.panel_client import panel_state
deadline = time.monotonic() + 10
while True:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        sys.exit(1)
    if panel_state(8879, timeout=min(1, remaining)) is not None:
        sys.exit(0)
    time.sleep(min(0.25, max(0, deadline - time.monotonic())))
'@
    $process = $null
    try {
        # Reuse this installation's interpreter and proxy-free panel client.
        # NoNewWindow keeps the one-time installer console; the hard process
        # deadline also bounds a slow HTTP response beyond its socket timeout.
        $process = Start-Process -FilePath (Join-Path $InstalledRoot 'python\python.exe') -ArgumentList @('-I','-S','-c',('"' + $probe + '"')) -WorkingDirectory $InstalledRoot -NoNewWindow -PassThru
        if (-not $process.WaitForExit(12000)) {
            $process.Kill()
            [void]$process.WaitForExit(1000)
            return $false
        }
        return ((Get-SetupExitCode $process 'Web panel health probe') -eq 0)
    } catch {
        return $false
    } finally {
        if ($null -ne $process) { try { $process.Dispose() } catch {} }
    }
}

function Test-ExistingDeployment([string]$ExistingRoot, [string]$Stage, [string]$ExpectedOwner) {
    $verificationCode = @'
import sys
from pathlib import Path
from ruleproxy.windows_proxy_service import load_deployment, ServiceControl
metadata = load_deployment(Path(sys.argv[1]))
if metadata['owner_sid'] != sys.argv[2] or 'package-manifest.json' not in metadata['files']:
    raise ValueError('Existing deployment identity or package receipt is incomplete')
ServiceControl().verify(metadata)
'@
    $global:LASTEXITCODE = $null
    & (Join-Path $Stage 'python\python.exe') -I -S -c $verificationCode $ExistingRoot $ExpectedOwner 2>&1 | Out-Null
    return ($null -ne $global:LASTEXITCODE -and $global:LASTEXITCODE -eq 0)
}

function Test-ReusableComponents([bool]$CompletedOwnedDeployment, [bool]$BundleRegistered,
    [bool]$RuntimeCompatible, [bool]$DriverCompatible, [string]$ExistingRoot,
    [string]$Stage, $Manifest, [string]$ExpectedOwner) {
    if (-not ($CompletedOwnedDeployment -and $BundleRegistered -and $RuntimeCompatible -and $DriverCompatible)) { return $false }
    try {
        # Only the protected installed receipt is eligible; source/cache receipts
        # do not establish what was installed. load_deployment below also checks
        # its recorded digest and every installed program/engine file and ACL.
        $receipt = Join-Path $ExistingRoot 'package-manifest.json'
        Assert-Protected $receipt
        if ((Get-Item -LiteralPath $receipt).Length -gt 4MB) { return $false }
        $previous = Get-Content -LiteralPath $receipt -Raw | ConvertFrom-Json
        if ($previous.schema_version -ne 1 -or $previous.platform -ne 'windows-amd64' -or $previous.backend -ne 'proxifyre') { return $false }
        foreach ($key in @('vc_redist','ndis_msi','proxifyre_msi','proxifyre_setup')) {
            $oldPin = $previous.installers.$key.sha256
            $newPin = $Manifest.installers.$key.sha256
            if ($oldPin -notmatch '^[a-f0-9]{64}$' -or $newPin -notmatch '^[a-f0-9]{64}$' -or $oldPin -cne $newPin) { return $false }
        }
        return (Test-ExistingDeployment $ExistingRoot $Stage $ExpectedOwner)
    } catch { return $false }
}

function Get-InstalledShortcutTarget([string]$InstalledRoot, [string]$ShortcutPath) {
    if (-not ('RuleProxyLinks.Links' -as [type])) {
        $global:LASTEXITCODE = $null
        $types = & (Join-Path $InstalledRoot 'python\python.exe') -I -S -c 'from ruleproxy.shortcuts import _SHELL_LINK_TYPES; print(_SHELL_LINK_TYPES)'
        if ($null -eq $global:LASTEXITCODE -or $global:LASTEXITCODE -ne 0) { throw 'Could not load the installed Unicode shortcut reader' }
        Add-Type -TypeDefinition ($types -join [Environment]::NewLine) -ErrorAction Stop
    }
    return [RuleProxyLinks.Links]::ReadTarget($ShortcutPath)
}

function Complete-OwnerSetup([string]$InstalledRoot, [string]$Desktop, [switch]$NoLaunch) {
    if ($NoLaunch) {
        Write-Host 'Installation complete; desktop shortcut and background panel launch were skipped as requested.'
        return
    }
    # This runs only in the original owner's continuation, whether that owner
    # started normally or as administrator. A different UAC account never runs it.
    try {
        if (-not $Desktop) { throw 'Desktop folder is unavailable' }
        $desktopLink = Join-Path $Desktop 'RuleProxy Web.lnk'
        if (Test-Path -LiteralPath $desktopLink) {
            $item = Get-Item -LiteralPath $desktopLink -Force
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Existing desktop entry is not an ordinary shortcut' }
            $target = Get-InstalledShortcutTarget $InstalledRoot $desktopLink
            if (-not [IO.Path]::IsPathRooted($target) -or $target -notmatch '^[A-Za-z]:[\\/]') { throw 'Existing desktop shortcut target is not an absolute local path' }
            $target = [IO.Path]::GetFullPath($target)
            $ownedPrefix = [IO.Path]::GetFullPath($InstalledRoot).TrimEnd('\') + '\'
            if (-not $target.StartsWith($ownedPrefix,[StringComparison]::OrdinalIgnoreCase)) { throw 'Existing desktop shortcut belongs to another program' }
        }
        Copy-Item -LiteralPath (Join-Path $InstalledRoot 'Start-Windows.lnk') -Destination $desktopLink -Force
        Write-Host ('Desktop Web panel launcher: ' + $desktopLink)
    } catch {
        Write-Warning ('Desktop shortcut left unchanged: ' + $_.Exception.Message + '. Use ' + (Join-Path $InstalledRoot 'Start-Windows.lnk'))
    }
    Write-Host 'Starting the background Web panel without opening a browser.'
    Start-Process -FilePath (Join-Path $InstalledRoot 'python\pythonw.exe') -ArgumentList @('-I','-S',('"' + (Join-Path $InstalledRoot 'Run-RuleProxy.py') + '"'),'--no-browser') -WorkingDirectory $InstalledRoot
    Write-Host 'Checking that the local Web panel is ready (up to twelve seconds).'
    if (-not (Test-OwnerPanel $InstalledRoot)) {
        $panelLog = Join-Path $env:LOCALAPPDATA 'RuleProxyWebSafe\panel.log'
        throw ('The program installation completed, but the Web panel failed to start. Installed components were retained. See ' + $panelLog + ' and retry the installed Start-Windows.lnk launcher.')
    }
    Write-Host 'Installation complete. Web panel: http://127.0.0.1:8879'
}

# A checkout or online release bootstraps a pinned private Python without pip/global Python.
# An offline archive already contains the complete verified payload.
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    if ($Elevated) { throw 'Build the source payload before requesting elevation' }
    $cache = Join-Path $SourceRoot '.windows-cache'
    $assets = Join-Path $cache 'assets'
    $bootstrap = Join-Path $cache 'bootstrap-python'
    New-Item -ItemType Directory -Path $assets, $bootstrap -Force | Out-Null
    Write-Host 'Preparing the online installation before requesting administrator access.'
    Write-Host ('Verified downloads are retained for another attempt in: ' + $assets)
    $archive = Join-Path $assets 'python-3.14.8-embed-amd64.zip'
    $pythonHash = 'a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310'
    if (-not (Test-Path -LiteralPath $archive) -or
        (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pythonHash) {
        Write-Host 'Downloading and verifying the private Python runtime...'
        $partial = $archive + '.partial'
        Invoke-WebRequest -UseBasicParsing -Uri 'https://www.python.org/ftp/python/3.14.8/python-3.14.8-embed-amd64.zip' -OutFile $partial -TimeoutSec 120
        if ((Get-Item -LiteralPath $partial).Length -ne 12601679 -or
            (Get-FileHash -LiteralPath $partial -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pythonHash) {
            Remove-Item -LiteralPath $partial -Force
            throw 'Pinned bootstrap Python failed verification'
        }
        Move-Item -LiteralPath $partial -Destination $archive -Force
    }
    Expand-Archive -LiteralPath $archive -DestinationPath $bootstrap -Force
    $stagedSource = Join-Path $cache 'offline-package'
    if (Test-Path -LiteralPath $stagedSource) { Remove-Item -LiteralPath $stagedSource -Recurse -Force }
    Write-Host 'Preparing the pinned components; cached files are checked and reused.'
    & (Join-Path $bootstrap 'python.exe') -I -S (Join-Path $SourceRoot '.github\build_windows_package.py') $stagedSource --stage-only --asset-cache $assets
    if ($LASTEXITCODE -ne 0) {
        throw ('Online installation preparation failed before system installation. See the download error above. ' +
            'After restoring network access, run Setup-Windows.cmd again from the same folder; verified downloads are retained in: ' + $assets)
    }
    $SourceRoot = $stagedSource
    $manifestPath = Join-Path $SourceRoot 'package-manifest.json'
    Write-Host 'Online preparation completed. The verified installation payload is ready.'
}

if (-not $isAdmin -or -not $Elevated) {
    if ($Elevated) { throw 'Installer elevation did not succeed' }
    # Only fixed installer parameters cross UAC. The child never starts the panel
    # or writes another account's desktop; the original owner does that below.
    $script = Join-Path $SourceRoot 'scripts\windows-setup.ps1'
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $script.Replace('"','') + '" -SourceRoot "' + $SourceRoot.Replace('"','') + '" -OwnerSid ' + $OwnerSid + ' -Elevated -NoLaunch'
    Write-Host 'Starting protected installation. Allow the administrator prompt if Windows displays it.'
    Write-Host ('Installer logs after security preflight: ' + (Join-Path $env:ProgramData 'RuleProxy-Web\setup-logs'))
    try {
        $child = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList $arguments -Wait -PassThru
    } catch {
        throw ('Administrator installation could not start. If the administrator prompt was cancelled or denied, rerun Setup-Windows.cmd and allow it. Details: ' + $_.Exception.Message)
    }
    $childCode = Get-SetupExitCode $child 'protected RuleProxy installation'
    Write-Host ('Protected installation returned exit code ' + $childCode + '.')
    if ($childCode -ne 0) {
        [Console]::Error.WriteLine(('Protected installation did not complete. See the administrator window and ' + (Join-Path $env:ProgramData 'RuleProxy-Web\setup-logs') + '.'))
        exit $childCode
    }
    Complete-OwnerSetup -InstalledRoot (Join-Path $env:ProgramFiles 'RuleProxy-Web') -Desktop ([Environment]::GetFolderPath('Desktop')) -NoLaunch:$NoLaunch
    exit 0
}

$root = Join-Path $env:ProgramFiles 'RuleProxy-Web'
$pfRoot = Join-Path $env:ProgramFiles 'ProxiFyre'
$stateRoot = Join-Path $env:ProgramData 'RuleProxy-Web'
$globalRoot = Join-Path $stateRoot 'global'
$namespaceRoot = Join-Path $stateRoot 'compartments'
$statePath = Join-Path $stateRoot 'install-state.json'
$logRoot = Join-Path $stateRoot 'setup-logs'
$serviceName = 'RuleProxyControl'
$serviceEntry = Join-Path $root 'ruleproxy\windows_proxy_service.py'
$serviceCommand = '"' + (Join-Path $root 'python\python.exe') + '" -I -S "' + $serviceEntry + '" --service'
$stage = Join-Path $env:ProgramFiles ('.RuleProxy-Web-staging-' + [guid]::NewGuid().ToString('N'))
$backup = Join-Path $env:ProgramFiles '.RuleProxy-Web-previous'
$swapped = $false
$oldRootMoved = $false
$newDeploymentHash = $null
$oldDeploymentHash = $null
$restoreControlService = $false
$setupFailed = $false
$setupPhase = 'preflight'
$activePackageFile = $null
$script:AclActivePath = $null

function Protect-Tree([string]$Path, [switch]$Private) {
    # Construct owner and the complete protected DACL in memory, then persist
    # them together. Do not remove a child's inherited grants in a separate
    # operation before its explicit administrator grants have been installed.
    $pending = New-Object 'System.Collections.Generic.Stack[string]'
    $pending.Push($Path)
    while ($pending.Count -gt 0) {
        $current = $pending.Pop()
        $script:AclActivePath = $current
        $item = Get-Item -LiteralPath $current -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse deployment object rejected' }
        if ($item.PSIsContainer) {
            $security = New-Object Security.AccessControl.DirectorySecurity
            $sddl = 'O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)'
            if ($Private) { $sddl = 'O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)' }
        } else {
            $security = New-Object Security.AccessControl.FileSecurity
            $sddl = 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;BU)'
            if ($Private) { $sddl = 'O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)' }
        }
        $security.SetSecurityDescriptorSddlForm($sddl)
        Set-Acl -LiteralPath $current -AclObject $security -ErrorAction Stop
        if ($item.PSIsContainer) {
            # Enumerate one level at a time; a junction is checked before it
            # can be traversed. No source or unrelated directory is changed.
            foreach ($child in Get-ChildItem -LiteralPath $current -Force) { $pending.Push($child.FullName) }
        }
    }
    $script:AclActivePath = $null
}
function Assert-Protected([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse deployment state rejected' }
    $acl = Get-Acl -LiteralPath $Path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18','S-1-5-32-544')) { throw 'Deployment state has an untrusted owner' }
    foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq 'Allow' -and $ace.IdentityReference.Value -notin @('S-1-5-18','S-1-5-32-544') -and
            (([long]$ace.FileSystemRights -band 0x000D0156) -ne 0)) { throw 'Deployment state is writable outside the administrator boundary' }
    }
}
function Write-State([string]$Phase, [bool]$PfOwned) {
    $value = [ordered]@{schema_version=1; owner_sid=$OwnerSid; root=$root; proxifyre_root=$pfRoot;
        proxifyre_owned=$PfOwned; phase=$Phase; reboot_required=($Phase -eq 'reboot_required');
        diagnostic_phase=$setupPhase; staging_path=$stage}
    $temp = $statePath + '.tmp'
    [IO.File]::WriteAllText($temp, ($value|ConvertTo-Json -Compress), $utf8)
    Move-Item -LiteralPath $temp -Destination $statePath -Force
    Protect-Tree $statePath
}
function Restore-ProgramInstallation {
    if (-not ($swapped -or $oldRootMoved)) { return }
    if ($oldRootMoved) {
        Assert-Protected $backup
        $previous = Join-Path $backup 'deployment.json'
        Assert-Protected $previous
        if ((Get-FileHash -LiteralPath $previous -Algorithm SHA256).Hash -ne $oldDeploymentHash) {
            throw 'Previous installation changed; rollback refused'
        }
    }
    $rootExists = Test-Path -LiteralPath $root
    if ($rootExists) {
        # A failed rename must never cause deletion of a newly appeared target.
        if (-not $swapped) { throw 'Installation target appeared during rollback; previous directory retained' }
        Assert-Protected $root
        $current = Join-Path $root 'deployment.json'
        Assert-Protected $current
        if ((Get-FileHash -LiteralPath $current -Algorithm SHA256).Hash -ne $newDeploymentHash) {
            throw 'Current installation changed; rollback refused'
        }
    }
    $control = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($control) { Stop-Service -Name $serviceName -ErrorAction Stop }
    if ($oldRootMoved) {
        if ($rootExists) { Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop }
        Move-Item -LiteralPath $backup -Destination $root -ErrorAction Stop
        if ($restoreControlService) { Start-Service -Name $serviceName -ErrorAction Stop }
    }
    # First-install failures retain their owned program files for repair and
    # uninstall. User state lives outside these program directories.
}
function Invoke-Installer([string]$File, [string]$Arguments, [string]$Label, [switch]$OfficialBurn) {
    $process = Start-Process -FilePath $File -ArgumentList $Arguments -Wait:$false -PassThru
    if (-not $process.WaitForExit(240000)) {
        & taskkill.exe /PID $process.Id /T /F | Out-Null
        throw ('Installer exceeded bound: ' + $Label)
    }
    $code = Get-SetupExitCode $process $Label
    if ($code -in @(1641,3010) -or ($OfficialBurn -and $code -eq 3017)) { return 3010 }
    if ($code -ne 0) { throw ('Installer failed: ' + $Label + ' exit ' + $code) }
    return 0
}
function Assert-Signature([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid') { throw ('Third-party signature invalid: ' + (Split-Path -Leaf $Path)) }
}
function Get-VisualCppRuntime {
    # Match ProxiFyre 2.6.4 Bundle.wxs, including its native UCRT check.
    # Registration alone is not evidence that the required DLLs are usable.
    $directory = Join-Path $env:SystemRoot 'System32'
    $minimum = [ordered]@{'ucrtbase.dll'='10.0.10240.0'; 'msvcp140.dll'='14.44.35211.0';
        'msvcp140_atomic_wait.dll'='14.44.35211.0'; 'vcruntime140.dll'='14.44.35211.0'; 'vcruntime140_1.dll'='14.44.35211.0'}
    $files = @()
    $complete = $true
    foreach ($name in $minimum.Keys) {
        $path = Join-Path $directory $name
        $file = [ordered]@{name=$name; path=$path; minimum=$minimum[$name]; version=$null; compatible=$false}
        try {
            $versionInfo = (Get-Item -LiteralPath $path -Force -ErrorAction Stop).VersionInfo
            $version = [version]('{0}.{1}.{2}.{3}' -f $versionInfo.FileMajorPart,$versionInfo.FileMinorPart,$versionInfo.FileBuildPart,$versionInfo.FilePrivatePart)
            $file.version = $version.ToString()
            $file.compatible = $version -ge [version]$minimum[$name]
            $file.sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        } catch { $file.error = $_.Exception.Message }
        if (-not $file.compatible) { $complete = $false }
        $files += $file
    }
    $registrations = @()
    $registered = $false
    foreach ($view in @([Microsoft.Win32.RegistryView]::Registry32,[Microsoft.Win32.RegistryView]::Registry64)) {
        $base = $null; $key = $null
        $record = [ordered]@{view=[string]$view; installed=$null; version=$null; compatible=$false}
        try {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine,$view)
            $key = $base.OpenSubKey('SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64',$false)
            if ($key) {
                $record.installed = $key.GetValue('Installed')
                $record.version = [string]$key.GetValue('Version')
                $record.major = $key.GetValue('Major'); $record.minor = $key.GetValue('Minor'); $record.build = $key.GetValue('Bld')
                # Official Burn registration detection uses the 32-bit view.
                $record.compatible = $record.installed -eq 1 -and (
                    $record.major -gt 14 -or ($record.major -eq 14 -and (
                    $record.minor -gt 44 -or ($record.minor -eq 44 -and $record.build -ge 35211))))
                if ($view -eq [Microsoft.Win32.RegistryView]::Registry32) { $registered = $record.compatible }
            }
        } catch { $record.error = $_.Exception.Message }
        finally { if ($key) { $key.Dispose() }; if ($base) { $base.Dispose() } }
        $registrations += $record
    }
    return [pscustomobject]@{files_compatible=$complete; registration_compatible=$registered;
        native_directory=$directory; files=$files; registrations=$registrations}
}
function Write-SetupDiagnostic($Failure) {
    try {
        if (-not (Test-Path -LiteralPath $logRoot -PathType Container)) { return }
        $facts = [ordered]@{schema_version=1; utc=[DateTime]::UtcNow.ToString('o');
            phase=$setupPhase; active_package_file=$activePackageFile; acl_active_path=$script:AclActivePath;
            staging_path=$stage; token_user_sid=$identity.User.Value; token_owner_sid=$identity.Owner.Value;
            token_is_admin=$isAdmin; error=$null; paths=@()}
        if ($Failure) {
            $facts.error = [ordered]@{message=$Failure.Exception.Message; type=$Failure.Exception.GetType().FullName;
                hresult=('0x{0:X8}' -f ($Failure.Exception.HResult -band 0xFFFFFFFFL));
                position=$Failure.InvocationInfo.PositionMessage; script_stack=$Failure.ScriptStackTrace}
        }
        $facts.token_groups = @(& whoami.exe /groups /fo csv /nh 2>&1)
        $facts.token_privileges = @(& whoami.exe /priv /fo csv /nh 2>&1)
        foreach ($path in (@($stage, $script:AclActivePath, (Join-Path $stage 'CHANGELOG.md'), (Join-Path $stage 'bin\windows-amd64\MIHOMO-LICENSE')) | Where-Object { $_ } | Select-Object -Unique)) {
            $entry = [ordered]@{path=$path}
            try {
                $item = Get-Item -LiteralPath $path -Force
                $acl = Get-Acl -LiteralPath $path
                $entry.attributes = [string]$item.Attributes
                $entry.owner_sid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
                $entry.protected_dacl = $acl.AreAccessRulesProtected
                $entry.sddl = $acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::All)
                $entry.aces = @($acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | ForEach-Object {
                    [ordered]@{sid=$_.IdentityReference.Value; rights=[string]$_.FileSystemRights;
                        type=[string]$_.AccessControlType; inherited=$_.IsInherited;
                        inheritance=[string]$_.InheritanceFlags; propagation=[string]$_.PropagationFlags}
                })
                $entry.icacls_verify = (@(& icacls.exe $path /verify /C 2>&1) | Out-String)
                $entry.icacls_exit = $LASTEXITCODE
            } catch { $entry.read_error = $_.Exception.Message }
            $facts.paths += $entry
        }
        $diagnosticName = if ($Failure) { 'setup-acl-facts.json' } else { 'setup-acl-before.json' }
        $diagnostic = Join-Path $logRoot $diagnosticName
        [IO.File]::WriteAllText($diagnostic,($facts | ConvertTo-Json -Depth 9),$utf8)
    } catch { Write-Warning ('Could not save setup diagnostics: ' + $_.Exception.Message) }
}

if (Test-Path -LiteralPath $stateRoot) { Assert-Protected $stateRoot }
else { New-Item -ItemType Directory -Path $stateRoot | Out-Null }
if (Test-Path -LiteralPath $statePath) { Assert-Protected $statePath }
# This tree now contains the SYSTEM core's YAML and node credentials. Keep
# state/log/config descendants private during upgrades too; never temporarily
# grant all local users read access to an existing global configuration.
Protect-Tree $stateRoot -Private
if (Test-Path -LiteralPath $globalRoot) { Assert-Protected $globalRoot }
else { New-Item -ItemType Directory -Path $globalRoot | Out-Null }
Protect-Tree $globalRoot -Private
if (Test-Path -LiteralPath $namespaceRoot) { Assert-Protected $namespaceRoot }
else { New-Item -ItemType Directory -Path $namespaceRoot | Out-Null }
Protect-Tree $namespaceRoot -Private
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
try {
    $sessionLog = Join-Path $logRoot ('setup-session-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N') + '.log')
    Start-Transcript -Path $sessionLog -NoClobber | Out-Null
    $script:SetupTranscriptPath = $sessionLog
    $script:SetupTranscriptActive = $true
    Write-Host ('Installation session log: ' + $sessionLog)
} catch { Write-Warning ('Could not start installation session logging: ' + $_.Exception.Message) }
Write-Host 'Checking installation ownership and the verified package.'
$pfOwned = $false
if (Test-Path -LiteralPath $statePath) {
    $oldState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($oldState.schema_version -ne 1 -or $oldState.owner_sid -ne $OwnerSid -or
        $oldState.root -ne $root -or $oldState.proxifyre_root -ne $pfRoot) { throw 'Existing deployment belongs to another owner or location' }
    $pfOwned = $oldState.proxifyre_owned -eq $true
    if ($oldState.phase -eq 'uninstall_reboot_required') {
        Write-Host ('Uninstall is pending. Restart Windows, then rerun ' + (Join-Path $root 'scripts\windows-uninstall.ps1') + ' to finish before installing again.')
        exit 3010
    }
}
$pfService = Get-Service -Name ProxiFyreService -ErrorAction SilentlyContinue
$bundleCode = '{0E6374A5-1B73-4710-80EA-43784F0BC546}'
$bundleRegistered = (Test-Path -LiteralPath ('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' + $bundleCode)) -or
    (Test-Path -LiteralPath ('HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\' + $bundleCode))
if (($null -ne $pfService -or (Test-Path -LiteralPath $pfRoot) -or $bundleRegistered) -and -not $pfOwned) { throw 'Refuse to take over an existing ProxiFyre deployment' }
if ((Test-Path -LiteralPath $root) -and -not (Test-Path -LiteralPath (Join-Path $root 'deployment.json'))) { throw 'Unowned RuleProxy installation directory exists' }
if (Test-Path -LiteralPath $backup) {
    Assert-Protected $backup
    Assert-Protected (Join-Path $backup 'deployment.json')
    $previous = Get-Content -LiteralPath (Join-Path $backup 'deployment.json') -Raw | ConvertFrom-Json
    if ($previous.owner_sid -ne $OwnerSid -or $previous.root -ne $root) { throw 'Previous deployment belongs to another installation' }
    if ($oldState.phase -eq 'completed' -and (Test-Path -LiteralPath (Join-Path $root 'deployment.json'))) {
        Remove-Item -LiteralPath $backup -Recurse -Force
    } else {
        $control = Get-CimInstance Win32_Service -Filter "Name='RuleProxyControl'"
        if ($control -and $control.PathName -ne $serviceCommand) { throw 'Unexpected service during deployment recovery' }
        if ($control) { Stop-Service RuleProxyControl -ErrorAction Stop }
        if (Test-Path -LiteralPath $root) {
            Assert-Protected (Join-Path $root 'deployment.json')
            $interrupted = Get-Content -LiteralPath (Join-Path $root 'deployment.json') -Raw | ConvertFrom-Json
            if ($interrupted.owner_sid -ne $OwnerSid -or $interrupted.root -ne $root) { throw 'Interrupted deployment is not owned' }
            Remove-Item -LiteralPath $root -Recurse -Force
        }
        Move-Item -LiteralPath $backup -Destination $root
    }
}
if (Test-Path -LiteralPath $root) { Assert-Protected $root; Assert-Protected (Join-Path $root 'deployment.json') }

try {
    $manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
    $manifest = [Text.Encoding]::UTF8.GetString($manifestBytes) | ConvertFrom-Json
    if ($manifest.schema_version -ne 1 -or $manifest.platform -ne 'windows-amd64' -or $manifest.backend -ne 'proxifyre') { throw 'Invalid offline package manifest' }
    $setupPhase = 'stage_create'
    New-Item -ItemType Directory -Path $stage | Out-Null
    Protect-Tree $stage
    $setupPhase = 'stage_copy'
    Write-Host 'Copying and verifying the protected application files.'
    foreach ($entry in $manifest.files.PSObject.Properties) {
        $name = [string]$entry.Name
        $activePackageFile = $name
        if ($name -eq 'package-manifest.json') { throw 'The package manifest cannot hash itself' }
        if ($name -match '(^/|\\|:|(^|/)\.\.?(/|$))' -or $entry.Value -notmatch '^[a-f0-9]{64}$') { throw 'Unsafe package manifest entry' }
        $from = Join-Path $SourceRoot $name.Replace('/','\')
        $to = Join-Path $stage $name.Replace('/','\')
        $item = Get-Item -LiteralPath $from -Force
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Package file must be ordinary' }
        if ((Get-FileHash -LiteralPath $from -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) { throw ('Package hash mismatch: ' + $name) }
        New-Item -ItemType Directory -Path (Split-Path -Parent $to) -Force | Out-Null
        Copy-Item -LiteralPath $from -Destination $to
        if ((Get-FileHash -LiteralPath $to -Algorithm SHA256).Hash.ToLowerInvariant() -ne $entry.Value) { throw 'Staged package hash mismatch' }
    }
    # Retain the exact parsed manifest for offline repair from this installation.
    # deployment.json hashes it; the package manifest cannot hash itself.
    [IO.File]::WriteAllBytes((Join-Path $stage 'package-manifest.json'), $manifestBytes)
    $activePackageFile = $null
    foreach ($required in @('python\python.exe','python\pythonw.exe','python\python314._pth','ruleproxy\windows_proxy_service.py','ruleproxy\windows_proxy_policy.py','ruleproxy\windows_global_runtime.py','ruleproxy\windows_global_guard.py','ruleproxy\windows_global_dns.py','ruleproxy\windows_app_guard.py','ruleproxy\windows_app_process.py','ruleproxy\windows_compartment.py','ruleproxy\config.py','bin\windows-amd64\mihomo.exe','Run-RuleProxy.py','scripts\windows-uninstall.ps1')) {
        if (-not (Test-Path -LiteralPath (Join-Path $stage $required) -PathType Leaf)) { throw ('Required product file missing: ' + $required) }
    }
    $setupPhase = 'stage_protect'
    Write-SetupDiagnostic $null
    Protect-Tree $stage
    $setupPhase = 'dependencies'
    $net = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
    if ([int]$net.Release -lt 461808) { throw '.NET Framework 4.7.2 or later is required' }
    Write-State 'dependencies' $pfOwned
    # The original fixed Burn engine owns the prerequisite decisions and MSI
    # chain. All external SourcePath payloads are local, hash-verified siblings.
    foreach ($key in @('vc_redist','ndis_msi','proxifyre_msi','proxifyre_setup')) {
        $asset = $manifest.installers.$key
        $path = Join-Path $stage ('installers\' + $asset.name)
        if ((Get-Item -LiteralPath $path).Length -ne [long]$asset.size -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $asset.sha256) { throw 'Installer pin mismatch' }
        if ($key -in @('vc_redist','ndis_msi')) { Assert-Signature $path }
    }
    $setupPhase = 'official_burn_layout_validate'
    $validationCode = "import sys; from pathlib import Path; from ruleproxy.windows_proxy_pins import validate_burn_layout; validate_burn_layout(Path(sys.argv[1]))"
    & (Join-Path $stage 'python\python.exe') -I -S -c $validationCode (Join-Path $stage 'installers')
    if ($LASTEXITCODE -ne 0) { throw 'Official Burn external payload layout verification failed' }
    $runtime = Get-VisualCppRuntime
    [IO.File]::WriteAllText((Join-Path $logRoot 'vc-runtime-before.json'),($runtime | ConvertTo-Json -Depth 7),$utf8)
    $driver = Join-Path $env:SystemRoot 'System32\drivers\ndisrd.sys'
    $driverCompatible = $false
    if ((Get-Service NDISRD -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $driver)) {
        Assert-Signature $driver
        $driverVersion = [version](Get-Item -LiteralPath $driver).VersionInfo.FileVersion
        if ($driverVersion -lt [version]'3.6.1.0' -or $driverVersion -ge [version]'4.0.0.0') { throw 'An incompatible shared NDIS driver is installed; refusing replacement' }
        $driverCompatible = $true
    }
    $setupPhase = 'existing_components_verify'
    $reuseComponents = Test-ReusableComponents ($pfOwned -and $oldState.phase -eq 'completed') $bundleRegistered $runtime.files_compatible $driverCompatible $root $stage $manifest $OwnerSid
    $control = Get-CimInstance Win32_Service -Filter "Name='RuleProxyControl'"
    if ($control -and $control.PathName -ne $serviceCommand) { throw 'Unexpected control service executable' }
    $restoreControlService = $null -ne $control
    if ($control) { Stop-Service -Name $serviceName -ErrorAction Stop }
    if (Get-Service ProxiFyreService -ErrorAction SilentlyContinue) { Stop-Service ProxiFyreService -ErrorAction Stop }
    if ($reuseComponents) {
        $setupPhase = 'existing_components_reused'
        Write-Host 'Reusing verified installed components with unchanged installer pins; the official installer and network driver repair are skipped.'
    } else {
        $setupPhase = 'official_burn_install'
        Write-Host 'Installing or repairing the official ProxiFyre components (up to four minutes); existing components did not meet every reuse check.'
        $pfOwned = $true
        Write-State 'installing_proxifyre_bundle' $pfOwned
        $bundle = Join-Path $stage ('installers\' + $manifest.installers.proxifyre_setup.name)
        $burnAction = if ($bundleRegistered) { '/repair' } else { '/install' }
        $log = Join-Path $logRoot 'official-setup.log'
        $code = Invoke-Installer $bundle ($burnAction + ' /quiet /norestart /log "' + $log + '"') 'official ProxiFyre setup' -OfficialBurn
        if ($code -eq 3010) {
            Write-State 'reboot_required' $pfOwned
            Write-Host 'The official installer requires a Windows restart. Installation is not complete; rerun Setup-Windows.cmd afterwards.'
            exit 3010
        }
    }
    $runtime = Get-VisualCppRuntime
    [IO.File]::WriteAllText((Join-Path $logRoot 'vc-runtime-after.json'),($runtime | ConvertTo-Json -Depth 7),$utf8)
    if (-not $runtime.files_compatible) { throw 'The native VC/UCRT file set remains incomplete after official setup success; inspect vc-runtime-after.json' }
    Write-State 'installed_proxifyre_bundle' $pfOwned
    Assert-Signature (Join-Path $env:SystemRoot 'System32\drivers\ndisrd.sys')
    $config = Join-Path $pfRoot 'app-config.json'
    if (-not (Test-Path -LiteralPath $config)) {
        # A deliberately unmatchable rule keeps a fresh service harmless until
        # the owner imports YAML and selects applications through the Web panel.
        [IO.File]::WriteAllText($config, '{"logLevel":"Info","bypassLan":false,"excludes":[],"proxies":[{"appNames":["RuleProxy-No-Selected-Application-71d8c7.exe"],"socks5ProxyEndpoint":"127.0.0.1:9","supportedProtocols":["TCP","UDP"],"supportedAddressFamilies":["IPv4","IPv6"]}]}', $utf8)
    }
    $setupPhase = 'panel_shortcut'
    Write-Host 'Creating the installed Web panel launcher.'
    # Create in staging before sealing the owned file hashes, but point at the
    # final protected root. The GUID staging directory is renamed below.
    & (Join-Path $stage 'python\python.exe') -I -S (Join-Path $stage 'Run-RuleProxy.py') --create-panel-shortcut (Join-Path $stage 'Start-Windows.lnk') --shortcut-root $root
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath (Join-Path $stage 'Start-Windows.lnk') -PathType Leaf)) { throw 'Could not create the daily Web panel launcher' }
    $files = @{}
    foreach ($path in Get-ChildItem -LiteralPath $stage -File -Recurse) {
        $relative = $path.FullName.Substring($stage.Length + 1).Replace('\','/')
        $files[$relative] = (Get-FileHash -LiteralPath $path.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    $pfFiles = @{}
    foreach ($path in Get-ChildItem -LiteralPath $pfRoot -File) {
        if ($path.Extension -in @('.exe','.dll','.config') -or $path.Name -eq 'app-config.sample.json') {
            $pfFiles[$path.Name] = (Get-FileHash -LiteralPath $path.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $sidHash = ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::ASCII.GetBytes($OwnerSid)))).Replace('-','').ToLowerInvariant().Substring(0,16) }
    finally { $hash.Dispose() }
    $deployment = [ordered]@{schema_version=1; global_backend_version=1; global_state_dir=$globalRoot;
        namespace_backend_version=1; namespace_state_dir=$namespaceRoot;
        owner_sid=$OwnerSid; root=$root; proxifyre_root=$pfRoot;
        service_name=$serviceName; pipe_name=('RuleProxyControl-v1-' + $sidHash); files=$files; proxifyre_files=$pfFiles}
    [IO.File]::WriteAllText((Join-Path $stage 'deployment.json'), ($deployment|ConvertTo-Json -Depth 6), $utf8)
    $newDeploymentHash = (Get-FileHash -LiteralPath (Join-Path $stage 'deployment.json') -Algorithm SHA256).Hash
    $setupPhase = 'program_swap'
    if (Test-Path -LiteralPath $root) {
        # Close only the owner's old private panel/core before replacing files.
        # Selected applications have external executable paths and are retained.
        foreach ($ownedProcess in Get-CimInstance Win32_Process) {
            if ($ownedProcess.ExecutablePath -and $ownedProcess.ExecutablePath.StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase)) {
                $processOwner = Invoke-CimMethod -InputObject $ownedProcess -MethodName GetOwnerSid
                if ($processOwner.Sid -eq $OwnerSid) { Stop-Process -Id $ownedProcess.ProcessId -Force -ErrorAction Stop }
            }
        }
        $oldDeploymentHash = (Get-FileHash -LiteralPath (Join-Path $root 'deployment.json') -Algorithm SHA256).Hash
        Move-Item -LiteralPath $root -Destination $backup
        $oldRootMoved = $true
    }
    Move-Item -LiteralPath $stage -Destination $root
    $swapped = $true
    Protect-Tree $root
    $setupPhase = 'control_service_start'
    Write-Host 'Starting the protected RuleProxy control service.'
    $existingService = Get-CimInstance Win32_Service -Filter "Name='RuleProxyControl'"
    if ($existingService -and $existingService.PathName -ne $serviceCommand) { throw 'Refuse a non-owned control service' }
    if (-not $existingService) {
        New-Service -Name $serviceName -DisplayName 'RuleProxy Web Control' -BinaryPathName $serviceCommand -StartupType Automatic | Out-Null
    }
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    Write-State 'completed' $true
    $setupPhase = 'completed'
    if ($oldRootMoved) { Remove-Item -LiteralPath $backup -Recurse -Force }
    Write-Host ('RuleProxy installed. Daily Web panel launcher: ' + (Join-Path $root 'Start-Windows.lnk'))
    Write-Host 'Setup starts the panel quietly. Clicking the daily launcher opens its Web page without a console window.'
    Write-Host 'Web panel: http://127.0.0.1:8879'
} catch {
    $originalFailure = $_
    $setupFailed = $true
    Write-SetupDiagnostic $originalFailure
    [Console]::Error.WriteLine(('Original setup failure in phase {0}; staging path {1}: {2}' -f $setupPhase,$stage,$originalFailure.Exception.Message))
    try {
        Restore-ProgramInstallation
    } catch { Write-Warning ('Program rollback incomplete: ' + $_.Exception.Message) }
    try { Write-State 'failed' $pfOwned } catch {}
    throw $originalFailure
} finally {
    if (Test-Path -LiteralPath $stage) {
        if ($setupFailed) {
            Write-Warning ('Protected staging retained for diagnosis: ' + $stage)
        } else {
            try {
                # Only this invocation's GUID directory is eligible for cleanup.
                Assert-Protected $stage
                Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction Stop
            } catch {
                Write-Warning ('Staging cleanup incomplete; retained at ' + $stage + ': ' + $_.Exception.Message)
            }
        }
    }
    if ($script:SetupTranscriptActive) {
        try { Stop-Transcript | Out-Null } catch {}
        $script:SetupTranscriptActive = $false
    }
}
