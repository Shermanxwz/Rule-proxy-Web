# Personal Windows 11 x64 deployment. All installer inputs are local after staging.
[CmdletBinding()]
param(
    [string]$SourceRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OwnerSid,
    [switch]$Elevated,
    [switch]$NoLaunch
)
$ErrorActionPreference = 'Stop'
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

# A source checkout bootstraps a pinned private Python without pip/global Python.
# The release archive already contains the complete offline payload.
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    if ($Elevated) { throw 'Build the source payload before requesting elevation' }
    $cache = Join-Path $SourceRoot '.windows-cache'
    $assets = Join-Path $cache 'assets'
    $bootstrap = Join-Path $cache 'bootstrap-python'
    New-Item -ItemType Directory -Path $assets, $bootstrap -Force | Out-Null
    $archive = Join-Path $assets 'python-3.14.8-embed-amd64.zip'
    $pythonHash = 'a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310'
    if (-not (Test-Path -LiteralPath $archive) -or
        (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant() -ne $pythonHash) {
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
    & (Join-Path $bootstrap 'python.exe') -I -S (Join-Path $SourceRoot '.github\build_windows_package.py') $stagedSource --stage-only --asset-cache $assets
    if ($LASTEXITCODE -ne 0) { throw 'Source offline-payload preparation failed' }
    $SourceRoot = $stagedSource
    $manifestPath = Join-Path $SourceRoot 'package-manifest.json'
}

if (-not $isAdmin -or -not $Elevated) {
    if ($Elevated) { throw 'Installer elevation did not succeed' }
    # Only fixed installer parameters cross UAC. Never run the panel elevated.
    $script = Join-Path $SourceRoot 'scripts\windows-setup.ps1'
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $script.Replace('"','') + '" -SourceRoot "' + $SourceRoot.Replace('"','') + '" -OwnerSid ' + $OwnerSid + ' -Elevated -NoLaunch'
    $child = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -ArgumentList $arguments -Wait -PassThru
    if ($child.ExitCode -ne 0) { exit $child.ExitCode }
    if (-not $NoLaunch -and -not $isAdmin) {
        # This continuation retains the original ordinary user's token.
        $installedRoot = Join-Path $env:ProgramFiles 'RuleProxy-Web'
        Start-Process -FilePath (Join-Path $installedRoot 'python\pythonw.exe') -ArgumentList @('-I','-S',('"' + (Join-Path $installedRoot 'Run-RuleProxy.py') + '"')) -WorkingDirectory $installedRoot
    }
    exit 0
}

$root = Join-Path $env:ProgramFiles 'RuleProxy-Web'
$pfRoot = Join-Path $env:ProgramFiles 'ProxiFyre'
$stateRoot = Join-Path $env:ProgramData 'RuleProxy-Web'
$statePath = Join-Path $stateRoot 'install-state.json'
$logRoot = Join-Path $stateRoot 'setup-logs'
$serviceName = 'RuleProxyControl'
$serviceEntry = Join-Path $root 'ruleproxy\windows_proxy_service.py'
$serviceCommand = '"' + (Join-Path $root 'python\python.exe') + '" -I -S "' + $serviceEntry + '" --service'
$stage = Join-Path $env:ProgramFiles ('.RuleProxy-Web-staging-' + [guid]::NewGuid().ToString('N'))
$backup = Join-Path $env:ProgramFiles '.RuleProxy-Web-previous'
$swapped = $false
$oldRootMoved = $false

function Protect-Tree([string]$Path) {
    if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse deployment directory rejected' }
    if ((Get-Item -LiteralPath $Path -Force).PSIsContainer) {
        & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)(F)' '*S-1-5-32-544:(OI)(CI)(F)' '*S-1-5-32-545:(OI)(CI)(RX)' /T /Q | Out-Null
    } else {
        & icacls.exe $Path /inheritance:r /grant:r '*S-1-5-18:(F)' '*S-1-5-32-544:(F)' '*S-1-5-32-545:(RX)' /Q | Out-Null
    }
    if ($LASTEXITCODE -ne 0) { throw 'Cannot protect deployment ACL' }
    & icacls.exe $Path /setowner '*S-1-5-32-544' /T /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Cannot set trusted deployment ownership' }
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
        proxifyre_owned=$PfOwned; phase=$Phase; reboot_required=($Phase -eq 'reboot_required')}
    $temp = $statePath + '.tmp'
    [IO.File]::WriteAllText($temp, ($value|ConvertTo-Json -Compress), $utf8)
    Move-Item -LiteralPath $temp -Destination $statePath -Force
    Protect-Tree $statePath
}
function Invoke-Installer([string]$File, [string]$Arguments, [string]$Label) {
    $process = Start-Process -FilePath $File -ArgumentList $Arguments -Wait:$false -PassThru
    if (-not $process.WaitForExit(240000)) {
        & taskkill.exe /PID $process.Id /T /F | Out-Null
        throw ('Installer exceeded bound: ' + $Label)
    }
    $code = $process.ExitCode
    if ($code -in @(1641,3010)) { return 3010 }
    if ($code -ne 0) { throw ('Installer failed: ' + $Label + ' exit ' + $code) }
    return 0
}
function Assert-Signature([string]$Path) {
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne 'Valid') { throw ('Third-party signature invalid: ' + (Split-Path -Leaf $Path)) }
}

if (Test-Path -LiteralPath $stateRoot) { Assert-Protected $stateRoot }
else { New-Item -ItemType Directory -Path $stateRoot | Out-Null }
if (Test-Path -LiteralPath $statePath) { Assert-Protected $statePath }
Protect-Tree $stateRoot
New-Item -ItemType Directory -Path $logRoot -Force | Out-Null
$pfOwned = $false
if (Test-Path -LiteralPath $statePath) {
    $oldState = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($oldState.schema_version -ne 1 -or $oldState.owner_sid -ne $OwnerSid -or
        $oldState.root -ne $root -or $oldState.proxifyre_root -ne $pfRoot) { throw 'Existing deployment belongs to another owner or location' }
    $pfOwned = $oldState.proxifyre_owned -eq $true
}
$pfService = Get-Service -Name ProxiFyreService -ErrorAction SilentlyContinue
if (($null -ne $pfService -or (Test-Path -LiteralPath $pfRoot)) -and -not $pfOwned) { throw 'Refuse to take over an existing ProxiFyre deployment' }
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
    New-Item -ItemType Directory -Path $stage | Out-Null
    Protect-Tree $stage
    foreach ($entry in $manifest.files.PSObject.Properties) {
        $name = [string]$entry.Name
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
    foreach ($required in @('python\python.exe','python\python314._pth','ruleproxy\windows_proxy_service.py','ruleproxy\windows_proxy_policy.py','Run-RuleProxy.py','scripts\windows-uninstall.ps1')) {
        if (-not (Test-Path -LiteralPath (Join-Path $stage $required) -PathType Leaf)) { throw ('Required product file missing: ' + $required) }
    }
    Protect-Tree $stage
    $net = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
    if ([int]$net.Release -lt 461808) { throw '.NET Framework 4.7.2 or later is required' }
    Write-State 'dependencies' $pfOwned
    foreach ($key in @('vc_redist','ndis_msi','proxifyre_msi')) {
        $asset = $manifest.installers.$key
        $path = Join-Path $stage ('installers\' + $asset.name)
        if ((Get-Item -LiteralPath $path).Length -ne [long]$asset.size -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -ne $asset.sha256) { throw 'Installer pin mismatch' }
        if ($key -ne 'proxifyre_msi') { Assert-Signature $path }
        $skip = $false
        if ($key -eq 'vc_redist') {
            $runtime = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64' -ErrorAction SilentlyContinue
            if ($runtime -and $runtime.Installed -eq 1 -and [version]$runtime.Version.TrimStart('v') -ge [version]'14.44.35211.0') { $skip = $true }
        }
        if ($key -eq 'ndis_msi') {
            $driver = Join-Path $env:SystemRoot 'System32\drivers\ndisrd.sys'
            if ((Get-Service NDISRD -ErrorAction SilentlyContinue) -and (Test-Path -LiteralPath $driver)) {
                Assert-Signature $driver
                $driverVersion = [version](Get-Item -LiteralPath $driver).VersionInfo.FileVersion
                if ($driverVersion -ge [version]'3.6.1.0' -and $driverVersion -lt [version]'4.0.0.0') { $skip = $true }
                else { throw 'An incompatible shared NDIS driver is installed; refusing replacement' }
            }
        }
        if (-not $skip) {
            if ($key -eq 'proxifyre_msi') {
                $control = Get-CimInstance Win32_Service -Filter "Name='RuleProxyControl'"
                if ($control -and $control.PathName -ne $serviceCommand) { throw 'Unexpected control service executable' }
                if ($control) { Stop-Service -Name $serviceName -ErrorAction Stop }
                if (Get-Service ProxiFyreService -ErrorAction SilentlyContinue) { Stop-Service ProxiFyreService -ErrorAction Stop }
                # Record ownership intent before MSI can create the service, so
                # a power loss between installation and result persistence can resume.
                $pfOwned = $true
                Write-State 'installing_proxifyre_msi' $pfOwned
            }
            $log = Join-Path $logRoot ($key + '.log')
            if ($key -eq 'vc_redist') { $code = Invoke-Installer $path ('/install /quiet /norestart /log "' + $log + '"') $key }
            else { $code = Invoke-Installer (Join-Path $env:SystemRoot 'System32\msiexec.exe') ('/i "' + $path + '" /qn /norestart /L*v "' + $log + '"') $key }
            if ($key -eq 'proxifyre_msi') { $pfOwned = $true }
            if ($code -eq 3010) { Write-State 'reboot_required' $pfOwned; exit 3010 }
            Write-State ('installed_' + $key) $pfOwned
        }
    }
    Assert-Signature (Join-Path $env:SystemRoot 'System32\drivers\ndisrd.sys')
    $config = Join-Path $pfRoot 'app-config.json'
    if (-not (Test-Path -LiteralPath $config)) {
        # A deliberately unmatchable rule keeps a fresh service harmless until
        # the owner imports YAML and selects applications through the Web panel.
        [IO.File]::WriteAllText($config, '{"logLevel":"Info","bypassLan":false,"excludes":[],"proxies":[{"appNames":["RuleProxy-No-Selected-Application-71d8c7.exe"],"socks5ProxyEndpoint":"127.0.0.1:9","supportedProtocols":["TCP","UDP"],"supportedAddressFamilies":["IPv4","IPv6"]}]}', $utf8)
    }
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
    $deployment = [ordered]@{schema_version=1; owner_sid=$OwnerSid; root=$root; proxifyre_root=$pfRoot;
        service_name=$serviceName; pipe_name=('RuleProxyControl-v1-' + $sidHash); files=$files; proxifyre_files=$pfFiles}
    [IO.File]::WriteAllText((Join-Path $stage 'deployment.json'), ($deployment|ConvertTo-Json -Depth 6), $utf8)
    if (Test-Path -LiteralPath $root) {
        # Close only the owner's old private panel/core before replacing files.
        # Selected applications have external executable paths and are retained.
        foreach ($ownedProcess in Get-CimInstance Win32_Process) {
            if ($ownedProcess.ExecutablePath -and $ownedProcess.ExecutablePath.StartsWith($root + '\',[StringComparison]::OrdinalIgnoreCase)) {
                $processOwner = Invoke-CimMethod -InputObject $ownedProcess -MethodName GetOwnerSid
                if ($processOwner.Sid -eq $OwnerSid) { Stop-Process -Id $ownedProcess.ProcessId -Force -ErrorAction Stop }
            }
        }
        Move-Item -LiteralPath $root -Destination $backup
        $oldRootMoved = $true
    }
    Move-Item -LiteralPath $stage -Destination $root
    $swapped = $true
    Protect-Tree $root
    $existingService = Get-CimInstance Win32_Service -Filter "Name='RuleProxyControl'"
    if ($existingService -and $existingService.PathName -ne $serviceCommand) { throw 'Refuse a non-owned control service' }
    if (-not $existingService) {
        New-Service -Name $serviceName -DisplayName 'RuleProxy Web Control' -BinaryPathName $serviceCommand -StartupType Automatic | Out-Null
    }
    Start-Service -Name $serviceName
    (Get-Service -Name $serviceName).WaitForStatus('Running',[TimeSpan]::FromSeconds(30))
    Write-State 'completed' $true
    if ($oldRootMoved) { Remove-Item -LiteralPath $backup -Recurse -Force }
    Write-Host 'RuleProxy installed. Start-Windows.cmd opens the ordinary-user Web panel.'
} catch {
    if ($swapped) {
        $control = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($control) { try { Stop-Service -Name $serviceName -ErrorAction Stop } catch {} }
        if ($oldRootMoved) {
            Remove-Item -LiteralPath $root -Recurse -Force
            Move-Item -LiteralPath $backup -Destination $root
            try { Start-Service -Name $serviceName } catch {}
        }
    }
    try { Write-State 'failed' $pfOwned } catch {}
    throw
} finally {
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
