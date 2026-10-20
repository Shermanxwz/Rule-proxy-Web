# Invoked by the normal interactive Startup folder, never a SYSTEM test task.
$ErrorActionPreference = 'Stop'
$root = 'C:\RuleProxyCI'
$result = @{schema_version=1; ordinary_account=$false; stock_build_verified=$false; servicing_verified=$false; harness_completed=$false; stage0_passed=$false}
$phase='configuration'; $failed=$false; $hresult=$null; $pythonExit=$null; $failureCategory='operation_failed'
# Pure predicates: fixed Windows path identity is case-insensitive, not alias tolerant.
function Test-InstalledDriveC($Value) {
    return ($Value -is [string] -and $Value -cmatch '^[A-Za-z]:$' -and
        [String]::Equals($Value,'C:',[StringComparison]::OrdinalIgnoreCase))
}
function Test-InstalledWindowsDirectory($Value) {
    if ($Value -isnot [string] -or $Value -notmatch '^[A-Za-z]:\\Windows$') { return $false }
    try {
        return [String]::Equals([IO.Path]::GetFullPath($Value),'C:\Windows',[StringComparison]::OrdinalIgnoreCase)
    } catch { return $false }
}
function Get-InstalledBootGates([hashtable]$Facts) {
    $gates=[ordered]@{product_winnt=$null;arch_amd64=$null;setup_not_busy=$null;oobe_not_busy=$null;
        image_complete=$null;env_drive_c=$null;os_drive_c=$null;windows_directory=$null;
        fixed_drive=$null;build_26200=$null;ubr_stock_or_target=$null}
    if ($Facts.ContainsKey('product')) { $gates.product_winnt=($Facts.product -ceq 'WinNT') }
    if ($Facts.ContainsKey('architecture')) { $gates.arch_amd64=($Facts.architecture -ceq 'AMD64') }
    if ($Facts.ContainsKey('system_setup')) { $gates.setup_not_busy=($null -ne $Facts.system_setup -and $Facts.system_setup -eq 0) }
    if ($Facts.ContainsKey('oobe_present')) {
        $gates.oobe_not_busy=($Facts.oobe_present -eq $false -or
            ($Facts.oobe_present -eq $true -and $Facts.ContainsKey('oobe') -and $null -ne $Facts.oobe -and $Facts.oobe -eq 0))
    }
    if ($Facts.ContainsKey('image')) { $gates.image_complete=($Facts.image -ceq 'IMAGE_STATE_COMPLETE') }
    if ($Facts.ContainsKey('env_drive')) { $gates.env_drive_c=Test-InstalledDriveC $Facts.env_drive }
    if ($Facts.ContainsKey('os_drive')) { $gates.os_drive_c=Test-InstalledDriveC $Facts.os_drive }
    if ($Facts.ContainsKey('windows_directory')) { $gates.windows_directory=Test-InstalledWindowsDirectory $Facts.windows_directory }
    if ($Facts.ContainsKey('drive_type')) { $gates.fixed_drive=($null -ne $Facts.drive_type -and $Facts.drive_type -eq 3) }
    if ($Facts.ContainsKey('build')) { $gates.build_26200=([string]$Facts.build -ceq '26200') }
    if ($Facts.ContainsKey('ubr')) { $gates.ubr_stock_or_target=([string]$Facts.ubr -cin @('6584','9711')) }
    return $gates
}
function Get-ClosedEarlyDiagnostic {
    param([string]$Phase,[string]$Operation,[string]$Category,$HResult,$Gates)
    $phases=@('configuration','identity','installed_boot_gate','installed_setup_wait','beacon','servicing_wait','serviced_build',
        'claim','endpoint','payload_download','payload_hash','payload_extract','python_hash','python_extract',
        'python_start','python_wait','report_read','report_parse','completed','transport')
    $operations=@('configuration_read','identity','cim_os','cim_drive','version','product','setup','image','gate','beacon','waiting_setup','other')
    $categories=@('none','operation_failed','identity_gate','stock_build_gate','endpoint_timeout','payload_bound','payload_overrun',
        'payload_incomplete','payload_hash','python_hash','python_not_started','process_handle_missing','python_deadline',
        'report_absent','report_over_bound','report_nonobject','report_parse','installed_boot_gate','installed_setup_deadline',
        'servicing_receipt','servicing_failed','servicing_deadline','serviced_build_gate')
    $knownGates=Get-InstalledBootGates @{}
    foreach ($key in @($knownGates.Keys)) {
        if ($Gates -is [Collections.IDictionary] -and $Gates.Contains($key) -and $Gates[$key] -is [bool]) { $knownGates[$key]=$Gates[$key] }
    }
    $code=$null
    if (($HResult -is [int] -or $HResult -is [long]) -and $HResult -ge -2147483648L -and $HResult -le 2147483647L) { $code=[long]$HResult }
    $record=[ordered]@{schema=1;phase=$(if ($Phase -cin $phases) {$Phase} else {'configuration'});
        operation=$(if ($Operation -cin $operations) {$Operation} else {'other'});
        failure_category=$(if ($Category -cin $categories) {$Category} else {'operation_failed'});
        hresult=$code;gates=$knownGates}
    $json=$record | ConvertTo-Json -Depth 4 -Compress
    if ([Text.Encoding]::ASCII.GetByteCount($json) -gt 2048 -or $json -match '[^\x20-\x7e]') { return }
    return $json
}
function Write-ClosedEarlyDiagnostic {
    param([string]$Phase,[string]$Operation,[string]$Category,$HResult,$Gates)
    $json=Get-ClosedEarlyDiagnostic -Phase $Phase -Operation $Operation -Category $Category -HResult $HResult -Gates $Gates
    if (-not $json) { return }
    $port=New-Object IO.Ports.SerialPort('COM1',115200)
    try { $port.WriteTimeout=2000; $port.Open(); $port.Write('RPDIAG1 '+$json+"`r`n") } finally { $port.Dispose() }
}
$earlyBootGateCompleted=$false; $earlyOperation='configuration_read'; $bootFacts=@{}; $bootGates=Get-InstalledBootGates $bootFacts
function Set-ClosedResultField {
    param([string]$Name, $Value)
    if ($script:result -is [hashtable]) { $script:result[$Name]=$Value }
    else { $script:result | Add-Member -NotePropertyName $Name -NotePropertyValue $Value -Force }
}
function Assert-UpdateFile($Path, [switch]$Directory) {
    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'update_reparse_point' }
    if ($Directory) {
        if (-not $item.PSIsContainer) { throw 'update_directory_required' }
    } elseif ($item.PSIsContainer) { throw 'update_file_required' }
    return $item
}

function Assert-ProtectedUpdatePath($Path, [switch]$Directory, [switch]$ProtectedDacl) {
    $null = Assert-UpdateFile $Path -Directory:$Directory
    $acl = Get-Acl -LiteralPath $Path
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin $trusted) { throw 'update_untrusted_owner' }
    if ($ProtectedDacl -and -not $acl.AreAccessRulesProtected) { throw 'update_directory_inherits_permissions' }
    # An untrusted principal must not change bytes, children, ownership or ACLs.
    $writeMask = [Security.AccessControl.FileSystemRights]::Write -bor
                 [Security.AccessControl.FileSystemRights]::Delete -bor
                 [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                 [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                 [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        if ($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
            ($rule.FileSystemRights -band $writeMask) -ne 0 -and $rule.IdentityReference.Value -notin $trusted) {
            throw 'update_untrusted_write_permission'
        }
    }
}


function ConvertTo-ServicedDeadline($Epoch, [DateTime]$Now) {
    if (($Epoch -isnot [int] -and $Epoch -isnot [long]) -or $Epoch -le 0) { throw 'service_deadline' }
    $deadline=[DateTimeOffset]::FromUnixTimeSeconds([long]$Epoch).UtcDateTime
    if ($deadline -le $Now -or ($deadline-$Now).TotalSeconds -gt 9600) { throw 'service_deadline' }
    return $deadline
}
function Get-ServicedDeadline {
    $path=Join-Path 'C:\RuleProxyCIUpdates' 'service-budget.json'
    Assert-ProtectedUpdatePath $path
    if ((Get-Item -LiteralPath $path).Length -gt 1024) { throw 'service_deadline' }
    $budget=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($budget.schema -ne 1) { throw 'service_deadline' }
    return ConvertTo-ServicedDeadline $budget.deadline_unix_seconds ([DateTime]::UtcNow)
}
function Expand-CheckedStage0Zip {
    param([string]$ArchivePath, [string]$Destination, [string[]]$RequiredNames,
          [int]$MemberCount, [long]$ExactBytes, [long]$MaximumBytes, [bool]$Flat, [bool]$ExactNames)
    # Both archives are digest checked first. Still reject Windows aliases,
    # duplicate names, links, directories and expansion overruns before writes.
    if (Test-Path -LiteralPath $Destination) { throw 'Fresh extraction directory required' }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        if ($zip.Entries.Count -ne $MemberCount) { throw 'ZIP member count differs' }
        $seen = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        $expanded = 0L
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            $kind = (($entry.ExternalAttributes -shr 16) -band 0xf000)
            if (-not $name -or $name.StartsWith('/') -or $name.Contains('\') -or $name.Contains(':') -or
                $name.IndexOf([char]0) -ge 0 -or -not $entry.Name -or
                ($Flat -and $name.Contains('/')) -or $kind -notin @(0,0x8000) -or
                ($entry.ExternalAttributes -band 0x10) -ne 0 -or
                -not $seen.Add($name) -or ($ExactNames -and $RequiredNames -cnotcontains $name)) { throw 'Unsafe ZIP member' }
            foreach ($part in $name.Split('/')) {
                if (-not $part -or $part -in @('.','..') -or $part.TrimEnd([char[]]' .') -cne $part -or
                    $part -match '^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$') { throw 'Unsafe ZIP path' }
            }
            if ($entry.Length -lt 0 -or $entry.Length -gt $MaximumBytes) { throw 'ZIP entry bound' }
            $expanded += $entry.Length
            if ($expanded -gt $MaximumBytes) { throw 'ZIP expansion bound' }
        }
        foreach ($name in $RequiredNames) {
            if (-not $seen.Contains($name)) { throw 'Required ZIP member absent' }
        }
        if ($ExactBytes -gt 0 -and $expanded -ne $ExactBytes) { throw 'ZIP expansion differs' }
        $base = [IO.Path]::GetFullPath($Destination) + '\'
        [void][IO.Directory]::CreateDirectory($Destination)
        foreach ($entry in $zip.Entries) {
            $target = [IO.Path]::GetFullPath((Join-Path $Destination $entry.FullName))
            if (-not $target.StartsWith($base,[StringComparison]::OrdinalIgnoreCase)) { throw 'ZIP path escaped' }
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target))
            $input=$output=$null
            try {
                $input=$entry.Open(); $output=[IO.File]::Open($target,[IO.FileMode]::CreateNew)
                $buffer=[byte[]]::new(65536); $written=0L
                while (($count=$input.Read($buffer,0,$buffer.Length)) -gt 0) {
                    $written+=$count
                    if ($written -gt $entry.Length) { throw 'ZIP entry overrun' }
                    $output.Write($buffer,0,$count)
                }
                if ($written -ne $entry.Length) { throw 'ZIP entry incomplete' }
            } finally {
                if ($null -ne $input) { $input.Dispose() }
                if ($null -ne $output) { $output.Dispose() }
            }
        }
    } finally { $zip.Dispose() }
}
try {
    $configuration = Get-Content -LiteralPath (Join-Path $root 'ruleproxy-vm-config.json') -Raw | ConvertFrom-Json
    $phase='identity'; $earlyOperation='identity'
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($identity.Name -ne 'RULEPROXY-VM\RuleProxyCI' -or
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
        [Diagnostics.Process]::GetCurrentProcess().SessionId -le 0) { $failureCategory='identity_gate'; throw 'Genuine ordinary account required' }
    $phase='installed_boot_gate'
    $earlyOperation='cim_os'; $bootOS=Get-CimInstance -ClassName Win32_OperatingSystem
    $bootFacts.os_drive=$bootOS.SystemDrive; $bootFacts.windows_directory=$bootOS.WindowsDirectory
    $bootGates=Get-InstalledBootGates $bootFacts
    $earlyOperation='cim_drive'; $bootDrive=Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"
    $bootFacts.drive_type=$bootDrive.DriveType; $bootGates=Get-InstalledBootGates $bootFacts
    $earlyOperation='version'; $bootVersion=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $bootFacts.build=$bootVersion.CurrentBuildNumber; $bootFacts.ubr=$bootVersion.UBR
    $bootFacts.architecture=$env:PROCESSOR_ARCHITECTURE; $bootFacts.env_drive=$env:SystemDrive
    $bootGates=Get-InstalledBootGates $bootFacts
    $earlyOperation='product'; $bootType=[string](Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType
    $bootFacts.product=$bootType; $bootGates=Get-InstalledBootGates $bootFacts
    $earlyOperation='gate'
    foreach ($key in @('product_winnt','arch_amd64','env_drive_c','os_drive_c','windows_directory','fixed_drive','build_26200','ubr_stock_or_target')) {
        if ($bootGates[$key] -ne $true) { $failureCategory='installed_boot_gate'; throw 'Installed fixed-disk guest required' }
    }
    # First-login setup flags can still be transitioning. Wait only for these
    # three completion facts, never bypass or mutate them; fixed OS gates held above.
    $phase='installed_setup_wait'; $setupReadyDeadline=[DateTime]::UtcNow.AddSeconds(120)
    do {
        $earlyOperation='setup'; $setup=Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\Setup'
        $bootFacts.system_setup=$setup.SystemSetupInProgress
        $bootFacts.oobe_present=('OOBEInProgress' -in @($setup.PSObject.Properties.Name))
        if ($bootFacts.oobe_present) { $bootFacts.oobe=$setup.OOBEInProgress }
        $bootGates=Get-InstalledBootGates $bootFacts
        $earlyOperation='image'; $image=Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State'
        $bootFacts.image=$image.ImageState; $bootGates=Get-InstalledBootGates $bootFacts
        if ($bootGates.setup_not_busy -eq $true -and $bootGates.oobe_not_busy -eq $true -and $bootGates.image_complete -eq $true) { break }
        $earlyOperation='waiting_setup'
        if ([DateTime]::UtcNow -ge $setupReadyDeadline) { $failureCategory='installed_setup_deadline'; throw 'Setup completion deadline' }
        Start-Sleep -Seconds 2
    } while ($true)
    if ([int]$bootVersion.UBR -eq 6584) {
        $phase='beacon'; $earlyOperation='beacon'
        $port = New-Object IO.Ports.SerialPort('COM1',115200)
        try { $port.WriteTimeout=2000; $port.Open(); $port.Write("RPBEACON identity-stock-installed-ready`r`n") } finally { $port.Dispose() }
    }
    $earlyBootGateCompleted=$true
    $phase='servicing_wait'; $earlyOperation='other'
    Assert-ProtectedUpdatePath 'C:\RuleProxyCIUpdates' -Directory -ProtectedDacl
    $statePath='C:\RuleProxyCIUpdates\update-state.json'
    $servicingDeadline=Get-ServicedDeadline
    do {
        if (Test-Path -LiteralPath $statePath) {
            Assert-ProtectedUpdatePath $statePath
            $item=Get-Item -LiteralPath $statePath -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 4096) { $failureCategory='servicing_receipt'; throw 'Closed servicing receipt rejected' }
            $service=Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            if ($service.status -ceq 'failed') { $failureCategory='servicing_failed'; throw 'Pinned servicing failed' }
            if ([DateTime]::UtcNow -ge $servicingDeadline) { $failureCategory='servicing_deadline'; throw 'Servicing deadline' }
            if ($service.status -ceq 'completed') { break }
        }
        if ([DateTime]::UtcNow -ge $servicingDeadline) { $failureCategory='servicing_deadline'; throw 'Servicing deadline' }
        Start-Sleep -Seconds 5
    } while ($true)
    $phase='serviced_build'
    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $type = [string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType
    if ([int]$os.CurrentBuildNumber -ne 26200 -or [int]$os.UBR -ne 9711 -or $type -ne 'WinNT' -or
        $env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or $service.schema_version -ne 1 -or
        $service.target_build -ne 26200 -or $service.target_ubr -ne 9711 -or
        $service.actual_build -ne 26200 -or $service.actual_ubr -ne 9711 -or
        $service.completed -ne $true -or $service.packages_verified -ne $true -or
        $service.reboot_observed -ne $true -or $service.reboot_required -ne $false -or
        $service.task_unregistered -ne $true -or
        $service.before_boot -isnot [string] -or $service.after_boot -isnot [string] -or
        $service.before_boot -ceq $service.after_boot -or
        $service.after_boot -cne $bootOS.LastBootUpTime.ToUniversalTime().Ticks.ToString() -or
        $service.dism_exit_code -notin @(0,3010)) {
        $failureCategory='serviced_build_gate'; throw 'Exact serviced client gate failed'
    }
    $phase='beacon'
    $port = New-Object IO.Ports.SerialPort('COM1',115200)
    try { $port.WriteTimeout=2000; $port.Open(); $port.Write("RPBEACON identity-ordinary-ready`r`n") } finally { $port.Dispose() }
    # Claim only after the verified servicing reboot, never on the stock startup.
    $phase='claim'
    $claim = [IO.File]::Open((Join-Path $root 'identity-stage0-claimed'),[IO.FileMode]::CreateNew)
    $claim.Dispose()
    $payload = Join-Path $root 'identity-payload.zip'
    # Host connects user NAT after reading the fixed ordinary-user beacon.
    $phase='endpoint'
    $endpoint = [Uri]$configuration.host_url
    $connected = $false
    for ($attempt=0; $attempt -lt 60; $attempt++) {
        $socket = New-Object Net.Sockets.TcpClient
        $pending = $null
        try {
            $pending = $socket.BeginConnect($endpoint.Host,$endpoint.Port,$null,$null)
            if ($pending.AsyncWaitHandle.WaitOne(1000)) { $socket.EndConnect($pending); $connected=$true; break }
        } catch {} finally {
            if ($null -ne $pending) { $pending.AsyncWaitHandle.Close() }
            $socket.Dispose()
        }
        Start-Sleep -Seconds 1
    }
    if (-not $connected) { $failureCategory='endpoint_timeout'; throw 'Owned endpoint timeout' }
    $phase='payload_download'
    $request=[Net.HttpWebRequest]::Create($configuration.host_url + '/payload.zip')
    $request.Proxy=$null; $request.Timeout=30000; $request.ReadWriteTimeout=30000
    $request.AllowAutoRedirect=$false
    $response=$request.GetResponse()
    $input=$output=$null
    try {
        if ($response.ContentLength -le 0 -or $response.ContentLength -gt 268435456) { $failureCategory='payload_bound'; throw 'Payload bound' }
        $input=$response.GetResponseStream()
        $output=[IO.File]::Open($payload,[IO.FileMode]::CreateNew)
        $buffer=[byte[]]::new(65536); $total=0L
        while (($count=$input.Read($buffer,0,$buffer.Length)) -gt 0) {
            $total+=$count
            if ($total -gt $response.ContentLength) { $failureCategory='payload_overrun'; throw 'Payload overrun' }
            $output.Write($buffer,0,$count)
        }
        if ($total -ne $response.ContentLength) { $failureCategory='payload_incomplete'; throw 'Payload incomplete' }
    } finally {
        if ($null -ne $input) { $input.Dispose() }
        if ($null -ne $output) { $output.Dispose() }
        $response.Dispose()
    }
    $phase='payload_hash'
    if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.payload_sha256) { $failureCategory='payload_hash'; throw 'Payload digest mismatch' }
    $workspace = Join-Path $root 'identity-workspace'
    $payloadNames = @('python-embed.zip','actor.exe','stage0-input.json',
        'g/wxc-exec.exe','g/build-manifest.json','g/MXC-LICENSE.md',
        '.github/windows_identity_serviced_stage0.py','.github/windows_identity_proof.py',
        '.github/windows_psec_compartment_smoke.py','ruleproxy/windows_runtime_pins.py')
    $phase='payload_extract'
    Expand-CheckedStage0Zip -ArchivePath $payload -Destination $workspace -RequiredNames $payloadNames `
        -MemberCount 10 -ExactBytes 0 -MaximumBytes 134217728 -Flat $false -ExactNames $true
    $runtime = Join-Path $workspace 'python-embed.zip'
    $pythonDigest = 'a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310'
    $phase='python_hash'
    if ((Get-Item -LiteralPath $runtime).Length -ne 12601679 -or $configuration.python_sha256 -cne $pythonDigest -or
        (Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pythonDigest) { $failureCategory='python_hash'; throw 'Pinned Python mismatch' }
    $pythonNames = @('python.exe','python314.dll','python3.dll','python314.zip','python314._pth',
        '_ctypes.pyd','_socket.pyd','_hashlib.pyd','select.pyd','libffi-8.dll','libcrypto-3.dll',
        'vcruntime140.dll','vcruntime140_1.dll','LICENSE.txt')
    $phase='python_extract'
    Expand-CheckedStage0Zip -ArchivePath $runtime -Destination (Join-Path $workspace 'python') -RequiredNames $pythonNames `
        -MemberCount 37 -ExactBytes 24405990 -MaximumBytes 24405990 -Flat $true -ExactNames $false
    $python = Join-Path $workspace 'python\python.exe'
    $public = Join-Path $workspace 'public-stage0.json'
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$python
    $info.Arguments='-I -S -B "' + (Join-Path $workspace '.github\windows_identity_serviced_stage0.py') + '" --guest --output "' + $public + '"'
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    # All diagnostics remain inside the VM. Do not stream raw actor paths/SIDs.
    $child = New-Object Diagnostics.Process
    $child.StartInfo=$info
    try {
        $phase='python_start'
        if (-not $child.Start()) { $failureCategory='python_not_started'; throw 'Stage0 did not start' }
        $heldHandle=$child.Handle
        if ($heldHandle -eq [IntPtr]::Zero) { $failureCategory='process_handle_missing'; throw 'Owned process handle missing' }
        $phase='python_wait'
        if (-not $child.WaitForExit(120000)) { $child.Kill(); [void]$child.WaitForExit(5000); $failureCategory='python_deadline'; throw 'Stage0 deadline' }
        $pythonExit=[int]$child.ExitCode
        $phase='report_read'
        if (-not (Test-Path -LiteralPath $public)) { $failureCategory='report_absent'; throw 'Bounded closed report absent' }
        if ((Get-Item -LiteralPath $public).Length -gt 16384) { $failureCategory='report_over_bound'; throw 'Bounded closed report absent' }
        $phase='report_parse'; $failureCategory='report_parse'
        $candidate = Get-Content -LiteralPath $public -Raw | ConvertFrom-Json
        if ($null -eq $candidate -or $candidate -isnot [PSCustomObject]) { $failureCategory='report_nonobject'; throw 'Closed report object required' }
        $result = $candidate
        if ($child.ExitCode -ne 0) { $result.stage0_passed=$false }
    } finally { $child.Dispose() }
    $result | Add-Member -NotePropertyName servicing_verified -NotePropertyValue $true -Force
    $result | Add-Member -NotePropertyName os -NotePropertyValue @{build=[int]$os.CurrentBuildNumber; ubr=[int]$os.UBR; product_type=$type; architecture=$env:PROCESSOR_ARCHITECTURE} -Force
    $phase='completed'; $failureCategory='none'
} catch {
    $failed=$true; $hresult=[int]$_.Exception.HResult
    # Closed failure only. Never export exception strings, identities or paths.
    $result.stage0_passed=$false
} finally {
    if ($failed -and -not $earlyBootGateCompleted) {
        try { Write-ClosedEarlyDiagnostic -Phase $phase -Operation $earlyOperation -Category $failureCategory -HResult $hresult -Gates $bootGates } catch {}
    }
    $status = if ($result.stage0_passed -eq $true) { 'passed' } else { 'failed' }
    if ($result -is [hashtable]) { $result.status=$status } else { $result | Add-Member -NotePropertyName status -NotePropertyValue $status -Force }
    $serviceFacts=@{dism_wait_timed_out=$false; dism_exit_observed=$false; dism_exit_observation_available=$false; phase='not_observed'; failure='none'; dism_exit_code=$null; packages_verified=$false; reboot_observed=$false; task_unregistered=$false; completed=$false}
    if ($null -ne (Get-Variable -Name service -ErrorAction SilentlyContinue)) {
        $phases=@('initializing','waiting_for_optical','verifying_optical','post_reboot_verify','installing_official_cu','reboot_pending','completed')
        $failures=@('none','service_deadline','system_required','prior_bound','prior_state','setup_deadline','optical_deadline',
            'optical_device','optical_root','optical_members','optical_package','optical_changed',
            'reboot_not_observed','exact_serviced_build','reboot_still_pending','task_remains',
            'exact_stock_build','dism_log_exists','dism_handle','dism_deadline','dism_exit_absent','dism_failed','operation_failed')
        $serviceFacts.phase=if ($service.phase -cin $phases) { [string]$service.phase } else { 'unclassified' }
        $serviceFacts.failure=if ($service.failure -cin $failures) { [string]$service.failure } else { 'unclassified' }
        if ($service.dism_exit_code -is [int] -or $service.dism_exit_code -is [long]) { $serviceFacts.dism_exit_code=[long]$service.dism_exit_code }
        foreach ($name in @('packages_verified','reboot_observed','task_unregistered','completed','dism_wait_timed_out','dism_exit_observed','dism_exit_observation_available')) { $serviceFacts[$name]=($service.$name -eq $true) }
    }
    Set-ClosedResultField 'servicing_diagnostic' $serviceFacts
    $launcher=@{phase=$phase; failure_category=$failureCategory; failed=$failed; hresult=$hresult; python_exit_code=$pythonExit; transport_attempt=0}
    Set-ClosedResultField 'launcher_diagnostic' $launcher
    $delivered=$false
    for ($i=0; $i -lt 3; $i++) {
        try {
            $launcher.transport_attempt=$i+1
            # Deep closed facts must remain JSON objects, not PS string summaries.
            $body = [Text.Encoding]::ASCII.GetBytes(($result | ConvertTo-Json -Depth 10 -Compress))
            if ($body.Length -gt 16384) { throw 'Closed report transport bound' }
            $request=[Net.HttpWebRequest]::Create($configuration.host_url + '/result')
            $request.Method='POST'; $request.Proxy=$null; $request.Timeout=10000; $request.ReadWriteTimeout=10000
            $request.ContentType='application/json'; $request.ContentLength=$body.Length
            $stream=$request.GetRequestStream(); try { $stream.Write($body,0,$body.Length) } finally { $stream.Dispose() }
            $response=$request.GetResponse(); $response.Dispose(); $delivered=$true; break
        } catch { Start-Sleep -Seconds 2 }
    }
    if (-not $delivered) {
        # Fixed closed marker only, on the already existing serial channel.
        # The host records it but retains its original wait/deadline behavior.
        try {
            $port = New-Object IO.Ports.SerialPort('COM1',115200)
            try { $port.WriteTimeout=2000; $port.Open(); $port.Write("RPBEACON identity-result-transport-failed`r`n") } finally { $port.Dispose() }
        } catch {}
    }
}
