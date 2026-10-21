# Exploratory direct 26300.9457, below documented support floor 26300.9550.
# Product acceptance is always false; Stage0 checks do not relax proof requirements.
# Invoked by the normal interactive Startup folder, never a SYSTEM test task.
$ErrorActionPreference = 'Stop'
$root = 'C:\RuleProxyCI'
$result = @{schema_version=1; ordinary_account=$false; direct_build_verified=$false; exploratory_stage0=$true; product_acceptance=$false; documented_support_floor='26300.9550'; harness_completed=$false; stage0_passed=$false}
$udpEnabled=$false; $n0aEnabled=$false; $n0aDeadline=0L; $n0aFrequency=0L; $n0aOriginalReady=$false
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
        fixed_drive=$null;build_26300=$null;ubr_direct=$null}
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
    if ($Facts.ContainsKey('build')) { $gates.build_26300=([string]$Facts.build -ceq '26300') }
    if ($Facts.ContainsKey('ubr')) { $gates.ubr_direct=([string]$Facts.ubr -ceq '9457') }
    return $gates
}
function Get-ClosedEarlyDiagnostic {
    param([string]$Phase,[string]$Operation,[string]$Category,$HResult,$Gates)
    $phases=@('configuration','identity','installed_boot_gate','installed_setup_wait','beacon',
        'claim','endpoint','payload_download','payload_hash','payload_extract','python_hash','python_extract',
        'python_start','python_wait','report_read','report_parse','completed','transport')
    $operations=@('configuration_read','identity','cim_os','cim_drive','version','product','setup','image','gate','beacon','waiting_setup','other')
    $categories=@('none','operation_failed','identity_gate','direct_build_gate','endpoint_timeout','payload_bound','payload_overrun',
        'payload_incomplete','payload_hash','python_hash','python_not_started','process_handle_missing','python_deadline',
        'report_absent','report_over_bound','report_nonobject','report_parse','installed_boot_gate','installed_setup_deadline')
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
# Optional N0a is a separate diagnostic; none of these fields alter Stage0.
function Test-N0aConfiguration($Value) {
    if ($null -eq $Value -or $Value -isnot [PSCustomObject]) { return $false }
    $keys=@('enabled','case_nonce','runner_port','actor_sha256','manifest_sha256','actor_source_sha256','identity_source_sha256')
    if (@($Value.PSObject.Properties).Count -ne $keys.Count) { return $false }
    foreach ($key in $keys) { if ($key -cnotin @($Value.PSObject.Properties.Name)) { return $false } }
    if ($Value.enabled -isnot [bool] -or $Value.enabled -ne $true -or $Value.case_nonce -isnot [string] -or $Value.case_nonce -cnotmatch '^[0-9a-f]{32}$') { return $false }
    if (($Value.runner_port -isnot [int] -and $Value.runner_port -isnot [long]) -or $Value.runner_port -lt 1025 -or $Value.runner_port -gt 65535) { return $false }
    foreach ($key in @('actor_sha256','manifest_sha256','actor_source_sha256','identity_source_sha256')) {
        if ($Value.$key -isnot [string] -or $Value.$key -cnotmatch '^[0-9a-f]{64}$') { return $false }
    }
    return $true
}
function Get-N0aRemainingMilliseconds([long]$Deadline,[long]$Frequency,[long]$Now) {
    if ($Frequency -le 0 -or $Frequency -gt 1000000000 -or $Now -lt 0 -or $Deadline -le $Now) { return 0 }
    return [int][Math]::Min(120000,[Math]::Floor((($Deadline-$Now)/[double]$Frequency)*1000))
}
function Wait-N0aOwnedChild($Child,[int]$Milliseconds) {
    $facts=@{process_exit_confirmed=$false;timed_out=$false;python_exit_code=$null}
    try {
        if ($Milliseconds -le 0 -or -not $Child.WaitForExit($Milliseconds)) {
            $facts.timed_out=$true
            try { $Child.Kill() } catch {}
            try { $facts.process_exit_confirmed=($Child.WaitForExit(5000) -eq $true) } catch {}
        } else { $facts.process_exit_confirmed=$true }
        if ($facts.process_exit_confirmed) { try { $facts.python_exit_code=[int]$Child.ExitCode } catch {} }
    } catch {
        try { $Child.Kill() } catch {}
        try { $facts.process_exit_confirmed=($Child.WaitForExit(5000) -eq $true) } catch {}
    }
    return $facts
}
function Write-N0aBoundedBody($Stream,[byte[]]$Body,[int]$RemainingMilliseconds) {
    if ($RemainingMilliseconds -le 0 -or -not $Stream.CanTimeout) { return $false }
    $Stream.WriteTimeout=$RemainingMilliseconds
    $Stream.Write($Body,0,$Body.Length)
    return $true
}
function Send-N0aClosedReport([string]$Url,[byte[]]$Body) {
    if ($Body.Length -gt 4096) { return $false }
    $request=$null; $stream=$null; $response=$null; $clock=[Diagnostics.Stopwatch]::StartNew()
    try {
        $request=[Net.HttpWebRequest]::Create($Url); $request.Method='POST'; $request.Proxy=$null
        $request.Timeout=10000; $request.ReadWriteTimeout=10000; $request.AllowAutoRedirect=$false
        $request.ContentType='application/json'; $request.ContentLength=$Body.Length
        $pending=$request.BeginGetRequestStream($null,$null)
        try { if (-not $pending.AsyncWaitHandle.WaitOne([Math]::Max(0,10000-[int]$clock.ElapsedMilliseconds))) { return $false } }
        finally { $pending.AsyncWaitHandle.Close() }
        $stream=$request.EndGetRequestStream($pending)
        $left=10000-[int]$clock.ElapsedMilliseconds; if ($left -le 0) { return $false }
        if (-not (Write-N0aBoundedBody $stream $Body $left)) { return $false }
        $stream.Dispose(); $stream=$null
        $pending=$request.BeginGetResponse($null,$null)
        try { if (-not $pending.AsyncWaitHandle.WaitOne([Math]::Max(0,10000-[int]$clock.ElapsedMilliseconds))) { return $false } }
        finally { $pending.AsyncWaitHandle.Close() }
        $response=$request.EndGetResponse($pending)
        return ($clock.ElapsedMilliseconds -le 10000 -and [int]$response.StatusCode -eq 200)
    } catch { return $false }
    finally {
        if ($null -ne $stream) { try { $stream.Dispose() } catch {} }
        if ($null -ne $response) { try { $response.Dispose() } catch {} }
        if ($null -ne $request) { try { $request.Abort() } catch {} }
    }
}

function Test-N0aCaptureConfiguration($Value) {
    if ($null -eq $Value -or @($Value.PSObject.Properties.Name).Count -ne 4) { return $false }
    foreach ($key in @('enabled','run_nonce','source_commit','vm_mac')) { if ($key -cnotin @($Value.PSObject.Properties.Name)) { return $false } }
    if ($Value.enabled -isnot [bool] -or -not $Value.enabled) { return $false }
    foreach ($pair in @(@('run_nonce',32),@('source_commit',40),@('vm_mac',12))) {
        if ($Value.($pair[0]) -isnot [string] -or $Value.($pair[0]) -cnotmatch ('\A[0-9a-f]{'+$pair[1]+'}\z')) { return $false }
    }
    return ($Value.vm_mac -cne '000000000000' -and ([Convert]::ToInt32($Value.vm_mac.Substring(0,2),16) -band 1) -eq 0)
}
function Get-N0aSha256([byte[]]$Bytes) {
    $hash=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
}
function Get-N0aFlowCommitment([byte[]]$Bytes) {
    if ($Bytes.Length -le 0 -or $Bytes.Length -gt 65536) { throw 'flow_bound' }
    foreach ($byte in $Bytes) { if ($byte -gt 127) { throw 'flow_encoding' } }
    $value=[Text.Encoding]::ASCII.GetString($Bytes) | ConvertFrom-Json
    $aggregate=[IO.MemoryStream]::new()
    try {
        $prefix=[Text.Encoding]::ASCII.GetBytes("N0A-ordinary-reports-v1`0")
        $aggregate.Write($prefix,0,$prefix.Length)
        foreach ($role in @('before','sample','after')) {
            $row=$value.reports.$role
            if ($row.sha256 -isnot [string] -or $row.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or ($row.bytes -isnot [int] -and $row.bytes -isnot [long]) -or $row.bytes -lt 1 -or $row.bytes -gt 32768) { throw 'flow_source' }
            $label=[Text.Encoding]::ASCII.GetBytes($role+"`0"); $aggregate.Write($label,0,$label.Length)
            $length=[BitConverter]::GetBytes([uint64]$row.bytes); if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($length) }
            $aggregate.Write($length,0,$length.Length)
            for ($index=0; $index -lt 64; $index+=2) { $aggregate.WriteByte([Convert]::ToByte($row.sha256.Substring($index,2),16)) }
        }
        $contained=$value.reports.contained.sha256
        if ($contained -isnot [string] -or $contained -cnotmatch '\A[0-9a-f]{64}\z') { throw 'flow_source' }
        return [ordered]@{sha256=(Get-N0aSha256 $Bytes);bytes=$Bytes.Length;contained_report_sha256=$contained;ordinary_report_sha256=(Get-N0aSha256 $aggregate.ToArray())}
    } finally { $aggregate.Dispose() }
}
function Read-N0aPrivateFlow([string]$Workspace) {
    $parent=Join-Path $Workspace 'private-n0a'; $path=Join-Path $parent 'runner-flow.json'
    $directory=Get-Item -LiteralPath $parent -Force
    $leaf=Get-Item -LiteralPath $path -Force
    if (-not $directory.PSIsContainer -or $leaf.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or ($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'flow_path' }
    if ($leaf.Length -le 0 -or $leaf.Length -gt 65536) { throw 'flow_bound' }
    $stream=$null
    try {
        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $buffer=New-Object byte[] 65537; $count=0
        while ($count -lt $buffer.Length) { $read=$stream.Read($buffer,$count,$buffer.Length-$count); if ($read -eq 0) { break }; $count+=$read }
        if ($count -le 0 -or $count -gt 65536) { throw 'flow_bound' }
        $body=New-Object byte[] $count; [Array]::Copy($buffer,$body,$count)
        return @{body=$body;commitment=(Get-N0aFlowCommitment $body)}
    } finally { if ($null -ne $stream) { $stream.Dispose() } }
}
function New-N0aReportingClock { return [Diagnostics.Stopwatch]::StartNew() }
function Send-N0aCaptureReports($Configuration,[string]$Workspace,$Envelope) {
    $clock=New-N0aReportingClock
    $private=$null
    try { $private=Read-N0aPrivateFlow $Workspace } catch {}
    $commitment=$null; if ($null -ne $private) { $commitment=$private.commitment }
    $wrapper=[ordered]@{schema_version=2;legacy=$Envelope;flow_commitment=$commitment}
    $body=[Text.Encoding]::ASCII.GetBytes(($wrapper | ConvertTo-Json -Depth 20 -Compress))
    if ($body.Length -gt 4096) {
        $wrapper.flow_commitment=$null; $private=$null
        $body=[Text.Encoding]::ASCII.GetBytes(($wrapper | ConvertTo-Json -Depth 20 -Compress))
    }
    if ($body.Length -gt 4096) { return $false }
    $delivered=Send-N0aCaptureRequest ($Configuration.host_url+'/n0a-capture-result') $body $clock
    if ($delivered -and $null -ne $private -and $clock.ElapsedMilliseconds -lt 10000) {
        [void](Send-N0aCaptureRequest ($Configuration.host_url+'/n0a-runner-flow') $private.body $clock)
    }
    return $delivered
}
function Send-N0aCaptureRequest([string]$Url,[byte[]]$Body,$clock) {
    if ($Body.Length -gt 65536 -or $clock.ElapsedMilliseconds -ge 10000) { return $false }
    $request=$null; $stream=$null; $response=$null
    try {
        $request=[Net.HttpWebRequest]::Create($Url); $request.Method='POST'; $request.Proxy=$null
        $request.Timeout=10000; $request.ReadWriteTimeout=10000; $request.AllowAutoRedirect=$false
        $request.ContentType='application/json'; $request.ContentLength=$Body.Length
        $pending=$request.BeginGetRequestStream($null,$null)
        try { if (-not $pending.AsyncWaitHandle.WaitOne([Math]::Max(0,10000-[int]$clock.ElapsedMilliseconds))) { return $false } }
        finally { $pending.AsyncWaitHandle.Close() }
        $stream=$request.EndGetRequestStream($pending)
        $left=10000-[int]$clock.ElapsedMilliseconds; if ($left -le 0) { return $false }
        if (-not (Write-N0aBoundedBody $stream $Body $left)) { return $false }
        $stream.Dispose(); $stream=$null
        $pending=$request.BeginGetResponse($null,$null)
        try { if (-not $pending.AsyncWaitHandle.WaitOne([Math]::Max(0,10000-[int]$clock.ElapsedMilliseconds))) { return $false } }
        finally { $pending.AsyncWaitHandle.Close() }
        $response=$request.EndGetResponse($pending)
        return ($clock.ElapsedMilliseconds -le 10000 -and [int]$response.StatusCode -eq 200)
    } catch { return $false }
    finally {
        if ($null -ne $stream) { try { $stream.Dispose() } catch {} }
        if ($null -ne $response) { try { $response.Dispose() } catch {} }
        if ($null -ne $request) { try { $request.Abort() } catch {} }
    }
}

function Invoke-N0aGuestDiagnostic($Configuration,[string]$Workspace,[string]$Python,[long]$Deadline,[long]$Frequency,[bool]$OriginalReady,[bool]$OriginalDelivered) {
    $launcher=[ordered]@{phase='not_started';failure='none';python_exit_code=$null;process_exit_confirmed=$null;timed_out=$false;budget_exhausted=$false}
    $envelope=[ordered]@{schema_version=1;case_nonce=$Configuration.n0a.case_nonce;actor_sha256=$Configuration.n0a.actor_sha256;report=$null;launcher=$launcher}
    $process=$null; $started=$false; $waitCompleted=$false; $executionFailure=$null
    try {
        $launcher.phase='configuration'
        if (-not (Test-N0aConfiguration $Configuration.n0a)) { $launcher.failure='configuration'; throw 'Closed diagnostic failure' }
        if (-not $OriginalReady) { $launcher.failure='original_unavailable'; throw 'Closed diagnostic failure' }
        if (-not $OriginalDelivered) { $launcher.failure='original_transport'; throw 'Closed diagnostic failure' }
        $launcher.phase='budget'
        $workEnd=$Deadline-20*$Frequency
        if ((Get-N0aRemainingMilliseconds $workEnd $Frequency ([Diagnostics.Stopwatch]::GetTimestamp())) -le 0) {
            $launcher.failure='work_budget_exhausted'; $launcher.budget_exhausted=$true; throw 'Closed diagnostic failure'
        }
        $output=Join-Path $Workspace 'public-n0a.json'
        if (Test-Path -LiteralPath $output) { $launcher.failure='report_bound'; throw 'Closed diagnostic failure' }
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=$Python
        $info.Arguments='-I -S -B "'+(Join-Path $Workspace '.github\windows_n0a_guest.py')+'" --configuration "C:\RuleProxyCI\ruleproxy-vm-config.json" --output "'+$output+'" --deadline-qpc '+$workEnd.ToString([Globalization.CultureInfo]::InvariantCulture)+' --qpc-frequency '+$Frequency.ToString([Globalization.CultureInfo]::InvariantCulture)
        $info.UseShellExecute=$false; $info.CreateNoWindow=$true
        $process=New-Object Diagnostics.Process; $process.StartInfo=$info
        $launcher.phase='python_start'; $launcher.failure='spawn'
        if (-not $process.Start()) { throw 'Closed diagnostic failure' }
        $started=$true
        if ($process.Handle -eq [IntPtr]::Zero) { throw 'Closed diagnostic failure' }
        $launcher.phase='python_wait'; $launcher.failure='process_exit'
        $wait=Wait-N0aOwnedChild $process (Get-N0aRemainingMilliseconds $workEnd $Frequency ([Diagnostics.Stopwatch]::GetTimestamp()))
        $waitCompleted=$true
        foreach ($key in @('process_exit_confirmed','timed_out','python_exit_code')) { $launcher[$key]=$wait[$key] }
        # Retain already-written bounded evidence even after timeout/uncertain exit.
        # This is not cleanup or denial acceptance; host independently adjudicates.
        if ($launcher.timed_out) { $executionFailure='timeout' }
        elseif (-not $launcher.process_exit_confirmed -or $null -eq $launcher.python_exit_code) { $executionFailure='process_exit' }
        $launcher.phase='report_read'; $launcher.failure='report_absent'
        if (-not (Test-Path -LiteralPath $output -PathType Leaf)) { throw 'Closed diagnostic failure' }
        $launcher.failure='report_bound'
        $item=Get-Item -LiteralPath $output -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 4096) { throw 'Closed diagnostic failure' }
        $file=[IO.File]::Open($output,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $buffer=[byte[]]::new(4097); $used=0
            while ($used -lt $buffer.Length) { $count=$file.Read($buffer,$used,$buffer.Length-$used); if ($count -eq 0) { break }; $used+=$count }
            if ($used -gt 4096 -or $used -eq 0) { throw 'Closed diagnostic failure' }
            for ($i=0;$i -lt $used;$i++) { if ($buffer[$i] -gt 127) { throw 'Closed diagnostic failure' } }
            $text=[Text.Encoding]::ASCII.GetString($buffer,0,$used)
        } finally { $file.Dispose() }
        $launcher.phase='report_parse'; $launcher.failure='report_parse'
        $value=$text | ConvertFrom-Json
        if ($null -ne $value -and $value -isnot [PSCustomObject]) { throw 'Closed diagnostic failure' }
        $envelope.report=$value
        $launcher.phase='completed'; $launcher.failure=if ($null -eq $value -or $launcher.python_exit_code -ne 0) { 'operation_failed' } else { 'none' }
    } catch { if ($launcher.failure -eq 'none') { $launcher.failure='operation_failed' } }
    finally {
        if ($null -ne $process) {
            if ($started -and -not $waitCompleted) {
                try { $process.Kill() } catch {}
                try { $launcher.process_exit_confirmed=($process.WaitForExit(5000) -eq $true) } catch { $launcher.process_exit_confirmed=$false }
            }
            try { $process.Dispose() } catch { $launcher.process_exit_confirmed=$false }
        }
    }
    if ($null -ne $executionFailure) { $launcher.failure=$executionFailure }
    # One reporting-only attempt can follow work expiry. It never renews work.
    try {
        $body=[Text.Encoding]::ASCII.GetBytes(($envelope | ConvertTo-Json -Depth 16 -Compress))
        if ($body.Length -gt 4096) {
            $envelope.report=$null; $launcher.failure='report_bound'; $launcher.phase='report_read'
            $body=[Text.Encoding]::ASCII.GetBytes(($envelope | ConvertTo-Json -Depth 16 -Compress))
        }
        if ('capture' -cin @($Configuration.PSObject.Properties.Name) -and (Test-N0aCaptureConfiguration $Configuration.capture)) {
            [void](Send-N0aCaptureReports $Configuration $Workspace $envelope)
        } else { [void](Send-N0aClosedReport ($Configuration.host_url+'/n0a-result') $body) }
    } catch {}
    return $envelope
}

# UDP-only opt-in helpers. Existing TCP functions above remain unchanged.
function Get-N0aUdpPayloadNames {
    return @('udp/actor.exe','udp/build-manifest.json','.github/windows_n0a_control.py',
        '.github/windows_n0a_guest.py','.github/windows_n0a_udp.py',
        '.github/windows_n0a_udp_guest.py','.github/windows_n0a_udp_flow.py')
}
function Get-N0aUdpFlowCommitment([byte[]]$Bytes) {
    if ($Bytes.Length -le 0 -or $Bytes.Length -gt 65536) { throw 'flow_bound' }
    foreach ($byte in $Bytes) { if ($byte -gt 127) { throw 'flow_encoding' } }
    $value=[Text.Encoding]::ASCII.GetString($Bytes) | ConvertFrom-Json
    if ($value.protocol -cne 'udp' -or $value.schema_version -ne 1) { throw 'udp_flow_protocol' }
    $aggregate=[IO.MemoryStream]::new()
    try {
        $prefix=[Text.Encoding]::ASCII.GetBytes("N0AU-ordinary-reports-v1`0")
        $aggregate.Write($prefix,0,$prefix.Length)
        foreach ($role in @('before','sample','after')) {
            $row=$value.reports.$role
            if ($row.sha256 -isnot [string] -or $row.sha256 -cnotmatch '\A[0-9a-f]{64}\z' -or ($row.bytes -isnot [int] -and $row.bytes -isnot [long]) -or $row.bytes -lt 1 -or $row.bytes -gt 32768) { throw 'flow_source' }
            $label=[Text.Encoding]::ASCII.GetBytes($role+"`0"); $aggregate.Write($label,0,$label.Length)
            $length=[BitConverter]::GetBytes([uint64]$row.bytes); if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($length) }
            $aggregate.Write($length,0,$length.Length)
            for ($index=0; $index -lt 64; $index+=2) { $aggregate.WriteByte([Convert]::ToByte($row.sha256.Substring($index,2),16)) }
        }
        $contained=$value.reports.contained.sha256
        if ($contained -isnot [string] -or $contained -cnotmatch '\A[0-9a-f]{64}\z') { throw 'flow_source' }
        return [ordered]@{sha256=(Get-N0aSha256 $Bytes);bytes=$Bytes.Length;contained_report_sha256=$contained;ordinary_report_sha256=(Get-N0aSha256 $aggregate.ToArray())}
    } finally { $aggregate.Dispose() }
}
function Read-N0aUdpPrivateFlow([string]$Workspace) {
    $parent=Join-Path $Workspace 'private-udp'; $path=Join-Path $parent 'runner-flow.json'
    $directory=Get-Item -LiteralPath $parent -Force
    $leaf=Get-Item -LiteralPath $path -Force
    if (-not $directory.PSIsContainer -or $leaf.PSIsContainer -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or ($leaf.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'flow_path' }
    if ($leaf.Length -le 0 -or $leaf.Length -gt 65536) { throw 'flow_bound' }
    $stream=$null
    try {
        $stream=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $buffer=New-Object byte[] 65537; $count=0
        while ($count -lt $buffer.Length) { $read=$stream.Read($buffer,$count,$buffer.Length-$count); if ($read -eq 0) { break }; $count+=$read }
        if ($count -le 0 -or $count -gt 65536) { throw 'flow_bound' }
        $body=New-Object byte[] $count; [Array]::Copy($buffer,$body,$count)
        return @{body=$body;commitment=(Get-N0aUdpFlowCommitment $body)}
    } finally { if ($null -ne $stream) { $stream.Dispose() } }
}
function Send-N0aUdpReports($Configuration,[string]$Workspace,$Envelope) {
    $clock=New-N0aReportingClock
    $private=$null
    try { $private=Read-N0aUdpPrivateFlow $Workspace } catch {}
    $commitment=$null; if ($null -ne $private) { $commitment=$private.commitment }
    $wrapper=[ordered]@{schema_version=3;udp=$Envelope;flow_commitment=$commitment}
    $body=[Text.Encoding]::ASCII.GetBytes(($wrapper | ConvertTo-Json -Depth 20 -Compress))
    if ($body.Length -gt 4096) {
        $wrapper.flow_commitment=$null; $private=$null
        $body=[Text.Encoding]::ASCII.GetBytes(($wrapper | ConvertTo-Json -Depth 20 -Compress))
    }
    if ($body.Length -gt 4096) { return $false }
    $delivered=Send-N0aCaptureRequest ($Configuration.host_url+'/udp-capture-result') $body $clock
    if ($delivered -and $null -ne $private -and $clock.ElapsedMilliseconds -lt 10000) {
        [void](Send-N0aCaptureRequest ($Configuration.host_url+'/udp-runner-flow') $private.body $clock)
    }
    return $delivered
}
function Invoke-N0aUdpGuestDiagnostic($Configuration,[string]$Workspace,[string]$Python,[long]$Deadline,[long]$Frequency,[bool]$OriginalReady,[bool]$OriginalDelivered) {
    $launcher=[ordered]@{phase='not_started';failure='none';python_exit_code=$null;process_exit_confirmed=$null;timed_out=$false;budget_exhausted=$false}
    $envelope=[ordered]@{schema_version=1;case_nonce=$Configuration.n0a_udp.case_nonce;actor_sha256=$Configuration.n0a_udp.actor_sha256;report=$null;launcher=$launcher}
    $process=$null; $started=$false; $waitCompleted=$false; $executionFailure=$null
    try {
        $launcher.phase='configuration'
        if (-not (Test-N0aConfiguration $Configuration.n0a_udp) -or -not (Test-N0aCaptureConfiguration $Configuration.capture)) { $launcher.failure='configuration'; throw 'Closed diagnostic failure' }
        if (-not $OriginalReady) { $launcher.failure='original_unavailable'; throw 'Closed diagnostic failure' }
        if (-not $OriginalDelivered) { $launcher.failure='original_transport'; throw 'Closed diagnostic failure' }
        $launcher.phase='budget'
        $workEnd=$Deadline-20*$Frequency
        if ((Get-N0aRemainingMilliseconds $workEnd $Frequency ([Diagnostics.Stopwatch]::GetTimestamp())) -le 0) {
            $launcher.failure='work_budget_exhausted'; $launcher.budget_exhausted=$true; throw 'Closed diagnostic failure'
        }
        $output=Join-Path $Workspace 'public-n0a-udp.json'
        if (Test-Path -LiteralPath $output) { $launcher.failure='report_bound'; throw 'Closed diagnostic failure' }
        $info=New-Object Diagnostics.ProcessStartInfo
        $info.FileName=$Python
        $info.Arguments='-I -S -B "'+(Join-Path $Workspace '.github\windows_n0a_udp_guest.py')+'" --configuration "C:\RuleProxyCI\ruleproxy-vm-config.json" --output "'+$output+'" --deadline-qpc '+$workEnd.ToString([Globalization.CultureInfo]::InvariantCulture)+' --qpc-frequency '+$Frequency.ToString([Globalization.CultureInfo]::InvariantCulture)
        $info.UseShellExecute=$false; $info.CreateNoWindow=$true
        $process=New-Object Diagnostics.Process; $process.StartInfo=$info
        $launcher.phase='python_start'; $launcher.failure='spawn'
        if (-not $process.Start()) { throw 'Closed diagnostic failure' }
        $started=$true
        if ($process.Handle -eq [IntPtr]::Zero) { throw 'Closed diagnostic failure' }
        $launcher.phase='python_wait'; $launcher.failure='process_exit'
        $wait=Wait-N0aOwnedChild $process (Get-N0aRemainingMilliseconds $workEnd $Frequency ([Diagnostics.Stopwatch]::GetTimestamp()))
        $waitCompleted=$true
        foreach ($key in @('process_exit_confirmed','timed_out','python_exit_code')) { $launcher[$key]=$wait[$key] }
        # Retain already-written bounded evidence even after timeout/uncertain exit.
        # This is not cleanup or denial acceptance; host independently adjudicates.
        if ($launcher.timed_out) { $executionFailure='timeout' }
        elseif (-not $launcher.process_exit_confirmed -or $null -eq $launcher.python_exit_code) { $executionFailure='process_exit' }
        $launcher.phase='report_read'; $launcher.failure='report_absent'
        if (-not (Test-Path -LiteralPath $output -PathType Leaf)) { throw 'Closed diagnostic failure' }
        $launcher.failure='report_bound'
        $item=Get-Item -LiteralPath $output -Force
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.Length -gt 4096) { throw 'Closed diagnostic failure' }
        $file=[IO.File]::Open($output,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        try {
            $buffer=[byte[]]::new(4097); $used=0
            while ($used -lt $buffer.Length) { $count=$file.Read($buffer,$used,$buffer.Length-$used); if ($count -eq 0) { break }; $used+=$count }
            if ($used -gt 4096 -or $used -eq 0) { throw 'Closed diagnostic failure' }
            for ($i=0;$i -lt $used;$i++) { if ($buffer[$i] -gt 127) { throw 'Closed diagnostic failure' } }
            $text=[Text.Encoding]::ASCII.GetString($buffer,0,$used)
        } finally { $file.Dispose() }
        $launcher.phase='report_parse'; $launcher.failure='report_parse'
        $value=$text | ConvertFrom-Json
        if ($null -ne $value -and $value -isnot [PSCustomObject]) { throw 'Closed diagnostic failure' }
        $envelope.report=$value
        $launcher.phase='completed'; $launcher.failure=if ($null -eq $value -or $launcher.python_exit_code -ne 0) { 'operation_failed' } else { 'none' }
    } catch { if ($launcher.failure -eq 'none') { $launcher.failure='operation_failed' } }
    finally {
        if ($null -ne $process) {
            if ($started -and -not $waitCompleted) {
                try { $process.Kill() } catch {}
                try { $launcher.process_exit_confirmed=($process.WaitForExit(5000) -eq $true) } catch { $launcher.process_exit_confirmed=$false }
            }
            try { $process.Dispose() } catch { $launcher.process_exit_confirmed=$false }
        }
    }
    if ($null -ne $executionFailure) { $launcher.failure=$executionFailure }
    # One reporting-only attempt can follow work expiry. It never renews work.
    try {
        $body=[Text.Encoding]::ASCII.GetBytes(($envelope | ConvertTo-Json -Depth 16 -Compress))
        if ($body.Length -gt 4096) {
            $envelope.report=$null; $launcher.failure='report_bound'; $launcher.phase='report_read'
            $body=[Text.Encoding]::ASCII.GetBytes(($envelope | ConvertTo-Json -Depth 16 -Compress))
        }
        [void](Send-N0aUdpReports $Configuration $Workspace $envelope)
    } catch {}
    return $envelope
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
    foreach ($key in @('product_winnt','arch_amd64','env_drive_c','os_drive_c','windows_directory','fixed_drive','build_26300','ubr_direct')) {
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
    $phase='beacon'; $earlyOperation='beacon'
    $port = New-Object IO.Ports.SerialPort('COM1',115200)
    try { $port.WriteTimeout=2000; $port.Open(); $port.Write("RPBEACON identity-ordinary-ready`r`n") } finally { $port.Dispose() }
    $earlyBootGateCompleted=$true
    $os=$bootVersion; $type=$bootType
    # Claim only after the exact exploratory installed-build and setup gates.
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
        '.github/windows_identity_direct_stage0.py','.github/windows_identity_proof.py',
        '.github/windows_psec_compartment_smoke.py','ruleproxy/windows_runtime_pins.py')
    $udpPresent=('n0a_udp' -cin @($configuration.PSObject.Properties.Name))
    if ($udpPresent) {
        if ('n0a' -cin @($configuration.PSObject.Properties.Name) -or
            'capture' -cnotin @($configuration.PSObject.Properties.Name) -or
            -not (Test-N0aConfiguration $configuration.n0a_udp) -or
            -not (Test-N0aCaptureConfiguration $configuration.capture)) { throw 'Invalid UDP diagnostic configuration' }
        $udpEnabled=$true
        $payloadNames+=@(Get-N0aUdpPayloadNames)
    }
    $n0aPresent=('n0a' -cin @($configuration.PSObject.Properties.Name))
    if ($n0aPresent) {
        if (-not (Test-N0aConfiguration $configuration.n0a)) { throw 'Invalid optional diagnostic configuration' }
        $n0aEnabled=$true
        $payloadNames+=@('n0a/actor.exe','n0a/build-manifest.json','.github/windows_n0a_control.py','.github/windows_n0a_guest.py')
    }
    $captureEnabled=$n0aEnabled -and 'capture' -cin @($configuration.PSObject.Properties.Name)
    if ($captureEnabled) {
        if (-not (Test-N0aCaptureConfiguration $configuration.capture)) { throw 'Invalid capture configuration' }
        $payloadNames+=@('.github/windows_n0a_flow.py')
    }
    $phase='payload_extract'
    if ($udpEnabled) {
        Expand-CheckedStage0Zip -ArchivePath $payload -Destination $workspace -RequiredNames $payloadNames `
            -MemberCount 17 -ExactBytes 0 -MaximumBytes 134217728 -Flat $false -ExactNames $true
    } elseif ($captureEnabled) {
        Expand-CheckedStage0Zip -ArchivePath $payload -Destination $workspace -RequiredNames $payloadNames `
            -MemberCount 15 -ExactBytes 0 -MaximumBytes 134217728 -Flat $false -ExactNames $true
    } elseif ($n0aEnabled) {
        Expand-CheckedStage0Zip -ArchivePath $payload -Destination $workspace -RequiredNames $payloadNames `
            -MemberCount 14 -ExactBytes 0 -MaximumBytes 134217728 -Flat $false -ExactNames $true
    } else {
        Expand-CheckedStage0Zip -ArchivePath $payload -Destination $workspace -RequiredNames $payloadNames `
            -MemberCount 10 -ExactBytes 0 -MaximumBytes 134217728 -Flat $false -ExactNames $true
    }
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
    $info.Arguments='-I -S -B "' + (Join-Path $workspace '.github\windows_identity_direct_stage0.py') + '" --guest --output "' + $public + '"'
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    # All diagnostics remain inside the VM. Do not stream raw actor paths/SIDs.
    $child = New-Object Diagnostics.Process
    $child.StartInfo=$info
    try {
        if ($n0aEnabled -or $udpEnabled) {
            $n0aFrequency=[Diagnostics.Stopwatch]::Frequency
            $now=[Diagnostics.Stopwatch]::GetTimestamp()
            if (-not [Diagnostics.Stopwatch]::IsHighResolution -or $n0aFrequency -le 0 -or $n0aFrequency -gt 1000000000 -or $now -lt 0 -or $now -gt ([long]::MaxValue-120*$n0aFrequency)) { throw 'Clock contract unavailable' }
            $n0aDeadline=$now+120*$n0aFrequency
        }
        $phase='python_start'
        if (-not $child.Start()) { $failureCategory='python_not_started'; throw 'Stage0 did not start' }
        $heldHandle=$child.Handle
        if ($heldHandle -eq [IntPtr]::Zero) { $failureCategory='process_handle_missing'; throw 'Owned process handle missing' }
        $phase='python_wait'
        $originalExited=if ($n0aEnabled -or $udpEnabled) { $child.WaitForExit((Get-N0aRemainingMilliseconds $n0aDeadline $n0aFrequency ([Diagnostics.Stopwatch]::GetTimestamp()))) } else { $child.WaitForExit(120000) }
        if (-not $originalExited) { $child.Kill(); [void]$child.WaitForExit(5000); $failureCategory='python_deadline'; throw 'Stage0 deadline' }
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
    $result | Add-Member -NotePropertyName direct_build_verified -NotePropertyValue $true -Force
    $result | Add-Member -NotePropertyName os -NotePropertyValue @{build=[int]$os.CurrentBuildNumber; ubr=[int]$os.UBR; product_type=$type; architecture=$env:PROCESSOR_ARCHITECTURE} -Force
    $n0aOriginalReady=($result.ordinary_account -is [bool] -and $result.ordinary_account -eq $true -and $result.harness_completed -is [bool] -and $result.harness_completed -eq $true)
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
    Set-ClosedResultField 'exploratory_stage0' $true
    Set-ClosedResultField 'product_acceptance' $false
    Set-ClosedResultField 'documented_support_floor' '26300.9550'
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

# Original Stage0 delivery above is independent and is never rewritten by N0a.
# Work shares one 120s QPC deadline; reporting-only allowance is separate (once, at most 10s).
if ($udpEnabled) {
    [void](Invoke-N0aUdpGuestDiagnostic $configuration $workspace $python $n0aDeadline $n0aFrequency $n0aOriginalReady $delivered)
} elseif ($n0aEnabled) {
    [void](Invoke-N0aGuestDiagnostic $configuration $workspace $python $n0aDeadline $n0aFrequency $n0aOriginalReady $delivered)
}
