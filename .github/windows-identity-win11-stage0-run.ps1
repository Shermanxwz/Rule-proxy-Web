# Invoked by the normal interactive Startup folder, never a SYSTEM test task.
$ErrorActionPreference = 'Stop'
$root = 'C:\RuleProxyCI'
$configuration = Get-Content -LiteralPath (Join-Path $root 'ruleproxy-vm-config.json') -Raw | ConvertFrom-Json
$result = @{schema_version=1; ordinary_account=$false; servicing_verified=$false; harness_completed=$false; stage0_passed=$false}
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($identity.Name -ne 'RULEPROXY-VM\RuleProxyCI' -or
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
        [Diagnostics.Process]::GetCurrentProcess().SessionId -le 0) { throw 'Genuine ordinary account required' }
    $port = New-Object IO.Ports.SerialPort('COM1',115200)
    try { $port.WriteTimeout=2000; $port.Open(); $port.Write("RPBEACON identity-ordinary-ready`r`n") } finally { $port.Dispose() }
    $deadline = [DateTime]::UtcNow.AddMinutes(85)
    $statePath = 'C:\RuleProxyCIUpdates\update-state.json'
    do {
        if (Test-Path -LiteralPath $statePath) {
            if ((Get-Item -LiteralPath $statePath).Length -gt 65536) { throw 'Oversized servicing receipt' }
            $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
            if ($state.status -eq 'failed') { throw 'Pinned servicing failed' }
            if ($state.status -eq 'completed' -and $state.completed -eq $true) { break }
        }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Servicing deadline' }
        Start-Sleep -Seconds 5
    } while ($true)
    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $type = [string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType
    if ([int]$os.CurrentBuildNumber -ne 26200 -or [int]$os.UBR -ne 9711 -or $type -ne 'WinNT' -or
        $env:PROCESSOR_ARCHITECTURE -ne 'AMD64' -or $state.packages_verified -ne $true -or
        $state.task_unregistered -ne $true -or $state.reboot_required -ne $false -or
        [int]$state.actual_build -ne 26200 -or [int]$state.actual_ubr -ne 9711) { throw 'Exact serviced client gate failed' }
    # Claim only after servicing/reboot. Startup during servicing never burns it.
    $claim = [IO.File]::Open((Join-Path $root 'identity-stage0-claimed'),[IO.FileMode]::CreateNew)
    $claim.Dispose()
    $payload = Join-Path $root 'identity-payload.zip'
    $client = New-Object Net.WebClient
    try { $client.Proxy=$null; $client.DownloadFile(($configuration.host_url + '/payload.zip'),$payload) } finally { $client.Dispose() }
    if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.payload_sha256) { throw 'Payload digest mismatch' }
    $workspace = Join-Path $root 'identity-workspace'
    Expand-Archive -LiteralPath $payload -DestinationPath $workspace
    $runtime = Join-Path $workspace 'runtime.zip'
    if ((Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.package_sha256) { throw 'Runtime package mismatch' }
    Expand-Archive -LiteralPath $runtime -DestinationPath (Join-Path $workspace 'runtime')
    $python = Join-Path $workspace 'runtime\RuleProxy-Web\python\python.exe'
    $public = Join-Path $workspace 'public-stage0.json'
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$python
    $info.Arguments='-I -S -B "' + (Join-Path $workspace '.github\windows_identity_win11_stage0.py') + '" --guest --output "' + $public + '"'
    $info.UseShellExecute=$false; $info.CreateNoWindow=$true
    # All diagnostics remain inside the VM. Do not stream raw actor paths/SIDs.
    $child = New-Object Diagnostics.Process
    $child.StartInfo=$info
    try {
        if (-not $child.Start()) { throw 'Stage0 did not start' }
        $heldHandle=$child.Handle
        if ($heldHandle -eq [IntPtr]::Zero) { throw 'Owned process handle missing' }
        if (-not $child.WaitForExit(120000)) { $child.Kill(); [void]$child.WaitForExit(5000); throw 'Stage0 deadline' }
        if (-not (Test-Path -LiteralPath $public) -or (Get-Item -LiteralPath $public).Length -gt 16384) { throw 'Bounded closed report absent' }
        $result = Get-Content -LiteralPath $public -Raw | ConvertFrom-Json
        if ($child.ExitCode -ne 0) { $result.stage0_passed=$false }
    } finally { $child.Dispose() }
    $result | Add-Member -NotePropertyName servicing_verified -NotePropertyValue $true -Force
    $result | Add-Member -NotePropertyName os -NotePropertyValue @{build=26200; ubr=9711; product_type='WinNT'; architecture='AMD64'} -Force
} catch {
    # Closed failure only. Never export exception strings, identities or paths.
    $result.stage0_passed=$false
} finally {
    $status = if ($result.stage0_passed -eq $true) { 'passed' } else { 'failed' }
    if ($result -is [hashtable]) { $result.status=$status } else { $result | Add-Member -NotePropertyName status -NotePropertyValue $status -Force }
    $body = [Text.Encoding]::ASCII.GetBytes(($result | ConvertTo-Json -Depth 5 -Compress))
    for ($i=0; $i -lt 3; $i++) {
        try {
            $request=[Net.HttpWebRequest]::Create($configuration.host_url + '/result')
            $request.Method='POST'; $request.Proxy=$null; $request.Timeout=10000; $request.ReadWriteTimeout=10000
            $request.ContentType='application/json'; $request.ContentLength=$body.Length
            $stream=$request.GetRequestStream(); try { $stream.Write($body,0,$body.Length) } finally { $stream.Dispose() }
            $response=$request.GetResponse(); $response.Dispose(); break
        } catch { Start-Sleep -Seconds 2 }
    }
}
