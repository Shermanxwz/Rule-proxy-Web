# Invoked by the normal interactive Startup folder, never a SYSTEM test task.
$ErrorActionPreference = 'Stop'
$root = 'C:\RuleProxyCI'
$configuration = Get-Content -LiteralPath (Join-Path $root 'ruleproxy-vm-config.json') -Raw | ConvertFrom-Json
$result = @{schema_version=1; ordinary_account=$false; stock_build_verified=$false; harness_completed=$false; stage0_passed=$false}
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
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($identity.Name -ne 'RULEPROXY-VM\RuleProxyCI' -or
        $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or
        [Diagnostics.Process]::GetCurrentProcess().SessionId -le 0) { throw 'Genuine ordinary account required' }
    $port = New-Object IO.Ports.SerialPort('COM1',115200)
    try { $port.WriteTimeout=2000; $port.Open(); $port.Write("RPBEACON identity-ordinary-ready`r`n") } finally { $port.Dispose() }
    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $type = [string](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\ProductOptions').ProductType
    if ([int]$os.CurrentBuildNumber -ne 26200 -or [int]$os.UBR -ne 6584 -or $type -ne 'WinNT' -or
        $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') { throw 'Exact stock client gate failed' }
    # One ordinary Startup invocation; no servicing task or MSUs.
    $claim = [IO.File]::Open((Join-Path $root 'identity-stage0-claimed'),[IO.FileMode]::CreateNew)
    $claim.Dispose()
    $payload = Join-Path $root 'identity-payload.zip'
    # Host connects user NAT after reading the fixed ordinary-user beacon.
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
    if (-not $connected) { throw 'Owned endpoint timeout' }
    $request=[Net.HttpWebRequest]::Create($configuration.host_url + '/payload.zip')
    $request.Proxy=$null; $request.Timeout=30000; $request.ReadWriteTimeout=30000
    $request.AllowAutoRedirect=$false
    $response=$request.GetResponse()
    $input=$output=$null
    try {
        if ($response.ContentLength -le 0 -or $response.ContentLength -gt 268435456) { throw 'Payload bound' }
        $input=$response.GetResponseStream()
        $output=[IO.File]::Open($payload,[IO.FileMode]::CreateNew)
        $buffer=[byte[]]::new(65536); $total=0L
        while (($count=$input.Read($buffer,0,$buffer.Length)) -gt 0) {
            $total+=$count
            if ($total -gt $response.ContentLength) { throw 'Payload overrun' }
            $output.Write($buffer,0,$count)
        }
        if ($total -ne $response.ContentLength) { throw 'Payload incomplete' }
    } finally {
        if ($null -ne $input) { $input.Dispose() }
        if ($null -ne $output) { $output.Dispose() }
        $response.Dispose()
    }
    if ((Get-FileHash -LiteralPath $payload -Algorithm SHA256).Hash.ToLowerInvariant() -ne $configuration.payload_sha256) { throw 'Payload digest mismatch' }
    $workspace = Join-Path $root 'identity-workspace'
    $payloadNames = @('python-embed.zip','actor.exe','stage0-input.json',
        'g/wxc-exec.exe','g/build-manifest.json','g/MXC-LICENSE.md',
        '.github/windows_identity_stock_stage0.py','.github/windows_identity_proof.py',
        '.github/windows_psec_compartment_smoke.py','ruleproxy/windows_runtime_pins.py')
    Expand-CheckedStage0Zip -ArchivePath $payload -Destination $workspace -RequiredNames $payloadNames `
        -MemberCount 10 -ExactBytes 0 -MaximumBytes 134217728 -Flat $false -ExactNames $true
    $runtime = Join-Path $workspace 'python-embed.zip'
    $pythonDigest = 'a93abe456ab01bd96d7a085b3cdb6566b3063f4241360d114142fbdb07f0a310'
    if ((Get-Item -LiteralPath $runtime).Length -ne 12601679 -or $configuration.python_sha256 -cne $pythonDigest -or
        (Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash.ToLowerInvariant() -cne $pythonDigest) { throw 'Pinned Python mismatch' }
    $pythonNames = @('python.exe','python314.dll','python3.dll','python314.zip','python314._pth',
        '_ctypes.pyd','_socket.pyd','_hashlib.pyd','select.pyd','libffi-8.dll','libcrypto-3.dll',
        'vcruntime140.dll','vcruntime140_1.dll','LICENSE.txt')
    Expand-CheckedStage0Zip -ArchivePath $runtime -Destination (Join-Path $workspace 'python') -RequiredNames $pythonNames `
        -MemberCount 37 -ExactBytes 24405990 -MaximumBytes 24405990 -Flat $true -ExactNames $false
    $python = Join-Path $workspace 'python\python.exe'
    $public = Join-Path $workspace 'public-stage0.json'
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName=$python
    $info.Arguments='-I -S -B "' + (Join-Path $workspace '.github\windows_identity_stock_stage0.py') + '" --guest --output "' + $public + '"'
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
    $result | Add-Member -NotePropertyName stock_build_verified -NotePropertyValue $true -Force
    $result | Add-Member -NotePropertyName os -NotePropertyValue @{build=[int]$os.CurrentBuildNumber; ubr=[int]$os.UBR; product_type=$type; architecture=$env:PROCESSOR_ARCHITECTURE} -Force
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
