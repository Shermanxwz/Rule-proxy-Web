# Only the owned disposable guest; this entrypoint runs as SYSTEM in specialize.
param([switch]$ServiceUpdate)
$ErrorActionPreference = 'Stop'
if ($ServiceUpdate) {
    # The immutable SYSTEM update manifest contains the private host endpoint.
    # Wait for the genuine user's COM1 beacon to reconnect QEMU user networking.
    $manifest = Get-Content -LiteralPath 'C:\RuleProxyCIUpdates\update-manifest.json' -Raw | ConvertFrom-Json
    $endpoint = [Uri]$manifest.packages[0].url
    $ready = $false
    for ($i=0; $i -lt 90; $i++) {
        $socket = New-Object Net.Sockets.TcpClient
        $pending = $null
        try {
            $pending = $socket.BeginConnect($endpoint.Host, $endpoint.Port, $null, $null)
            if ($pending.AsyncWaitHandle.WaitOne(1000)) { $socket.EndConnect($pending); $ready=$true; break }
        } catch {} finally {
            if ($null -ne $pending) { $pending.AsyncWaitHandle.Close() }
            $socket.Dispose()
        }
        Start-Sleep -Seconds 2
    }
    if (-not $ready) { exit 1 }
    . 'C:\RuleProxyCIUpdates\windows-vm-update.ps1'
    exit (Invoke-RuleProxyCIUpdate)
}
# Existing helper protects SYSTEM servicing scripts; only the test workspace is
# writable by Users. It creates no account: the pinned unattend creates one.
& (Join-Path $PSScriptRoot 'identity-base-setup.ps1')
# Reuse only these two guest-only settings from the established PSEC lab:
# main 3e90bb1f129a7d08b85fb816c7c70ba4f346ee66,
# .github/windows-proxifyre-vm-setup.ps1. No host/device policy is changed.
# Offline OOBE must complete before the ordinary user's beacon attaches NIC;
# automatic servicing must not race the separately pinned exact-build update.
& reg.exe add 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' /v BypassNRO /t REG_DWORD /d 1 /f | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Inherited guest offline OOBE setting failed' }
& reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v NoAutoUpdate /t REG_DWORD /d 1 /f | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Inherited guest deterministic servicing setting failed' }
$wrapper = 'C:\RuleProxyCIUpdates\identity-update-bootstrap.ps1'
Copy-Item -LiteralPath $PSCommandPath -Destination $wrapper
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -ExecutionPolicy Bypass -File ' + $wrapper + ' -ServiceUpdate')
Set-ScheduledTask -TaskName 'RuleProxyCI-InstallOfficialUpdate' -Action $action | Out-Null
