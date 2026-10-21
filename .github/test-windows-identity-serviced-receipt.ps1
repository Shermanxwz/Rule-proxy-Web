# Windows compile gate: actual owned two-process locks and production atomic writer.
# No service/task/account/VM/clock changes; no ordinary-token read claim.
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$runner=Join-Path $PSScriptRoot 'windows-identity-serviced-stage0-run.ps1'
$worker=Join-Path $PSScriptRoot 'windows-identity-serviced-update.ps1'
$ast=[System.Management.Automation.Language.Parser]::ParseFile($runner,[ref]$tokens,[ref]$errors)
if($errors.Count -ne 0){throw 'Receipt parser failed'}
foreach($name in @('Test-ServicedReceiptSharing','Read-ServicedReceiptSnapshot')) {
    $definitions=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$false))
    if($definitions.Count -ne 1){throw 'Receipt helper missing'};Invoke-Expression $definitions[0].Extent.Text
}
. $worker
$passed=0;$created=$false;$process=$null;$fixturePhase='setup';$fixtureStep='not_started';$childResult=$null
$root=Join-Path ([IO.Path]::GetTempPath()) ('ruleproxy-receipt-'+[Guid]::NewGuid().ToString('N'))
$oldUpdateDirectory=$script:UpdateDirectory
function Start-ReceiptFixtureChild($Mode) {
    $info=New-Object Diagnostics.ProcessStartInfo
    $info.FileName=Join-Path ([Environment]::GetFolderPath('Windows')) 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $info.Arguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$child+'" -Mode '+$Mode+' -Root "'+$root+'" -Worker "'+$worker+'"'
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    return [Diagnostics.Process]::Start($info)
}
function Wait-ReceiptReady {
    $deadline=[DateTime]::UtcNow.AddSeconds(10)
    while(-not (Test-Path -LiteralPath $ready)) {
        if($process.HasExited -or [DateTime]::UtcNow -ge $deadline){throw 'Receipt child readiness failed'}
        Start-Sleep -Milliseconds 10
    }
}
function Read-FixtureReceipt {
    $script:ServicingReadDiagnostic=@{step='not_started';reason='none'}
    return Read-ServicedReceiptSnapshot $path ([DateTime]::UtcNow.AddSeconds(10))
}
try {
    $null=New-Item -ItemType Directory -Path $root;$created=$true
    $admins=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $system=New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $users=New-Object Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $acl=New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($admins);$acl.SetAccessRuleProtection($true,$false)
    foreach($sid in @($admins,$system)){$acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')))}
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users,'ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')))
    Set-Acl -LiteralPath $root -AclObject $acl
    $script:UpdateDirectory=$root;$path=Join-Path $root 'update-state.json'
    $state=@{schema_version=1;generation=0;payload=('a'*100);target_build=26200;target_ubr=9711}
    Write-ServicedState $state
    $leafAcl=Get-Acl -LiteralPath $path;$naturalTrusted=$leafAcl.GetOwner([Security.Principal.SecurityIdentifier]).Value -in @('S-1-5-18','S-1-5-32-544')
    $leafAcl.SetOwner($admins);Set-Acl -LiteralPath $path -AclObject $leafAcl
    if(-not $naturalTrusted){$fixturePhase='natural_owner';throw 'Concurrent writer natural owner not trusted'}
    $raw=Read-FixtureReceipt;$value=$raw|ConvertFrom-Json
    if($value.generation -ne 0){throw 'Initial Move receipt failed'};$passed++
    $child=Join-Path $root 'fixture-child.ps1';$childResult=Join-Path $root 'child-result.json';$ready=Join-Path $root 'ready';$release=Join-Path $root 'release'
    $childCode=@'
param([string]$Mode,[string]$Root,[string]$Worker)
$ErrorActionPreference='Stop';Set-StrictMode -Version Latest
$handle=$null
try {
    . $Worker
    $script:UpdateDirectory=$Root
    $path=Join-Path $Root 'update-state.json'
    $ready=Join-Path $Root 'ready';$release=Join-Path $Root 'release'
    $childResult=Join-Path $Root 'child-result.json';$childStep='started'
    if($Mode -ceq 'lock') {
        $handle=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        [IO.File]::WriteAllText($ready,'1')
        $deadline=[DateTime]::UtcNow.AddSeconds(10)
        while(-not [IO.File]::Exists($release)){if([DateTime]::UtcNow -ge $deadline){exit 2};Start-Sleep -Milliseconds 5}
        Start-Sleep -Milliseconds 30
    } elseif($Mode -ceq 'stress') {
        [IO.File]::WriteAllText($ready,'1')
        for($generation=1;$generation -le 120;$generation++) {
            $childStep='writer_call'
            Write-ServicedState @{schema_version=1;generation=$generation;payload=([string]($generation%10)*100);target_build=26200;target_ubr=9711}
            Start-Sleep -Milliseconds 2
        }
    } else {exit 2}
    $childStep='completed'
    [IO.File]::WriteAllText($childResult,'{"step":"completed","hresult":null}',[Text.Encoding]::ASCII)
    exit 0
} catch {
    try {
        $closed=@{step=$childStep;hresult=[int]$_.Exception.GetBaseException().HResult}
        [IO.File]::WriteAllText($childResult,($closed|ConvertTo-Json -Compress),[Text.Encoding]::ASCII)
    } catch {}
    exit 1
} finally {if($null -ne $handle){$handle.Dispose()}}
'@
    [IO.File]::WriteAllText($child,$childCode,[Text.Encoding]::ASCII)
    $fixturePhase='lock_baseline'
    $process=Start-ReceiptFixtureChild 'lock';Wait-ReceiptReady
    # Deterministic baseline: actual old reader fails while another process holds exclusive lock.
    $baseline=$false
    try {$null=Get-Content -LiteralPath $path -Raw}catch{$baseline=Test-ServicedReceiptSharing $_.Exception}
    if(-not $baseline){throw 'Exclusive holder baseline not reproduced'};$passed++
    $script:ServicingReadDiagnostic=@{step='not_started';reason='none'}
    $stillLocked=$false
    try {$null=Read-ServicedReceiptSnapshot $path ([DateTime]::UtcNow.AddSeconds(5))}catch{$stillLocked=Test-ServicedReceiptSharing $_.Exception}
    if(-not $stillLocked -or $script:ServicingReadDiagnostic.reason -cne 'read'){throw 'Sharing retry did not remain bounded'};$passed++
    $script:ServicingReadDiagnostic=@{step='not_started';reason='none'}
    $boundedFailure=$false;$timer=[Diagnostics.Stopwatch]::StartNew()
    try{$null=Read-ServicedReceiptSnapshot $path ([DateTime]::UtcNow.AddMilliseconds(50))}catch{
        $boundedFailure=($script:ServicingReadDiagnostic.reason -ceq 'expired') -or
            (($script:ServicingReadDiagnostic.reason -ceq 'read') -and (Test-ServicedReceiptSharing $_.Exception))
    }finally{$timer.Stop()}
    # Floor-rounded sleeps may exhaust the fixed four attempts just before expiry.
    if(-not $boundedFailure -or $timer.ElapsedMilliseconds -gt 2000){throw 'Sharing retry extended deadline'};$passed++
    $fixturePhase='lock_released'
    [IO.File]::WriteAllText($release,'1')
    $raw=Read-FixtureReceipt
    if(($raw|ConvertFrom-Json).generation -ne 0 -or -not $process.WaitForExit(5000) -or $process.ExitCode -ne 0){throw 'Released lock snapshot failed'}
    $process.Dispose();$process=$null;Remove-Item -LiteralPath $ready,$release -Force;$passed++
    $fixturePhase='stress'
    Remove-Item -LiteralPath $childResult -Force
    $fixtureStep='child_start';$process=Start-ReceiptFixtureChild 'stress'
    $fixtureStep='wait_ready';Wait-ReceiptReady
    $reads=0;$deadline=[DateTime]::UtcNow.AddSeconds(30)
    do {
        $fixtureStep='snapshot';$raw=Read-FixtureReceipt
        $fixtureStep='json';$snapshot=$raw|ConvertFrom-Json
        $fixtureStep='validate'
        if($snapshot.schema_version -ne 1 -or $snapshot.target_build -ne 26200 -or $snapshot.target_ubr -ne 9711 -or $snapshot.generation -isnot [int] -or $snapshot.generation -lt 0 -or $snapshot.generation -gt 120){throw 'Concurrent snapshot schema failed'}
        $expected=if($snapshot.generation -eq 0){'a'*100}else{[string]($snapshot.generation%10)*100}
        if($snapshot.payload -cne $expected){throw 'Concurrent mixed receipt accepted'}
        $reads++
        if([DateTime]::UtcNow -ge $deadline){throw 'Concurrent fixture deadline'}
    } while(-not $process.HasExited)
    $fixtureStep='child_exit'
    if($process.ExitCode -ne 0 -or $reads -lt 1){throw 'Atomic writer stress failed'}
    $process.Dispose();$process=$null;$passed++
    $fixturePhase='exact_bound'
    $validJson='{"schema_version":1}'
    [IO.File]::WriteAllText($path,$validJson.PadRight(4096,' '),[Text.UTF8Encoding]::new($false))
    if((Read-FixtureReceipt|ConvertFrom-Json).schema_version -ne 1){throw 'Valid 4096-byte receipt rejected'};$passed++
    $fixturePhase='access_denied'
    $restoreAcl=Get-Acl -LiteralPath $path
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    try{$currentSid=$identity.User}finally{$identity.Dispose()}
    try{
        $denyAcl=Get-Acl -LiteralPath $path
        $denyAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($currentSid,'ReadData','Deny')))
        Set-Acl -LiteralPath $path -AclObject $denyAcl
        $script:ServicingReadDiagnostic=@{step='not_started';reason='none'};$rejected=$false;$sharing=$false
        try{$null=Read-ServicedReceiptSnapshot $path ([DateTime]::UtcNow.AddSeconds(5))}catch{$rejected=$true;$sharing=Test-ServicedReceiptSharing $_.Exception}
        if(-not $rejected -or $sharing -or $script:ServicingReadDiagnostic.reason -cne 'read'){throw 'Actual denied read classification failed'};$passed++
    }finally{Set-Acl -LiteralPath $path -AclObject $restoreAcl}
    foreach($bad in @('oversize','utf8','json','expired','acl')) {
        $fixturePhase=$bad
        [IO.File]::WriteAllText($path,'{"schema_version":1}',[Text.UTF8Encoding]::new($false))
        $script:ServicingReadDiagnostic=@{step='not_started';reason='none'}
        $deadline=[DateTime]::UtcNow.AddSeconds(5)
        switch($bad){
            'oversize'{[IO.File]::WriteAllBytes($path,(New-Object byte[] 4097))}
            'utf8'{[IO.File]::WriteAllBytes($path,[byte[]]@(0xc3,0x28))}
            'json'{[IO.File]::WriteAllText($path,'{',[Text.UTF8Encoding]::new($false))}
            'expired'{$deadline=[DateTime]::UtcNow.AddSeconds(-1)}
            'acl'{$badAcl=Get-Acl -LiteralPath $path;$badAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($users,'Write','Allow')));Set-Acl -LiteralPath $path -AclObject $badAcl}
        }
        $rejected=$false
        try {$raw=Read-ServicedReceiptSnapshot $path $deadline;$null=$raw|ConvertFrom-Json}catch{$rejected=$true}
        if(-not $rejected){throw 'Invalid receipt accepted'}
        if($bad -ceq 'acl'){Set-Acl -LiteralPath $path -AclObject $leafAcl};$passed++
    }
    # Access/malformed errors must never be misclassified as sharing32.
    if(Test-ServicedReceiptSharing ([UnauthorizedAccessException]::new('fixture'))){throw 'Nonsharing error retry allowed'};$passed++
    Write-Output ((@{fixture='receipt_snapshot';passed=$passed;baseline_sharing_reproduced=$true;concurrent_valid_snapshots=$true;natural_owner_trusted=$naturalTrusted;explicit_owner_fixture=$true;ordinary_token_tested=$false})|ConvertTo-Json -Compress)
} catch {
    $failureHresult=[int]$_.Exception.HResult;$baseHresult=[int]$_.Exception.GetBaseException().HResult
    $childExited=$null;$childExitCode=$null;$childStep=$null;$childHresult=$null
    if($null -ne $process){try{$childExited=[bool]$process.HasExited;if($childExited){$childExitCode=[int]$process.ExitCode}}catch{}}
    # Owned marker is diagnostic only; absence/partial write remains unavailable.
    try {
        if($null -ne $childResult -and [IO.File]::Exists($childResult)) {
            $markerStream=$null
            try {
                $markerStream=[IO.File]::Open($childResult,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
                $markerBytes=New-Object byte[] 257;$markerCount=0
                do{$chunk=$markerStream.Read($markerBytes,$markerCount,257-$markerCount);$markerCount+=$chunk}while($chunk -gt 0 -and $markerCount -lt 257)
            }finally{if($null -ne $markerStream){$markerStream.Dispose()}}
            if($markerCount -le 256) {
                $marker=[Text.Encoding]::ASCII.GetString($markerBytes,0,$markerCount)|ConvertFrom-Json
                if(@($marker.PSObject.Properties.Name).Count -eq 2 -and 'step' -in @($marker.PSObject.Properties.Name) -and 'hresult' -in @($marker.PSObject.Properties.Name) -and $marker.step -cin @('started','writer_call','completed') -and ($null -eq $marker.hresult -or $marker.hresult -is [int])) {
                    $childStep=$marker.step;$childHresult=$marker.hresult
                }
            }
        }
    }catch{}
    $readStep=if($script:ServicingReadDiagnostic.step -cin @('not_started','receipt_acl','receipt_read')){$script:ServicingReadDiagnostic.step}else{$null}
    $readReason=if($script:ServicingReadDiagnostic.reason -cin @('none','acl','read','over_bound','expired')){$script:ServicingReadDiagnostic.reason}else{$null}
    # Existence observations are adjacent, non-atomic, and do not authorize retry.
    Write-Output ((@{fixture='receipt_snapshot';phase=$fixturePhase;step=$fixtureStep;failed=$true;hresult=$failureHresult;base_hresult=$baseHresult;read_step=$readStep;read_reason=$readReason;child_exited=$childExited;child_exit_code=$childExitCode;child_step=$childStep;child_hresult=$childHresult;receipt_exists=[IO.File]::Exists((Join-Path $root 'update-state.json'));temporary_exists=[IO.File]::Exists((Join-Path $root 'update-state.json.tmp'))})|ConvertTo-Json -Compress)
    throw 'Owned receipt fixture failed'
} finally {
    $script:UpdateDirectory=$oldUpdateDirectory;$cleanup=$true
    if($null -ne $process){try{if(-not $process.HasExited){$process.Kill();if(-not $process.WaitForExit(1000)){$cleanup=$false}}}catch{$cleanup=$false}finally{try{$process.Dispose()}catch{$cleanup=$false}}}
    $rootRemovalSkipped=($created -and -not $cleanup)
    try{if($created -and $cleanup){foreach($item in @(Get-ChildItem -LiteralPath $root -Force)){if($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'cleanup'};Remove-Item -LiteralPath $item.FullName -Force};Remove-Item -LiteralPath $root -Force}}catch{$cleanup=$false}
    Write-Output ((@{fixture='receipt_snapshot_cleanup';confirmed=$cleanup;root_removal_skipped=$rootRemovalSkipped})|ConvertTo-Json -Compress)
    if(-not $cleanup){throw 'Receipt fixture cleanup unconfirmed'}
}
