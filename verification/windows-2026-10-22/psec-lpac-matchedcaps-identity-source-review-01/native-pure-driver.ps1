$ErrorActionPreference='Stop'
$candidate=Join-Path $PSScriptRoot 'psec-lpac-matchedcaps-candidate'
$freezePath=Join-Path $PSScriptRoot 'psec-lpac-matchedcaps-native-freeze-01.json'
if((Get-FileHash -LiteralPath $freezePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne '7e702eac67a463682878c9d40ee1d8665d30a2f596a9ebf1edf1b2801de3fc1f'){throw 'Frozen native candidate required'}
$freeze=Get-Content -LiteralPath $freezePath -Raw | ConvertFrom-Json
foreach($group in @('files','native_sources','dependencies')){
    foreach($property in $freeze.$group.PSObject.Properties){
        $expected=if($group -eq 'files'){$property.Value.sha256}else{$property.Value}
        if((Get-FileHash -LiteralPath (Join-Path $candidate $property.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $expected){throw ('Pure input drift: '+$property.Name)}
    }
}
$log=Join-Path $PSScriptRoot 'psec-lpac-matchedcaps-native-pure-01.log'
$receipt=Join-Path $PSScriptRoot 'psec-lpac-matchedcaps-native-pure-01.json'
if((Test-Path -LiteralPath $log) -or (Test-Path -LiteralPath $receipt)){throw 'Fresh pure outputs required'}
$vswhere="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $vs){throw 'Installed MSVC required'}
Import-Module "$vs\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
$watch=[Diagnostics.Stopwatch]::StartNew()
Push-Location -LiteralPath $candidate
try{
    & python -I -S -B -m unittest discover -s tests -p 'test_windows_identity_psec_lpac_matchedcaps_native.py' -v *> $log
    $code=$LASTEXITCODE
}finally{Pop-Location;$watch.Stop()}
Get-Content -LiteralPath $log -Tail 30
$text=Get-Content -LiteralPath $log -Raw
if($code -ne 0 -or $text -notmatch 'Ran 3 tests in ' -or $text -notmatch '(?m)^OK\s*$' -or $text -match '(?i)skipped|FAILED|ERROR:'){throw 'Three zero-skip pure tests must pass'}
[pscustomobject]@{SchemaVersion=1;Stage='matchedcaps-native-portable-pure';NativeFreezeSha256='7e702eac67a463682878c9d40ee1d8665d30a2f596a9ebf1edf1b2801de3fc1f';Tests=3;Failures=0;Errors=0;Skipped=0;WallSeconds=$watch.Elapsed.TotalSeconds;LogBytes=(Get-Item -LiteralPath $log).Length;LogSha256=(Get-FileHash -LiteralPath $log -Algorithm SHA256).Hash.ToLowerInvariant();DllLoaded=$false;ProcessmodelLoaded=$false;CpseCalled=$false;ActorExecuted=$false;NetworkExecuted=$false} | ConvertTo-Json | Set-Content -LiteralPath $receipt -Encoding utf8
