$ErrorActionPreference='Stop'
$candidate=Join-Path $PSScriptRoot 'psec-lpac-matchedcaps-candidate'
$repo=Join-Path $PSScriptRoot 'Rule-proxy-Web'
$target=Join-Path $PSScriptRoot 'psec-lpac-matchedcaps-bridge-compile-01'
if(Test-Path -LiteralPath $target){throw 'Fresh compile directory required'}
$freezePath=Join-Path $PSScriptRoot 'psec-lpac-matchedcaps-native-freeze-01.json'
if((Get-FileHash -LiteralPath $freezePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne '7e702eac67a463682878c9d40ee1d8665d30a2f596a9ebf1edf1b2801de3fc1f'){throw 'Frozen ABI3 native review required'}
$freeze=Get-Content -LiteralPath $freezePath -Raw | ConvertFrom-Json
if($freeze.native_source_count -ne 6 -or $freeze.dependency_count -ne 31 -or $freeze.compile_input_count -ne 37 -or $freeze.constructor_policy -cne 'bootstrap-held-primary-matched-security-capabilities-aap-only-v1'){throw 'Exact ABI3 closure required'}
$newNames=@('.github/native/windows_psec_lpac_matchedcaps_bridge.hpp','.github/native/windows_psec_lpac_matchedcaps_bridge_core.hpp','.github/native/windows_psec_lpac_matchedcaps_bridge.cpp')
if(@($freeze.files.PSObject.Properties|Where-Object Name -in $newNames).Count -ne 3){throw 'Three new native paths required'}
foreach($property in $freeze.old_37_inputs_unchanged.PSObject.Properties){
    if((Get-FileHash -LiteralPath (Join-Path $repo $property.Name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $property.Value){throw ('Old frozen input changed: '+$property.Name)}
}
$rows=@()
foreach($group in @('native_sources','dependencies')){
    foreach($property in $freeze.$group.PSObject.Properties){
        $kind=if($group -eq 'native_sources'){'source'}else{'dependency'}
        $sourceRoot=if($property.Name -in $newNames){$candidate}else{$repo}
        $source=Join-Path $sourceRoot $property.Name
        if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $property.Value){throw ('Unfrozen input: '+$property.Name)}
        $rows+=[pscustomobject]@{Path=$property.Name;Sha256=$property.Value;Kind=$kind;Source=$source}
    }
}
if($rows.Count -ne 37 -or @($rows|Where-Object Kind -eq 'source').Count -ne 6 -or @($rows.Path|Sort-Object -Unique).Count -ne 37){throw 'Six unique sources and31 dependencies required'}
$null=New-Item -ItemType Directory -Path (Join-Path $target 'src')
foreach($row in $rows){
    $destination=Join-Path (Join-Path $target 'src') $row.Path
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force
    Copy-Item -LiteralPath $row.Source -Destination $destination
    foreach($checked in @($destination,$row.Source)){
        if((Get-FileHash -LiteralPath $checked -Algorithm SHA256).Hash.ToLowerInvariant() -cne $row.Sha256){throw ('Snapshot byte mismatch: '+$row.Path)}
    }
}
$publicRows=@($rows|Select-Object Path,Sha256,Kind)
[pscustomobject]@{SchemaVersion=1;SnapshotBeforeCompile=$true;SourcesAndDependencies=$publicRows;NativeFreezeSha256='7e702eac67a463682878c9d40ee1d8665d30a2f596a9ebf1edf1b2801de3fc1f';ConstructorPolicy='bootstrap-held-primary-matched-security-capabilities-aap-only-v1';LibraryAbiVersion=3;PayloadVersion=1;DllLoaded=$false;CpseCalled=$false;ActorExecuted=$false} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $target 'input-snapshot.json') -Encoding utf8
$vswhere="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $vs){throw 'Installed MSVC required'}
Import-Module "$vs\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
[pscustomobject]@{CompilerPath=(Get-Command cl.exe).Source;CompilerFileVersion=(Get-Item -LiteralPath (Get-Command cl.exe).Source).VersionInfo.FileVersion;WindowsSDKVersion=$env:WindowsSDKVersion;VCToolsVersion=$env:VCToolsVersion;Runtime='MT';Architecture='amd64';CompileOnly=$true} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $target 'toolchain.json') -Encoding utf8
$snapshot=Join-Path $target 'src'
$newCpp='.github/native/windows_psec_lpac_matchedcaps_bridge.cpp'
Push-Location -LiteralPath $target
try{
    & cl.exe /nologo /std:c++17 /EHsc /W4 /WX /LD /MT /O2 /guard:cf /I (Join-Path $snapshot '.github/native') /I (Join-Path $snapshot 'generated') /I (Join-Path $snapshot 'vendor/flatbuffers/include') (Join-Path $snapshot $newCpp) /link /OUT:windows_psec_lpac_matchedcaps_bridge.dll /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT *> (Join-Path $target 'compile.log')
    $code=$LASTEXITCODE
    Get-Content -LiteralPath (Join-Path $target 'compile.log') -Tail 45
    if($code -ne 0){exit $code}
    [pscustomobject]@{CompileOnly=$true;DllLoaded=$false;CpseCalled=$false;ActorExecuted=$false;DllSha256=(Get-FileHash -LiteralPath (Join-Path $target 'windows_psec_lpac_matchedcaps_bridge.dll') -Algorithm SHA256).Hash.ToLowerInvariant()}
}finally{Pop-Location}
