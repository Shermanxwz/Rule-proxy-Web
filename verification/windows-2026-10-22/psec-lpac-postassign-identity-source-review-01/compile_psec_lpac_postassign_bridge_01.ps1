$ErrorActionPreference='Stop'
$candidate=Join-Path $PSScriptRoot 'psec-lpac-postassign-native-candidate'
$repo=Join-Path $PSScriptRoot 'Rule-proxy-Web'
$target=Join-Path $PSScriptRoot 'psec-lpac-postassign-bridge-compile-01'
if(Test-Path -LiteralPath $target){throw 'Fresh compile directory required'}
$freezePath=Join-Path $PSScriptRoot 'psec-lpac-postassign-native-freeze-01.json'
if((Get-FileHash -LiteralPath $freezePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'f7d62220f30d11ad245ab7de859bd4c93ca4bee13294c1c8b64e5db5aad4b981'){throw 'Frozen native review required'}
$oldManifestPath=Join-Path $PSScriptRoot 'psec-lpac-bridge-compile-02/psec-lpac-bridge-manifest.json'
if((Get-FileHash -LiteralPath $oldManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne '9b9ab93826c99bbde32c18cca3a32389d75086c3b1f7abbc453a2dda98d09209'){throw 'Original immutable manifest required'}
$old=Get-Content -LiteralPath $oldManifestPath -Raw | ConvertFrom-Json
$rows=@()
foreach($group in @('sources','dependencies')){
    foreach($property in $old.$group.PSObject.Properties){
        $kind=if($group -eq 'sources'){'source'}else{'dependency'}
        $source=Join-Path $repo $property.Name
        if((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $property.Value){throw ('Original source changed: '+$property.Name)}
        if($property.Name -eq '.github/native/windows_psec_lpac_bridge.cpp'){continue}
        $rows+=[pscustomobject]@{Path=$property.Name;Sha256=$property.Value;Kind=$kind;Source=$source}
    }
}
$newName='.github/native/windows_psec_lpac_postassign_bridge.cpp'
$newSha='806ead04ee3f583bac1f0d7dc72f51fa10de4634bb7cd2b597f0a3a3c8b29f36'
$rows+=[pscustomobject]@{Path=$newName;Sha256=$newSha;Kind='source';Source=(Join-Path $candidate $newName)}
if($rows.Count -ne 37 -or @($rows|Where-Object Kind -eq 'source').Count -ne 6){throw 'Six source and31 dependency inputs required'}
foreach($row in $rows){
    if((Get-FileHash -LiteralPath $row.Source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $row.Sha256){throw ('Unfrozen source: '+$row.Path)}
}
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
[pscustomobject]@{SchemaVersion=1;SnapshotBeforeCompile=$true;SourcesAndDependencies=$publicRows;ConstructorPolicy='outer-guarded-held-explicit-inner-assignment-v1';LibraryAbiVersion=2;PayloadVersion=1;DllLoaded=$false;CpseCalled=$false;ActorExecuted=$false} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $target 'input-snapshot.json') -Encoding utf8
$vswhere="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $vs){throw 'Installed MSVC required'}
Import-Module "$vs\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
[pscustomobject]@{CompilerPath=(Get-Command cl.exe).Source;CompilerFileVersion=(Get-Item -LiteralPath (Get-Command cl.exe).Source).VersionInfo.FileVersion;WindowsSDKVersion=$env:WindowsSDKVersion;VCToolsVersion=$env:VCToolsVersion;Runtime='MT';Architecture='amd64';CompileOnly=$true} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $target 'toolchain.json') -Encoding utf8
$snapshot=Join-Path $target 'src'
Push-Location -LiteralPath $target
try{
    & cl.exe /nologo /std:c++17 /EHsc /W4 /WX /LD /MT /O2 /guard:cf /I (Join-Path $snapshot 'generated') /I (Join-Path $snapshot 'vendor/flatbuffers/include') (Join-Path $snapshot $newName) /link /OUT:windows_psec_lpac_postassign_bridge.dll /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT *> (Join-Path $target 'compile.log')
    $code=$LASTEXITCODE
    Get-Content -LiteralPath (Join-Path $target 'compile.log') -Tail 45
    if($code -ne 0){exit $code}
    [pscustomobject]@{CompileOnly=$true;DllLoaded=$false;CpseCalled=$false;ActorExecuted=$false;DllSha256=(Get-FileHash -LiteralPath (Join-Path $target 'windows_psec_lpac_postassign_bridge.dll') -Algorithm SHA256).Hash.ToLowerInvariant()}
}finally{Pop-Location}
