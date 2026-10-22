$ErrorActionPreference='Stop'
$candidate=Join-Path $PSScriptRoot 'psec-lpac-identity-bridge-candidate'
$target=Join-Path $PSScriptRoot 'psec-lpac-bridge-compile-02'
if(Test-Path -LiteralPath $target){throw 'Fresh compile directory required'}
$freeze=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'psec-lpac-native-candidate-freeze-01.json') | ConvertFrom-Json
$verified=Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot 'psec-lpac-bridge-deps/verification.json') | ConvertFrom-Json
$rows=@()
foreach($property in $freeze.files.PSObject.Properties){
    if($property.Name.StartsWith('tests/')){continue}
    $rows+= [pscustomobject]@{Path=$property.Name;Sha256=$property.Value;Kind='source'}
}
if($rows.Count -ne 6){throw 'Exactly six native source inputs required'}
foreach($member in $verified.source_files){
    $rows+=[pscustomobject]@{Path=('vendor/flatbuffers/'+$member.path);Sha256=$member.sha256;Kind='dependency'}
}
if($rows.Count -ne 37){throw 'Exactly 31 dependency inputs required'}
foreach($row in $rows){
    if((Get-FileHash -LiteralPath (Join-Path $candidate $row.Path) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $row.Sha256){throw ('Unfrozen source: '+$row.Path)}
}
$null=New-Item -ItemType Directory -Path (Join-Path $target 'src')
foreach($row in $rows){
    $destination=Join-Path (Join-Path $target 'src') $row.Path
    $null=New-Item -ItemType Directory -Path (Split-Path -Parent $destination) -Force
    Copy-Item -LiteralPath (Join-Path $candidate $row.Path) -Destination $destination
    foreach($checked in @($destination,(Join-Path $candidate $row.Path))){
        if((Get-FileHash -LiteralPath $checked -Algorithm SHA256).Hash.ToLowerInvariant() -cne $row.Sha256){throw ('Snapshot byte mismatch: '+$row.Path)}
    }
}
[pscustomobject]@{SchemaVersion=1;SnapshotBeforeCompile=$true;SourcesAndDependencies=$rows;DllLoaded=$false;CpseCalled=$false;ActorExecuted=$false} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $target 'input-snapshot.json') -Encoding utf8
$vswhere="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $vs){throw 'Installed MSVC required'}
Import-Module "$vs\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
[pscustomobject]@{CompilerPath=(Get-Command cl.exe).Source;CompilerFileVersion=(Get-Item -LiteralPath (Get-Command cl.exe).Source).VersionInfo.FileVersion;WindowsSDKVersion=$env:WindowsSDKVersion;VCToolsVersion=$env:VCToolsVersion;Runtime='MT';Architecture='amd64';CompileOnly=$true} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $target 'toolchain.json') -Encoding utf8
$snapshot=Join-Path $target 'src'
Push-Location -LiteralPath $target
try{
    & cl.exe /nologo /std:c++17 /EHsc /W4 /WX /LD /MT /O2 /guard:cf /I (Join-Path $snapshot 'generated') /I (Join-Path $snapshot 'vendor/flatbuffers/include') (Join-Path $snapshot '.github/native/windows_psec_lpac_bridge.cpp') /link /OUT:windows_psec_lpac_bridge.dll /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT *> (Join-Path $target 'compile.log')
    $code=$LASTEXITCODE
    Get-Content -LiteralPath (Join-Path $target 'compile.log') -Tail 45
    if($code -ne 0){exit $code}
    [pscustomobject]@{CompileOnly=$true;DllLoaded=$false;CpseCalled=$false;ActorExecuted=$false;DllSha256=(Get-FileHash -LiteralPath (Join-Path $target 'windows_psec_lpac_bridge.dll') -Algorithm SHA256).Hash.ToLowerInvariant()}
}finally{Pop-Location}
