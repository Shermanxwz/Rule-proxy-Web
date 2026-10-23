param([switch]$Compile)
$ErrorActionPreference='Stop'
$streamCandidate=Join-Path $PSScriptRoot 'lpac-stream-origin-candidate'
$streamFreezePath=Join-Path $PSScriptRoot 'lpac-stream-native-freeze-01.json'
if((Get-Item -LiteralPath $streamFreezePath).Length -ne 4309 -or (Get-FileHash -LiteralPath $streamFreezePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne '04a400a90b3fcbbaa03f0fe065a4181812b3a0ec48d729ebb04b785e73126023'){throw 'Exact frozen native metadata required'}
$streamFreeze=Get-Content -LiteralPath $streamFreezePath -Raw | ConvertFrom-Json
if($streamFreeze.stage -cne 'work-lpac-stream-native-frozen' -or $streamFreeze.actual_ready -ne $false){throw 'Native freeze required'}
foreach($entry in $streamFreeze.native_sources.PSObject.Properties){
    $path=Join-Path $streamCandidate $entry.Name
    if((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value.sha256 -or (Get-Item -LiteralPath $path).Length -ne $entry.Value.bytes){throw 'Native input drift'}
}
if(-not $Compile){[pscustomobject]@{Stage='lpac-stream-compile-preview';SourceCount=4;ActorExecuted=$false;CompilerExecuted=$false;ApiExecuted=$false} | ConvertTo-Json;exit 0}
$streamBuild=Join-Path $PSScriptRoot 'lpac-stream-native-compile-01'
if(Test-Path -LiteralPath $streamBuild){throw 'Fresh immutable build directory required'}
New-Item -ItemType Directory -Path (Join-Path $streamBuild 'src') | Out-Null
$streamSnapshot=@{}
foreach($entry in $streamFreeze.native_sources.PSObject.Properties){
    $destination=Join-Path (Join-Path $streamBuild 'src') (Split-Path $entry.Name -Leaf)
    Copy-Item -LiteralPath (Join-Path $streamCandidate $entry.Name) -Destination $destination
    if((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value.sha256){throw 'Snapshot mismatch'}
    $streamSnapshot[$entry.Name]=@{bytes=$entry.Value.bytes;sha256=$entry.Value.sha256}
}
# Save/close the entire immutable input map before the first compiler invocation.
$streamSnapshot | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $streamBuild 'input-snapshot.json') -Encoding utf8
$streamVswhere="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$streamVS=& $streamVswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $streamVS){throw 'Installed x64 compiler required'}
Import-Module "$streamVS\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $streamVS -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
$streamCompiler=Get-Command cl.exe -ErrorAction Stop
[pscustomobject]@{schema_version=1;stage='lpac-stream-native-compile-only';compiler_file_version=(Get-Item -LiteralPath $streamCompiler.Source).VersionInfo.FileVersion;windows_sdk_version=$env:WindowsSDKVersion;vc_tools_version=$env:VCToolsVersion;target='x64';runtime='/MT';flags='/std:c++17 /O2 /W4 /WX /EHsc /guard:cf /SUBSYSTEM:WINDOWS';actor_executed=$false;api_executed=$false;dll_loaded=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $streamBuild 'toolchain.json') -Encoding utf8
foreach($streamRole in @('front','network')){
    $streamStem='windows_identity_lpac_stream_'+$streamRole+'_actor'
    $streamSource=Join-Path (Join-Path $streamBuild 'src') ($streamStem+'.cpp')
    $streamExe=Join-Path $streamBuild ($streamStem+'.exe')
    $streamObject=Join-Path $streamBuild ($streamStem+'.obj')
    $streamLog=Join-Path $streamBuild ($streamRole+'-compile.log')
    & cl.exe /nologo /std:c++17 /O2 /W4 /WX /EHsc /MT /guard:cf /DUNICODE /D_UNICODE $streamSource "/Fo$streamObject" "/Fe$streamExe" /link /SUBSYSTEM:WINDOWS /DYNAMICBASE /NXCOMPAT /guard:cf *> $streamLog
    if($LASTEXITCODE -ne 0){throw ('Compile failed; preserve '+$streamRole+' log')}
    foreach($entry in $streamFreeze.native_sources.PSObject.Properties){
        $snapshot=Join-Path (Join-Path $streamBuild 'src') (Split-Path $entry.Name -Leaf)
        if((Get-FileHash -LiteralPath $snapshot -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.Value.sha256){throw 'Compile input changed'}
    }
    $streamActorKey='.github/native/'+$streamStem+'.cpp'
    $streamManifest=[ordered]@{schemaVersion=1;compileOnly=$true;runtimeAcceptance=$false;interfaceVersion=1;executableSha256=(Get-FileHash -LiteralPath $streamExe -Algorithm SHA256).Hash.ToLowerInvariant();actorSourceSha256=$streamFreeze.native_sources.$streamActorKey.sha256;streamContractSha256=$streamFreeze.native_sources.'.github/native/windows_identity_lpac_stream_contract.hpp'.sha256;identitySourceSha256=$streamFreeze.native_sources.'.github/native/windows_identity_actor.cpp'.sha256}
    $streamManifestPath=Join-Path $streamBuild ('identity-lpac-stream-'+$streamRole+'-manifest.json')
    [IO.File]::WriteAllText($streamManifestPath,($streamManifest | ConvertTo-Json)+"`n",[Text.UTF8Encoding]::new($false))
}
# No execution, LoadLibrary, process/profile/ACL/firewall/DNS/route operation.
[pscustomobject]@{Stage='lpac-stream-two-artifact-compile-only';CompilerExecuted=$true;ActorExecuted=$false;ApiExecuted=$false;Output='lpac-stream-native-compile-01'} | ConvertTo-Json
