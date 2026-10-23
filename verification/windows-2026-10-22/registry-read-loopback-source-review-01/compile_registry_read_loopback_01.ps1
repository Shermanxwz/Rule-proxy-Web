$ErrorActionPreference='Stop'
$registryCandidate=Join-Path $PSScriptRoot 'registry-read-same-sid-loopback-candidate'
$registryTarget=Join-Path $PSScriptRoot 'registry-read-loopback-compile-01'
$registryFreezePath=Join-Path $PSScriptRoot 'registry-read-loopback-native-freeze-01.json'
if((Get-FileHash -LiteralPath $registryFreezePath -Algorithm SHA256).Hash.ToLowerInvariant() -cne '456f5c83ba8c35d9af31cedbb63c8be248ca4bab15dbce288287511580d5e5ce'){throw 'Fixed new native freeze required'}
$registryFreeze=Get-Content -LiteralPath $registryFreezePath -Raw | ConvertFrom-Json
$registryNames=@('.github/native/windows_identity_lpac_registry_loopback_actor.cpp','.github/native/windows_identity_lpac_registry_loopback_contract.hpp')
if(Test-Path -LiteralPath $registryTarget){throw 'Fresh compile directory required'}
if($registryFreeze.native_source_count -ne 2 -or $registryFreeze.interface_version -ne 1 -or @($registryFreeze.native_sources.PSObject.Properties).Count -ne 2){throw 'Exact two-source interface required'}
foreach($registryName in $registryNames){
 if((Get-FileHash -LiteralPath (Join-Path $registryCandidate $registryName) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $registryFreeze.native_sources.$registryName.sha256){throw ('Source drift: '+$registryName)}
}
$null=New-Item -ItemType Directory -Path (Join-Path $registryTarget 'src/.github/native')
foreach($registryName in $registryNames){
 $registrySource=Join-Path $registryCandidate $registryName
 $registryCopy=Join-Path (Join-Path $registryTarget 'src') $registryName
 Copy-Item -LiteralPath $registrySource -Destination $registryCopy
 foreach($registryChecked in @($registrySource,$registryCopy)){
  if((Get-FileHash -LiteralPath $registryChecked -Algorithm SHA256).Hash.ToLowerInvariant() -cne $registryFreeze.native_sources.$registryName.sha256){throw ('Snapshot mismatch: '+$registryName)}
 }
}
[pscustomobject]@{SchemaVersion=1;Stage='registry-read-loopback-before-compile-inputs';SnapshotBeforeCompile=$true;InterfaceVersion=1;NativeSourceCount=2;Sources=$registryFreeze.native_sources;NativeFreezeSha256='456f5c83ba8c35d9af31cedbb63c8be248ca4bab15dbce288287511580d5e5ce';ActorExecuted=$false;NetworkExecuted=$false} | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $registryTarget 'input-snapshot.json') -Encoding utf8
$registryVswhere="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$registryVs=& $registryVswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $registryVs){throw 'Installed MSVC developer environment required'}
Import-Module "$registryVs\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $registryVs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
[pscustomobject]@{CompilerPath=(Get-Command cl.exe).Source;CompilerFileVersion=(Get-Item -LiteralPath (Get-Command cl.exe).Source).VersionInfo.FileVersion;WindowsSDKVersion=$env:WindowsSDKVersion;VCToolsVersion=$env:VCToolsVersion;Runtime='MT';Architecture='amd64';CompileOnly=$true;ActorExecuted=$false;NetworkExecuted=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $registryTarget 'toolchain.json') -Encoding utf8
Push-Location -LiteralPath $registryTarget
try{
 & cl.exe /nologo /std:c++17 /EHsc /W4 /WX /MT /O2 /guard:cf /DUNICODE /D_UNICODE (Join-Path $registryTarget 'src/.github/native/windows_identity_lpac_registry_loopback_actor.cpp') /link /OUT:windows_identity_lpac_registry_loopback_actor.exe /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT ws2_32.lib advapi32.lib *> (Join-Path $registryTarget 'compile.log')
 $registryCode=$LASTEXITCODE
 Get-Content -LiteralPath (Join-Path $registryTarget 'compile.log') -Tail 45
 if($registryCode -ne 0){exit $registryCode}
 [pscustomobject]@{schemaVersion=1;compileOnly=$true;runtimeAcceptance=$false;interfaceVersion=1;executableSha256=(Get-FileHash -LiteralPath (Join-Path $registryTarget 'windows_identity_lpac_registry_loopback_actor.exe') -Algorithm SHA256).Hash.ToLowerInvariant();actorSourceSha256=$registryFreeze.native_sources.'.github/native/windows_identity_lpac_registry_loopback_actor.cpp'.sha256;contractSourceSha256=$registryFreeze.native_sources.'.github/native/windows_identity_lpac_registry_loopback_contract.hpp'.sha256} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $registryTarget 'identity-lpac-registry-loopback-manifest.json') -Encoding utf8
}finally{Pop-Location}
