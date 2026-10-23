$ErrorActionPreference='Stop'
$candidate=Join-Path $PSScriptRoot 'zero-cap-same-sid-loopback-candidate'
$target=Join-Path $PSScriptRoot 'zero-cap-loopback-compile-01'
$inputPath=Join-Path $PSScriptRoot 'zero-cap-loopback-native-compile-input-01.json'
if((Get-FileHash -LiteralPath $inputPath -Algorithm SHA256).Hash.ToLowerInvariant() -cne 'a92d15a257efcfd85dc5069d7cadba2c7406204c6a9fb3fef3ec1ec26911796a'){throw 'Frozen two-source input required'}
$loopbackCompileInput=Get-Content -LiteralPath $inputPath -Raw | ConvertFrom-Json
if(Test-Path -LiteralPath $target){throw 'Fresh compile directory required'}
if($loopbackCompileInput.native_source_count -ne 2 -or $loopbackCompileInput.interface_version -ne 1 -or $loopbackCompileInput.actual_ready -ne $false){throw 'Exact compile-only contract required'}
$names=@('.github/native/windows_identity_lpac_loopback_actor.cpp','.github/native/windows_identity_lpac_loopback_contract.hpp')
if(@($loopbackCompileInput.sources.PSObject.Properties).Count -ne 2){throw 'Exact source closure required'}
foreach($name in $names){
 if((Get-FileHash -LiteralPath (Join-Path $candidate $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $loopbackCompileInput.sources.$name.sha256){throw ('Source drift: '+$name)}
}
$null=New-Item -ItemType Directory -Path (Join-Path $target 'src/.github/native')
foreach($name in $names){
 $source=Join-Path $candidate $name
 $copy=Join-Path (Join-Path $target 'src') $name
 Copy-Item -LiteralPath $source -Destination $copy
 foreach($checked in @($source,$copy)){
  if((Get-FileHash -LiteralPath $checked -Algorithm SHA256).Hash.ToLowerInvariant() -cne $loopbackCompileInput.sources.$name.sha256){throw ('Snapshot mismatch: '+$name)}
 }
}
Copy-Item -LiteralPath $inputPath -Destination (Join-Path $target 'input-snapshot.json')
$vswhere="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $vs){throw 'Installed MSVC developer environment required'}
Import-Module "$vs\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
[pscustomobject]@{CompilerPath=(Get-Command cl.exe).Source;CompilerFileVersion=(Get-Item -LiteralPath (Get-Command cl.exe).Source).VersionInfo.FileVersion;WindowsSDKVersion=$env:WindowsSDKVersion;VCToolsVersion=$env:VCToolsVersion;Runtime='MT';Architecture='amd64';CompileOnly=$true;ActorExecuted=$false;NetworkExecuted=$false} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $target 'toolchain.json') -Encoding utf8
Push-Location -LiteralPath $target
try{
 & cl.exe /nologo /std:c++17 /EHsc /W4 /WX /MT /O2 /guard:cf /DUNICODE /D_UNICODE (Join-Path $target 'src/.github/native/windows_identity_lpac_loopback_actor.cpp') /link /OUT:windows_identity_lpac_loopback_actor.exe /SUBSYSTEM:WINDOWS /INCREMENTAL:NO /DYNAMICBASE /NXCOMPAT ws2_32.lib advapi32.lib *> (Join-Path $target 'compile.log')
 $code=$LASTEXITCODE
 Get-Content -LiteralPath (Join-Path $target 'compile.log') -Tail 45
 if($code -ne 0){exit $code}
 [pscustomobject]@{schemaVersion=1;compileOnly=$true;runtimeAcceptance=$false;interfaceVersion=1;executableSha256=(Get-FileHash -LiteralPath (Join-Path $target 'windows_identity_lpac_loopback_actor.exe') -Algorithm SHA256).Hash.ToLowerInvariant();actorSourceSha256=$loopbackCompileInput.sources.'.github/native/windows_identity_lpac_loopback_actor.cpp'.sha256;contractSourceSha256=$loopbackCompileInput.sources.'.github/native/windows_identity_lpac_loopback_contract.hpp'.sha256} | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $target 'identity-lpac-loopback-manifest.json') -Encoding utf8
}finally{Pop-Location}
