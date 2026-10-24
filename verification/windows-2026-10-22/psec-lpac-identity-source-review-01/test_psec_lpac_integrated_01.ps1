$ErrorActionPreference='Stop'
$log=Join-Path $PSScriptRoot 'psec-lpac-main-pure-01.log'
if(Test-Path -LiteralPath $log){throw 'Fresh test log required'}
$vswhere="${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vs=& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if(-not $vs){throw 'Installed x64 compiler required'}
Import-Module "$vs\Common7\Tools\Microsoft.VisualStudio.DevShell.dll"
Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
Push-Location -LiteralPath (Join-Path $PSScriptRoot 'Rule-proxy-Web')
try{
    & python -S -B -m unittest discover -s tests -p 'test_windows_identity*.py' -v *> $log
    $code=$LASTEXITCODE
    Get-Content -LiteralPath $log -Tail 30
    exit $code
}finally{Pop-Location}
