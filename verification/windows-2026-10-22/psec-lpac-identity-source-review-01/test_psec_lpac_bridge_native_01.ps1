$ErrorActionPreference='Stop'
Import-Module 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools/Common7/Tools/Microsoft.VisualStudio.DevShell.dll'
Enter-VsDevShell -VsInstallPath 'C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools' -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64'
$tests=Join-Path $PSScriptRoot 'psec-lpac-identity-bridge-candidate/tests'
python -I -S -B -m unittest discover -s $tests -p 'test_windows_identity_psec_lpac_bridge_native.py' -v
if($LASTEXITCODE -ne 0){throw 'pure fake tests failed'}
