@echo off
setlocal DisableDelayedExpansion
rem Installation needs elevation once; the Web panel and applications never do.
powershell.exe -NoProfile -NonInteractive -Command "$p=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent()); if($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){exit 5}"
if errorlevel 1 goto elevated
set "ruleproxy_root=%ProgramFiles%\RuleProxy-Web"
if not exist "%ruleproxy_root%\deployment.json" goto setup
if not exist "%ruleproxy_root%\python\pythonw.exe" goto setup
start "" "%ruleproxy_root%\python\pythonw.exe" -I -S "%ruleproxy_root%\Run-RuleProxy.py" %*
exit /b 0
:setup
call "%~dp0Setup-Windows.cmd" --no-pause
exit /b %ERRORLEVEL%
:elevated
echo Open Start-Windows.cmd from your normal desktop account, without Run as administrator.
pause
exit /b 5
