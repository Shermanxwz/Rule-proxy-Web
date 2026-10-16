@echo off
setlocal DisableDelayedExpansion
rem Daily background entry: Start-Windows.lnk avoids even the CMD host window.
set "ruleproxy_root=%ProgramFiles%\RuleProxy-Web"
if not exist "%ruleproxy_root%\deployment.json" goto setup
if not exist "%ruleproxy_root%\python\pythonw.exe" goto setup
start "" "%ruleproxy_root%\python\pythonw.exe" -I -S "%ruleproxy_root%\Run-RuleProxy.py" --no-browser %*
exit /b 0
:setup
call "%~dp0Setup-Windows.cmd" --no-pause
exit /b %ERRORLEVEL%
