@echo off
setlocal DisableDelayedExpansion
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows-setup.ps1" -SourceRoot "%~dp0."
set "ruleproxy_exit=%ERRORLEVEL%"
if "%ruleproxy_exit%"=="0" echo RuleProxy setup completed. Web panel: http://127.0.0.1:8879
if "%ruleproxy_exit%"=="3010" echo Windows requires a restart. Restart and run Setup-Windows.cmd again to continue.
if not "%ruleproxy_exit%"=="0" if not "%ruleproxy_exit%"=="3010" echo RuleProxy setup failed. See the error above for details and recovery instructions.
if /i not "%~1"=="--no-pause" pause
exit /b %ruleproxy_exit%
