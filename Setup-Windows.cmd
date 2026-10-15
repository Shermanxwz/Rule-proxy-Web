@echo off
setlocal DisableDelayedExpansion
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\windows-setup.ps1" -SourceRoot "%~dp0."
set "ruleproxy_exit=%ERRORLEVEL%"
if "%ruleproxy_exit%"=="0" exit /b 0
if "%ruleproxy_exit%"=="3010" echo Windows requires a restart. Restart and run Setup-Windows.cmd again to continue.
if not "%ruleproxy_exit%"=="3010" echo RuleProxy setup failed. See the error above; setup logs are in ProgramData\RuleProxy-Web.
if /i not "%~1"=="--no-pause" pause
exit /b %ruleproxy_exit%
