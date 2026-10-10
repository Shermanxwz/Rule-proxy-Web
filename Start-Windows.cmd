@echo off
setlocal
cd /d "%~dp0"
py -3 Run-RuleProxy.py
if errorlevel 1 (
  echo.
  echo RuleProxy could not start. Python 3.10+ and PyYAML are required.
  echo Source checkout: run Setup-Windows.cmd once.
  pause
)
