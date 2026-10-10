@echo off
setlocal
cd /d "%~dp0"
py -3 -m pip install --target vendor -r requirements.txt
if errorlevel 1 goto failed
py -3 install_runtime.py --platform windows-amd64
if errorlevel 1 goto failed
echo Setup complete. Open Start-Windows.cmd.
pause
exit /b 0
:failed
echo Setup failed. No system network settings were changed.
pause
exit /b 1
