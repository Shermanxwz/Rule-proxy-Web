@echo off
setlocal
cd /d "%~dp0"
rem The release package carries its own Python. A source checkout uses the installed one
rem and prepares PyYAML and the pinned runtimes the first time.
if exist "python\python.exe" (
    "python\python.exe" Run-RuleProxy.py %*
    goto finished
)
where py >nul 2>nul || goto no_python
py -3 install_runtime.py --check >nul 2>nul && if exist "vendor\yaml\__init__.py" goto start
call "%~dp0Setup-Windows.cmd" --no-pause || goto finished
:start
py -3 Run-RuleProxy.py %*
:finished
if errorlevel 1 (
    echo.
    echo RuleProxy did not start. See the message above.
    pause
)
exit /b
:no_python
echo Python 3.10 or newer was not found.
echo Download the release package instead; it includes Python:
echo https://github.com/Shermanxwz/Rule-proxy-Web/releases/latest
pause
exit /b 1
