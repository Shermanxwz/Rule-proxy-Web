@echo off
setlocal
cd /d "%~dp0"
rem Starts the panel without a console window and opens it in the browser. The page's
rem Quit button stops it, and its messages go to panel.log in the data folder.
rem The release package carries its own Python. A source checkout uses the installed one
rem and prepares PyYAML and the pinned runtimes the first time.
if exist "python\pythonw.exe" (
    start "" "python\pythonw.exe" Run-RuleProxy.py %*
    exit /b 0
)
where pyw >nul 2>nul || goto no_python
py -3 install_runtime.py --check >nul 2>nul && if exist "vendor\yaml\__init__.py" goto start
call "%~dp0Setup-Windows.cmd" --no-pause || goto setup_failed
:start
start "" pyw -3 Run-RuleProxy.py %*
exit /b 0
:setup_failed
echo.
echo RuleProxy setup did not finish. See the message above.
pause
exit /b 1
:no_python
echo Python 3.10 or newer was not found.
echo Download the release package instead; it includes Python:
echo https://github.com/Shermanxwz/Rule-proxy-Web/releases/latest
pause
exit /b 1
