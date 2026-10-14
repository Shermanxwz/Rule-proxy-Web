@echo off
setlocal DisableDelayedExpansion
rem Starts the panel without a console window and opens it in the browser. The page's
rem Quit button stops it, and its messages go to panel.log in the data folder.
rem The release package carries its own Python. A source checkout uses the installed one
rem and prepares PyYAML and the pinned runtimes the first time.
if exist "%~dp0python\pythonw.exe" (
    start "" "%~dp0python\pythonw.exe" "%~dp0Run-RuleProxy.py" %*
    exit /b 0
)
where pyw >nul 2>nul || goto no_python
py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul || goto no_python
py -3 "%~dp0install_runtime.py" --check >nul 2>nul || goto setup
if not exist "%~dp0vendor\yaml\__init__.py" goto setup
py -3 -c "import sys; sys.path.insert(0, sys.argv[1]); import yaml; sys.exit(not hasattr(yaml, 'safe_load'))" "%~dp0vendor" >nul 2>nul && goto start
:setup
rem Expand this path once in the child cmd, so percent signs in folder names survive.
set "ruleproxy_setup=%~dp0Setup-Windows.cmd"
"%ComSpec%" /d /v:off /s /c ""%%ruleproxy_setup%%" --no-pause" || goto setup_failed
:start
start "" pyw -3 "%~dp0Run-RuleProxy.py" %*
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
