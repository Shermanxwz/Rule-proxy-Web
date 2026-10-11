@echo off
setlocal
cd /d "%~dp0"
rem Prepares a source checkout once: PyYAML and the pinned runtimes, written only inside this folder.
rem The release package needs none of this.
where py >nul 2>nul || goto no_python
py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul || goto no_python
if not exist "vendor\yaml\__init__.py" (
    py -3 -m pip install --disable-pip-version-check --target vendor -r requirements.txt || goto failed
)
py -3 install_runtime.py --platform windows-amd64 --if-needed || goto failed
echo Setup complete.
if /i "%~1"=="--no-pause" exit /b 0
echo Open Start-Windows.cmd to start RuleProxy.
pause
exit /b 0
:no_python
echo Python 3.10 or newer was not found. Install it from https://www.python.org/downloads/
echo or download the release package, which includes Python:
echo https://github.com/Shermanxwz/Rule-proxy-Web/releases/latest
goto stop
:failed
echo Setup failed. No system network settings were changed.
:stop
if /i not "%~1"=="--no-pause" pause
exit /b 1
