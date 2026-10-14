@echo off
setlocal DisableDelayedExpansion
rem Prepares a source checkout once: PyYAML and the pinned runtimes, written only inside this folder.
rem The release package needs none of this.
where py >nul 2>nul || goto no_python
py -3 -c "import sys; sys.exit(sys.version_info < (3, 10))" >nul 2>nul || goto no_python
if not exist "%~dp0vendor\yaml\__init__.py" goto install_yaml
py -3 -c "import sys; sys.path.insert(0, sys.argv[1]); import yaml; sys.exit(not hasattr(yaml, 'safe_load'))" "%~dp0vendor" >nul 2>nul && goto runtime
:install_yaml
py -3 -m pip install --disable-pip-version-check --upgrade --target "%~dp0vendor" -r "%~dp0requirements.txt" || goto failed
:runtime
py -3 "%~dp0install_runtime.py" --platform windows-amd64 --if-needed || goto failed
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
