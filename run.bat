@echo off
setlocal EnableExtensions
rem Home SOC launcher: creates a venv on first run, installs deps, initialises, runs.
rem No admin needed. Close the window or press Ctrl-C to stop.
rem
rem Every step's exit code is checked, so a wrong Python version or an offline first run
rem ends in one sentence you can act on instead of a Python traceback.
rem
rem Pass --autostart (the Startup-folder shortcut does) to run unattended: no "press any key"
rem prompt is ever shown; failures are appended to data\logs\launcher.log and, where msg.exe
rem exists, popped up once.
cd /d "%~dp0"

set "AUTOSTART="
set "ARGS="
:parse_args
if "%~1"=="" goto args_parsed
if /i "%~1"=="--autostart" goto parse_autostart
set "ARGS=%ARGS% %1"
shift
goto parse_args
:parse_autostart
set "AUTOSTART=1"
shift
goto parse_args
:args_parsed

set "LOGDIR=%~dp0data\logs"
set "LAUNCHLOG=%LOGDIR%\launcher.log"
if not exist "%LOGDIR%" mkdir "%LOGDIR%" >nul 2>nul

set "VENVPY=.venv\Scripts\python.exe"
if exist "%VENVPY%" goto have_venv

rem ---- bootstrap interpreter (only needed the very first time) ----------------
rem Probe `python` first, then the `py` launcher. Probing (not `where`) is what catches the
rem Microsoft-Store python.exe stub, which is on PATH but is not an interpreter.
set "PY=python"
%PY% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>nul
if not errorlevel 1 goto bootstrap_ok
set "PY=py -3"
%PY% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>nul
if not errorlevel 1 goto bootstrap_ok
goto bad_bootstrap
:bootstrap_ok
echo [Home SOC] creating virtual environment ...
%PY% -m venv .venv
if errorlevel 1 goto venv_failed
if not exist "%VENVPY%" goto venv_failed
:have_venv

call ".venv\Scripts\activate.bat"
if errorlevel 1 goto activate_failed

rem ---- the venv must itself be 3.12+ (an old venv left over from an old Python) ----
python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)" >nul 2>nul
if errorlevel 1 goto bad_venv

rem ---- dependencies: only when requirements.txt actually changed --------------
rem Re-running pip at every logon is slow and, offline, prints a wall of errors.
rem requirements.txt is the hash-locked lock file (every transitive package, pip included), so
rem its SHA-256 below changes whenever any locked version is bumped - that is how a security fix
rem in urllib3/werkzeug/... reaches an existing .venv. --require-hashes makes pip refuse anything
rem unpinned, unlisted or whose bytes differ from the lock.
set "STAMP=.venv\.requirements.sha"
set "REQHASH="
for /f "skip=1 delims=" %%h in ('certutil -hashfile requirements.txt SHA256 2^>nul') do if not defined REQHASH set "REQHASH=%%h"
if not defined REQHASH goto pip_install
set "OLDHASH="
if exist "%STAMP%" set /p OLDHASH=<"%STAMP%"
if "%OLDHASH%"=="%REQHASH%" goto deps_ready
:pip_install
echo [Home SOC] installing dependencies ...
python -m pip install --require-hashes -r requirements.txt -q --disable-pip-version-check
if errorlevel 1 goto pip_failed
if not defined REQHASH goto deps_ready
>"%STAMP%" echo %REQHASH%
:deps_ready

python -m homesoc init
if errorlevel 1 goto init_failed

python -m homesoc run%ARGS%
set "RC=%ERRORLEVEL%"
if not "%RC%"=="0" goto run_failed
exit /b 0

rem --------------------------------------------------------------- failure paths
:bad_bootstrap
set "FOUNDVER=none on PATH"
for /f "delims=" %%v in ('%PY% --version 2^>^&1') do set "FOUNDVER=%%v"
set "MSG=Python 3.12 or newer is required - found: %FOUNDVER%. Install it from https://www.python.org/downloads/ and tick 'Add python.exe to PATH', then run run.bat again."
goto fail

:venv_failed
set "MSG=could not create the virtual environment in .venv - check that %PY% works and that this folder is writable."
goto fail

:activate_failed
set "MSG=.venv exists but .venv\Scripts\activate.bat failed - delete the .venv folder and run run.bat again."
goto fail

:bad_venv
set "FOUNDVER=unknown"
for /f "delims=" %%v in ('python --version 2^>^&1') do set "FOUNDVER=%%v"
set "MSG=the .venv virtual environment runs %FOUNDVER%, but Home SOC needs Python 3.12 or newer. Delete the .venv folder, install a newer Python, then run run.bat again."
goto fail

:pip_failed
set "MSG=dependency install failed - this usually means no internet connection. Connect and run run.bat again. If it keeps failing with a HASH mismatch, a download did not match requirements.txt - do not work around it; report it. See data\logs\launcher.log."
goto fail

:init_failed
set "MSG=python -m homesoc init failed - see data\logs\homesoc.log for the reason."
goto fail

:run_failed
set "MSG=Home SOC exited with code %RC% - see data\logs\homesoc.log."
goto fail

:fail
echo [Home SOC] %MSG%
>>"%LAUNCHLOG%" echo [%DATE% %TIME%] %MSG%
if defined AUTOSTART goto fail_unattended
pause
exit /b 1
:fail_unattended
msg "%USERNAME%" /TIME:120 "Home SOC could not start: %MSG%" >nul 2>nul
exit /b 1
