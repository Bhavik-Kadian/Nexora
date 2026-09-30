@echo off
rem Start SecureGate: double-click this file in File Explorer.
rem
rem It shows SecureGate at work on the demo project, without typing a single command:
rem   1. the first time only, it sets SecureGate up in .venv, like make setup (it asks first)
rem   2. the first time only, it builds the demo project in ..\securegate-demo, like make demo
rem   3. it scans the demo project's whole Git history, like make scan-demo
rem   4. it opens the dashboard in your browser, like make ui. Closing this window stops it.
rem
rem Keep this file in the SecureGate folder. Its line endings must stay CRLF (see
rem .gitattributes): cmd.exe can misread a batch file with LF line endings.

setlocal
title SecureGate
pushd "%~dp0"

set "PYTHON=.venv\Scripts\python.exe"
set "DEMO_DIR=..\securegate-demo"
set "REPORT=findings-demo.json"
set "HINT="

echo.
echo  SecureGate finds secrets in a Git project, masks them, and blocks the dangerous ones.
echo.

if not exist "pyproject.toml" goto :moved
if not exist "src\securegate\" goto :moved
if exist "%PYTHON%" goto :check

echo SecureGate is not set up in this folder yet. Setting it up installs it into the .venv
echo folder, like make setup. It needs the internet and takes a minute or two.
choice /c YN /m "Set it up now"
if errorlevel 2 goto :not_now
set "HINT=Setting it up needs Python 3.12 and the internet. Install Python with: winget install --id Python.Python.3.12 -e"
py -3.12 -m venv .venv || goto :failed
"%PYTHON%" -m pip install --upgrade pip || goto :failed
"%PYTHON%" -m pip install -e ".[dev]" || goto :failed
echo.

:check
set "HINT=The setup in the .venv folder looks broken. Delete that folder, then double-click this file again to set it up anew."
"%PYTHON%" -m securegate version || goto :failed
set "HINT="

echo.
if not exist "%DEMO_DIR%\.securegate-demo" goto :build
echo [1/3] The demo project is ready in %DEMO_DIR%
goto :scan

:build
echo [1/3] Building the demo project in %DEMO_DIR% (the first time only)...
"%PYTHON%" -m securegate demo-repo --out "%DEMO_DIR%" --seed 42 --force || goto :failed

:scan
echo.
echo [2/3] Scanning the demo project's whole Git history...
"%PYTHON%" -m securegate scan "%DEMO_DIR%" --mode repo --out "%REPORT%"
set "CODE=%ERRORLEVEL%"
rem 0 = nothing to block, 1 = secrets blocked (expected here). Anything else: the scan failed,
rem so stop rather than show an old report.
if not "%CODE%"=="0" if not "%CODE%"=="1" goto :failed
if "%CODE%"=="1" echo That is the expected result: the demo project is full of planted fake secrets.

echo.
echo [3/3] Opening the dashboard in your browser...
echo       Keep this window open while you use the dashboard. Close it to stop SecureGate.
echo.
title SecureGate dashboard - close this window to stop it
set "HINT=If SecureGate is open in another window, use that one: reload its page to see this scan. Or open PowerShell in this folder and run: .venv\Scripts\securegate ui --report %REPORT% --port 5050 --open"
"%PYTHON%" -m securegate ui --report "%REPORT%" --open || goto :failed
popd
exit /b 0

:moved
echo This file must stay in the SecureGate folder, next to pyproject.toml and the src folder.
echo To start SecureGate from the desktop, put a shortcut there instead: in the SecureGate
echo folder, right-click this file and select Show more options, Send to, Desktop (create shortcut).
goto :wait

:not_now
echo Nothing was changed. Double-click this file again when you are ready.
goto :wait

:failed
echo.
echo SecureGate stopped. The lines above say what went wrong.
if defined HINT echo %HINT%
echo More help: "If something goes wrong" in docs\presenting-to-judges.md

:wait
echo.
pause
popd
exit /b 1
