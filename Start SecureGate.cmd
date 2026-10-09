@echo off
rem Start SecureGate: double-click this file in File Explorer.
rem
rem It opens SecureGate's menu in this window, so nobody has to type a command:
rem   1. the first time only, it sets SecureGate up in .venv, like make setup (it asks first)
rem   2. it checks that the setup works, like securegate version
rem   3. it opens the menu, like make menu: scan the demo project or a project of your own,
rem      open the dashboard, see the rules. Choosing Q in the menu closes this window.
rem
rem Keep this file in the SecureGate folder. Its line endings must stay CRLF (see
rem .gitattributes): cmd.exe can misread a batch file with LF line endings.

setlocal
title SecureGate
pushd "%~dp0"

set "PYTHON=.venv\Scripts\python.exe"
set "HINT="

if not exist "pyproject.toml" goto :moved
if not exist "src\securegate\" goto :moved
if exist "%PYTHON%" goto :check

echo.
echo  SecureGate finds secrets in a Git project, masks them, and blocks the dangerous ones.
echo.
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

"%PYTHON%" -m securegate menu || goto :failed
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
echo More help: "If something goes wrong" in docs\getting-started.md

:wait
echo.
pause
popd
exit /b 1
