@echo off
REM ============================================================
REM  R.O.D.E v4 - one-click launcher (Windows)
REM  Double-click. Sets up a venv, installs deps, opens the app.
REM ============================================================
setlocal
cd /d "%~dp0"
title R.O.D.E v4

echo.
echo   R.O.D.E v4 - starting up...
echo.

where python >nul 2>&1
if errorlevel 1 (
  echo   [X] Python not found. Install Python 3.10+ from https://python.org
  echo       Tick "Add Python to PATH" during install.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo   [*] Creating virtual environment ^(first run only^)...
  python -m venv .venv
)
set PY=.venv\Scripts\python.exe

REM  ---- security self-check:  start.bat audit  ----
if /I "%~1"=="audit" goto :audit

echo   [*] Installing / upgrading dependencies...
"%PY%" -m pip install --quiet --upgrade pip
"%PY%" -m pip install --quiet --upgrade -r requirements.txt
if errorlevel 1 (
  echo   [X] Dependency install failed. See messages above.
  pause
  exit /b 1
)

echo.
echo   [OK] Open  http://127.0.0.1:8000   ^(opening browser^)
echo   Press Ctrl+C in this window to stop.
echo.
start "" http://127.0.0.1:8000
"%PY%" -m backend.run

pause
exit /b 0

REM ============================================================
REM  Security self-check (dogfood):  start.bat audit
REM ============================================================
:audit
echo.
echo   [*] R.O.D.E security self-check (pip-audit)...
"%PY%" -m pip install --quiet --upgrade pip pip-audit
"%PY%" -m pip_audit -r requirements.txt
echo.
echo   Tip: also run  trivy fs .  from this folder for secrets + misconfig scanning.
echo   (see docs\OFFENSIVE_SETUP.md)
echo.
pause
exit /b 0
