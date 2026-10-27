@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Primero ejecuta: py -3.12 -m venv .venv
  echo Luego ejecuta: .venv\Scripts\python.exe -m pip install -r requirements.txt
  pause
  exit /b 1
)
".venv\Scripts\python.exe" relay.py %*
if errorlevel 1 pause
