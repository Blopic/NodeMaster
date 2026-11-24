@echo off
setlocal
cd /d "%~dp0"
if not exist .venv\Scripts\python.exe (
  echo No NodeMaster environment found. Stop the server with Ctrl+C in its window.
  exit /b 1
)
.venv\Scripts\python.exe -m nodemaster --stop
