@echo off
setlocal
cd /d "%~dp0"
if exist .venv\Scripts\python.exe goto :install
for %%P in ("py -3.11" "py -3" "python") do (
  call %%~P -c "import sys; sys.exit(sys.version_info < (3, 11))" >nul 2>&1
  if not errorlevel 1 (
    set "NODEMASTER_PYTHON=%%~P"
    goto :create_venv
  )
)
echo Install Python 3.11 or newer from https://www.python.org/downloads/windows/.
echo Enable the option to add Python to PATH, then open a new terminal and run run.bat again.
exit /b 1

:create_venv
call %NODEMASTER_PYTHON% -m venv .venv
if errorlevel 1 exit /b %errorlevel%

:install
.venv\Scripts\python.exe -c "import pip" >nul 2>nul
if errorlevel 1 .venv\Scripts\python.exe -m ensurepip --upgrade
.venv\Scripts\python.exe -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 exit /b 1
if not exist nodemaster\static\index.html (
  where npm.cmd >nul 2>nul
  if errorlevel 1 (
    echo Install Node.js 22 or newer to build the NodeMaster interface.
    exit /b 1
  )
  call npm.cmd --prefix frontend ci --no-audit --no-fund
  if errorlevel 1 exit /b 1
  call npm.cmd --prefix frontend run build
  if errorlevel 1 exit /b 1
)
.venv\Scripts\python.exe -m nodemaster
