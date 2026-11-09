@echo off
cd /d "%~dp0"
set "DEMO_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if exist "%DEMO_PYTHON%" (
  "%DEMO_PYTHON%" run_crapi_demo.py
) else (
  py -3 run_crapi_demo.py
)
if errorlevel 1 pause
