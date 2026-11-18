@echo off
cd /d "%~dp0"
set "LAB_PYTHON=%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe"
if exist "%LAB_PYTHON%" (
  "%LAB_PYTHON%" run_crapi_lab.py
) else (
  py -3 run_crapi_lab.py
)
if errorlevel 1 pause
