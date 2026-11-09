@echo off
setlocal
cd /d "%~dp0"
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" (
  "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" run_lab.py --open
  goto done
)
where py >nul 2>nul
if not errorlevel 1 (
  py -3 run_lab.py --open
  goto done
)
where python >nul 2>nul
if not errorlevel 1 (
  python run_lab.py --open
  goto done
)
echo Python belum ditemukan. Gunakan Python 3.10 atau lebih baru, lalu jalankan ulang.
:done
if errorlevel 1 pause
endlocal
