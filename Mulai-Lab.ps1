$ErrorActionPreference='Stop'
Set-Location -LiteralPath $PSScriptRoot
$bundledPython=Join-Path $env:USERPROFILE '.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
if(Test-Path -LiteralPath $bundledPython){& $bundledPython run_lab.py --open}
elseif(Get-Command py -ErrorAction SilentlyContinue){py -3 run_lab.py --open}
elseif(Get-Command python -ErrorAction SilentlyContinue){python run_lab.py --open}
else{throw 'Python belum ditemukan. Gunakan Python 3.10 atau lebih baru.'}
