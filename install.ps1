$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw "Установите Python 3.11+ с python.org (Python Launcher)." }
$wireshark = Join-Path $env:ProgramFiles "Wireshark\tshark.exe"
if (Test-Path $wireshark) { $env:TSHARK = $wireshark }
elseif (-not (Get-Command tshark -ErrorAction SilentlyContinue)) { throw "Установите Wireshark с компонентом TShark. Для офлайн-разбора Npcap не обязателен." }
py -3 -c "import sys; assert sys.version_info >= (3,11)"
if ($LASTEXITCODE -ne 0) { throw "Нужен Python 3.11+" }
py -3 -m venv .venv
if ($LASTEXITCODE -ne 0) { throw "Ошибка создания окружения" }
& .venv\Scripts\python.exe -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) { throw "Не удалось установить зависимости" }
& .venv\Scripts\python.exe tools\make_examples.py
Write-Host "Установлено. Запуск: .\run.ps1"
