$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$wireshark = Join-Path $env:ProgramFiles "Wireshark\tshark.exe"
if (Test-Path $wireshark) { $env:TSHARK = $wireshark }
& .venv\Scripts\python.exe launcher.py @args
