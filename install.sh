#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
if [[ "${1:-}" == "--system-tools" ]]; then
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y python3 python3-venv python3-tk tshark
  else
    echo 'Установите Python 3.11+ и TShark средствами своей ОС, затем повторите без --system-tools.'
    exit 1
  fi
fi
command -v python3 >/dev/null || { echo 'Установите Python 3.11+.'; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3,11), "Нужен Python 3.11+"'
command -v tshark >/dev/null || { echo 'TShark не найден. Ubuntu/Debian: bash install.sh --system-tools'; exit 1; }
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python tools/make_examples.py
echo 'Установка завершена. Запуск: bash run.sh --project ./my-research'
